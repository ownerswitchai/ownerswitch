/**
 * RenderableAlertV1 — mint-time conformance and its canonical hash (DESIGN.md
 * §3, "Truthful rendering"). The payload hash proves the device rendered the
 * bytes the server issued; these bounds are what make those bytes mean what
 * the human read. UTR #36: bidi overrides, control characters, and truncation
 * can make true bytes read as a false sentence — so conformance is enforced
 * where the text is MINTED: a conforming alert cannot reorder or hide its
 * decisive facts, and its size makes native truncation UNLIKELY — an
 * assumption about platform surfaces, not something the app can prove (the
 * Notifications API reports no truncation or visibility result). Which is why
 * no notification render ever produces ack evidence: the ack comes only from
 * the app's own foreground detail view, where it renders the full envelope
 * itself, each field in its own bidi isolate (DESIGN.md §3–§4).
 *
 * Self-contained by intent (this package's wire types import nothing across the
 * network boundary): the byte helpers mirror `bytes.ts` and the canonical JSON
 * mirrors `@ownerswitchai/shared`'s `canonicalJson` — to be unified at
 * integration, pinned meanwhile by the golden tests here.
 */
import { RENDERABLE_ALERT_V1_LIMITS, type Base64Url, type RenderableAlertV1 } from "./types.js";

/* --- minimal byte helpers (mirror bytes.ts; see the header note) --- */

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // Copy into a plain ArrayBuffer: a Uint8Array's buffer may type as
  // SharedArrayBuffer, which is not a BufferSource for subtle.digest().
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
}

/**
 * Deep-key-sorted, whitespace-free JSON (UTF-8) — the executor's
 * canonicalization vocabulary (DESIGN.md §5), mirrored locally so one
 * revision pins exactly one rendering.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/* --- conformance --- */

/**
 * Everything that can lie about or hide visible content, by Unicode
 * PROPERTY, not by a hand-maintained list — the same classes (and the same
 * regex) as `FORBIDDEN` in packages/shared/src/merge-args.ts:
 *  - Cc/Cf: controls and format characters (CR/LF/TAB, ZWSP, SOFT HYPHEN,
 *    LRM/RLM/ALM — every field is a single visible line);
 *  - Zl/Zp: line/paragraph separators;
 *  - Bidi_Control: the "reorder the visible sentence" class (UTR #36) —
 *    including U+061C and the marks, not just the nine embedding/override/
 *    isolate controls a list would name;
 *  - Default_Ignorable_Code_Point: invisibly renderable characters
 *    (variation selectors, Hangul fillers, tag characters).
 * A property net has no "we forgot U+061C" failure mode.
 */
const FORBIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Bidi_Control}\p{Default_Ignorable_Code_Point}]/u;

/** Unicode code points, not UTF-16 units — the limit holds for astral chars too. */
function codePointLength(text: string): number {
  let count = 0;
  for (const _ of text) count++;
  return count;
}

export type AlertField = "agentId" | "tool" | "summary";

export interface AlertViolation {
  field: AlertField | "v" | "envelope";
  reason:
    | "malformed"
    | "unexpected-property"
    | "unsupported-version"
    | "not-a-string"
    | "too-long"
    | "forbidden-character";
}

const ALLOWED_KEYS: ReadonlySet<string> = new Set(["v", "agentId", "tool", "summary"]);

/**
 * The first conformance violation, or null if the alert conforms. Takes
 * `unknown` on purpose — this is the mint boundary, and the check is the
 * whole runtime V1 schema, not just the text fields: a plain object with the
 * literal `v: 1`, exactly the four known properties, three string fields;
 * then per-field code-point limits (RENDERABLE_ALERT_V1_LIMITS) and the
 * FORBIDDEN property classes above. An unknown version or an extra property
 * is refused — a function that hashes "RenderableAlertV1" must never hash
 * something else. Legitimate RTL text (Hebrew, Arabic letters) is NOT a
 * control and conforms; the client isolates it at display (DESIGN.md §3).
 */
export function validateRenderableAlert(alert: unknown): AlertViolation | null {
  if (typeof alert !== "object" || alert === null || Array.isArray(alert)) {
    return { field: "envelope", reason: "malformed" };
  }
  const record = alert as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(key)) return { field: "envelope", reason: "unexpected-property" };
  }
  if (record.v !== 1) return { field: "v", reason: "unsupported-version" };
  const fields: ReadonlyArray<readonly [AlertField, number]> = [
    ["agentId", RENDERABLE_ALERT_V1_LIMITS.agentId],
    ["tool", RENDERABLE_ALERT_V1_LIMITS.tool],
    ["summary", RENDERABLE_ALERT_V1_LIMITS.summary],
  ];
  for (const [field, limit] of fields) {
    const value = record[field];
    if (typeof value !== "string") return { field, reason: "not-a-string" };
    if (codePointLength(value) > limit) return { field, reason: "too-long" };
    if (FORBIDDEN.test(value)) return { field, reason: "forbidden-character" };
  }
  return null;
}

/** Throwing form — the server refuses to mint a non-conforming revision. */
export function assertRenderableAlert(alert: unknown): asserts alert is RenderableAlertV1 {
  const violation = validateRenderableAlert(alert);
  if (violation !== null) {
    throw new Error(`RenderableAlertV1.${violation.field}: ${violation.reason}`);
  }
}

/** The canonical envelope string — full V1 conformance is a precondition. */
export function canonicalRenderableAlert(alert: unknown): string {
  assertRenderableAlert(alert);
  return canonicalJson({
    v: alert.v,
    agentId: alert.agentId,
    tool: alert.tool,
    summary: alert.summary,
  });
}

/**
 * renderContentHash — SHA-256 of the canonical envelope, base64url. Pinned into
 * the WindowRevision so one revision means exactly one rendering (DESIGN.md
 * §3): two summaries, or two schema versions, can never both be valid under one
 * revision. Refuses a non-conforming alert (via assertRenderableAlert).
 */
export async function renderContentHash(alert: unknown): Promise<Base64Url> {
  return base64urlEncode(await sha256(utf8(canonicalRenderableAlert(alert))));
}
