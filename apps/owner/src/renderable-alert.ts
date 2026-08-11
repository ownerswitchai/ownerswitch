/**
 * RenderableAlertV1 — mint-time conformance and its canonical hash (DESIGN.md
 * §3, "Truthful rendering"). The payload hash proves the device rendered the
 * bytes the server issued; these bounds are what make those bytes mean what
 * the human read. UTR #36: bidi overrides, control characters, and truncation
 * can make true bytes read as a false sentence — so conformance is enforced
 * where the text is MINTED, and a conforming alert fits un-truncated and cannot
 * reorder or hide its decisive facts. The client only renders each field in its
 * own bidi isolate and verifies.
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

/** LRE RLE PDF LRO RLO LRI RLI FSI PDI — the explicit bidi controls (UTR #36). */
const BIDI_CONTROLS: ReadonlySet<number> = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
]);

function isForbiddenCodePoint(codePoint: number): boolean {
  if (codePoint <= 0x1f || codePoint === 0x7f) return true; // C0 controls (incl. TAB/LF/CR) + DEL
  if (codePoint >= 0x80 && codePoint <= 0x9f) return true; // C1 controls
  return BIDI_CONTROLS.has(codePoint); // explicit bidi embedding/override/isolate
}

/** Unicode code points, not UTF-16 units — the limit holds for astral chars too. */
function codePointLength(text: string): number {
  let count = 0;
  for (const _ of text) count++;
  return count;
}

export type AlertField = "agentId" | "tool" | "summary";

export interface AlertViolation {
  field: AlertField;
  reason: "too-long" | "forbidden-character";
}

/**
 * The first conformance violation, or null if the alert conforms: per-field
 * code-point limits (RENDERABLE_ALERT_V1_LIMITS), no C0/C1 controls (every
 * field is a single line — CR/LF/TAB included), no explicit bidi controls.
 * Legitimate RTL text (Hebrew, Arabic letters) is NOT a control and conforms;
 * the client isolates it at display (DESIGN.md §3).
 */
export function validateRenderableAlert(alert: RenderableAlertV1): AlertViolation | null {
  const fields: ReadonlyArray<readonly [AlertField, string, number]> = [
    ["agentId", alert.agentId, RENDERABLE_ALERT_V1_LIMITS.agentId],
    ["tool", alert.tool, RENDERABLE_ALERT_V1_LIMITS.tool],
    ["summary", alert.summary, RENDERABLE_ALERT_V1_LIMITS.summary],
  ];
  for (const [field, value, limit] of fields) {
    if (codePointLength(value) > limit) return { field, reason: "too-long" };
    for (const char of value) {
      const codePoint = char.codePointAt(0);
      if (codePoint !== undefined && isForbiddenCodePoint(codePoint)) {
        return { field, reason: "forbidden-character" };
      }
    }
  }
  return null;
}

/** Throwing form — the server refuses to mint a non-conforming revision. */
export function assertRenderableAlert(alert: RenderableAlertV1): void {
  const violation = validateRenderableAlert(alert);
  if (violation !== null) {
    throw new Error(`RenderableAlertV1.${violation.field}: ${violation.reason}`);
  }
}

/** The canonical envelope string — conformance is a precondition. */
export function canonicalRenderableAlert(alert: RenderableAlertV1): string {
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
export async function renderContentHash(alert: RenderableAlertV1): Promise<Base64Url> {
  return base64urlEncode(await sha256(utf8(canonicalRenderableAlert(alert))));
}
