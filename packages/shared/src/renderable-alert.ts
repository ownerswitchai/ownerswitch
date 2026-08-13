import { canonicalJson } from "./merge-grant.js";

/**
 * RenderableAlertV1 — the ONE canonical alert envelope and its conformance,
 * shared by the mint (control plane) and the render (owner app), so
 * "the server issued these bytes" and "the device rendered these bytes" are
 * the same bytes by construction (apps/owner/DESIGN.md §3). Previously this
 * lived only in apps/owner; unifying it here is what the design note there
 * anticipated ("to be unified at integration").
 *
 * The envelope is EXACTLY {v, agentId, tool, summary} — nothing else is
 * hashed, so no ad-hoc field can ride in the render hash. The FORBIDDEN net
 * blocks, by Unicode PROPERTY, everything that can make true bytes read as a
 * false sentence (UTR #36): controls/format (Cc/Cf), line/paragraph
 * separators (Zl/Zp), bidi controls, and default-ignorable code points. The
 * per-field code-point limits keep the alert short enough that native
 * truncation is unlikely.
 *
 * Hashing is done per side over `canonicalRenderableAlert()` — the server
 * with node:crypto, the client with WebCrypto — both as base64url(sha256(utf8)),
 * so the strings match. This module stays crypto-free and portable.
 */

export const RENDERABLE_ALERT_V1_LIMITS = { agentId: 64, tool: 64, summary: 200 } as const;

export interface RenderableAlertV1 {
  v: 1;
  agentId: string;
  tool: string;
  summary: string;
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

/**
 * Everything that can lie about or hide visible content, by Unicode PROPERTY
 * (the same class as FORBIDDEN in merge-args.ts). A property net has no "we
 * forgot U+061C" failure mode. Legitimate RTL letters (Hebrew, Arabic) are
 * NOT controls and conform — the client isolates them at display.
 */
export const RENDERABLE_ALERT_FORBIDDEN =
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Bidi_Control}\p{Default_Ignorable_Code_Point}]/u;

const ALLOWED_KEYS: ReadonlySet<string> = new Set(["v", "agentId", "tool", "summary"]);

/** Unicode code points, not UTF-16 units — the limit holds for astral chars too. */
export function codePointLength(text: string): number {
  let count = 0;
  for (const _ of text) count++;
  return count;
}

/**
 * The first conformance violation, or null if the alert conforms. The whole
 * runtime V1 schema: exactly {v:1, agentId, tool, summary}, three strings,
 * per-field code-point limits, and no FORBIDDEN characters. An unknown
 * version or an extra property is refused — a function that hashes
 * "RenderableAlertV1" must never hash something else.
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
    if (RENDERABLE_ALERT_FORBIDDEN.test(value)) return { field, reason: "forbidden-character" };
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
  return canonicalJson({ v: alert.v, agentId: alert.agentId, tool: alert.tool, summary: alert.summary });
}
