/*
 * renderable-alert.mjs — the browser side of the RenderableAlertV1 contract:
 * validate the envelope the control plane served, canonicalize it, and
 * recompute its hash with WebCrypto. The device REFUSES to ack a render whose
 * recomputed hash differs from the server's renderContentHash — the ack must
 * prove "I rendered THESE bytes", not "I echoed the hash you told me to echo"
 * (apps/owner/DESIGN.md §3).
 *
 * DRIFT-PINNED to @ownerswitchai/shared's renderable-alert.ts (validator,
 * limits, FORBIDDEN classes, canonical JSON) by src/render-ack.test.ts, the
 * same way owner-crypto.mjs is pinned to the shared preimage: public/ is
 * served as plain files with no bundler, so the shared TS module cannot be
 * imported here — the test is what keeps the two implementations one.
 */

export const RENDERABLE_ALERT_V1_LIMITS = { agentId: 64, tool: 64, summary: 200 };

// Everything that can lie about or hide visible content, by Unicode PROPERTY —
// identical to shared's RENDERABLE_ALERT_FORBIDDEN.
export const RENDERABLE_ALERT_FORBIDDEN =
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Bidi_Control}\p{Default_Ignorable_Code_Point}]/u;

const ALLOWED_KEYS = new Set(["v", "agentId", "tool", "summary"]);

function codePointLength(text) {
  let count = 0;
  for (const _ of text) count++;
  return count;
}

/** First conformance violation or null — the exact V1 schema, nothing else. */
export function validateRenderableAlert(alert) {
  if (typeof alert !== "object" || alert === null || Array.isArray(alert)) {
    return { field: "envelope", reason: "malformed" };
  }
  for (const key of Object.keys(alert)) {
    if (!ALLOWED_KEYS.has(key)) return { field: "envelope", reason: "unexpected-property" };
  }
  if (alert.v !== 1) return { field: "v", reason: "unsupported-version" };
  for (const [field, limit] of [
    ["agentId", RENDERABLE_ALERT_V1_LIMITS.agentId],
    ["tool", RENDERABLE_ALERT_V1_LIMITS.tool],
    ["summary", RENDERABLE_ALERT_V1_LIMITS.summary],
  ]) {
    const value = alert[field];
    if (typeof value !== "string") return { field, reason: "not-a-string" };
    if (codePointLength(value) > limit) return { field, reason: "too-long" };
    if (RENDERABLE_ALERT_FORBIDDEN.test(value)) return { field, reason: "forbidden-character" };
  }
  return null;
}

/** Deep-key-sorted, whitespace-free JSON — mirrors shared's canonicalJson. */
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

/** The canonical envelope string; full V1 conformance is a precondition. */
export function canonicalRenderableAlert(alert) {
  const violation = validateRenderableAlert(alert);
  if (violation !== null) throw new Error(`RenderableAlertV1.${violation.field}: ${violation.reason}`);
  return canonicalJson({ v: alert.v, agentId: alert.agentId, tool: alert.tool, summary: alert.summary });
}

function base64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * base64url(sha256(canonical envelope)) — byte-identical to the control
 * plane's renderContentHashOf, so the device can recompute the hash the server
 * issued from the very fields it rendered.
 */
export async function renderContentHash(alert) {
  const bytes = new TextEncoder().encode(canonicalRenderableAlert(alert));
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return base64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer)));
}
