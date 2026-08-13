/**
 * RenderableAlertV1 — mint-time conformance and its canonical hash (DESIGN.md
 * §3, "Truthful rendering"). The payload hash proves the device rendered the
 * bytes the server issued; those bounds are what make the bytes mean what the
 * human read (UTR #36: bidi overrides, control characters, and truncation can
 * make true bytes read as a false sentence).
 *
 * The conformance schema and the canonical envelope are NO LONGER duplicated
 * here: they are the ONE definition in @ownerswitchai/shared, so "the server
 * minted these bytes" and "the device rendered these bytes" are the same bytes
 * by construction — a validator that drifts between the two sides is the exact
 * failure this unification removes (the header note the previous local copy
 * carried: "to be unified at integration"). This module now adds only the
 * WebCrypto hashing the shared, crypto-free module leaves to each side.
 */
import {
  assertRenderableAlert,
  canonicalRenderableAlert,
  validateRenderableAlert,
} from "@ownerswitchai/shared";
import type { Base64Url } from "./types.js";

// Re-exported so existing owner-app importers keep one import site; the
// definitions are shared's.
export { assertRenderableAlert, canonicalRenderableAlert, validateRenderableAlert };
export type { AlertField, AlertViolation } from "@ownerswitchai/shared";

/* --- WebCrypto hashing (the one thing shared leaves per-side) --- */

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
 * renderContentHash — base64url(sha256(canonical RenderableAlertV1)). Pinned
 * into the WindowRevision so one revision means exactly one rendering
 * (DESIGN.md §3): two summaries, or two schema versions, can never both be
 * valid under one revision. Byte-identical to the control plane's
 * base64url(sha256(canonicalRenderableAlert)) — SAME canonical envelope, SAME
 * encoding — so the device can recompute the hash the server issued and refuse
 * to ack a render that does not match. Refuses a non-conforming alert (via
 * shared's assertRenderableAlert, inside canonicalRenderableAlert).
 */
export async function renderContentHash(alert: unknown): Promise<Base64Url> {
  return base64urlEncode(await sha256(utf8(canonicalRenderableAlert(alert))));
}
