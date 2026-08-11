/**
 * Byte primitives for the owner app's canonical encoders — the injective
 * length-prefixed concatenation the design leans on everywhere (DESIGN.md
 * §2, §3), plus base64url (RFC 4648 §5, no padding) and SHA-256. Portable
 * across the browser app and Node: WebCrypto, TextEncoder, and atob/btoa are
 * globals in both, and nothing here reaches for anything else.
 */

/** A length that cannot be counted in a 4-byte big-endian prefix. */
const MAX_FIELD = 0xffff_ffff;

/**
 * Concatenate `fields`, each prefixed by its byte length as a 4-byte
 * big-endian unsigned integer. Injective by construction: the prefixes make
 * `["ab",""]`, `["a","b"]`, and `["","ab"]` three distinct byte strings — the
 * same ambiguity guard as the dot-length rule in the control plane, so a
 * signature over the encoding binds the field boundaries, not just their
 * concatenation. A field longer than 2^32−1 bytes cannot be counted in four
 * bytes and is refused rather than silently truncated (which would reopen the
 * ambiguity).
 */
export function lengthPrefixed(fields: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const field of fields) {
    if (field.length > MAX_FIELD) {
      throw new RangeError("field too long to length-prefix in 4 bytes");
    }
    total += 4 + field.length;
  }
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint32(offset, field.length, false); // false = big-endian
    offset += 4;
    out.set(field, offset);
    offset += field.length;
  }
  return out;
}

/** UTF-8 encode — text becomes bytes exactly one way. */
export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The base64url alphabet, no padding — rejected input never guesses. */
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** base64url encode (RFC 4648 §5), no padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url decode (RFC 4648 §5); refuses non-alphabet input rather than guessing. */
export function base64urlDecode(text: string): Uint8Array {
  if (!BASE64URL.test(text)) throw new Error("invalid base64url");
  const padding = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + padding);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** SHA-256 via WebCrypto (a global in modern browsers and Node ≥ 20). */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // Copy into a plain ArrayBuffer: a Uint8Array's buffer may type as
  // SharedArrayBuffer, which is not a BufferSource for subtle.digest().
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return new Uint8Array(digest);
}
