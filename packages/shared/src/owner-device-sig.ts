/**
 * The owner app's cheap-lane device-signature preimage — the ONE source of
 * truth for "what bytes get signed", shared by the signer (the owner app,
 * apps/owner) and the verifier (the control plane). The owner app holds a
 * NON-EXTRACTABLE ECDSA P-256 private key; the control plane holds only the
 * exportable SPKI public key and verifies signatures over exactly these
 * bytes (apps/owner/DESIGN.md §3). Keeping the encoder here — not duplicated
 * per side — is what makes "the app signed X, the server verified X" a fact
 * rather than a hope.
 *
 * Signature algorithm is pinned by the design: ECDSA on P-256 with SHA-256,
 * signature in WebCrypto's RAW r||s form (64 bytes), never DER. The verifier
 * lives in the control plane (packages/control-plane/src/owner-device.ts).
 *
 * Portable across the browser app and Node: only TextEncoder/DataView are
 * used, both globals in each.
 */

/** Domain-separation label. MUST match apps/owner/src/types.ts byte-for-byte. */
export const OWNER_DEVICE_SIG_LABEL = "ownerswitch/device-sig/v1";

/** SHA-256 digest length — the body-hash field is exactly this. */
const SHA256_LEN = 32;

/** A length that cannot be counted in a 4-byte big-endian prefix. */
const MAX_FIELD = 0xffff_ffff;

/**
 * Concatenate `fields`, each prefixed by its 4-byte big-endian length.
 * Injective: the prefixes bind the field boundaries, so `["a","b"]` and
 * `["ab",""]` are distinct byte strings and a signature over the encoding
 * cannot be transplanted across a re-split.
 */
export function lengthPrefixed(fields: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const field of fields) {
    if (field.length > MAX_FIELD) throw new RangeError("field too long to length-prefix in 4 bytes");
    total += 4 + field.length;
  }
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint32(offset, field.length, false); // big-endian
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

/**
 * The request path AND query must be the ALREADY-SERIALIZED origin-form
 * request target, byte-exact as sent: leading "/", printable ASCII only, no
 * fragment, complete UPPERCASE-hex percent escapes, and stable under the URL
 * serializer every fetch runs. Raw Unicode or lowercase-hex would sign bytes
 * the wire never carries (or let two spellings both verify). Ported verbatim
 * from apps/owner/src/device-sig.ts so signer and verifier agree exactly.
 */
export function assertCanonicalPathAndQuery(pathAndQuery: string): void {
  if (!pathAndQuery.startsWith("/")) {
    throw new Error('pathAndQuery must be origin-form — it must start with "/"');
  }
  for (let i = 0; i < pathAndQuery.length; i++) {
    const code = pathAndQuery.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) {
      throw new Error(
        "pathAndQuery must be the serialized request target: printable ASCII only, " +
          "no spaces — percent-encode everything else exactly as it will be sent",
      );
    }
  }
  if (pathAndQuery.includes("#")) {
    throw new Error("pathAndQuery must not carry a fragment — a fragment is never sent");
  }
  for (const m of pathAndQuery.matchAll(/%.{0,2}/g)) {
    if (!/^%[0-9A-F]{2}$/.test(m[0])) {
      throw new Error(
        `pathAndQuery has a non-canonical percent escape ${JSON.stringify(m[0])} — ` +
          "escapes must be complete and uppercase-hex",
      );
    }
  }
  let parsed: URL;
  try {
    parsed = new URL(pathAndQuery, "http://canonical.invalid");
  } catch {
    throw new Error("pathAndQuery does not parse as a request target");
  }
  if (parsed.pathname + parsed.search !== pathAndQuery) {
    throw new Error(
      "pathAndQuery is not serialized request-target bytes — the URL serializer would " +
        `transmit ${JSON.stringify(parsed.pathname + parsed.search)}; sign that instead`,
    );
  }
}

/**
 * Fields of a cheap-lane device signature. The preimage binds the method,
 * the path AND query, and the body hash — so a signature for `GET /veto/w1`
 * is useless for `POST /veto/w1` or `GET /veto/w2`.
 */
export interface OwnerDeviceSigFields {
  deviceId: string;
  /** HTTP method — signed UPPER-cased, so "get" and "GET" cannot disagree. */
  method: string;
  /** request path AND query, byte-exact as sent (see assertCanonicalPathAndQuery). */
  pathAndQuery: string;
  /** SHA-256 of the EXACT body bytes (32 bytes); empty body = hash of zero bytes. */
  bodyHash: Uint8Array;
  /** decimal ms timestamp; the 60 s skew/replay bound reads it. */
  timestamp: number;
  /** single-use nonce. */
  nonce: string;
}

/**
 * The signed preimage: label, deviceId, upper-cased method, path+query, the
 * 32-byte body hash, the decimal timestamp, the nonce — each length-prefixed.
 */
export function ownerDeviceSigPreimage(fields: OwnerDeviceSigFields): Uint8Array {
  if (fields.bodyHash.length !== SHA256_LEN) {
    throw new RangeError(`bodyHash must be a ${SHA256_LEN}-byte SHA-256 digest`);
  }
  if (!Number.isSafeInteger(fields.timestamp)) {
    throw new RangeError("timestamp must be a safe integer (ms since epoch)");
  }
  assertCanonicalPathAndQuery(fields.pathAndQuery);
  return lengthPrefixed([
    utf8(OWNER_DEVICE_SIG_LABEL),
    utf8(fields.deviceId),
    utf8(fields.method.toUpperCase()),
    utf8(fields.pathAndQuery),
    fields.bodyHash,
    utf8(String(fields.timestamp)),
    utf8(fields.nonce),
  ]);
}
