/**
 * The owner app's cheap-lane canonical transcripts — the exact bytes that get
 * signed for a device signature (DESIGN.md §3) and for the enrolment proof of
 * possession (DESIGN.md §2). Building the preimage and signing it are separate
 * concerns; this module is only the deterministic, injective encoding, so the
 * app (signer) and the control plane (verifier) can share one source of truth
 * for "what was signed" and a test can pin it byte-for-byte.
 */
import { lengthPrefixed, utf8 } from "./bytes.js";
import { DEVICE_SIG_LABEL, ENROLL_POP_LABEL } from "./types.js";

/** SHA-256 digest length — the body hash field is exactly this. */
const SHA256_LEN = 32;

/**
 * The design pins pathAndQuery as "the request path and query EXACTLY AS SENT
 * (byte-exact, percent-encoding preserved)" — so the value signed here must
 * BE serialized request-target bytes, not something that merely serializes to
 * them. A raw-Unicode "/x?q=é" would UTF-8-sign bytes the wire never carries
 * (it sends "/x?q=%C3%A9"), and lowercase percent-hex would let two spellings
 * of one target both verify. Accepted: origin-form only — starts with "/",
 * printable ASCII (no spaces, no controls, nothing above 0x7E), no "#"
 * fragment, and every "%" beginning a complete UPPERCASE-hex escape (the
 * canonical case, RFC 3986 §6.2.2.1, and what encodeURIComponent emits).
 */
function assertCanonicalPathAndQuery(pathAndQuery: string): void {
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
  const escapes = pathAndQuery.matchAll(/%.{0,2}/g);
  for (const m of escapes) {
    if (!/^%[0-9A-F]{2}$/.test(m[0])) {
      throw new Error(
        `pathAndQuery has a non-canonical percent escape ${JSON.stringify(m[0])} — ` +
          "escapes must be complete and uppercase-hex",
      );
    }
  }
  // WHATWG fixpoint: printable-ASCII is necessary but not sufficient — the URL
  // serializer every fetch runs re-encodes some code points position-dependently
  // (`"` `<` `>` `` ` `` always; `{` `}` in the path; `\` becomes `/`), so a
  // string it would rewrite signs bytes the wire never carries. Parse against a
  // fixed dummy origin and require the serialized form to reproduce the input
  // byte-for-byte. This is the exact per-position truth: `^` or `{` in a query
  // survive serialization verbatim, so they verify; the same `{` in a path does
  // not, so it is refused. Also collapses protocol-relative "//host" smuggling.
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
 * Fields of a cheap-lane device signature (DESIGN.md §3, DEVICE_SIG_LABEL).
 * The preimage binds the method, the path AND query, and the body — so a
 * signature for `GET /veto/w1` is useless for `POST /veto/w1` or `GET /veto/w2`.
 */
export interface DeviceSigFields {
  deviceId: string;
  /** HTTP method — signed upper-cased, so "get" and "GET" can never disagree. */
  method: string;
  /**
   * Request path AND query, byte-exact as sent — the ALREADY-SERIALIZED
   * origin-form request target: leading "/", printable ASCII only, no
   * fragment, complete uppercase-hex percent escapes. Raw Unicode is
   * refused: it would sign bytes the wire never carries.
   */
  pathAndQuery: string;
  /**
   * SHA-256 of the EXACT body bytes (32 bytes). An empty body is the hash of
   * zero bytes — present, not omitted — so a body-less GET is still bound to
   * its method and path (DESIGN.md §3).
   */
  bodyHash: Uint8Array;
  /** decimal ms timestamp; the scheme's 60 s skew/replay bound reads it. */
  timestamp: number;
  /** single-use nonce. */
  nonce: string;
}

/**
 * The signed preimage of a cheap-lane device signature. Order and framing are
 * pinned: label, deviceId, upper-cased method, path+query, the 32-byte body
 * hash, the decimal timestamp, the nonce — each length-prefixed (injective).
 */
export function deviceSigPreimage(fields: DeviceSigFields): Uint8Array {
  if (fields.bodyHash.length !== SHA256_LEN) {
    throw new RangeError(`bodyHash must be a ${SHA256_LEN}-byte SHA-256 digest`);
  }
  if (!Number.isSafeInteger(fields.timestamp)) {
    throw new RangeError("timestamp must be a safe integer (ms since epoch)");
  }
  assertCanonicalPathAndQuery(fields.pathAndQuery);
  return lengthPrefixed([
    utf8(DEVICE_SIG_LABEL),
    utf8(fields.deviceId),
    utf8(fields.method.toUpperCase()),
    utf8(fields.pathAndQuery),
    fields.bodyHash,
    utf8(String(fields.timestamp)),
    utf8(fields.nonce),
  ]);
}

/**
 * Fields of the enrolment proof of possession (DESIGN.md §2, ENROLL_POP_LABEL).
 * `credentialId` and `spki` are RAW bytes — decode their base64url wire forms
 * before building the transcript, because the raw bytes are what gets signed.
 */
export interface EnrollPopFields {
  inviteId: string;
  ownerId: string;
  /** raw WebAuthn credential id bytes (base64url-decoded). */
  credentialId: Uint8Array;
  /** raw SPKI public-key bytes of the cheap-lane key. */
  spki: Uint8Array;
}

/**
 * The signed transcript proving possession of the cheap-lane private key at
 * enrolment. Pinned order: label, inviteId, ownerId, raw credential id, raw
 * SPKI — each length-prefixed, so no field's bytes can migrate into another.
 */
export function enrollPopTranscript(fields: EnrollPopFields): Uint8Array {
  return lengthPrefixed([
    utf8(ENROLL_POP_LABEL),
    utf8(fields.inviteId),
    utf8(fields.ownerId),
    fields.credentialId,
    fields.spki,
  ]);
}
