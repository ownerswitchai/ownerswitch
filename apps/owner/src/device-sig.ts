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
 * Fields of a cheap-lane device signature (DESIGN.md §3, DEVICE_SIG_LABEL).
 * The preimage binds the method, the path AND query, and the body — so a
 * signature for `GET /veto/w1` is useless for `POST /veto/w1` or `GET /veto/w2`.
 */
export interface DeviceSigFields {
  deviceId: string;
  /** HTTP method — signed upper-cased, so "get" and "GET" can never disagree. */
  method: string;
  /** request path AND query, byte-exact as sent (percent-encoding preserved). */
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
  if (!Number.isInteger(fields.timestamp)) {
    throw new RangeError("timestamp must be an integer (ms since epoch)");
  }
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
