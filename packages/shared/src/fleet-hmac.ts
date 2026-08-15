import {
  assertCanonicalPathAndQuery,
  lengthPrefixed,
  utf8,
} from "./owner-device-sig.js";

/**
 * The FLEET device-HMAC v2 preimage — the one source of truth for what a
 * fleet-secret holder signs, shared by every signer (gateway veto-client,
 * escalation relay, honeytoken reporter, button daemon, verify/doctor) and
 * the control-plane verifier. The workspace console keeps a byte-identical
 * LOCAL mirror (zero-runtime-dependency rule), drift-pinned by test.
 *
 * v2 exists because v1 (`deviceId.timestamp.nonce.body`, PR #62 audit #7)
 * bound no method and no path: a captured signature's FIRST use could be
 * redirected to a different verb, endpoint or window id. v2 reuses the
 * owner-device lane's canonical transcript machinery — length-prefixed
 * fields (injective: boundaries are part of the bytes), UPPER-cased method,
 * the byte-exact origin-form path+query (assertCanonicalPathAndQuery), and
 * the SHA-256 of the exact body bytes — under its own domain label, so a
 * fleet MAC and an owner-device signature can never be confused even if a
 * secret were misused as a key.
 *
 * There is deliberately NO v1 acceptance path in the verifier: every signer
 * lives in this repo and moves in the same commit, and a "temporary"
 * downgrade lane would be the exact hole v2 closes.
 */

/** Domain-separation label; the version lives INSIDE the signed bytes. */
export const FLEET_HMAC_LABEL = "ownerswitch/fleet-hmac/v2";

export interface FleetHmacFields {
  deviceId: string;
  /** HTTP method — signed UPPER-cased, so "post" and "POST" cannot disagree. */
  method: string;
  /** request path AND query, byte-exact as sent (assertCanonicalPathAndQuery). */
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
 * Throws on non-canonical inputs; the VERIFIER maps a throw to "invalid".
 */
export function fleetHmacPreimage(fields: FleetHmacFields): Uint8Array {
  if (fields.bodyHash.length !== 32) {
    throw new RangeError("bodyHash must be a 32-byte SHA-256 digest");
  }
  if (!Number.isSafeInteger(fields.timestamp)) {
    throw new RangeError("timestamp must be a safe integer (ms since epoch)");
  }
  assertCanonicalPathAndQuery(fields.pathAndQuery);
  return lengthPrefixed([
    utf8(FLEET_HMAC_LABEL),
    utf8(fields.deviceId),
    utf8(fields.method.toUpperCase()),
    utf8(fields.pathAndQuery),
    fields.bodyHash,
    utf8(String(fields.timestamp)),
    utf8(fields.nonce),
  ]);
}
