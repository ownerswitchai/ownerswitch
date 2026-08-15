import { createHash, createHmac, randomBytes } from "node:crypto";

/**
 * The fleet device-HMAC v2 signature the control plane verifies in
 * packages/control-plane/src/auth.ts — mirrored locally so the console has
 * ZERO runtime dependency on the other packages, and drift-pinned to the
 * canonical @ownerswitchai/shared fleetHmacPreimage by test
 * (device-sig.test.ts), the same discipline as
 * apps/owner/public/renderable-alert.mjs vs @ownerswitchai/shared.
 *
 * v2 binds the METHOD, the origin-form PATH+QUERY and the SHA-256 of the
 * exact body bytes into a length-prefixed transcript under a domain label —
 * so a MAC minted for `POST /veto/w1` is useless for `POST /kill`, for
 * `GET /veto/pending`, for another window id, or for different body bytes,
 * even on its first use (PR #62 audit #7).
 */

/** MUST equal @ownerswitchai/shared FLEET_HMAC_LABEL byte-for-byte. */
export const FLEET_HMAC_LABEL = "ownerswitch/fleet-hmac/v2";

export interface DeviceSigFields {
  deviceId: string;
  /** ms since epoch, exactly as signed */
  timestamp: number;
  nonce: string;
}

const unambiguousField = (value: string): boolean => value !== "" && !value.includes(".");

/** MUST mirror @ownerswitchai/shared lengthPrefixed byte-for-byte. */
function lengthPrefixed(fields: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const field of fields) total += 4 + field.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint32(offset, field.length, false);
    offset += 4;
    out.set(field, offset);
    offset += field.length;
  }
  return out;
}

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** origin-form, printable ASCII, no fragment — what the wire will carry */
function assertCanonicalPathAndQuery(pathAndQuery: string): void {
  if (!pathAndQuery.startsWith("/") || pathAndQuery.includes("#") || !/^[\x21-\x7e]+$/.test(pathAndQuery)) {
    throw new Error("pathAndQuery must be the serialized origin-form request target");
  }
}

export function signDeviceRequest(
  fields: DeviceSigFields,
  rawBody: string,
  secret: string,
  context: { method: string; pathAndQuery: string },
): string {
  if (!unambiguousField(fields.deviceId) || !unambiguousField(fields.nonce)) {
    throw new Error('deviceId and nonce must be non-empty and contain no "."');
  }
  if (!Number.isInteger(fields.timestamp)) {
    throw new Error("timestamp must be an integer (ms since epoch)");
  }
  assertCanonicalPathAndQuery(context.pathAndQuery);
  const preimage = lengthPrefixed([
    utf8(FLEET_HMAC_LABEL),
    utf8(fields.deviceId),
    utf8(context.method.toUpperCase()),
    utf8(context.pathAndQuery),
    createHash("sha256").update(rawBody, "utf8").digest(),
    utf8(String(fields.timestamp)),
    utf8(fields.nonce),
  ]);
  return createHmac("sha256", secret).update(preimage).digest("hex");
}

/** A fresh single-use nonce; base64url never contains ".". */
export function newNonce(): string {
  return randomBytes(12).toString("base64url");
}

/** The four x-device-* headers for one signed request. */
export function deviceSignedHeaders(
  deviceId: string,
  secret: string,
  rawBody: string,
  timestamp: number,
  context: { method: string; pathAndQuery: string },
  nonce: string = newNonce(),
): Record<string, string> {
  return {
    "x-device-id": deviceId,
    "x-device-timestamp": String(timestamp),
    "x-device-nonce": nonce,
    "x-device-signature": signDeviceRequest({ deviceId, timestamp, nonce }, rawBody, secret, context),
  };
}
