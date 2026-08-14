import { createHmac, randomBytes } from "node:crypto";

/**
 * The fleet device-HMAC signature the control plane verifies in
 * packages/control-plane/src/auth.ts — reproduced locally so the console has
 * ZERO runtime dependency on the control-plane package, and drift-pinned to
 * the original by test (device-sig.test.ts), the same discipline as
 * apps/owner/public/renderable-alert.mjs vs @ownerswitchai/shared.
 *
 * Format (auth.ts documents it as the contract): hex HMAC-SHA256 over
 * `${deviceId}.${timestamp}.${nonce}.${rawBody}`. The payload is dot-joined,
 * so deviceId and nonce must not contain "." and the timestamp must be an
 * integer — one signed string must never parse as two credentials.
 */
export interface DeviceSigFields {
  deviceId: string;
  /** ms since epoch, exactly as signed */
  timestamp: number;
  nonce: string;
}

const unambiguousField = (value: string): boolean => value !== "" && !value.includes(".");

export function signDeviceRequest(fields: DeviceSigFields, rawBody: string, secret: string): string {
  if (!unambiguousField(fields.deviceId) || !unambiguousField(fields.nonce)) {
    throw new Error('deviceId and nonce must be non-empty and contain no "."');
  }
  if (!Number.isInteger(fields.timestamp)) {
    throw new Error("timestamp must be an integer (ms since epoch)");
  }
  return createHmac("sha256", secret)
    .update(`${fields.deviceId}.${fields.timestamp}.${fields.nonce}.${rawBody}`)
    .digest("hex");
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
  nonce: string = newNonce(),
): Record<string, string> {
  return {
    "x-device-id": deviceId,
    "x-device-timestamp": String(timestamp),
    "x-device-nonce": nonce,
    "x-device-signature": signDeviceRequest({ deviceId, timestamp, nonce }, rawBody, secret),
  };
}
