import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import { base64urlEncode, sha256 } from "./bytes.js";

/**
 * The owner app's cheap-lane device key and request signer — the browser
 * (and Node-test) side of the asymmetric credential the control plane
 * verifies (packages/control-plane/src/owner-device.ts). The private key is
 * created NON-EXTRACTABLE (`extractable: false`), so it lives only inside
 * the platform key store and never appears in JS memory, in the app's
 * storage, or on the wire — which is exactly why this is stronger than any
 * HMAC secret a browser could hold (apps/owner/DESIGN.md §3): a compromised
 * page can ask the key to sign, but can never exfiltrate it.
 *
 * Algorithm is pinned by the design and by the verifier: ECDSA on P-256 with
 * SHA-256, signature in WebCrypto's RAW r||s form (64 bytes), never DER. The
 * preimage — method, path+query, body hash, timestamp, nonce — is the ONE
 * shared encoder, so "the app signed X" and "the server verified X" are the
 * same X by construction.
 *
 * WebCrypto is a global in modern browsers and in Node ≥ 20, so this module
 * is used unchanged by the app and exercised directly by the test suite.
 */

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;

/** The signing headers the control plane reads (x-device-*). */
export interface DeviceSigHeaders {
  "x-device-id": string;
  "x-device-timestamp": string;
  "x-device-nonce": string;
  "x-device-signature": string;
}

export interface SignRequestInput {
  deviceId: string;
  method: string;
  /** the request target EXACTLY as it will be sent (origin-form, byte-exact) */
  pathAndQuery: string;
  /** the exact request body bytes (default empty) */
  body?: string | Uint8Array;
  /** unix ms; the control plane's 60 s skew window reads it */
  timestamp: number;
  /** single-use nonce; the app must not reuse one within the skew window */
  nonce: string;
}

/**
 * Create the owner device's cheap-lane keypair. The PRIVATE key is
 * non-extractable — `exportKey` on it rejects — so it can sign but never
 * leave the device; the PUBLIC key is exportable for enrollment.
 */
export async function generateOwnerDeviceKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDSA_P256, false, ["sign"]) as Promise<CryptoKeyPair>;
}

/** The device's PUBLIC key as base64url SPKI — what the deployment enrolls. */
export async function exportPublicKeySpki(publicKey: CryptoKey): Promise<string> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  return base64urlEncode(spki);
}

/** The same SPKI as a PEM block, for a `deviceId → SPKI PEM` keys file. */
export async function exportPublicKeyPem(publicKey: CryptoKey): Promise<string> {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("spki", publicKey))));
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/**
 * Sign a request with the device's private key and return the x-device-*
 * headers. The signature binds the method, the exact path+query, and the
 * body hash (via the shared preimage), so it authorizes THIS request and no
 * other — a captured ack header cannot be replayed onto a different window,
 * route, or body.
 */
export async function signRequestHeaders(
  privateKey: CryptoKey,
  input: SignRequestInput,
): Promise<DeviceSigHeaders> {
  const bodyBytes =
    input.body === undefined
      ? new Uint8Array(0)
      : typeof input.body === "string"
        ? new TextEncoder().encode(input.body)
        : input.body;
  const preimage = ownerDeviceSigPreimage({
    deviceId: input.deviceId,
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    bodyHash: await sha256(bodyBytes),
    timestamp: input.timestamp,
    nonce: input.nonce,
  });
  // Copy into a fresh ArrayBuffer: a Uint8Array's buffer may type as
  // SharedArrayBuffer, which subtle.sign does not accept.
  const buf = new ArrayBuffer(preimage.byteLength);
  new Uint8Array(buf).set(preimage);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, buf));
  return {
    "x-device-id": input.deviceId,
    "x-device-timestamp": String(input.timestamp),
    "x-device-nonce": input.nonce,
    "x-device-signature": base64urlEncode(raw),
  };
}
