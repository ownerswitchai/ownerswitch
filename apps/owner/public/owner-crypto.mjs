/*
 * owner-crypto.mjs — the browser-native owner-device signer, loaded as an ES
 * module by app.js and sw.js (CSP script-src 'self' allows same-origin module
 * imports; there is no bundler and no third-party code).
 *
 * This is the DEPLOYABLE copy of the cheap-lane signer. Because the browser
 * cannot import the workspace package @ownerswitchai/shared, the canonical
 * preimage encoder is re-implemented here — and pinned byte-for-byte to the
 * shared encoder by a Node test (src/owner-crypto-browser.test.ts), so this
 * copy can never silently drift from what the control plane verifies.
 *
 * Algorithm, pinned by the verifier (packages/control-plane/src/owner-device.ts):
 * ECDSA P-256 / SHA-256, signature RAW r||s (64 bytes). The device private
 * key is created NON-EXTRACTABLE, so it signs but never leaves the platform
 * key store.
 */

export const OWNER_DEVICE_SIG_LABEL = "ownerswitch/device-sig/v1";
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };

function utf8(text) {
  return new TextEncoder().encode(text);
}

/** 4-byte big-endian length-prefixed concatenation (injective). */
function lengthPrefixed(fields) {
  let total = 0;
  for (const f of fields) total += 4 + f.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const f of fields) {
    view.setUint32(off, f.length, false);
    off += 4;
    out.set(f, off);
    off += f.length;
  }
  return out;
}

async function sha256(bytes) {
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The signed preimage — MUST match @ownerswitchai/shared ownerDeviceSigPreimage
 * byte-for-byte (pinned by test). Fields: label, deviceId, UPPER method,
 * path+query, 32-byte body hash, decimal timestamp, nonce.
 */
export async function deviceSigPreimage({ deviceId, method, pathAndQuery, body, timestamp, nonce }) {
  const bodyBytes = body === undefined ? new Uint8Array(0) : typeof body === "string" ? utf8(body) : body;
  return lengthPrefixed([
    utf8(OWNER_DEVICE_SIG_LABEL),
    utf8(deviceId),
    utf8(method.toUpperCase()),
    utf8(pathAndQuery),
    await sha256(bodyBytes),
    utf8(String(timestamp)),
    utf8(nonce),
  ]);
}

/** Create the device's non-extractable P-256 keypair (sign-only private key). */
export function generateOwnerDeviceKey() {
  return crypto.subtle.generateKey(ECDSA_P256, false, ["sign"]);
}

/** The public key as base64url SPKI — what the deployment enrolls. */
export async function exportPublicKeySpki(publicKey) {
  return base64url(new Uint8Array(await crypto.subtle.exportKey("spki", publicKey)));
}

/** Sign a request; returns the x-device-* headers the control plane reads. */
export async function signRequestHeaders(privateKey, { deviceId, method, pathAndQuery, body, timestamp, nonce }) {
  const preimage = await deviceSigPreimage({ deviceId, method, pathAndQuery, body, timestamp, nonce });
  const buf = new ArrayBuffer(preimage.byteLength);
  new Uint8Array(buf).set(preimage);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, buf));
  return {
    "x-device-id": deviceId,
    "x-device-timestamp": String(timestamp),
    "x-device-nonce": nonce,
    "x-device-signature": base64url(raw),
  };
}

/** A single-use nonce (hex from the CSPRNG). */
export function nonce() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
