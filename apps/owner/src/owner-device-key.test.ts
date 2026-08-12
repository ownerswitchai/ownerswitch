import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { base64urlDecode } from "./bytes.js";
import {
  exportPublicKeyPem,
  exportPublicKeySpki,
  generateOwnerDeviceKey,
  signRequestHeaders,
  type DeviceSigHeaders,
} from "./owner-device-key.js";

/**
 * Verify a signed request the way the control plane does
 * (packages/control-plane/src/owner-device.ts): rebuild the shared preimage
 * and check the raw r||s ECDSA signature against the enrolled SPKI. If this
 * passes, the app's signature is one the real verifier accepts.
 */
const verifyLikeControlPlane = (
  spkiPem: string,
  headers: DeviceSigHeaders,
  method: string,
  pathAndQuery: string,
  body: string,
): boolean => {
  const preimage = ownerDeviceSigPreimage({
    deviceId: headers["x-device-id"],
    method,
    pathAndQuery,
    bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
    timestamp: Number(headers["x-device-timestamp"]),
    nonce: headers["x-device-nonce"],
  });
  const sig = Buffer.from(base64urlDecode(headers["x-device-signature"]));
  if (sig.length !== 64) return false;
  return nodeVerify(
    "sha256",
    Buffer.from(preimage),
    { key: createPublicKey(spkiPem), dsaEncoding: "ieee-p1363" },
    sig,
  );
};

describe("owner device key — the phone's non-extractable signer", () => {
  it("the private key is non-extractable; the public key exports as SPKI/PEM", async () => {
    const { publicKey, privateKey } = await generateOwnerDeviceKey();
    expect(privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", privateKey)).rejects.toBeTruthy();

    const pem = await exportPublicKeyPem(publicKey);
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----\n/);
    expect(() => createPublicKey(pem)).not.toThrow();
    expect(createPublicKey(pem).asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect((await exportPublicKeySpki(publicKey)).length).toBeGreaterThan(0);
  });

  it("signs a delivery ack the control-plane verifier accepts (end to end)", async () => {
    const { publicKey, privateKey } = await generateOwnerDeviceKey();
    const pem = await exportPublicKeyPem(publicKey);

    const headers = await signRequestHeaders(privateKey, {
      deviceId: "owner-phone",
      method: "POST",
      pathAndQuery: "/veto/veto_abc/seen",
      body: "",
      timestamp: 1_700_000_000_000,
      nonce: "n-1",
    });
    expect(headers["x-device-id"]).toBe("owner-phone");
    expect(verifyLikeControlPlane(pem, headers, "POST", "/veto/veto_abc/seen", "")).toBe(true);
  });

  it("binds method, path, and body — a signature does not transfer", async () => {
    const { publicKey, privateKey } = await generateOwnerDeviceKey();
    const pem = await exportPublicKeyPem(publicKey);
    const body = JSON.stringify({ subscription: { endpoint: "https://push.example/x" } });

    const headers = await signRequestHeaders(privateKey, {
      deviceId: "owner-phone",
      method: "POST",
      pathAndQuery: "/push/subscription",
      body,
      timestamp: 1_700_000_000_000,
      nonce: "n-2",
    });
    // the exact request verifies
    expect(verifyLikeControlPlane(pem, headers, "POST", "/push/subscription", body)).toBe(true);
    // a different route, method, or body does not
    expect(verifyLikeControlPlane(pem, headers, "POST", "/veto/w/seen", body)).toBe(false);
    expect(verifyLikeControlPlane(pem, headers, "GET", "/push/subscription", body)).toBe(false);
    expect(verifyLikeControlPlane(pem, headers, "POST", "/push/subscription", body + " ")).toBe(false);
  });

  it("a different device's key does not verify against this device's enrolled key", async () => {
    const a = await generateOwnerDeviceKey();
    const b = await generateOwnerDeviceKey();
    const pemA = await exportPublicKeyPem(a.publicKey);
    const headers = await signRequestHeaders(b.privateKey, {
      deviceId: "owner-phone",
      method: "POST",
      pathAndQuery: "/veto/w/seen",
      timestamp: 1,
      nonce: "n",
    });
    expect(verifyLikeControlPlane(pemA, headers, "POST", "/veto/w/seen", "")).toBe(false);
  });
});
