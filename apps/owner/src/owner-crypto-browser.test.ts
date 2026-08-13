import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
// The DEPLOYED browser module, imported directly (plain ESM, runs in Node too).
import {
  deviceSigPreimage as browserPreimage,
  exportPublicKeySpki,
  generateOwnerDeviceKey,
  OWNER_DEVICE_SIG_LABEL,
  signRequestHeaders,
} from "../public/owner-crypto.mjs";

const bodyHash = (body: string) => new Uint8Array(createHash("sha256").update(body).digest());

describe("public/owner-crypto.mjs — the deployed browser signer", () => {
  it("its preimage matches @ownerswitchai/shared byte-for-byte (drift guard)", async () => {
    const fields = {
      deviceId: "owner-phone",
      method: "post",
      pathAndQuery: "/veto/veto_abc/seen",
      body: "",
      timestamp: 1_000_000,
      nonce: "n-1",
    };
    const browser = await browserPreimage(fields);
    const shared = ownerDeviceSigPreimage({ ...fields, bodyHash: bodyHash("") });
    expect(Buffer.from(browser).equals(Buffer.from(shared))).toBe(true);
    expect(OWNER_DEVICE_SIG_LABEL).toBe("ownerswitch/device-sig/v1");
  });

  it("signs a request a P-256 verifier (the control plane's) accepts, bound to method/path/body", async () => {
    const { publicKey, privateKey } = (await generateOwnerDeviceKey()) as CryptoKeyPair;
    // enroll the SPKI exactly as the control plane accepts base64 DER
    const der = Buffer.from(await exportPublicKeySpki(publicKey), "base64url");
    const keyObject = createPublicKey({ key: der, format: "der", type: "spki" });

    const body = JSON.stringify({ subscription: { endpoint: "https://push.example/x" } });
    const headers = await signRequestHeaders(privateKey, {
      deviceId: "owner-phone",
      method: "POST",
      pathAndQuery: "/push/subscription",
      body,
      timestamp: 1_700_000_000_000,
      nonce: "n-2",
    });

    const verify = (method: string, path: string, b: string) => {
      const preimage = ownerDeviceSigPreimage({
        deviceId: "owner-phone",
        method,
        pathAndQuery: path,
        bodyHash: bodyHash(b),
        timestamp: Number(headers["x-device-timestamp"]),
        nonce: headers["x-device-nonce"],
      });
      const sig = Buffer.from(headers["x-device-signature"], "base64url");
      return (
        sig.length === 64 &&
        nodeVerify("sha256", Buffer.from(preimage), { key: keyObject, dsaEncoding: "ieee-p1363" }, sig)
      );
    };

    expect(verify("POST", "/push/subscription", body)).toBe(true);
    expect(verify("GET", "/push/subscription", body)).toBe(false);
    expect(verify("POST", "/veto/w/seen", body)).toBe(false);
  });
});
