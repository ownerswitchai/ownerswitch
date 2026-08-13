import { createHash, generateKeyPairSync, sign as edsign, type KeyObject } from "node:crypto";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import {
  enrolledOwnerDeviceFromSpki,
  verifyOwnerDeviceSignature,
  type EnrolledOwnerDevice,
  type OwnerDeviceCredential,
} from "./owner-device.js";

/** A P-256 keypair; the private key signs r||s like WebCrypto does. */
const keypair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });

const spkiPem = (publicKey: KeyObject) => publicKey.export({ format: "pem", type: "spki" }).toString();

/** Sign the exact preimage the verifier will reconstruct, r||s (ieee-p1363). */
const signFields = (
  privateKey: KeyObject,
  fields: { deviceId: string; method: string; pathAndQuery: string; rawBody: string; timestamp: number; nonce: string },
) => {
  const preimage = ownerDeviceSigPreimage({
    deviceId: fields.deviceId,
    method: fields.method,
    pathAndQuery: fields.pathAndQuery,
    bodyHash: new Uint8Array(createHash("sha256").update(fields.rawBody).digest()),
    timestamp: fields.timestamp,
    nonce: fields.nonce,
  });
  return edsign("sha256", preimage, { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
};

const registry = (device: EnrolledOwnerDevice) => new Map([[device.deviceId, device]]);

describe("verifyOwnerDeviceSignature — asymmetric owner-device auth", () => {
  const at = 1_000_000;
  const base = {
    deviceId: "owner-phone",
    method: "POST",
    pathAndQuery: "/veto/veto_abc/seen",
    rawBody: "",
    timestamp: at,
    nonce: "n-1",
  };

  const setup = () => {
    const { publicKey, privateKey } = keypair();
    const device = enrolledOwnerDeviceFromSpki("owner-phone", spkiPem(publicKey));
    return { device, privateKey };
  };

  const cred = (privateKey: KeyObject, over = base, sigOver = base): OwnerDeviceCredential => ({
    deviceId: over.deviceId,
    timestamp: over.timestamp,
    nonce: over.nonce,
    signature: signFields(privateKey, sigOver),
  });

  it("verifies a real WebCrypto-style r||s signature over the shared preimage", () => {
    const { device, privateKey } = setup();
    const seen = new Map<string, number>();
    const ok = verifyOwnerDeviceSignature(
      cred(privateKey),
      base.method,
      base.pathAndQuery,
      base.rawBody,
      registry(device),
      { now: () => at, seenNonces: seen },
    );
    expect(ok).toBe("owner-phone");
  });

  it("binds the method, the path+query, and the body — a signature does not transfer", () => {
    const { device, privateKey } = setup();
    const reg = registry(device);
    const c = cred(privateKey); // signed for POST /veto/veto_abc/seen with empty body

    // same signature, different METHOD
    expect(verifyOwnerDeviceSignature(c, "GET", base.pathAndQuery, "", reg, { now: () => at })).toBeNull();
    // different PATH
    expect(
      verifyOwnerDeviceSignature(c, "POST", "/veto/veto_OTHER/seen", "", reg, { now: () => at }),
    ).toBeNull();
    // different BODY
    expect(
      verifyOwnerDeviceSignature(c, "POST", base.pathAndQuery, '{"x":1}', reg, { now: () => at }),
    ).toBeNull();
  });

  it("rejects a signature from a different key, and an unknown device", () => {
    const { device } = setup();
    const other = keypair();
    const reg = registry(device);
    // right device id, wrong key
    const forged = cred(other.privateKey);
    expect(verifyOwnerDeviceSignature(forged, base.method, base.pathAndQuery, "", reg, { now: () => at })).toBeNull();
    // unknown device id
    const empty = new Map<string, EnrolledOwnerDevice>();
    const { privateKey } = setup();
    expect(
      verifyOwnerDeviceSignature(cred(privateKey), base.method, base.pathAndQuery, "", empty, { now: () => at }),
    ).toBeNull();
  });

  it("enforces the 60 s skew window and burns the nonce exactly once (replay refused)", () => {
    const { device, privateKey } = setup();
    const reg = registry(device);
    const seen = new Map<string, number>();

    // outside skew -> rejected
    expect(
      verifyOwnerDeviceSignature(cred(privateKey), base.method, base.pathAndQuery, "", reg, {
        now: () => at + 61_000,
        seenNonces: seen,
      }),
    ).toBeNull();

    // valid once
    const c = cred(privateKey);
    expect(
      verifyOwnerDeviceSignature(c, base.method, base.pathAndQuery, "", reg, { now: () => at, seenNonces: seen }),
    ).toBe("owner-phone");
    // replay of the same nonce -> refused
    expect(
      verifyOwnerDeviceSignature(c, base.method, base.pathAndQuery, "", reg, { now: () => at, seenNonces: seen }),
    ).toBeNull();
  });

  it("rejects a signature that is not 64-byte raw r||s (e.g. DER)", () => {
    const { device, privateKey } = setup();
    const reg = registry(device);
    // DER-encoded signature over the same preimage — must NOT verify (r||s only)
    const preimage = ownerDeviceSigPreimage({
      deviceId: base.deviceId,
      method: base.method,
      pathAndQuery: base.pathAndQuery,
      bodyHash: new Uint8Array(createHash("sha256").update("").digest()),
      timestamp: base.timestamp,
      nonce: base.nonce,
    });
    const der = edsign("sha256", preimage, privateKey).toString("base64url"); // default DER
    const c: OwnerDeviceCredential = { deviceId: base.deviceId, timestamp: at, nonce: "n-der", signature: der };
    expect(verifyOwnerDeviceSignature(c, base.method, base.pathAndQuery, "", reg, { now: () => at })).toBeNull();
  });

  it("refuses to enroll a non-P-256 key", () => {
    const ed = generateKeyPairSync("ed25519");
    expect(() => enrolledOwnerDeviceFromSpki("x", spkiPem(ed.publicKey))).toThrow(/P-256|prime256v1/);
  });
});
