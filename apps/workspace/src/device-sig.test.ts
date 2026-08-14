import {
  signDeviceRequest as controlPlaneSign,
  verifyDeviceSignature,
} from "@ownerswitchai/control-plane";
import { describe, expect, it } from "vitest";
import { deviceSignedHeaders, newNonce, signDeviceRequest } from "./device-sig.js";

/**
 * The console's local HMAC implementation is DRIFT-PINNED to the control
 * plane's auth.ts: byte-identical signatures across a battery of inputs, and
 * headers the real verifier accepts. If auth.ts ever changes shape, this
 * suite fails before any deployment does.
 */
describe("device-sig — drift-pinned to @ownerswitchai/control-plane", () => {
  const battery = [
    { deviceId: "workspace-console", timestamp: 1_755_000_000_000, nonce: "n-1", body: "" },
    { deviceId: "workspace-console", timestamp: 1, nonce: "abc_DEF-123", body: "{}" },
    {
      deviceId: "console-grupa-rapid",
      timestamp: 42,
      nonce: newNonce(),
      body: JSON.stringify({ source: "api", reason: "workspace console e-stop" }),
    },
    { deviceId: "d", timestamp: 0, nonce: "n", body: "x".repeat(4096) },
  ];

  it("signs exactly like the control plane across the battery", () => {
    for (const { deviceId, timestamp, nonce, body } of battery) {
      for (const secret of ["fleet-secret", "another-secret"]) {
        expect(signDeviceRequest({ deviceId, timestamp, nonce }, body, secret)).toBe(
          controlPlaneSign({ deviceId, timestamp, nonce }, body, secret),
        );
      }
    }
  });

  it("produces headers the real verifier accepts, bound to the exact body", () => {
    const secret = "fleet-secret";
    const body = JSON.stringify({ source: "api", reason: "workspace console e-stop" });
    const at = 1_755_000_000_000;
    const headers = deviceSignedHeaders("workspace-console", secret, body, at);
    const credential = {
      deviceId: headers["x-device-id"] as string,
      timestamp: Number(headers["x-device-timestamp"]),
      nonce: headers["x-device-nonce"] as string,
      signature: headers["x-device-signature"] as string,
    };
    const seenNonces = new Map<string, number>();
    expect(verifyDeviceSignature(credential, body, secret, { now: () => at, seenNonces })).toBe(true);
    // bound to THIS body: the same headers over different bytes verify nothing
    expect(
      verifyDeviceSignature(credential, `${body} `, secret, { now: () => at, seenNonces: new Map() }),
    ).toBe(false);
  });

  it("refuses the ambiguity the dot-joined payload cannot carry", () => {
    expect(() => signDeviceRequest({ deviceId: "a.b", timestamp: 1, nonce: "n" }, "", "s")).toThrow();
    expect(() => signDeviceRequest({ deviceId: "a", timestamp: 1, nonce: "n.1" }, "", "s")).toThrow();
    expect(() => signDeviceRequest({ deviceId: "a", timestamp: 1.5, nonce: "n" }, "", "s")).toThrow();
    expect(() => signDeviceRequest({ deviceId: "", timestamp: 1, nonce: "n" }, "", "s")).toThrow();
  });

  it("nonces are dot-free and non-repeating", () => {
    const a = newNonce();
    const b = newNonce();
    expect(a).not.toContain(".");
    expect(a.length).toBeGreaterThan(8);
    expect(a).not.toBe(b);
  });
});
