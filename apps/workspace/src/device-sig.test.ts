import {
  signDeviceRequest as controlPlaneSign,
  verifyDeviceSignature,
} from "@ownerswitchai/control-plane";
import { describe, expect, it } from "vitest";
import { deviceSignedHeaders, newNonce, signDeviceRequest } from "./device-sig.js";

/**
 * The console's local fleet-hmac v2 implementation is DRIFT-PINNED to the
 * canonical one (@ownerswitchai/shared via the control plane's auth.ts):
 * byte-identical signatures across a battery of inputs — method, path+query
 * and body variations included — and headers the real verifier accepts for
 * exactly the bound request and nothing else. If the canonical transcript
 * ever changes shape, this suite fails before any deployment does.
 */
describe("device-sig — drift-pinned to the fleet-hmac v2 transcript", () => {
  const battery = [
    {
      deviceId: "workspace-console",
      timestamp: 1_755_000_000_000,
      nonce: "n-1",
      body: "",
      ctx: { method: "GET", pathAndQuery: "/veto/pending" },
    },
    {
      deviceId: "workspace-console",
      timestamp: 1,
      nonce: "abc_DEF-123",
      body: "{}",
      ctx: { method: "POST", pathAndQuery: "/veto/veto_8c21" },
    },
    {
      deviceId: "console-grupa-rapid",
      timestamp: 42,
      nonce: newNonce(),
      body: JSON.stringify({ source: "api", reason: "workspace console e-stop" }),
      ctx: { method: "POST", pathAndQuery: "/kill" },
    },
    {
      deviceId: "d",
      timestamp: 0,
      nonce: "n",
      body: "x".repeat(4096),
      ctx: { method: "post", pathAndQuery: "/kill?drill=1" },
    },
  ];

  it("signs exactly like the control plane across the battery", () => {
    for (const { deviceId, timestamp, nonce, body, ctx } of battery) {
      for (const secret of ["fleet-secret", "another-secret"]) {
        expect(signDeviceRequest({ deviceId, timestamp, nonce }, body, secret, ctx)).toBe(
          controlPlaneSign({ deviceId, timestamp, nonce }, body, secret, ctx),
        );
      }
    }
  });

  it("produces headers the real verifier accepts, bound to the exact method+path+body", () => {
    const secret = "fleet-secret";
    const body = JSON.stringify({ source: "api", reason: "workspace console e-stop" });
    const at = 1_755_000_000_000;
    const ctx = { method: "POST", pathAndQuery: "/kill" };
    const headers = deviceSignedHeaders("workspace-console", secret, body, at, ctx);
    const credential = {
      deviceId: headers["x-device-id"] as string,
      timestamp: Number(headers["x-device-timestamp"]),
      nonce: headers["x-device-nonce"] as string,
      signature: headers["x-device-signature"] as string,
    };
    const fresh = () => ({ now: () => at, seenNonces: new Map<string, number>() });
    expect(verifyDeviceSignature(credential, body, secret, ctx, fresh())).toBe(true);
    // bound to THIS body: the same headers over different bytes verify nothing
    expect(verifyDeviceSignature(credential, `${body} `, secret, ctx, fresh())).toBe(false);
    // bound to THIS method and path: a captured MAC cannot be redirected
    expect(
      verifyDeviceSignature(credential, body, secret, { ...ctx, method: "GET" }, fresh()),
    ).toBe(false);
    expect(
      verifyDeviceSignature(credential, body, secret, { ...ctx, pathAndQuery: "/alert" }, fresh()),
    ).toBe(false);
  });

  it("refuses malformed fields and non-canonical request targets", () => {
    const ctx = { method: "POST", pathAndQuery: "/kill" };
    expect(() => signDeviceRequest({ deviceId: "a.b", timestamp: 1, nonce: "n" }, "", "s", ctx)).toThrow();
    expect(() => signDeviceRequest({ deviceId: "a", timestamp: 1, nonce: "n.1" }, "", "s", ctx)).toThrow();
    expect(() => signDeviceRequest({ deviceId: "a", timestamp: 1.5, nonce: "n" }, "", "s", ctx)).toThrow();
    expect(() => signDeviceRequest({ deviceId: "", timestamp: 1, nonce: "n" }, "", "s", ctx)).toThrow();
    expect(() =>
      signDeviceRequest({ deviceId: "a", timestamp: 1, nonce: "n" }, "", "s", {
        method: "POST",
        pathAndQuery: "kill",
      }),
    ).toThrow();
  });

  it("nonces are dot-free and non-repeating", () => {
    const a = newNonce();
    const b = newNonce();
    expect(a).not.toContain(".");
    expect(a.length).toBeGreaterThan(8);
    expect(a).not.toBe(b);
  });
});
