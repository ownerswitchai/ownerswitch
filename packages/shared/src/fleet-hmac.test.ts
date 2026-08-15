import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FLEET_HMAC_LABEL, fleetHmacPreimage } from "./fleet-hmac.js";
import { OWNER_DEVICE_SIG_LABEL, ownerDeviceSigPreimage } from "./owner-device-sig.js";

const HASH = (body: string) => new Uint8Array(createHash("sha256").update(body, "utf8").digest());

const base = {
  deviceId: "mcp-gateway",
  method: "POST",
  pathAndQuery: "/veto",
  bodyHash: HASH("{}"),
  timestamp: 1_755_000_000_000,
  nonce: "n-1",
};

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

describe("fleetHmacPreimage — the fleet lane's canonical transcript", () => {
  it("binds every field: a change anywhere changes the bytes", () => {
    const reference = hex(fleetHmacPreimage(base));
    const variants = [
      { ...base, deviceId: "mcp-gateway-2" },
      { ...base, method: "GET" },
      { ...base, pathAndQuery: "/kill" },
      { ...base, pathAndQuery: "/veto?x=1" },
      { ...base, bodyHash: HASH("{ }") },
      { ...base, timestamp: base.timestamp + 1 },
      { ...base, nonce: "n-2" },
    ];
    for (const variant of variants) {
      expect(hex(fleetHmacPreimage(variant)), JSON.stringify(variant.pathAndQuery)).not.toBe(reference);
    }
  });

  it("case-folds the method only — 'post' and 'POST' are the same transcript", () => {
    expect(hex(fleetHmacPreimage({ ...base, method: "post" }))).toBe(hex(fleetHmacPreimage(base)));
  });

  it("is INJECTIVE across field boundaries — no re-split can forge a match", () => {
    // the length prefixes are part of the bytes: moving a character from the
    // device id to the nonce cannot produce the same preimage
    const a = fleetHmacPreimage({ ...base, deviceId: "ab", nonce: "cd" });
    const b = fleetHmacPreimage({ ...base, deviceId: "abc", nonce: "d" });
    expect(hex(a)).not.toBe(hex(b));
  });

  it("is DOMAIN-SEPARATED from the owner-device lane — the same fields, different bytes", () => {
    const fleet = fleetHmacPreimage(base);
    const owner = ownerDeviceSigPreimage(base);
    expect(hex(fleet)).not.toBe(hex(owner));
    expect(FLEET_HMAC_LABEL).not.toBe(OWNER_DEVICE_SIG_LABEL);
    // and the version is INSIDE the signed bytes
    expect(FLEET_HMAC_LABEL).toContain("/v2");
  });

  it("refuses a non-canonical request target, a bad hash length and an unsafe timestamp", () => {
    expect(() => fleetHmacPreimage({ ...base, pathAndQuery: "veto" })).toThrow(/origin-form/);
    expect(() => fleetHmacPreimage({ ...base, pathAndQuery: "/veto#f" })).toThrow(/fragment/);
    expect(() => fleetHmacPreimage({ ...base, pathAndQuery: "/veto space" })).toThrow(/printable ASCII/);
    expect(() => fleetHmacPreimage({ ...base, pathAndQuery: "/veto%2" })).toThrow(/percent escape/);
    expect(() => fleetHmacPreimage({ ...base, bodyHash: new Uint8Array(16) })).toThrow(/32-byte/);
    expect(() => fleetHmacPreimage({ ...base, timestamp: 1.5 })).toThrow(/safe integer/);
  });
});
