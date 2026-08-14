import { describe, expect, it } from "vitest";
import { isLoopbackBind, validateDeviceId } from "./startup.js";

describe("startup validation matches the runtime (audit #10)", () => {
  it("isLoopbackBind accepts only literal loopback", () => {
    for (const good of ["127.0.0.1", "127.0.0.53", "127.255.255.254", "localhost", "::1"]) {
      expect(isLoopbackBind(good), good).toBe(true);
    }
    for (const bad of [
      "127.999.999.999", // not an IP literal — a resolver would decide what it means
      "127.0.0.1.evil.example",
      "localhost.evil.example",
      "0.0.0.0",
      "192.168.1.20",
      "128.0.0.1",
      "",
      "127.1", // shorthand notations are resolver food, not literals
    ]) {
      expect(isLoopbackBind(bad), bad).toBe(false);
    }
  });

  it("validateDeviceId enforces the signer's grammar at startup, not inside the first signed call", () => {
    expect(() => validateDeviceId("workspace-console")).not.toThrow();
    expect(() => validateDeviceId("console_2")).not.toThrow();
    for (const bad of ["", "has.dot", "has space", "x".repeat(129), "névvel", "tab\there"]) {
      expect(() => validateDeviceId(bad), JSON.stringify(bad)).toThrow(/OWNERSWITCH_DEVICE_ID/);
    }
  });
});
