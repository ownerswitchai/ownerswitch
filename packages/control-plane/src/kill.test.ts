import { describe, expect, it } from "vitest";
import { KillSwitch } from "./kill.js";

const auth = { ceremonyId: "c1", ownerId: "adam", completedAt: 2000 };

describe("KillSwitch", () => {
  it("starts armed (not killed)", () => {
    expect(new KillSwitch().killed).toBe(false);
  });

  it("any source can engage, idempotently", () => {
    const k = new KillSwitch(() => 1000);
    k.engage("honeytoken", "decoy key touched");
    k.engage("button");
    expect(k.killed).toBe(true);
    expect(k.auditLog()).toHaveLength(2);
  });

  it("every engage bumps the kill epoch, even while already killed", () => {
    const k = new KillSwitch(() => 1000);
    expect(k.epoch).toBe(0);
    k.engage("button");
    expect(k.epoch).toBe(1);
    k.engage("api"); // already killed — a repeat trigger still opens a new epoch
    expect(k.epoch).toBe(2);
    k.restore(auth);
    expect(k.epoch).toBe(2); // restoring does not
  });

  it("restore needs a ceremony-shaped authorization", () => {
    const k = new KillSwitch(() => 1000);
    k.engage("app");
    expect(() => k.restore({ ceremonyId: "", ownerId: "", completedAt: 0 })).toThrow(/2GO/);
    expect(k.killed).toBe(true);
    k.restore(auth);
    expect(k.killed).toBe(false);
  });

  it("cannot restore when not killed", () => {
    expect(() => new KillSwitch().restore(auth)).toThrow(/nothing to restore/);
  });

  it("audit log records both directions and is a copy", () => {
    const k = new KillSwitch(() => 5);
    k.engage("voice", "owner pressed 1");
    k.restore(auth);
    const log = k.auditLog();
    expect(log.map((e) => e.type)).toEqual(["kill", "restore"]);
    (log as unknown[]).push("tamper");
    expect(k.auditLog()).toHaveLength(2);
  });
});
