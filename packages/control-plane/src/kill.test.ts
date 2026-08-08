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

  it("alert() records a flagged event WITHOUT engaging the switch", () => {
    const k = new KillSwitch(() => 42);
    k.alert("honeytoken", "read of /decoys/.env.backup");
    expect(k.killed).toBe(false); // the whole point of the DoS fix
    const log = k.auditLog();
    expect(log).toHaveLength(1);
    expect(log[0]).toEqual({
      type: "alert",
      event: { source: "honeytoken", reason: "read of /decoys/.env.backup", at: 42 },
    });
  });

  it("alerts and kills share one timeline, in order", () => {
    const k = new KillSwitch(() => 7);
    k.alert("honeytoken", "decoy file read");
    k.engage("honeytoken", "decoy value in tool call");
    expect(k.killed).toBe(true);
    expect(k.auditLog().map((e) => e.type)).toEqual(["alert", "kill"]);
  });

  it("alert() flags the unauthenticated case like engage() does", () => {
    const k = new KillSwitch(() => 1);
    k.alert("api", "loopback", { unauthenticated: true });
    const [entry] = k.auditLog();
    expect(entry.type === "alert" && entry.event.unauthenticated).toBe(true);
  });
});
