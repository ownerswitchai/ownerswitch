import { describe, expect, it } from "vitest";
import { KillSwitch, RestoreCeremony } from "./index.js";

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("control-plane integration: kill -> 2GO -> restore", () => {
  it("engage, complete the ceremony after cooldown, restore — once", () => {
    const c = clock();
    const kill = new KillSwitch(c.now);

    kill.engage("honeytoken", "decoy AWS key touched");
    expect(kill.killed).toBe(true);

    // GO 1/2: owner authenticates, ceremony starts
    const ceremony = new RestoreCeremony("cer-1", "adam", {
      cooldownMs: 30_000,
      ttlMs: 5 * 60_000,
      now: c.now,
    });
    expect(() => ceremony.confirm()).toThrow(/go1/); // GO 2/2 before cooldown fails

    c.advance(30_000);
    expect(ceremony.tick()).toBe("ready");

    // GO 2/2 authorizes the restore
    const auth = ceremony.confirm();
    kill.restore(auth);
    expect(kill.killed).toBe(false);
    expect(kill.auditLog().map((e) => e.type)).toEqual(["kill", "restore"]);

    // the same authorization must not restore a second kill
    kill.engage("honeytoken", "decoy AWS key touched again");
    expect(() => kill.restore(auth)).toThrow(/single-use/);
    expect(kill.killed).toBe(true);
  });
});
