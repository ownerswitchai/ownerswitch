import { describe, expect, it } from "vitest";
import { RestoreCeremony } from "./twogo.js";

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("RestoreCeremony (2GO)", () => {
  it("GO 2/2 too early is rejected — the pause is mandatory", () => {
    const c = clock();
    const r = new RestoreCeremony("c1", "adam", { cooldownMs: 1000, now: c.now });
    expect(() => r.confirm()).toThrow(/go1/);
  });

  it("after the cooldown the ceremony completes and authorizes", () => {
    const c = clock();
    const r = new RestoreCeremony("c1", "adam", { cooldownMs: 1000, ttlMs: 10_000, now: c.now });
    c.advance(1500);
    const auth = r.confirm();
    expect(auth).toEqual({ ceremonyId: "c1", ownerId: "adam", completedAt: 1500 });
    expect(r.state).toBe("completed");
  });

  it("a stale ceremony expires and cannot be confirmed", () => {
    const c = clock();
    const r = new RestoreCeremony("c1", "adam", { cooldownMs: 1000, ttlMs: 5000, now: c.now });
    c.advance(5001);
    expect(r.tick()).toBe("expired");
    expect(() => r.confirm()).toThrow(/expired/);
  });

  it("reports the remaining cooldown and its expiry instant", () => {
    const c = clock(100);
    const r = new RestoreCeremony("c1", "adam", { cooldownMs: 1000, ttlMs: 5000, now: c.now });
    expect(r.cooldownRemainingMs()).toBe(1000);
    expect(r.expiresAt).toBe(5100);
    c.advance(600);
    expect(r.cooldownRemainingMs()).toBe(400);
    c.advance(600);
    expect(r.cooldownRemainingMs()).toBe(0); // never negative
  });

  it("completion is terminal — no double-spend of a ceremony", () => {
    const c = clock();
    const r = new RestoreCeremony("c1", "adam", { cooldownMs: 10, now: c.now });
    c.advance(11);
    r.confirm();
    expect(() => r.confirm()).toThrow(/completed/);
  });
});
