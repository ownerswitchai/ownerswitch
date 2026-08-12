import { describe, expect, it } from "vitest";
import { VetoWindow } from "./veto.js";

const call = { agentId: "a1", tool: "github.merge_pr" };
const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("VetoWindow", () => {
  it("owner veto wins while pending", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { now: c.now });
    w.markDelivered();
    w.veto("adam");
    expect(w.state).toBe("vetoed");
    expect(w.vetoedBy).toBe("adam");
  });

  it("silence releases — but only when delivery was confirmed", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { windowMs: 1000, now: c.now });
    w.markDelivered();
    c.advance(1001);
    expect(w.tick()).toBe("released");
  });

  it("RELEASE-TIME CAS: at the decision itself, a witness that lost standing cannot release", () => {
    // the standing flips INVALID without any revokeDeliveryEvidence() sweep —
    // this models a revocation path the proactive sweep never saw (admin
    // tooling, a standing-registry reload, another process's persisted state)
    const c = clock();
    let standingValid = true;
    const w = new VetoWindow(call, 0, {
      windowMs: 1000,
      extensionMs: 2000,
      now: c.now,
      witnessStanding: (deviceId, generation) =>
        standingValid && deviceId === "phone-1" && generation === 1,
    });
    w.markDelivered("phone-1", 1);
    standingValid = false; // revoked through a path tick() alone must catch
    c.advance(1001);
    expect(w.tick()).toBe("extended"); // NOT released — evidence invalid at the decision
    expect(w.isDelivered).toBe(false);
    c.advance(2001);
    expect(w.tick()).toBe("held"); // and silence fails closed from there
  });

  it("RELEASE-TIME CAS: a generation mismatch alone (same device id) refuses the release", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, {
      windowMs: 1000,
      now: c.now,
      // the registry's CURRENT generation is 2; the ack was witnessed under 1
      witnessStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 2,
    });
    w.markDelivered("phone-1", 1);
    c.advance(1001);
    expect(w.tick()).toBe("extended");
  });

  it("RELEASE-TIME CAS: evidence with no witness identity cannot be validated and never releases", () => {
    const c = clock();
    // markDelivered() with no device/generation — the checker receives nulls,
    // and a server-style checker refuses evidence it cannot attribute
    const w = new VetoWindow(call, 0, {
      windowMs: 1000,
      now: c.now,
      witnessStanding: (deviceId, generation) => deviceId !== null && generation !== null,
    });
    w.markDelivered();
    c.advance(1001);
    expect(w.tick()).toBe("extended");
  });

  it("unreachable owner: extends once instead of releasing", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    expect(w.tick()).toBe("extended");
    // still vetoable during the extension
    w.veto("adam");
    expect(w.state).toBe("vetoed");
  });

  it("still unreachable after extension: held for active approval", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    w.tick(); // extended
    c.advance(2001);
    expect(w.tick()).toBe("held");
  });

  it("late delivery during extension lets silence release", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    w.tick(); // extended
    w.markDelivered();
    c.advance(2001);
    expect(w.tick()).toBe("released");
  });

  it("terminal states reject veto", () => {
    const c = clock();
    const w = new VetoWindow(call, 0, { windowMs: 10, now: c.now });
    w.markDelivered();
    c.advance(11);
    w.tick();
    expect(() => w.veto("adam")).toThrow(/released/);
  });
});
