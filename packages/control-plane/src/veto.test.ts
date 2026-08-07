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
    const w = new VetoWindow(call, { now: c.now });
    w.markDelivered();
    w.veto("adam");
    expect(w.state).toBe("vetoed");
    expect(w.vetoedBy).toBe("adam");
  });

  it("silence releases — but only when delivery was confirmed", () => {
    const c = clock();
    const w = new VetoWindow(call, { windowMs: 1000, now: c.now });
    w.markDelivered();
    c.advance(1001);
    expect(w.tick()).toBe("released");
  });

  it("unreachable owner: extends once instead of releasing", () => {
    const c = clock();
    const w = new VetoWindow(call, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    expect(w.tick()).toBe("extended");
    // still vetoable during the extension
    w.veto("adam");
    expect(w.state).toBe("vetoed");
  });

  it("still unreachable after extension: held for active approval", () => {
    const c = clock();
    const w = new VetoWindow(call, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    w.tick(); // extended
    c.advance(2001);
    expect(w.tick()).toBe("held");
  });

  it("late delivery during extension lets silence release", () => {
    const c = clock();
    const w = new VetoWindow(call, { windowMs: 1000, extensionMs: 2000, now: c.now });
    c.advance(1001);
    w.tick(); // extended
    w.markDelivered();
    c.advance(2001);
    expect(w.tick()).toBe("released");
  });

  it("terminal states reject veto", () => {
    const c = clock();
    const w = new VetoWindow(call, { windowMs: 10, now: c.now });
    w.markDelivered();
    c.advance(11);
    w.tick();
    expect(() => w.veto("adam")).toThrow(/released/);
  });
});
