import { describe, expect, it } from "vitest";
import type { LimitRule, ToolCall } from "@ownerswitchai/shared";
import { LimitTracker, limitTripReason, MAX_WINDOW_EVENTS } from "./limits.js";

const call = (tool: string, args?: Record<string, unknown>): ToolCall => ({
  agentId: "a1",
  tool,
  args,
});

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

describe("LimitTracker", () => {
  it("a lifetime calls limit trips exactly when the total crosses max, once", () => {
    const rule: LimitRule = { id: "l1", tool: "stripe.*", metric: "calls", max: 2, action: "alert" };
    const tracker = new LimitTracker([rule]);
    expect(tracker.observeCall(call("stripe.payout"))).toEqual([]); // 1
    expect(tracker.observeCall(call("stripe.payout"))).toEqual([]); // 2 == max: not over
    const trips = tracker.observeCall(call("stripe.payout")); // 3 > 2: crossing
    expect(trips).toHaveLength(1);
    expect(trips[0]).toMatchObject({ cause: "threshold-crossed", total: 3 });
    expect(tracker.observeCall(call("stripe.payout"))).toEqual([]); // still over: no re-fire
  });

  it("only matching calls count: tool glob and argsPattern filter, same semantics as policy", () => {
    const rule: LimitRule = {
      id: "l1",
      tool: "bash",
      argsPattern: "rm\\s+-rf",
      metric: "calls",
      max: 0,
      action: "alert",
    };
    const tracker = new LimitTracker([rule]);
    expect(tracker.observeCall(call("search.web"))).toEqual([]); // wrong tool
    expect(tracker.observeCall(call("bash", { cmd: "ls" }))).toEqual([]); // args don't match
    expect(tracker.observeCall(call("bash", { cmd: "rm -rf /tmp/x" }))).toHaveLength(1);
  });

  it("a sliding window decays: totals expire, and a fresh crossing after quiet re-fires", () => {
    const c = clock();
    const rule: LimitRule = {
      id: "l1",
      tool: "*",
      metric: "calls",
      max: 1,
      windowMs: 1_000,
      action: "alert",
    };
    const tracker = new LimitTracker([rule], { now: c.now });
    tracker.observeCall(call("x")); // 1
    expect(tracker.observeCall(call("x"))).toHaveLength(1); // 2 > 1: trip
    c.advance(5_000); // both events expire
    expect(tracker.observeCall(call("x"))).toEqual([]); // 1 again: under
    expect(tracker.observeCall(call("x"))).toHaveLength(1); // re-crossing fires again
  });

  it("a single call that alone crosses after decay still fires — the crossing is computed fresh", () => {
    const c = clock();
    const rule: LimitRule = {
      id: "l1",
      tool: "*",
      metric: "calls",
      max: 0,
      windowMs: 1_000,
      action: "alert",
    };
    const tracker = new LimitTracker([rule], { now: c.now });
    expect(tracker.observeCall(call("x"))).toHaveLength(1); // 1 > 0
    c.advance(5_000);
    expect(tracker.observeCall(call("x"))).toHaveLength(1); // decayed to 0, crosses again alone
  });

  it("errors count only through observeError, calls only through observeCall", () => {
    const errRule: LimitRule = { id: "errs", tool: "*", metric: "errors", max: 1, action: "kill" };
    const callRule: LimitRule = { id: "calls", tool: "*", metric: "calls", max: 99, action: "kill" };
    const tracker = new LimitTracker([errRule, callRule]);
    tracker.observeCall(call("x"));
    tracker.observeCall(call("x"));
    expect(tracker.killTripped).toBeUndefined(); // calls did not feed the error budget
    tracker.observeError(call("x"));
    const trips = tracker.observeError(call("x"));
    expect(trips).toHaveLength(1);
    expect(trips[0].rule.id).toBe("errs");
  });

  it("an amount limit sums the value at amountPath, including nested paths", () => {
    const rule: LimitRule = {
      id: "spend",
      tool: "stripe.payout",
      metric: "amount",
      amountPath: "payment.cents",
      max: 1_000,
      action: "kill",
    };
    const tracker = new LimitTracker([rule]);
    expect(tracker.observeCall(call("stripe.payout", { payment: { cents: 600 } }))).toEqual([]);
    const trips = tracker.observeCall(call("stripe.payout", { payment: { cents: 600 } }));
    expect(trips).toHaveLength(1);
    expect(trips[0]).toMatchObject({ cause: "threshold-crossed", total: 1_200 });
    expect(tracker.killTripped?.id).toBe("spend");
  });

  it("an unreadable amount TRIPS the rule — an unmetered spend fails closed at the first call", () => {
    const rule: LimitRule = {
      id: "spend",
      tool: "stripe.*",
      metric: "amount",
      amountPath: "cents",
      max: 1_000_000,
      action: "kill",
    };
    for (const args of [
      undefined,
      {},
      { cents: "600" }, // string, not number
      { cents: -5 }, // negative
      { cents: Number.NaN },
      { cents: Number.POSITIVE_INFINITY },
    ]) {
      const tracker = new LimitTracker([rule]);
      const trips = tracker.observeCall(call("stripe.payout", args));
      expect(trips, JSON.stringify(args)).toHaveLength(1);
      expect(trips[0].cause).toBe("amount-unreadable");
      expect(tracker.killTripped?.id).toBe("spend");
    }
  });

  it("a kill-action trip LATCHES for the process lifetime; alert-action does not", () => {
    const c = clock();
    const alertRule: LimitRule = {
      id: "soft",
      tool: "*",
      metric: "calls",
      max: 0,
      windowMs: 1_000,
      action: "alert",
    };
    const killRule: LimitRule = { id: "hard", tool: "*", metric: "calls", max: 2, action: "kill" };
    const tracker = new LimitTracker([alertRule, killRule], { now: c.now });
    tracker.observeCall(call("x")); // soft trips
    expect(tracker.killTripped).toBeUndefined(); // alert never latches
    tracker.observeCall(call("x"));
    tracker.observeCall(call("x")); // hard crosses 2
    expect(tracker.killTripped?.id).toBe("hard");
    c.advance(60_000);
    expect(tracker.killTripped?.id).toBe("hard"); // no decay un-latches a kill
  });

  it("a flooded window fails closed at the event cap rather than dropping events", () => {
    const rule: LimitRule = {
      id: "flood",
      tool: "*",
      metric: "calls",
      // max above the event cap: the cap, not the threshold, must fire
      max: MAX_WINDOW_EVENTS * 2,
      windowMs: 60_000,
      action: "kill",
    };
    const tracker = new LimitTracker([rule], { now: () => 1 });
    let overflowed: string | undefined;
    for (let i = 0; i <= MAX_WINDOW_EVENTS; i += 1) {
      const trips = tracker.observeCall(call("x"));
      if (trips.length > 0) {
        overflowed = trips[0].cause;
        break;
      }
    }
    expect(overflowed).toBe("tracking-overflow");
    expect(tracker.killTripped?.id).toBe("flood");
  });

  it("limitTripReason names the rule, the agent, the totals and the failure cause", () => {
    const rule: LimitRule = { id: "l1", tool: "stripe.*", metric: "calls", max: 2, action: "kill" };
    const reason = limitTripReason({ rule, total: 3, cause: "threshold-crossed" }, "agent-7");
    expect(reason).toContain('"l1"');
    expect(reason).toContain('"agent-7"');
    expect(reason).toContain("3");
    expect(reason).toContain("2");
  });
});
