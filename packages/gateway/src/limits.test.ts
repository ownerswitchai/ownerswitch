import { describe, expect, it } from "vitest";
import type { LimitRule, ToolCall } from "@ownerswitchai/shared";
import {
  LimitTracker,
  limitTripReason,
  MAX_WINDOW_EVENTS,
  type LimitTripStore,
  type PersistedLimitTrip,
} from "./limits.js";

/** In-memory store: records saves/clears, serves a scripted load. */
class FakeTripStore implements LimitTripStore {
  stored: PersistedLimitTrip | null = null;
  saves: PersistedLimitTrip[] = [];
  clears = 0;
  load(): PersistedLimitTrip | null {
    return this.stored;
  }
  save(record: PersistedLimitTrip): void {
    this.saves.push(record);
    this.stored = record;
  }
  clear(): void {
    this.clears += 1;
    this.stored = null;
  }
}

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
    expect(tracker.killTripped?.ruleId).toBe("spend");
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
      expect(tracker.killTripped?.ruleId).toBe("spend");
    }
  });

  it("a kill-action trip LATCHES until the lifecycle releases it; alert-action does not", () => {
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
    expect(tracker.killTripped?.ruleId).toBe("hard");
    c.advance(60_000);
    expect(tracker.killTripped?.ruleId).toBe("hard"); // no decay un-latches a kill
  });

  it("a flooded window SATURATES at the event cap: bounded memory, one alert, re-armed after the window", () => {
    const c = clock(1);
    const rule: LimitRule = {
      id: "flood",
      tool: "*",
      metric: "calls",
      // max above the event cap: the cap, not the threshold, must fire
      max: 1_000_000,
      windowMs: 60_000,
      action: "alert",
    };
    const tracker = new LimitTracker([rule], { now: c.now, maxWindowEvents: 3 });
    const alerts: string[] = [];
    // an alert-action rule keeps running — this is exactly the case where an
    // unbounded buffer and an alert-per-call flood would have been possible
    for (let i = 0; i < 50; i += 1) {
      for (const trip of tracker.observeCall(call("x"))) alerts.push(trip.cause);
    }
    expect(alerts).toEqual(["tracking-overflow"]); // exactly once per saturation
    // still saturated inside the window: quiet
    c.advance(30_000);
    expect(tracker.observeCall(call("x"))).toEqual([]);
    // the window fully expired: counting resumes fresh, and a NEW flood
    // saturates (and alerts) again
    c.advance(61_000);
    for (let i = 0; i < 50; i += 1) {
      for (const trip of tracker.observeCall(call("x"))) alerts.push(trip.cause);
    }
    expect(alerts).toEqual(["tracking-overflow", "tracking-overflow"]);
  });

  it("a kill-action flood saturates once and latches", () => {
    const rule: LimitRule = {
      id: "flood",
      tool: "*",
      metric: "calls",
      max: 1_000_000,
      windowMs: 60_000,
      action: "kill",
    };
    const tracker = new LimitTracker([rule], { now: () => 1, maxWindowEvents: 3 });
    let overflowed: string | undefined;
    for (let i = 0; i < 10; i += 1) {
      const trips = tracker.observeCall(call("x"));
      if (trips.length > 0) overflowed = trips[0].cause;
    }
    expect(overflowed).toBe("tracking-overflow");
    expect(tracker.killTripped?.ruleId).toBe("flood");
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

describe("the kill-trip lifecycle: tripped-unconfirmed → confirmed → released", () => {
  const KILL_RULE: LimitRule = { id: "hard", tool: "*", metric: "calls", max: 0, action: "kill" };

  it("a fresh trip persists UNCONFIRMED and is offered for (re-)reporting", () => {
    const store = new FakeTripStore();
    const tracker = new LimitTracker([KILL_RULE], { now: () => 5, tripStore: store });
    tracker.observeCall(call("x"));
    expect(tracker.killTripped?.ruleId).toBe("hard");
    expect(tracker.pendingKillReport).toMatchObject({
      ruleId: "hard",
      agentId: "a1",
      confirmed: false,
      at: 5,
    });
    expect(store.stored?.confirmed).toBe(false);
  });

  it("a restart re-latches from the store and re-offers the unconfirmed kill report", () => {
    // the crash-before-delivery case: the trip must survive the process
    const store = new FakeTripStore();
    new LimitTracker([KILL_RULE], { now: () => 5, tripStore: store }).observeCall(call("x"));

    const rebooted = new LimitTracker([KILL_RULE], { now: () => 9, tripStore: store });
    expect(rebooted.killTripped?.ruleId).toBe("hard"); // latched before any call
    expect(rebooted.pendingKillReport?.reason).toContain('"hard"'); // re-fire with the stored reason
  });

  it("an UNCONFIRMED latch never releases on absence — before the kill lands the agent is absent too", () => {
    const store = new FakeTripStore();
    const tracker = new LimitTracker([KILL_RULE], { tripStore: store });
    tracker.observeCall(call("x"));
    tracker.observeKillState([]); // control plane does not (yet) list the agent
    tracker.observeKillState([]);
    expect(tracker.killTripped?.ruleId).toBe("hard"); // still latched — fail closed
    expect(store.stored).not.toBeNull();
  });

  it("seen listed → CONFIRMED (persisted); later absence → released, store cleared, budgets re-armed", () => {
    const store = new FakeTripStore();
    const tracker = new LimitTracker([KILL_RULE], { tripStore: store });
    tracker.observeCall(call("x"));

    tracker.observeKillState(["a1"]); // the scoped kill landed on /status
    expect(store.stored?.confirmed).toBe(true);
    expect(tracker.pendingKillReport).toBeUndefined(); // nothing left to re-fire
    expect(tracker.killTripped?.ruleId).toBe("hard"); // still refusing, honestly

    tracker.observeKillState([]); // the owner's 2GO restore
    expect(tracker.killTripped).toBeUndefined();
    expect(store.clears).toBe(1);
    // budgets re-armed FRESH: the very next call is a new crossing, not a
    // stale continuation of the pre-restore totals
    const trips = tracker.observeCall(call("x"));
    expect(trips).toHaveLength(1);
    expect(trips[0].cause).toBe("threshold-crossed");
  });

  it("confirmKillDelivered() is the same transition as being seen listed", () => {
    const store = new FakeTripStore();
    const tracker = new LimitTracker([KILL_RULE], { tripStore: store });
    tracker.observeCall(call("x"));
    tracker.confirmKillDelivered(); // POST /kill confirmed by the reporter
    expect(store.stored?.confirmed).toBe(true);
    tracker.observeKillState([]); // absence after confirmation = restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a confirmed record loaded at boot releases only on observed absence", () => {
    const store = new FakeTripStore();
    store.stored = { ruleId: "hard", agentId: "a1", reason: "r", at: 1, confirmed: true };
    const tracker = new LimitTracker([KILL_RULE], { tripStore: store });
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState(["a1"]); // still killed: stays latched
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState([]); // restored
    expect(tracker.killTripped).toBeUndefined();
  });
});

describe("safe-integer arithmetic — an overspend must never round into invisibility", () => {
  it("a float amount is unreadable: amounts count in atomic units", () => {
    const rule: LimitRule = {
      id: "spend",
      tool: "*",
      metric: "amount",
      amountPath: "cents",
      max: 1_000,
      action: "kill",
    };
    const tracker = new LimitTracker([rule]);
    const trips = tracker.observeCall(call("stripe.payout", { cents: 10.5 }));
    expect(trips).toHaveLength(1);
    expect(trips[0].cause).toBe("amount-unreadable");
  });

  it("a total leaving safe-integer range trips instead of rounding — 2^53 + 1 must not read as 2^53", () => {
    const rule: LimitRule = {
      id: "spend",
      tool: "*",
      metric: "amount",
      amountPath: "cents",
      max: 2 ** 50, // the config ceiling: every legal max is far below the clamp
      action: "kill",
    };
    const tracker = new LimitTracker([rule]);
    // first call: at max exactly — no crossing (total == max)
    expect(tracker.observeCall(call("pay", { cents: 2 ** 50 }))).toEqual([]);
    // an ordinary over-max sum still inside safe range is a plain crossing
    const crossing = tracker.observeCall(call("pay", { cents: 1 }));
    expect(crossing[0]?.cause).toBe("threshold-crossed");

    // a fresh tracker where one more unit would leave safe range: without
    // the checked add, MAX_SAFE + 2 rounds and the spend goes unmetered —
    // here it trips instead (a total landing exactly ON MAX_SAFE also reads
    // as overflow, deliberately: the boundary is indistinguishable from the
    // clamp, and ambiguity fails closed)
    const t2 = new LimitTracker([rule]);
    t2.observeCall(call("pay", { cents: Number.MAX_SAFE_INTEGER - 1 }));
    const overflow = t2.observeCall(call("pay", { cents: 2 }));
    expect(overflow[0]?.cause).toBe("total-overflow");
    expect(t2.killTripped?.ruleId).toBe("spend");
  });
});
