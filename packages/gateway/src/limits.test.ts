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

  it("a fresh trip latches UNCONFIRMED with the record the kill report carries", () => {
    const tracker = new LimitTracker([KILL_RULE], { now: () => 5 });
    tracker.observeCall(call("x"));
    expect(tracker.killTripped).toMatchObject({
      ruleId: "hard",
      agentId: "a1",
      confirmed: false,
      at: 5,
    });
    expect(tracker.killTripped?.reason).toContain('"hard"');
  });

  it("an UNCONFIRMED latch never releases on absence — before the kill lands the agent is absent too", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"));
    tracker.observeKillState([], { epoch: 9 }); // control plane does not (yet) list the agent
    tracker.observeKillState([], { epoch: 9 });
    expect(tracker.killTripped?.ruleId).toBe("hard"); // still latched — fail closed
  });

  it("confirmed → later absence → released and budgets re-armed", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeKillState([], { epoch: 4 }); // the world before the trip
    tracker.observeCall(call("x"));

    tracker.confirmKillDelivered(5, 1); // our kill's own commit epoch
    expect(tracker.killTripped?.confirmed).toBe(true);
    expect(tracker.killTripped?.ruleId).toBe("hard"); // still refusing, honestly

    tracker.observeKillState([], { epoch: 5 }); // the owner's 2GO restore
    expect(tracker.killTripped).toBeUndefined();
    // budgets re-armed FRESH: the very next call is a new crossing, not a
    // stale continuation of the pre-restore totals
    const trips = tracker.observeCall(call("x"));
    expect(trips).toHaveLength(1);
    expect(trips[0].cause).toBe("threshold-crossed");
  });

  it("a STALE pre-kill answer never releases a confirmed latch — ordering is enforced by epoch", () => {
    // the race: a /status fetched BEFORE the kill lands after the
    // confirmation. Its empty killedAgents looks exactly like the owner's
    // restore; only the epoch tells them apart (a kill bumps it, a restore
    // does not).
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeKillState([], { epoch: 7 }); // the world before the trip
    tracker.observeCall(call("x")); // trips; the kill will make epoch 8
    tracker.confirmKillDelivered(8, 1); // our kill's own response → confirmed
    expect(tracker.killTripped?.confirmed).toBe(true);

    tracker.observeKillState([], { epoch: 7 }); // the stale answer, arriving late
    expect(tracker.killTripped?.ruleId).toBe("hard"); // NOT released
    tracker.observeKillState([], { epoch: 6 }); // even older
    expect(tracker.killTripped?.ruleId).toBe("hard");

    tracker.observeKillState([], { epoch: 8 }); // the genuine restore (epoch unchanged by restore)
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a NEIGHBOURING kill's epoch cannot release us: the commit epoch anchors the latch", () => {
    // The epoch line is SHARED. Baseline E, so the provisional floor is E+1
    // — but another agent's kill takes E+1, and a snapshot from THAT world
    // legitimately lacks our agent (our kill has not landed yet). Only the
    // control plane's own commit epoch (E+2) can tell the two apart.
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 10 }); // baseline 10 → provisional floor 11
    tracker.confirmKillDelivered(12, 1); // OUR kill actually committed at 12
    expect(tracker.killTripped?.confirmed).toBe(true);

    // the neighbour's-epoch snapshot, arriving late, does NOT release us
    tracker.observeKillState([], { epoch: 11 });
    expect(tracker.killTripped?.ruleId).toBe("hard");

    tracker.observeKillState([], { epoch: 12 }); // our world: the real restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a PREVIOUS kill-cycle's late 'listed' answer cannot confirm a new trip", () => {
    // an old, since-restored kill of the SAME agent, whose status answer is
    // still in flight when the agent trips again
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 5 }); // new trip: floor 6
    tracker.observeKillState(["a1"], { epoch: 5 }); // the stale listing from the OLD kill
    expect(tracker.killTripped?.confirmed).toBe(false); // not our evidence

    // ...and it did not lower the floor either: an epoch-5 absence holds
    tracker.observeKillState([], { epoch: 5 });
    expect(tracker.killTripped?.ruleId).toBe("hard");

    // our own kill response is what confirms
    tracker.confirmKillDelivered(6, 1);
    expect(tracker.killTripped?.confirmed).toBe(true);
    tracker.observeKillState([], { epoch: 6 });
    expect(tracker.killTripped).toBeUndefined();
  });

  it("floors only ever rise: an out-of-order answer cannot widen the release window", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 3 }); // floor 4
    tracker.confirmKillDelivered(4, 1); // our commit epoch anchors at 4
    tracker.observeKillState(["a1"], { epoch: 9 }); // still killed at 9 → floor 9
    expect(tracker.killTripped?.confirmed).toBe(true);
    for (const stale of [4, 5, 8]) {
      tracker.observeKillState([], { epoch: stale });
      expect(tracker.killTripped?.ruleId, `epoch ${stale}`).toBe("hard");
    }
    tracker.observeKillState([], { epoch: 9 });
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a concurrent call's epoch cannot re-anchor another call's trip", () => {
    // each observation carries ITS OWN call's pre-dispatch epoch; a later
    // call reading a moved epoch must not retro-anchor an existing trip
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 2 }); // trip: floor 3
    tracker.observeCall(call("y"), { epoch: 7 }); // a concurrent call, already over max
    tracker.confirmKillDelivered(3, 1);
    tracker.observeKillState([], { epoch: 3 }); // our commit epoch: genuine restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("an epoch-less answer holds a confirmed latch rather than guessing", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x")); // no epoch ever observed → no floor
    tracker.confirmKillDelivered(4, 1); // our commit epoch anchors it exactly
    tracker.observeKillState([]); // no epoch on the answer: cannot order it
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState([], { epoch: 4 }); // our world: the real restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a DEGRADED answer drives no transition — a kill that may not survive a restart proves nothing", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeKillState([], { epoch: 1 });
    tracker.observeCall(call("x"));
    // our kill's own response confirms (the only path that can)
    tracker.confirmKillDelivered(2, 1);
    expect(tracker.killTripped?.confirmed).toBe(true);
    // a DEGRADED absence cannot release: the kill it describes may not
    // survive a restart, so it proves nothing durable in either direction
    tracker.observeKillState([], { epoch: 2, durable: false });
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState([], { epoch: 2 }); // healthy: the real restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("our own kill response is the ONLY confirmation, and its epoch is the anchor", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeKillState([], { epoch: 2 });
    tracker.observeCall(call("x")); // floor = 3 (the kill will bump 2 → 3)
    tracker.confirmKillDelivered(3, 1); // POST /kill confirmed, commit epoch 3
    expect(tracker.killTripped?.confirmed).toBe(true);
    tracker.observeKillState([], { epoch: 2 }); // a stale pre-kill answer: holds
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState([], { epoch: 3 }); // the post-kill world: restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a foreign kill's listing cannot confirm us, and its restore cannot release us", () => {
    // The v7 finding: /status only proves the agent was killed by
    // SOMETHING — a manual stop, a honeytoken, a previous limit cycle.
    // Binding this trip to that kill would let ITS restore release US.
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 10 }); // our trip; provisional floor 11
    tracker.observeKillState(["a1"], { epoch: 11 }); // some OTHER kill of this agent
    expect(tracker.killTripped?.confirmed).toBe(false); // not our evidence
    tracker.observeKillState([], { epoch: 11 }); // that kill's restore
    expect(tracker.killTripped?.ruleId).toBe("hard"); // we are STILL latched

    tracker.confirmKillDelivered(12, 1); // now OUR kill's response arrives
    expect(tracker.killTripped?.confirmed).toBe(true);
    tracker.observeKillState([], { epoch: 11 }); // the older world: inadmissible
    expect(tracker.killTripped?.ruleId).toBe("hard");
    tracker.observeKillState([], { epoch: 12 }); // our own restore
    expect(tracker.killTripped).toBeUndefined();
  });

  it("a foreign listing+absence BEFORE our response leaves the latch untouched", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 4 });
    tracker.observeKillState(["a1"], { epoch: 5 }); // foreign kill
    tracker.observeKillState([], { epoch: 6 }); // its restore
    expect(tracker.killTripped?.ruleId).toBe("hard"); // never confirmed, never released
    expect(tracker.killTripped?.confirmed).toBe(false);
  });

  it("refuses a confirmation that cannot be a real commit anchor", () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
      const tracker = new LimitTracker([KILL_RULE]);
      tracker.observeCall(call("x"), { epoch: 2 });
      tracker.confirmKillDelivered(bad, 1);
      expect(tracker.killTripped?.confirmed, `epoch ${bad}`).toBe(false);
    }
    // below the trip's own floor: an older world than we already saw
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 9 }); // floor 10
    tracker.confirmKillDelivered(9, 1);
    expect(tracker.killTripped?.confirmed).toBe(false);
    tracker.confirmKillDelivered(10, 1); // the real one
    expect(tracker.killTripped?.confirmed).toBe(true);
  });

  it("ONE call crossing TWO kill rules latches ONCE — only that trip carries a kill", () => {
    // The v8 finding: a payout can cross a `calls` budget and an `amount`
    // budget in the same observation. Reporting both would fire two scoped
    // kills, each bumping the control plane's epoch, while the latch is
    // anchored to ONE commit epoch — the second kill would then have no
    // anchor, and the owner's restore of the first would re-arm every budget
    // while the agent was still killed by the second, with no ceremony for
    // it. Exactly one trip is stamped, and the stamp IS the instruction.
    const tracker = new LimitTracker([
      { id: "call-budget", tool: "*", metric: "calls", max: 0, action: "kill" },
      { id: "spend-budget", tool: "*", metric: "amount", amountPath: "cents", max: 0, action: "kill" },
      { id: "watch", tool: "*", metric: "calls", max: 0, action: "alert" },
    ]);
    const trips = tracker.observeCall(call("stripe.payout", { cents: 900 }), { epoch: 4 });

    // every crossing is REPORTED to the caller — nothing is hidden
    expect(trips.map((t) => t.rule.id)).toEqual(["call-budget", "spend-budget", "watch"]);
    // ...but exactly one of them carries the kill
    const stamped = trips.filter((t) => t.latchGeneration !== undefined);
    expect(stamped).toHaveLength(1);
    expect(stamped[0].rule.id).toBe("call-budget"); // deterministically the first
    expect(stamped[0].latchGeneration).toBe(1);
    expect(tracker.killTripped).toMatchObject({ ruleId: "call-budget", generation: 1 });

    // and the single kill covers everything: one commit epoch anchors the
    // latch, one owner restore re-arms BOTH budgets
    tracker.confirmKillDelivered(5, 1);
    tracker.observeKillState([], { epoch: 5 });
    expect(tracker.killTripped).toBeUndefined();
    const again = tracker.observeCall(call("stripe.payout", { cents: 900 }), { epoch: 5 });
    expect(again.filter((t) => t.latchGeneration !== undefined)).toHaveLength(1);
  });

  it("a confirmation is BOUND to its latch: a late answer cannot anchor the NEXT latch", () => {
    const tracker = new LimitTracker([KILL_RULE]);
    tracker.observeCall(call("x"), { epoch: 5 }); // latch 1
    expect(tracker.killTripped?.generation).toBe(1);
    tracker.confirmKillDelivered(6, 1);
    tracker.observeKillState([], { epoch: 6 }); // the owner's restore of latch 1
    expect(tracker.killTripped).toBeUndefined();

    // a NEW trip, with no epoch of its own — nothing but the generation can
    // tell the retry's late answer apart from this latch's own
    tracker.observeCall(call("x"));
    expect(tracker.killTripped?.generation).toBe(2);
    tracker.confirmKillDelivered(6, 1); // latch 1's retry, landing late
    expect(tracker.killTripped?.confirmed).toBe(false); // not ours: still holding
    tracker.confirmKillDelivered(7, 2); // latch 2's own answer
    expect(tracker.killTripped?.confirmed).toBe(true);
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
