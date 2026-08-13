/**
 * LimitTracker — the counting half of cumulative limit rules (the shared
 * `LimitRule` type documents the model; this class enforces it).
 *
 * Doctrine, same as everything else here:
 *  - fail closed on doubt: a counted "amount" call whose amount cannot be
 *    read trips the rule outright; a windowed rule whose event buffer
 *    overflows reads as exceeded rather than silently dropping events.
 *  - a KILL trip is sticky: once a kill-action rule trips, the tracker
 *    reports this agent as tripped until the process ends — the local belt
 *    while the signed scoped kill lands on the control plane and comes back
 *    on /status.
 *  - counters are process-local and honest about it: a gateway restart
 *    resets them (documented in limit-rule.ts). The kill they fire is
 *    durable; the path to it is not.
 *
 * Trip semantics: a rule fires when one observation moves its total from
 * ≤ max to > max — the crossing is computed fresh per observation, from the
 * decayed pre-observation total, so a sliding window that quietly decayed
 * below the line re-arms even when the very next call crosses it alone.
 * Kill-action rules latch (the agent is being stopped); the crossing rule
 * keeps alert-action rules from flooding one alert per call while over the
 * line.
 */
import type { LimitRule, ToolCall } from "@ownerswitchai/shared";
import { toolGlobMatches } from "./engine.js";

export interface LimitTrip {
  rule: LimitRule;
  /** the windowed total at the moment of the trip */
  total: number;
  /** why the trip fired — a threshold crossing, or a fail-closed refusal to guess */
  cause: "threshold-crossed" | "amount-unreadable" | "tracking-overflow";
}

/**
 * Ceiling on remembered events per windowed rule. A window under a call
 * flood would otherwise grow memory without bound; at the cap the rule
 * reads as EXCEEDED (fail closed — traffic too heavy to track is itself a
 * limit violation), never as "events silently dropped".
 */
export const MAX_WINDOW_EVENTS = 16_384;

interface RuleState {
  rule: LimitRule;
  /** lifetime rules: one accumulator */
  lifetimeTotal: number;
  /** windowed rules: (at, value) events inside the window, oldest first */
  events: Array<{ at: number; value: number }>;
  /** a kill-action rule has tripped — latched for the process lifetime */
  killLatched: boolean;
}

/** Read a dot-path (e.g. "payment.total") off the call args; null = unreadable. */
function amountAt(args: Record<string, unknown> | undefined, path: string): number | null {
  let node: unknown = args;
  for (const key of path.split(".")) {
    if (typeof node !== "object" || node === null || Array.isArray(node)) return null;
    node = (node as Record<string, unknown>)[key];
  }
  return typeof node === "number" && Number.isFinite(node) && node >= 0 ? node : null;
}

export class LimitTracker {
  private readonly states: RuleState[];
  private readonly now: () => number;

  constructor(rules: readonly LimitRule[], opts: { now?: () => number } = {}) {
    this.now = opts.now ?? Date.now;
    this.states = rules.map((rule) => ({
      rule,
      lifetimeTotal: 0,
      events: [],
      killLatched: false,
    }));
  }

  /**
   * Count a call that is ABOUT TO BE FORWARDED (calls/amount metrics) and
   * return the rules this observation tripped. The caller decides what a
   * trip means (refuse + report kill, or report alert and continue).
   */
  observeCall(call: ToolCall): LimitTrip[] {
    return this.observe(call, ["calls", "amount"]);
  }

  /** Count a counted call whose execution FAILED (errors metric). */
  observeError(call: ToolCall): LimitTrip[] {
    return this.observe(call, ["errors"]);
  }

  /**
   * The first kill-action rule that has tripped, if any: the local,
   * process-lifetime belt while the signed scoped kill propagates. The
   * caller should refuse every subsequent call with this rule's account.
   */
  get killTripped(): LimitRule | undefined {
    return this.states.find((s) => s.killLatched)?.rule;
  }

  private observe(call: ToolCall, metrics: readonly string[]): LimitTrip[] {
    const trips: LimitTrip[] = [];
    const at = this.now();
    for (const state of this.states) {
      const { rule } = state;
      if (!metrics.includes(rule.metric)) continue;
      if (!toolGlobMatches(rule.tool, call.tool)) continue;
      if (
        rule.argsPattern !== undefined &&
        !new RegExp(rule.argsPattern).test(JSON.stringify(call.args ?? {}))
      ) {
        continue;
      }

      // decay first, so the pre-observation total (and the crossing it
      // defines) is exact even after a long quiet gap
      this.prune(state, at);
      const before = this.currentTotal(state);

      let value: number;
      if (rule.metric === "amount") {
        const amount = amountAt(call.args, rule.amountPath ?? "");
        if (amount === null) {
          // FAIL CLOSED: an unmetered spend must surface at the FIRST call —
          // a typo'd path or a schema drift becomes a loud trip at deploy
          // time, never thirty silently uncounted payouts.
          trips.push({ rule, total: before, cause: "amount-unreadable" });
          if (rule.action === "kill") state.killLatched = true;
          continue;
        }
        value = amount;
      } else {
        value = 1;
      }

      if (rule.windowMs === undefined) {
        state.lifetimeTotal += value;
      } else {
        state.events.push({ at, value });
        if (state.events.length > MAX_WINDOW_EVENTS) {
          // FAIL CLOSED: too much traffic to track is itself a violation.
          trips.push({ rule, total: before + value, cause: "tracking-overflow" });
          if (rule.action === "kill") state.killLatched = true;
          continue;
        }
      }
      const total = before + value;
      if (before <= rule.max && total > rule.max) {
        trips.push({ rule, total, cause: "threshold-crossed" });
        if (rule.action === "kill") state.killLatched = true;
      }
    }
    return trips;
  }

  private prune(state: RuleState, at: number): void {
    const windowMs = state.rule.windowMs;
    if (windowMs === undefined) return;
    const cutoff = at - windowMs;
    let drop = 0;
    while (drop < state.events.length && state.events[drop].at <= cutoff) drop += 1;
    if (drop > 0) state.events.splice(0, drop);
  }

  /** Total over the (already pruned) current window, or the lifetime total. */
  private currentTotal(state: RuleState): number {
    if (state.rule.windowMs === undefined) return state.lifetimeTotal;
    return state.events.reduce((sum, e) => sum + e.value, 0);
  }
}

/** The audit-trail reason a tripped limit sends with its kill or alert. */
export function limitTripReason(trip: LimitTrip, agentId: string): string {
  const why =
    trip.cause === "threshold-crossed"
      ? `total ${trip.total} exceeded max ${trip.rule.max}`
      : trip.cause === "amount-unreadable"
        ? `a counted call's amount at "${trip.rule.amountPath}" was unreadable — failing closed`
        : `event tracking overflowed (${MAX_WINDOW_EVENTS} events in window) — failing closed`;
  return `limit "${trip.rule.id}" tripped for agent "${agentId}": ${why} (metric ${trip.rule.metric}, tool ${trip.rule.tool})`;
}
