/**
 * LimitTracker — the counting half of cumulative limit rules (the shared
 * `LimitRule` type documents the model; this class enforces it).
 *
 * Doctrine, same as everything else here:
 *  - fail closed on doubt: a counted "amount" call whose amount cannot be
 *    read as a non-negative SAFE INTEGER trips the rule outright; a
 *    windowed rule whose event buffer overflows saturates as exceeded
 *    rather than dropping events; a running total that would leave safe
 *    integer range trips instead of silently rounding (IEEE-754 would
 *    otherwise let 2^53 + 1 spend read as 2^53 — an unmetered overspend).
 *  - a KILL trip follows an explicit LIFECYCLE, not a process-lifetime
 *    boolean:
 *      armed → tripped-UNCONFIRMED → tripped-CONFIRMED → released
 *    A fresh trip latches locally and (with a store wired in) persists, so
 *    a crash before the signed kill lands does not un-trip the budget: the
 *    next boot latches again and the caller re-fires the report
 *    (`pendingKillReport`). The latch becomes CONFIRMED when the control
 *    plane is seen listing the agent scope-killed (`observeKillState`) or
 *    when the kill report's delivery confirms (`confirmKillDelivered`).
 *    Only a CONFIRMED latch releases when the agent later leaves
 *    `killedAgents` — that absence is the owner's 2GO restore, and it
 *    re-arms every budget fresh (reset). An UNCONFIRMED latch never
 *    releases on absence: before the kill lands the agent is absent from
 *    the list too, and reading that as "restored" would be fail-open.
 *  - counters are process-local and honest about it: a gateway restart
 *    resets them (documented in limit-rule.ts). The latch is the one thing
 *    the store carries across restarts, because the latch is enforcement;
 *    the counters that led to it are bookkeeping.
 *
 * Trip semantics: a rule fires when one observation moves its total from
 * ≤ max to > max — the crossing is computed fresh per observation, from the
 * decayed pre-observation total, so a sliding window that quietly decayed
 * below the line re-arms even when the very next call crosses it alone.
 */
import type { LimitRule, ToolCall } from "@ownerswitchai/shared";
import { toolGlobMatches } from "./engine.js";

export interface LimitTrip {
  rule: LimitRule;
  /** the windowed total at the moment of the trip */
  total: number;
  /** why the trip fired — a threshold crossing, or a fail-closed refusal to guess */
  cause: "threshold-crossed" | "amount-unreadable" | "tracking-overflow" | "total-overflow";
}

/**
 * The durable record of a kill-action trip: everything a fresh process
 * needs to keep refusing and to RE-FIRE the signed scoped kill. `confirmed`
 * flips when the control plane is seen holding the kill (listed on
 * /status.killedAgents, or the report's delivery confirmed) — only then may
 * a later absence from the list read as the owner's restore.
 */
export interface PersistedLimitTrip {
  ruleId: string;
  agentId: string;
  /** the audit reason the kill report carries — re-fired verbatim after a restart */
  reason: string;
  at: number;
  confirmed: boolean;
}

/**
 * Where a kill-action trip survives a process restart. Load runs once at
 * construction; save/clear on latch transitions. An implementation that
 * cannot durably persist should THROW from save — a trip the caller
 * believes persisted but was not is the one lie this interface must not
 * tell (the tracker latches in memory regardless; see observe()).
 */
export interface LimitTripStore {
  load(): PersistedLimitTrip | null;
  save(record: PersistedLimitTrip): void;
  clear(): void;
}

/**
 * Ceiling on remembered events per windowed rule. At the cap the rule
 * SATURATES fail-closed: the buffer is emptied (bounding memory), the rule
 * reads as exceeded for one full window (nothing can prove otherwise —
 * the evidence was at capacity), exactly one trip fires, and counting
 * resumes fresh once the old window has provably expired.
 */
export const MAX_WINDOW_EVENTS = 16_384;

/**
 * Ceiling on a rule's `max` (enforced at config load): keeping max well
 * under Number.MAX_SAFE_INTEGER means a checked, clamped total is ALWAYS
 * comparable against it — a clamped MAX_SAFE_INTEGER total is over every
 * legal max, so overflow can never read as under-budget.
 */
export const MAX_LIMIT_MAX = 2 ** 50;

interface RuleState {
  rule: LimitRule;
  /** lifetime rules: one accumulator (safe integer or MAX_SAFE clamp) */
  lifetimeTotal: number;
  /** windowed rules: (at, value) events inside the window, oldest first */
  events: Array<{ at: number; value: number }>;
  /** saturated (overflowed) until this instant; no counting, no re-alerts */
  saturatedUntil?: number;
}

type LatchState =
  | { phase: "armed" }
  | { phase: "unconfirmed"; record: PersistedLimitTrip }
  | { phase: "confirmed"; record: PersistedLimitTrip };

/**
 * Read a dot-path (e.g. "payment.total") off the call args. Amounts count
 * in ATOMIC UNITS (integer cents, not fractional dollars): only a
 * non-negative SAFE INTEGER is readable — floats round, and a rounding
 * budget is no budget. null = unreadable.
 */
function amountAt(args: Record<string, unknown> | undefined, path: string): number | null {
  let node: unknown = args;
  for (const key of path.split(".")) {
    if (typeof node !== "object" || node === null || Array.isArray(node)) return null;
    node = (node as Record<string, unknown>)[key];
  }
  return typeof node === "number" && Number.isSafeInteger(node) && node >= 0 ? node : null;
}

/** Checked addition: clamps to MAX_SAFE_INTEGER instead of rounding past it. */
function checkedAdd(a: number, b: number): number {
  const sum = a + b;
  return Number.isSafeInteger(sum) ? sum : Number.MAX_SAFE_INTEGER;
}

export class LimitTracker {
  private readonly states: RuleState[];
  private readonly now: () => number;
  private readonly maxWindowEvents: number;
  private readonly store?: LimitTripStore;
  private latch: LatchState = { phase: "armed" };

  constructor(
    rules: readonly LimitRule[],
    opts: { now?: () => number; tripStore?: LimitTripStore; maxWindowEvents?: number } = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.maxWindowEvents = opts.maxWindowEvents ?? MAX_WINDOW_EVENTS;
    this.store = opts.tripStore;
    this.states = rules.map((rule) => ({ rule, lifetimeTotal: 0, events: [] }));
    // A persisted trip re-latches BEFORE any call can be observed: a crash
    // between the trip and the kill's delivery must not reopen the budget.
    const persisted = this.store?.load() ?? null;
    if (persisted !== null) {
      this.latch = { phase: persisted.confirmed ? "confirmed" : "unconfirmed", record: persisted };
    }
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
   * The latched kill trip, if any — the local, durable belt while the
   * signed scoped kill propagates (or awaits the owner's restore). The
   * caller should refuse every call while this is set.
   */
  get killTripped(): PersistedLimitTrip | undefined {
    return this.latch.phase === "armed" ? undefined : this.latch.record;
  }

  /**
   * The trip whose kill report has NOT been confirmed delivered — a fresh
   * process re-fires this at startup so a crash cannot swallow the kill.
   */
  get pendingKillReport(): PersistedLimitTrip | undefined {
    return this.latch.phase === "unconfirmed" ? this.latch.record : undefined;
  }

  /**
   * Drive the latch lifecycle off the live /status answer the caller
   * already fetched for its own decision. Two transitions, both explicit:
   *  - UNCONFIRMED + agent listed  → CONFIRMED (the kill landed)
   *  - CONFIRMED  + agent absent   → released (the owner's 2GO restore):
   *    the latch clears, the store clears, and EVERY budget re-arms fresh.
   * An UNCONFIRMED latch is deliberately deaf to absence — before the kill
   * lands the agent is absent too, and releasing on that would be fail-open.
   */
  observeKillState(killedAgents: readonly string[]): void {
    if (this.latch.phase === "unconfirmed" && killedAgents.includes(this.latch.record.agentId)) {
      this.confirmKillDelivered();
      return;
    }
    if (this.latch.phase === "confirmed" && !killedAgents.includes(this.latch.record.agentId)) {
      this.latch = { phase: "armed" };
      for (const state of this.states) {
        state.lifetimeTotal = 0;
        state.events.length = 0;
        state.saturatedUntil = undefined;
      }
      this.store?.clear();
    }
  }

  /** The kill report's delivery confirmed — same transition as being seen listed. */
  confirmKillDelivered(): void {
    if (this.latch.phase !== "unconfirmed") return;
    const record: PersistedLimitTrip = { ...this.latch.record, confirmed: true };
    this.latch = { phase: "confirmed", record };
    this.persist(record);
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

      // Saturated: the window overflowed. No counting and no re-alerts
      // until the old window has provably expired — then resume fresh
      // (every overflowed event is by then outside any window anyway).
      if (state.saturatedUntil !== undefined) {
        if (at < state.saturatedUntil) continue;
        state.saturatedUntil = undefined;
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
          // a typo'd path, a schema drift or a float becomes a loud trip at
          // deploy time, never thirty silently uncounted payouts.
          this.trip(trips, { rule, total: before, cause: "amount-unreadable" }, call);
          continue;
        }
        value = amount;
      } else {
        value = 1;
      }

      const total = checkedAdd(before, value);
      if (total === Number.MAX_SAFE_INTEGER && before !== Number.MAX_SAFE_INTEGER) {
        // FAIL CLOSED: past safe-integer range addition starts rounding and
        // an overspend could read as no spend. max is capped far below the
        // clamp (MAX_LIMIT_MAX), so a clamped total is over every legal max.
        this.trip(trips, { rule, total, cause: "total-overflow" }, call);
        // the clamp persists so the rule stays visibly exceeded
        if (rule.windowMs === undefined) state.lifetimeTotal = Number.MAX_SAFE_INTEGER;
        else this.saturate(state, at);
        continue;
      }

      if (rule.windowMs === undefined) {
        state.lifetimeTotal = total;
      } else {
        state.events.push({ at, value });
        if (state.events.length > this.maxWindowEvents) {
          // FAIL CLOSED: too much traffic to track is itself a violation.
          // Saturate: bound memory NOW, alert exactly once, resume counting
          // only after the whole window has expired.
          this.saturate(state, at);
          this.trip(trips, { rule, total, cause: "tracking-overflow" }, call);
          continue;
        }
      }
      if (before <= rule.max && total > rule.max) {
        this.trip(trips, { rule, total, cause: "threshold-crossed" }, call);
      }
    }
    return trips;
  }

  /** Record a trip; kill-action trips latch and persist as UNCONFIRMED. */
  private trip(trips: LimitTrip[], trip: LimitTrip, call: ToolCall): void {
    trips.push(trip);
    if (trip.rule.action !== "kill" || this.latch.phase !== "armed") return;
    const record: PersistedLimitTrip = {
      ruleId: trip.rule.id,
      agentId: call.agentId,
      reason: limitTripReason(trip, call.agentId),
      at: this.now(),
      confirmed: false,
    };
    // Latch in memory FIRST: a store that throws must never leave the
    // budget open. The caller decides whether an unpersistable trip is a
    // startup-blocking condition (the file store refuses to construct on a
    // bad path, so a throw here is disk trouble mid-flight — the in-memory
    // latch still refuses everything until the process ends).
    this.latch = { phase: "unconfirmed", record };
    this.persist(record);
  }

  private persist(record: PersistedLimitTrip): void {
    try {
      this.store?.save(record);
    } catch (err) {
      console.error(
        `[ownerswitch] FAILED to persist limit trip (rule "${record.ruleId}"): ` +
          `${err instanceof Error ? err.message : String(err)} — the in-memory latch stands, ` +
          `but a crash before the kill lands could lose it`,
      );
    }
  }

  private saturate(state: RuleState, at: number): void {
    state.events.length = 0;
    state.saturatedUntil = at + (state.rule.windowMs ?? 0);
  }

  private prune(state: RuleState, at: number): void {
    const windowMs = state.rule.windowMs;
    if (windowMs === undefined) return;
    const cutoff = at - windowMs;
    let drop = 0;
    while (drop < state.events.length && state.events[drop].at <= cutoff) drop += 1;
    if (drop > 0) state.events.splice(0, drop);
  }

  /** Total over the (already pruned) current window, or the lifetime total. Clamped, never rounded. */
  private currentTotal(state: RuleState): number {
    if (state.rule.windowMs === undefined) return state.lifetimeTotal;
    let sum = 0;
    for (const e of state.events) sum = checkedAdd(sum, e.value);
    return sum;
  }
}

/** The audit-trail reason a tripped limit sends with its kill or alert. */
export function limitTripReason(trip: LimitTrip, agentId: string): string {
  const why =
    trip.cause === "threshold-crossed"
      ? `total ${trip.total} exceeded max ${trip.rule.max}`
      : trip.cause === "amount-unreadable"
        ? `a counted call's amount at "${trip.rule.amountPath}" was not a non-negative integer — failing closed`
        : trip.cause === "total-overflow"
          ? `the running total left safe-integer range — failing closed rather than rounding`
          : `event tracking overflowed the window buffer — failing closed`;
  return `limit "${trip.rule.id}" tripped for agent "${agentId}": ${why} (metric ${trip.rule.metric}, tool ${trip.rule.tool})`;
}
