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
 *    The DURABLE latch authority is the CONTROL PLANE's persisted scoped
 *    kill — a separate-uid, fsync'd, deletion-protected record the agent
 *    cannot reach — not any gateway-side file (within one uid a gateway
 *    file is the agent's file, so it can never be a boundary; an earlier
 *    design tried and was rightly rejected in review). The caller delivers
 *    the signed kill SYNCHRONOUSLY on the crossing refusal; the in-memory
 *    latch only bridges an unreachable control plane — a state in which
 *    the fail-closed /status client is already denying every call anyway.
 *    The latch becomes CONFIRMED when the control plane is seen listing
 *    the agent scope-killed (`observeKillState`) or when the kill report's
 *    delivery confirms (`confirmKillDelivered`). Only a CONFIRMED latch
 *    releases when the agent later leaves `killedAgents` — that absence is
 *    the owner's 2GO restore, and it re-arms every budget fresh (reset).
 *    An UNCONFIRMED latch never releases on absence: before the kill
 *    lands the agent is absent from the list too, and reading that as
 *    "restored" would be fail-open.
 *  - counters are process-local and honest about it: a gateway restart
 *    resets them (documented in limit-rule.ts). The accepted residual,
 *    stated plainly: a crash while the control plane was UNREACHABLE at
 *    the exact moment of a trip loses that trip — no executed overspend
 *    (the crossing call was refused, and every call during the outage was
 *    denied fail-closed), only the counter history and the undelivered
 *    kill. A durable commit to an unreachable authority does not exist,
 *    and a same-uid local file is not one either.
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
 * The latched record of a kill-action trip: what the refusals cite and what
 * the kill report carries. `confirmed` flips when the control plane is seen
 * holding the kill (listed on /status.killedAgents, or the report's
 * delivery confirmed) — only then may a later absence from the list read as
 * the owner's restore.
 */
export interface LatchedLimitTrip {
  ruleId: string;
  agentId: string;
  /** the audit reason the kill report carries */
  reason: string;
  at: number;
  confirmed: boolean;
  /**
   * The lowest control-plane kill epoch whose answer can possibly include
   * THIS trip's scoped kill: the last epoch observed before the trip, plus
   * one (every scoped kill bumps the epoch). Any `/status` answer at or
   * below the pre-trip epoch is a pre-kill snapshot — its empty
   * `killedAgents` says nothing about our kill, and reading it as the
   * owner's restore would be fail-open. Undefined only when the tracker
   * had never observed an epoch at trip time (no live lookup yet); then
   * the floor is learned from the first answer that LISTS the agent.
   */
  epochFloor?: number;
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
  | { phase: "unconfirmed"; record: LatchedLimitTrip }
  | { phase: "confirmed"; record: LatchedLimitTrip };

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
    // own properties only: the wire hands us plain JSON, and an inherited
    // property standing in for an amount would be a boundary leak
    if (!Object.hasOwn(node, key)) return null;
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
  private latch: LatchState = { phase: "armed" };
  /** newest control-plane kill epoch this tracker has been shown */
  private lastObservedEpoch?: number;

  constructor(
    rules: readonly LimitRule[],
    opts: { now?: () => number; maxWindowEvents?: number } = {},
  ) {
    // Monotonic by default: sliding windows are process-local, and a
    // wall-clock jump (NTP step, manual set) must not silently expire or
    // extend a window. Injectable for tests.
    this.now = opts.now ?? (() => performance.now());
    this.maxWindowEvents = opts.maxWindowEvents ?? MAX_WINDOW_EVENTS;
    this.states = rules.map((rule) => ({ rule, lifetimeTotal: 0, events: [] }));
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
  get killTripped(): LatchedLimitTrip | undefined {
    return this.latch.phase === "armed" ? undefined : this.latch.record;
  }

  /**
   * Drive the latch lifecycle off the live /status answer the caller
   * already fetched for its own decision. Two transitions, both explicit:
   *  - UNCONFIRMED + agent listed  → CONFIRMED (the kill landed)
   *  - CONFIRMED  + agent absent   → released (the owner's 2GO restore):
   *    the latch clears and EVERY budget re-arms fresh.
   *
   * Three things gate those transitions, each closing a fail-open path:
   *
   *  1. An UNCONFIRMED latch is deaf to absence — before the kill lands the
   *     agent is absent too, and releasing on that would be fail-open.
   *  2. ORDERING. Answers can arrive out of order: a `/status` fetched
   *     before the kill can land after the confirmation, and its empty
   *     `killedAgents` would look exactly like the owner's restore. Every
   *     scoped kill bumps the control plane's epoch, so an answer at or
   *     below the trip's `epochFloor` is a pre-kill snapshot and is
   *     ignored. (A restore does NOT bump the epoch, so a genuine
   *     post-restore answer still carries the kill's epoch and passes.)
   *  3. DURABILITY. A control plane whose persistence is degraded lists a
   *     kill it may lose on restart: confirming from such an answer would
   *     let a restart erase the kill and the next answer's absence re-arm
   *     the budget with no owner ceremony. A degraded answer drives no
   *     transition at all — neither confirm nor release.
   */
  observeKillState(
    killedAgents: readonly string[],
    opts: { epoch?: number; durable?: boolean } = {},
  ): void {
    const { epoch, durable = true } = opts;
    if (epoch !== undefined) this.lastObservedEpoch = epoch;
    if (!durable) return; // says nothing trustworthy in either direction
    const listed =
      this.latch.phase !== "armed" && killedAgents.includes(this.latch.record.agentId);

    if (this.latch.phase === "unconfirmed" && listed) {
      // The authoritative confirmation: the kill is IN this answer, so this
      // answer's epoch is exactly the floor every later answer must clear.
      // Set it BEFORE confirming — confirmKillDelivered copies the record.
      if (epoch !== undefined) this.latch.record.epochFloor = epoch;
      this.confirmKillDelivered();
      return;
    }
    if (this.latch.phase !== "confirmed") return;
    if (listed) {
      // Still killed. If the floor is unknown (confirmed by DELIVERY alone,
      // before any epoch was observed), learn it here: seeing the kill in
      // force at this epoch means every answer from this epoch on is fresh
      // enough to speak about it.
      if (this.latch.record.epochFloor === undefined && epoch !== undefined) {
        this.latch.record.epochFloor = epoch;
      }
      return;
    }

    const floor = this.latch.record.epochFloor;
    // Without a floor we cannot tell a stale pre-kill answer from a
    // restore, and cannot prove our kill was ever visible — hold.
    if (floor === undefined) return;
    if (epoch === undefined || epoch < floor) return; // stale/unknown: hold

    this.latch = { phase: "armed" };
    for (const state of this.states) {
      state.lifetimeTotal = 0;
      state.events.length = 0;
      state.saturatedUntil = undefined;
    }
  }

  /** The kill report's delivery confirmed — same transition as being seen listed. */
  confirmKillDelivered(): void {
    if (this.latch.phase !== "unconfirmed") return;
    this.latch = { phase: "confirmed", record: { ...this.latch.record, confirmed: true } };
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
    const record: LatchedLimitTrip = {
      ruleId: trip.rule.id,
      agentId: call.agentId,
      reason: limitTripReason(trip, call.agentId),
      at: this.now(),
      confirmed: false,
      // the kill this trip is about to fire will bump the epoch, so only an
      // answer strictly past the last one we saw can reflect it
      ...(this.lastObservedEpoch !== undefined
        ? { epochFloor: this.lastObservedEpoch + 1 }
        : {}),
    };
    this.latch = { phase: "unconfirmed", record };
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
