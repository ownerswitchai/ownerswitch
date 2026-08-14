/**
 * Cumulative limit rules — the circuit-breaker tier of the policy model.
 *
 * A PolicyRule answers "may THIS call run?"; a LimitRule answers "has this
 * agent done TOO MUCH of something?", counting across calls: spend
 * thresholds, error budgets, call-rate ceilings — the boundaries the
 * community KILLSWITCH.md convention declares in prose, here as enforced
 * configuration. Where a KILLSWITCH.md is advice an agent can ignore, a
 * LimitRule trips the same signed kill path as a honeytoken: the declared
 * boundary becomes a stop.
 *
 * Counting happens where the calls are seen — in the gateway process
 * (@ownerswitchai/gateway `LimitTracker`), per agent, since the control
 * plane never sees allow-lane calls. Stated honestly:
 *  - counters live in gateway memory and reset when that process restarts;
 *    what survives is the KILL — the control plane's persisted scoped kill
 *    of the agent, on a separate uid the agent cannot reach. The kill is
 *    the enforcement; the counters that led to it are bookkeeping;
 *  - one crossing observation produces ONE kill, even when several kill
 *    rules cross together (a `calls` budget and an `amount` budget on the
 *    same payout): the agent is stopped once, the co-crossing rules are
 *    audited, and the owner's single 2GO restore re-arms every budget;
 *  - each gateway process counts alone: two gateways running under the
 *    same agentId hold two separate budgets. Deploy one gateway per agent
 *    when a budget must be a single number;
 *  - `alert`-action rules NEVER block: on any trip — a crossing, an
 *    unreadable amount, an overflowed window — the flag fires and the call
 *    still runs. Only `kill`-action rules are fail-closed enforcement;
 *    "alert" is visibility.
 *  - WHEN a metric counts decides what its kill can promise:
 *      `calls` / `amount` meter PRE-dispatch — the crossing call is refused
 *        before it runs, so the budget bounds what actually happens;
 *      `errors` meters POST-dispatch — an error exists only after the call
 *        ran, so the crossing execution ALREADY HAPPENED (possibly
 *        partially, possibly ambiguously) and the kill stops the NEXT call.
 *    An error budget is a circuit breaker on a failing agent, never a
 *    promise that the failure which crossed it was prevented.
 */

export type LimitMetric =
  /** every counted call adds 1 */
  | "calls"
  /** every counted call whose execution FAILED adds 1 */
  | "errors"
  /** every counted call adds the number found at `amountPath` in its args */
  | "amount";

export type LimitAction =
  /** trip → scoped kill of this agent (signed POST /kill {agentId}) */
  | "kill"
  /** trip → flagged event only (signed POST /alert); the call still runs */
  | "alert";

export interface LimitRule {
  id: string;
  description?: string;
  /** which calls count: glob over the tool name, same matcher as PolicyRule */
  tool: string;
  /** optional regex tested against JSON.stringify(args), same as PolicyRule */
  argsPattern?: string;
  metric: LimitMetric;
  /**
   * Dot-path into the call's args naming the amount to add, e.g.
   * "amount_cents" or "payment.total". Required exactly when `metric` is
   * "amount". A counted call where this path does not hold a finite,
   * non-negative number TRIPS the rule outright (fail closed): an unmetered
   * spend must surface at the first call, not after thirty silent ones.
   */
  amountPath?: string;
  /** trips when the windowed total EXCEEDS this (strictly greater) */
  max: number;
  /**
   * Sliding window in ms; totals older than this stop counting. Absent =
   * the lifetime of the counting process.
   */
  windowMs?: number;
  action: LimitAction;
}
