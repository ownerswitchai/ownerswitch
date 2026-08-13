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
 * plane never sees allow-lane calls. Stated honestly: counters live in
 * gateway memory and reset when that process restarts; the KILL a tripped
 * rule fires is durable and authoritative (persisted scoped kill on the
 * control plane), the counters that led to it are not.
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
