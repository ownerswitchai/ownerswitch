/**
 * @ownerswitchai/shared — core types of the OwnerSwitch policy model.
 *
 * Decisions:
 *  - allow   : runs immediately, logged
 *  - veto    : held in a veto window (3–5 min); one tap from the owner stops it
 *  - approve : default-deny; runs only after the owner's passkey approval (2GO)
 *  - deny    : never runs
 */
export type Decision = "allow" | "veto" | "approve" | "deny";

export interface ToolCall {
  /** stable id of the agent making the call */
  agentId: string;
  /** tool identifier, e.g. "bash", "github.merge_pr", "stripe.payout" */
  tool: string;
  /** raw arguments of the call */
  args?: Record<string, unknown>;
  /** unix ms; defaults to now at evaluation time */
  timestamp?: number;
}

export interface PolicyRule {
  id: string;
  description?: string;
  /** glob-style tool matcher: "stripe.*", "bash", "*" */
  tool: string;
  /** optional regex tested against JSON.stringify(args) */
  argsPattern?: string;
  decision: Decision;
}

export interface Policy {
  /** evaluated top-down; first match wins */
  rules: PolicyRule[];
  /**
   * applied when no rule matches.
   * Fail-closed: ship "approve" as the default so unknown actions
   * always need the owner.
   */
  defaultDecision: Decision;
}

export interface Verdict {
  decision: Decision;
  /** id of the matching rule, or null for default / kill */
  ruleId: string | null;
  reason: string;
}
