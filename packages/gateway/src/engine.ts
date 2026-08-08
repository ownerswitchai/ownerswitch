/**
 * Enforcement boundary: after KILL, no NEW authorized action crosses this
 * point — every call is evaluated against live kill state at decision time
 * (the guarantee holds for callers that supply it, as the gateway's
 * fail-closed remote kill lookup does). KILL does NOT
 * retroactively revoke credentials already issued downstream; those are
 * bounded by their TTL and by each connector's revocation capability.
 * Short TTLs are the mitigation. Don't document KILL as "revokes existing
 * tokens" — that overclaims what this boundary can enforce.
 */
import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";

/** Global kill state — when engaged, EVERYTHING is denied. Fail-closed. */
export interface KillState {
  killed: boolean;
  reason?: string;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const globToRegex = (glob: string) =>
  new RegExp("^" + glob.split("*").map(escapeRe).join(".*") + "$");

/**
 * The core decision function of OwnerSwitch.
 * Order of authority:
 *   1. kill switch (deny everything)
 *   2. first matching policy rule
 *   3. fail-closed default
 *
 * `kill` is required and deliberately has no default. A default of
 * `{ killed: false }` would grant silent permission to any caller that
 * forgot to look up live kill state — fail-open at exactly the moment the
 * kill switch matters most. In a fail-closed system, an omitted kill state
 * must be a compile error, not an allow. Callers with a live source should
 * fetch it (see evaluateRemote); a caller with none must write
 * `{ killed: false }` itself, making that assumption visible at the call site.
 */
export function evaluate(
  call: ToolCall,
  policy: Policy,
  kill: KillState,
): Verdict {
  if (kill.killed) {
    return {
      decision: "deny",
      ruleId: null,
      reason: `kill switch engaged${kill.reason ? `: ${kill.reason}` : ""}`,
    };
  }

  for (const rule of policy.rules) {
    if (!globToRegex(rule.tool).test(call.tool)) continue;
    if (
      rule.argsPattern &&
      !new RegExp(rule.argsPattern).test(JSON.stringify(call.args ?? {}))
    ) {
      continue;
    }
    return {
      decision: rule.decision,
      ruleId: rule.id,
      reason: rule.description ?? `matched rule ${rule.id}`,
    };
  }

  return {
    decision: policy.defaultDecision,
    ruleId: null,
    reason: "no rule matched — fail-closed default",
  };
}
