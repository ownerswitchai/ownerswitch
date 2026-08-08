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
 */
export function evaluate(
  call: ToolCall,
  policy: Policy,
  kill: KillState = { killed: false },
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
