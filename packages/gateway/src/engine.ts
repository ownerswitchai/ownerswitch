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
import type { Policy, PolicyRule, ToolCall, Verdict } from "@ownerswitchai/shared";

/** Global kill state — when engaged, EVERYTHING is denied. Fail-closed. */
export interface KillState {
  killed: boolean;
  reason?: string;
  /**
   * Agents under a SCOPED kill: every call whose `agentId` appears here is
   * denied, while the rest of the fleet keeps running under policy. The
   * global `killed` above stays supreme — when it is true this list is
   * irrelevant, everything is denied.
   *
   * REQUIRED, no default — deliberately unlike `epoch` (which evaluate()
   * never consults) and exactly like the `kill` parameter itself: this
   * field is enforcement input. An optional list would let any caller that
   * forgot to thread it through silently un-scope every scoped kill —
   * fail-open at the one layer that must not be. A caller with no scoped
   * state must write `killedAgents: []` itself, making the assumption
   * visible at the call site. `createControlPlaneClient`'s fetched answers
   * always populate it or fail the whole lookup closed (see client.ts).
   */
  killedAgents: readonly string[];
  /**
   * The control plane's kill epoch — a monotone count of every kill this
   * deployment has ever had; a restore never resets it. `evaluate()` itself
   * does not consult it: `killed` is enough to decide a policy call. It
   * rides along on `KillState` so a live-fetched answer also carries what a
   * future ticket-epoch check (packages/executor/DESIGN.md §3) needs,
   * without a second round trip. Optional here because hand-built
   * `KillState` values (tests, callers with no epoch source) stay valid;
   * `createControlPlaneClient`'s fetched answers always populate it (see
   * client.ts) or fail the whole lookup closed.
   */
  epoch?: number;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const globToRegex = (glob: string) =>
  new RegExp("^" + glob.split("*").map(escapeRe).join(".*") + "$");

/**
 * The rules whose tool glob matches `tool`, in policy order — the exact
 * candidate set evaluate() walks (argsPattern then decides per call which
 * candidate fires). Exported so callers that need to reason about a tool
 * NAME's possible verdicts — e.g. the executor-route coherence check in
 * @ownerswitchai/mcp — use the engine's own matcher instead of re-deriving
 * glob semantics that could drift.
 */
export function rulesMatchingTool(policy: Policy, tool: string): PolicyRule[] {
  return policy.rules.filter((rule) => globToRegex(rule.tool).test(tool));
}

/**
 * The core decision function of OwnerSwitch.
 * Order of authority:
 *   1. kill switch (deny everything)
 *   2. scoped kill (deny everything from a killed agent)
 *   3. first matching policy rule
 *   4. fail-closed default
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

  // Scoped kill: outranked only by the global switch, and outranks every
  // policy rule — an `allow` lane must not keep a killed agent acting.
  if (kill.killedAgents.includes(call.agentId)) {
    return {
      decision: "deny",
      ruleId: null,
      reason: `agent "${call.agentId}" is scope-killed — denied until an owner restores it`,
    };
  }

  for (const rule of rulesMatchingTool(policy, call.tool)) {
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
