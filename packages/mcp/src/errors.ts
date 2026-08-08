import type { Verdict } from "@ownerswitchai/shared";

/**
 * JSON-RPC error codes for calls the gateway refuses to forward.
 *
 * One code per thing the agent should tell its user. Refusals are protocol
 * errors, not tool results: the upstream tool never ran, and the error object
 * (code + message + data) is the agent's only account of why.
 */
export const OwnerSwitchErrorCode = {
  /** a policy rule says this action never runs */
  PolicyDenied: -32050,
  /** the action runs only after the owner's explicit approval (2GO) */
  ApprovalRequired: -32051,
  /** the action sits in an open veto window — pending owner review */
  VetoPending: -32052,
  /** the owner saw this action and stopped it */
  OwnerVetoed: -32053,
  /** kill switch engaged or control plane unreachable — everything is denied */
  Lockdown: -32054,
} as const;

export type OwnerSwitchErrorCodeName = keyof typeof OwnerSwitchErrorCode;

/** Machine-readable refusal detail, carried in the error's `data`. */
export interface RefusalData {
  decision: "deny" | "approve" | "veto" | "lockdown";
  tool: string;
  reason: string;
  ruleId?: string | null;
  vetoWindowId?: string;
  vetoStatus?: string;
}

/**
 * A refusal, thrown from a request handler. The SDK serializes any thrown
 * error structurally (`code`, `message`, `data`) into the JSON-RPC error
 * response, so the agent receives exactly this code and message. Deliberately
 * NOT an McpError instance: McpError bakes an "MCP error <code>:" prefix into
 * `.message`, which the client side prefixes again — agents would read the
 * refusal twice-wrapped.
 */
export class OwnerSwitchRefusal extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly data: RefusalData,
  ) {
    super(message);
    this.name = "OwnerSwitchRefusal";
  }
}

export function policyDenied(tool: string, verdict: Verdict): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.PolicyDenied,
    `OwnerSwitch denied "${tool}": ${verdict.reason}. The call did not run, and retrying will ` +
      `not change the decision — tell the user this action is blocked by the owner's policy.`,
    { decision: "deny", tool, reason: verdict.reason, ruleId: verdict.ruleId },
  );
}

export function approvalRequired(tool: string, verdict: Verdict): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.ApprovalRequired,
    `OwnerSwitch blocked "${tool}": ${verdict.reason}. This action runs only after the owner ` +
      `explicitly approves it (2GO), and it has NOT run. Tell the user it is waiting on the ` +
      `owner's approval; once they approve it in OwnerSwitch, call the tool again.`,
    { decision: "approve", tool, reason: verdict.reason, ruleId: verdict.ruleId },
  );
}

export function vetoPending(
  tool: string,
  verdict: Verdict,
  vetoWindowId: string,
  justOpened: boolean,
  vetoStatus = "pending",
): OwnerSwitchRefusal {
  const opening = justOpened
    ? `A veto window (id "${vetoWindowId}") is now open — the owner has a few minutes to stop it.`
    : `Its veto window (id "${vetoWindowId}", status "${vetoStatus}") is still open.`;
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.VetoPending,
    `OwnerSwitch held "${tool}" for owner review: ${verdict.reason}. The call has NOT run. ` +
      `${opening} Tell the user the action is pending owner review, and call the same tool ` +
      `again later: a released window lets it run, a vetoed one stays blocked. Do not assume ` +
      `it succeeded.`,
    {
      decision: "veto",
      tool,
      reason: verdict.reason,
      ruleId: verdict.ruleId,
      vetoWindowId,
      vetoStatus,
    },
  );
}

export function ownerVetoed(tool: string, vetoWindowId: string): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.OwnerVetoed,
    `OwnerSwitch blocked "${tool}": the owner vetoed this action (veto window "${vetoWindowId}"). ` +
      `The call did not run. Do not retry — tell the user the owner stopped it.`,
    { decision: "veto", tool, reason: "vetoed by the owner", vetoWindowId, vetoStatus: "vetoed" },
  );
}

export function vetoHeld(tool: string, vetoWindowId: string): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.ApprovalRequired,
    `OwnerSwitch blocked "${tool}": its veto window ("${vetoWindowId}") expired without ` +
      `confirmation that the owner saw it, so the action escalated to explicit approval ` +
      `(fail closed). It has NOT run. Tell the user it now needs the owner's approval in ` +
      `OwnerSwitch.`,
    {
      decision: "approve",
      tool,
      reason: "owner unreachable during veto window",
      vetoWindowId,
      vetoStatus: "held",
    },
  );
}

/** Kill switch engaged — or unreachable control plane, which reads the same. */
export function lockdown(tool: string, reason: string | undefined): OwnerSwitchRefusal {
  const why = reason ?? "kill switch engaged";
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.Lockdown,
    `OwnerSwitch denied "${tool}": ${why}. Every tool call is denied until the owner ` +
      `restores OwnerSwitch — do not retry other tools; tell the user why.`,
    { decision: "lockdown", tool, reason: why },
  );
}

/** A veto-lane control-plane call failed — refuse the call, fail closed. */
export function controlPlaneUnavailable(tool: string, detail: string): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.Lockdown,
    `OwnerSwitch denied "${tool}": ${detail}. Fail closed — the call did not run and calls ` +
      `needing owner review are denied until the gateway can reach its control plane. Tell ` +
      `the user.`,
    { decision: "lockdown", tool, reason: detail },
  );
}
