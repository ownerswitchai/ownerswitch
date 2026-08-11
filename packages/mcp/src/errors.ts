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
  /** a decoy credential surfaced in a tool call — the kill is already firing */
  HoneytokenTripped: -32055,
  /** the executor refused an already-approved action ticket at execution time */
  TicketRefused: -32056,
  /** the executor's connector call failed after the single-use ticket was consumed */
  ExecutionFailed: -32057,
} as const;

export type OwnerSwitchErrorCodeName = keyof typeof OwnerSwitchErrorCode;

/** Machine-readable refusal detail, carried in the error's `data`. */
export interface RefusalData {
  decision: "deny" | "approve" | "veto" | "lockdown" | "refused" | "failed";
  tool: string;
  reason: string;
  ruleId?: string | null;
  vetoWindowId?: string;
  vetoStatus?: string;
  /** the executor's refusal code, e.g. "epoch-mismatch" (TicketRefused only) */
  refusalCode?: string;
  /**
   * ExecutionFailed only: whether the connector could establish that the
   * action definitively did not happen ("not-performed" — e.g. GitHub
   * received and refused the request) or genuinely cannot know ("unknown" —
   * the request died on the wire and verification could not settle it).
   */
  connectorOutcome?: "not-performed" | "unknown";
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

/**
 * A honeytoken surfaced in the call's arguments. Unlike every other refusal,
 * this one is not a decision an owner might revisit — it is a tripwire, and
 * by the time the agent reads this message the kill is already being
 * reported. Deliberately blunt: the one wrong takeaway would be "retry with
 * different arguments".
 */
export function honeytokenTripped(tool: string, canaryIds: string[]): OwnerSwitchRefusal {
  const ids = canaryIds.join("+") || "(id unknown)";
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.HoneytokenTripped,
    `OwnerSwitch tripped a honeytoken in the arguments of "${tool}" (canary ${ids}): that ` +
      `value is a decoy credential planted as a tripwire, and touching it engages the kill ` +
      `switch. The call did NOT run and the kill is being reported now — every further tool ` +
      `call will be denied until the owner restores OwnerSwitch. Do not retry with different ` +
      `arguments; tell the user what happened.`,
    { decision: "lockdown", tool, reason: `honeytoken ${ids} in tool-call arguments` },
  );
}

/**
 * The executor refused an already-approved ticket at execution time —
 * expired, replayed, or minted before a kill that has since happened. The
 * decision that produced the ticket was a yes; the world changed between
 * yes and run. The approval is void: a retry goes through the whole
 * decision path again from the start.
 *
 * The guarantee behind this refusal, stated precisely: a ticket is refused
 * if the final pre-dispatch live-state check observes a kill or an epoch
 * change. A kill landing after that check may race with dispatch; once the
 * connector call is dispatched it cannot be recalled — the same in-flight
 * boundary THREAT-MODEL.md draws for the kill switch itself.
 */
export function ticketRefused(
  tool: string,
  refusalCode: string,
  reason: string,
): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.TicketRefused,
    `OwnerSwitch refused to execute "${tool}": ${reason}. The action did NOT run, and the ` +
      `approval this call carried is void. Calling the tool again starts a fresh owner ` +
      `decision — do not assume it will be approved; tell the user what happened.`,
    { decision: "refused", tool, reason, refusalCode },
  );
}

/**
 * A routed call refused BEFORE any owner review opened or any ticket
 * minted — invalid arguments for the route, or a review-time prerequisite
 * (like pinning the pull request head) that could not be met. Unlike
 * ticketRefused there is no approval to void: nothing was spent, nothing
 * ran, and the agent may retry once the named cause is fixed.
 */
export function routedCallRefused(
  tool: string,
  refusalCode: string,
  reason: string,
): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.TicketRefused,
    `OwnerSwitch refused "${tool}": ${reason}. The action did NOT run and no owner review ` +
      `was opened; nothing was spent. Fix the named cause before calling again.`,
    { decision: "refused", tool, reason, refusalCode },
  );
}

/**
 * A veto window released, but a kill happened after the window was opened —
 * the control plane reports the release "spent" (its server-side record
 * binds every window to the kill epoch at registration). Approvals do not
 * survive a kill, even one that was later restored: the release authorizes
 * nothing, and only a fresh window can.
 */
export function vetoReleaseSpent(tool: string, vetoWindowId: string): OwnerSwitchRefusal {
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.TicketRefused,
    `OwnerSwitch refused "${tool}": its veto window ("${vetoWindowId}") was released, but a ` +
      `kill switch engagement happened after the window was opened, so the release is spent — ` +
      `approvals do not survive a kill, even one that was later restored. The action did NOT ` +
      `run. Calling the tool again opens a fresh owner review; do not assume it will be ` +
      `released again.`,
    {
      decision: "refused",
      tool,
      reason: "veto release spent — a kill happened after the window was opened",
      vetoWindowId,
      vetoStatus: "spent",
      refusalCode: "release-spent",
    },
  );
}

/**
 * The connector call failed AFTER the single-use ticket was consumed. The
 * nonce burns before the call (at-most-once, DESIGN.md §3), so the ticket is
 * spent either way — but the connector can often still say WHICH way the
 * world went, and the agent must be told the strongest truth available:
 *
 *  - "not-performed": the backend received the request and refused it (or
 *    it was never dispatched at all) — the action definitively did not run.
 *    A retry is safe from double-execution, though it starts a fresh owner
 *    decision and will likely refuse again for the same reason.
 *  - "unknown": the request died on the wire and post-dispatch verification
 *    could not settle it — the action MAY OR MAY NOT have completed. The
 *    one wrong takeaway would be "retry until it works".
 *
 * Connectors signal the distinction with ConnectorCallError
 * (packages/executor/src/connector-error.ts); anything else stays "unknown"
 * — ambiguity is the fail-safe reading, never the optimistic one.
 */
export function executionFailed(
  tool: string,
  detail: string,
  connectorOutcome: "not-performed" | "unknown" = "unknown",
): OwnerSwitchRefusal {
  const consequence =
    connectorOutcome === "not-performed"
      ? `The single-use ticket was consumed and the action did NOT run — the backend refused ` +
        `it before performing anything. Retrying starts a fresh owner decision and will ` +
        `likely fail the same way until the cause is fixed; tell the user why it failed.`
      : `The single-use ticket was consumed, and the action MAY OR MAY NOT have completed — ` +
        `check the resource directly before doing anything else. Retrying starts a fresh ` +
        `owner decision and could run the action twice; tell the user.`;
  return new OwnerSwitchRefusal(
    OwnerSwitchErrorCode.ExecutionFailed,
    `OwnerSwitch accepted "${tool}" but the backend call failed: ${detail}. ${consequence}`,
    { decision: "failed", tool, reason: detail, connectorOutcome },
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
