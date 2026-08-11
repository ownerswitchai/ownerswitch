import type { ActionTicket } from "./ticket.js";

/**
 * The executor's front door. Order of authority mirrors the gateway:
 *   1. live kill state (fetched immediately before executing, never cached)
 *   2. kill epoch match — approvals do not survive a kill, even a restored one
 *   3. expiry and nonce
 *   4. only then does a backend run the action, with OwnerSwitch's own
 *      credential — the agent gets the result, never a token.
 *
 * The guarantee, stated precisely: a ticket is refused if the final
 * pre-dispatch live-state check observes a kill or an epoch change. A kill
 * landing after that check may race with dispatch; once the connector call
 * is dispatched it cannot be recalled. Against an external API with no
 * fencing there is no mechanism that could close that race — the second
 * re-check in run() narrows it, it does not close it. This is the same
 * boundary the kill switch itself documents for in-flight actions
 * (packages/mcp/THREAT-MODEL.md, gateway/src/engine.ts). See DESIGN.md §3.
 */

/** Live answer from the control plane at execution time. */
export interface LiveKillState {
  killed: boolean;
  /** monotone count of kill engagements; restore never resets it */
  epoch: number;
  /**
   * Present when the lookup carried a grant-liveness PROBE (a jti): true
   * iff the control plane still vouches for that specific grant — it
   * minted it, remembers it, and its window has NOT been vetoed since.
   * The broker's read-only pre-mint check requires this. Absent when no
   * probe was made (plain kill lookups).
   */
  grantLive?: boolean;
  /**
   * Present on a COMMIT probe: the control plane ATOMICALLY transitioned
   * this grant live→committed-for-dispatch (true), or refused because a
   * veto/kill won the race first (false). This is the broker's FINAL
   * pre-PUT check — not a snapshot. Once committed, a later veto is
   * reported "in flight"; if the veto landed first, commit is false and no
   * PUT is sent. The transition is single-threaded on the control plane,
   * so it and a concurrent veto cannot interleave.
   */
  committed?: boolean;
}

export interface Refusal {
  code: "kill-engaged" | "epoch-mismatch" | "ticket-expired" | "nonce-consumed";
  reason: string;
}

/** Connector-reported outcome of the action — data, never a credential. */
export interface ExecutionResult {
  /** echoed for the audit trail */
  resourceId: string;
  /** e.g. { merged: true, sha: "..." } */
  detail: Record<string, unknown>;
}

export type ExecutionOutcome =
  | { status: "executed"; result: ExecutionResult }
  | { status: "refused"; refusal: Refusal };

/**
 * Per-run context threaded to the backend. Carries the control-plane-minted
 * MergeGrant (as an opaque signed object) for backends that execute behind
 * an agent-inaccessible boundary — the executing merge broker. The in-process
 * and same-process backends ignore it; the broker REQUIRES it, because within
 * one uid the ticket alone is agent-forgeable and only the signed grant is
 * not (packages/shared/src/merge-grant.ts).
 */
export interface ExecutionContext {
  /** the signed grant, verbatim, to relay to an executing broker */
  grant?: unknown;
}

/** A connector backend performs the call for an already-validated ticket. */
export interface ExecutorBackend {
  execute(ticket: ActionTicket, ctx?: ExecutionContext): Promise<ExecutionResult>;
}

/**
 * Pure refusal core — the sync, testable heart, like the gateway's
 * evaluate(). Returns null when the ticket may execute.
 */
export function refuseTicket(
  ticket: ActionTicket,
  live: LiveKillState,
  now: number,
  consumedNonces: ReadonlySet<string>,
): Refusal | null {
  if (live.killed) {
    return { code: "kill-engaged", reason: "kill switch engaged — nothing executes" };
  }
  if (ticket.killEpoch !== live.epoch) {
    return {
      code: "epoch-mismatch",
      reason: `ticket minted in kill epoch ${ticket.killEpoch}, current epoch is ${live.epoch} — a kill happened in between; approvals do not survive it`,
    };
  }
  if (now >= ticket.expiresAt) {
    return { code: "ticket-expired", reason: "ticket expired — a yes is not a standing grant" };
  }
  if (consumedNonces.has(ticket.nonce)) {
    return { code: "nonce-consumed", reason: "ticket already used — tickets are single-use" };
  }
  return null;
}

export interface ExecutorOptions {
  /**
   * MUST hit the control plane live; never cache. Throwing reads as
   * killed — fail-closed, like the gateway's fetchKillState.
   */
  fetchLiveKillState: () => Promise<LiveKillState>;
  now?: () => number;
}

export class Executor {
  private readonly consumedNonces = new Set<string>();
  private readonly now: () => number;

  constructor(
    private readonly backend: ExecutorBackend,
    private readonly opts: ExecutorOptions,
  ) {
    this.now = opts.now ?? Date.now;
  }

  async run(ticket: ActionTicket, ctx?: ExecutionContext): Promise<ExecutionOutcome> {
    const live = await this.fetchLive();
    const refusal = refuseTicket(ticket, live, this.now(), this.consumedNonces);
    if (refusal) return { status: "refused", refusal };

    // Burn before the call: at-most-once. If the process dies mid-call the
    // ticket is dead and the owner re-approves — a duplicate merge is not
    // a retry, it's an incident.
    this.consumedNonces.add(ticket.nonce);

    // Second live re-check, immediately before dispatch. This NARROWS the
    // window in which a kill can land unseen — it does not and cannot close
    // it: a kill arriving after this fetch resolves, or while the connector
    // call is on the wire, races with dispatch and may not be caught. The
    // guarantee stays exactly what this check can deliver: refused if THIS
    // check observes a kill or an epoch change; not recallable once
    // dispatched. The nonce is checked against an empty set here because
    // THIS attempt burned it above; a refusal at this point still spends
    // the ticket — at-most-once means the owner re-approves, never that we
    // retry.
    const liveAtDispatch = await this.fetchLive();
    const lateRefusal = refuseTicket(ticket, liveAtDispatch, this.now(), NO_BURNED_NONCES);
    if (lateRefusal) return { status: "refused", refusal: lateRefusal };

    const result = await this.backend.execute(ticket, ctx);
    return { status: "executed", result };
  }

  private async fetchLive(): Promise<LiveKillState> {
    try {
      return await this.opts.fetchLiveKillState();
    } catch {
      // an unreadable control plane never reads as "go"
      return { killed: true, epoch: -1 };
    }
  }
}

/** The pre-dispatch re-check runs after this attempt burned its own nonce. */
const NO_BURNED_NONCES: ReadonlySet<string> = new Set();
