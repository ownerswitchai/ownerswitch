import type { ActionTicket } from "./ticket.js";

/**
 * The executor's front door. Order of authority mirrors the gateway:
 *   1. live kill state (fetched immediately before executing, never cached)
 *   2. kill epoch match — approvals do not survive a kill, even a restored one
 *   3. expiry and nonce
 *   4. only then does a backend run the action, with OwnerSwitch's own
 *      credential — the agent gets the result, never a token.
 * See DESIGN.md §3.
 */

/** Live answer from the control plane at execution time. */
export interface LiveKillState {
  killed: boolean;
  /** monotone count of kill engagements; restore never resets it */
  epoch: number;
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

/** A connector backend performs the call for an already-validated ticket. */
export interface ExecutorBackend {
  execute(ticket: ActionTicket): Promise<ExecutionResult>;
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

  async run(ticket: ActionTicket): Promise<ExecutionOutcome> {
    let live: LiveKillState;
    try {
      live = await this.opts.fetchLiveKillState();
    } catch {
      // an unreadable control plane never reads as "go"
      live = { killed: true, epoch: -1 };
    }

    const refusal = refuseTicket(ticket, live, this.now(), this.consumedNonces);
    if (refusal) return { status: "refused", refusal };

    // Burn before the call: at-most-once. If the process dies mid-call the
    // ticket is dead and the owner re-approves — a duplicate merge is not
    // a retry, it's an incident.
    this.consumedNonces.add(ticket.nonce);

    const result = await this.backend.execute(ticket);
    return { status: "executed", result };
  }
}
