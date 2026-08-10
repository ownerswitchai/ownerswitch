import type { ToolCall } from "@ownerswitchai/shared";

/**
 * VetoWindow — the "medium risk" lane of OwnerSwitch.
 *
 * Lifecycle (driven by tick() against an injected clock):
 *   pending  --veto()--------------------> vetoed         (owner stopped it)
 *   pending  --deadline & delivered-----> released        (silence lets it run)
 *   pending  --deadline & NOT delivered-> extended        (owner unreachable: extend once)
 *   extended --veto()-------------------> vetoed
 *   extended --deadline & delivered-----> released
 *   extended --deadline & NOT delivered-> held            (fail-closed: becomes an approval)
 *
 * The reachability rule in code: silence only approves if we KNOW the
 * owner saw the notification (markDelivered()).
 */
export type VetoStatus = "pending" | "vetoed" | "released" | "extended" | "held";

/**
 * What the status surface (GET /veto/:id) may report, beyond the state
 * machine's own states: "spent" is a would-be release from a window whose
 * kill epoch is no longer current — a kill happened after the window was
 * registered, so its release must not authorize anything, even after a
 * restore. The window record itself never holds "spent"; the server derives
 * it by comparing the window's recorded epoch to the live one (server.ts).
 */
export type VetoWireStatus = VetoStatus | "spent";

/**
 * The canonical purpose a window was registered under — which backend
 * (`connector`) and which action within it (`operation`) a release would
 * authorize, plus the authorization-world hash (`policyVersion`) the
 * registering gateway computed. The control plane signs these into any
 * MergeGrant it mints for the window, and mints ONLY for purposes it knows
 * to be grant-eligible — so an approval registered for one purpose can
 * never be spent as another, no matter what its arguments look like.
 * Windows registered without a purpose (plain forwarded tools) release
 * normally but are never grant-eligible.
 */
export interface VetoPurpose {
  connector: string;
  operation: string;
  policyVersion: string;
}

export interface VetoOptions {
  /** initial window; default 4 min */
  windowMs?: number;
  /** extension when delivery unconfirmed; default 6 min */
  extensionMs?: number;
  /** the canonical purpose the registering gateway declared, if any */
  purpose?: VetoPurpose;
  now?: () => number;
}

export class VetoWindow {
  private status: VetoStatus = "pending";
  private delivered = false;
  private deadline: number;
  private releasedAtMs: number | null = null;
  private approvedByOwner: string | null = null;
  private approvedAtMs: number | null = null;
  private approvalEpochValue: number | null = null;
  private readonly extensionMs: number;
  private readonly now: () => number;
  readonly purpose: VetoPurpose | undefined;
  vetoedBy: string | null = null;

  /**
   * `killEpoch` is the control plane's kill epoch in force when the window
   * was CREATED, recorded server-side in the window record itself — so the
   * binding survives a gateway restart and holds across multiple gateways.
   * A release only authorizes while this epoch is still current: a kill
   * after registration (even one later restored) makes the release "spent"
   * on the status surface. Required, no default — an omitted epoch must be
   * a compile error, not a window that silently survives kills (the same
   * stance as evaluate()'s kill parameter).
   */
  constructor(
    readonly call: ToolCall,
    readonly killEpoch: number,
    opts: VetoOptions = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.extensionMs = opts.extensionMs ?? 6 * 60_000;
    this.deadline = this.now() + (opts.windowMs ?? 4 * 60_000);
    this.purpose = opts.purpose;
  }

  /**
   * The owner's enrolled app confirmed the alert was seen — the only
   * signal that may flip this bit. A carrier SMS receipt doesn't count:
   * after a SIM swap it's proof the attacker's handset got the bytes,
   * not that the owner did. See packages/escalation/DESIGN.md §3.
   */
  markDelivered(): void {
    this.delivered = true;
  }

  /** One tap from the owner. Valid while the window is open. */
  veto(by: string): void {
    if (this.status !== "pending" && this.status !== "extended") {
      throw new Error(`cannot veto in status "${this.status}"`);
    }
    this.status = "vetoed";
    this.vetoedBy = by;
  }

  /**
   * The owner ACTIVELY approves this call — the CP-verifiable assertion the
   * merge lane requires (see server.ts). Unlike a veto, this is a positive
   * "yes" the agent cannot manufacture: it rides an owner SESSION (a token
   * on the owner's device), not the gateway's device secret, so a same-uid
   * agent that can forge a registration still cannot forge THIS. Silence
   * never produces it; a merge grant is minted only after it. `epoch` is
   * the kill epoch in force AT APPROVAL, captured here and signed into the
   * grant — a window registered during a kill cannot be approved (the
   * server refuses while killed), so an approval always binds a live,
   * post-restore epoch, never a stale killed one.
   */
  approve(by: string, epoch: number): void {
    if (this.status === "vetoed") throw new Error("cannot approve a vetoed window");
    if (this.approvedByOwner !== null) throw new Error("window already approved");
    this.approvedByOwner = by;
    this.approvedAtMs = this.now();
    this.approvalEpochValue = epoch;
  }

  /** Advance the state machine; call on a timer or before executing. */
  tick(): VetoStatus {
    if (this.status !== "pending" && this.status !== "extended") return this.status;
    if (this.now() < this.deadline) return this.status;

    if (this.delivered) {
      this.status = "released";
      // The release happened at the DEADLINE — the moment silence became
      // approval — not at whatever later moment a poll finally ran tick().
      // Grant freshness anchors here (server.ts): recording now() instead
      // would let a release that sat unread for days mint a brand-new
      // capability on its first late read.
      this.releasedAtMs = this.deadline;
    } else if (this.status === "pending") {
      this.status = "extended";
      this.deadline += this.extensionMs;
    } else {
      this.status = "held"; // unreachable owner: escalate to active approval
    }
    return this.status;
  }

  get state(): VetoStatus {
    return this.status;
  }

  /** When silence became approval (the deadline), or null while unreleased. */
  get releasedAt(): number | null {
    return this.releasedAtMs;
  }

  /** The owner who actively approved, or null. */
  get approvedBy(): string | null {
    return this.approvedByOwner;
  }

  /** When the owner actively approved (ms), or null. Anchors grant expiry. */
  get approvedAt(): number | null {
    return this.approvedAtMs;
  }

  /** The kill epoch in force when the owner approved, or null. */
  get approvalEpoch(): number | null {
    return this.approvalEpochValue;
  }
}
