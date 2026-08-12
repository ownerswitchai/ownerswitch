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
  /**
   * The release-time witness check: does the device named by the ack
   * evidence STILL exist, in good standing, at the SAME generation it held
   * when it acked? Consulted INSIDE tick() at the release decision itself —
   * not only by the revocation handler's proactive sweep — so any in-process
   * path that changed standing without running the sweep, standing loaded at
   * boot from a previous lifetime, and a quarantined registry are all
   * enforced exactly where they would otherwise release. (The control plane
   * is the SINGLE standing writer at runtime; a write by another process to
   * the shared file is honored at the next boot, not re-read per decision —
   * see server.ts witnessStanding.) A missing checker (unit tests,
   * non-owner-device windows) trusts the delivered bit as before; the server
   * always injects one for windows it registers.
   */
  witnessStanding?: (deviceId: string | null, generation: number | null) => boolean;
  now?: () => number;
}

export class VetoWindow {
  private status: VetoStatus = "pending";
  private delivered = false;
  private deliveredByDevice: string | null = null;
  private deliveredByGenerationValue: number | null = null;
  private deliveredAtMs: number | null = null;
  private revisionValue = 1;
  private deadline: number;
  private releasedAtMs: number | null = null;
  private approvedByOwner: string | null = null;
  private approvedAtMs: number | null = null;
  private approvalEpochValue: number | null = null;
  private readonly extensionMs: number;
  private readonly now: () => number;
  private readonly witnessStanding:
    | ((deviceId: string | null, generation: number | null) => boolean)
    | undefined;
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
    this.witnessStanding = opts.witnessStanding;
  }

  /**
   * The owner's enrolled app confirmed the alert was seen — the only
   * signal that may flip this bit. A carrier SMS receipt doesn't count:
   * after a SIM swap it's proof the attacker's handset got the bytes,
   * not that the owner did. See packages/escalation/DESIGN.md §3.
   */
  markDelivered(deviceId?: string, deviceGeneration?: number): void {
    // First ack wins the attribution: a "released on silence" must be
    // explainable from one recorded (device, generation, time) triple, not
    // the last of many retries.
    if (!this.delivered) {
      this.delivered = true;
      this.deliveredByDevice = deviceId ?? null;
      this.deliveredByGenerationValue = deviceGeneration ?? null;
      this.deliveredAtMs = this.now();
    }
  }

  /**
   * The ONE event that may clear delivered evidence: the witnessing device
   * was REVOKED. The release decision is deadline-anchored (see tick), so
   * this first advances the clock — a window whose deadline already passed
   * with valid evidence has RELEASED (silence became approval while the
   * witness was still trusted) and stays released; evidence on a still-open
   * window from the revoked device is cleared, so the window walks
   * extend→held (fail closed) instead of releasing on a dead witness. A
   * different device's evidence is untouched. Returns whether evidence was
   * cleared.
   */
  revokeDeliveryEvidence(deviceId: string): boolean {
    const status = this.tick(); // decide any already-due release FIRST
    if (status !== "pending" && status !== "extended") return false;
    if (!this.delivered || this.deliveredByDevice !== deviceId) return false;
    this.delivered = false;
    this.deliveredByDevice = null;
    this.deliveredByGenerationValue = null;
    this.deliveredAtMs = null;
    return true;
  }

  /**
   * One tap from the owner. For a plain window, valid while it is open —
   * after a release the call may already have forwarded, so a late veto is
   * an honest error. A PURPOSED window is different: its authority is a
   * revocable signed grant, and the whole point of grant liveness is that
   * the owner's "no" invalidates an issued-but-undispatched grant — so a
   * purposed window accepts a veto at ANY point (even after approval),
   * and only a repeated veto is refused.
   */
  veto(by: string): void {
    if (this.status === "vetoed") {
      throw new Error('cannot veto in status "vetoed"');
    }
    if (this.purpose === undefined && this.status !== "pending" && this.status !== "extended") {
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

    // THE RELEASE-TIME CAS: before "delivered" may become "released", the
    // witnessing device must still exist, unrevoked, at the SAME generation
    // it acked under — checked HERE, at the decision itself, not only by the
    // revocation handler's proactive sweep (which stays as an accelerator:
    // it clears evidence eagerly and preserves deadline-anchored releases
    // for revocations arriving through the API). Any in-process standing
    // change the sweep never saw, standing loaded at boot from a previous
    // lifetime, and a quarantined registry are all enforced here, and the
    // failure direction is held/passkey, never a release on a dead witness.
    if (
      this.delivered &&
      this.witnessStanding !== undefined &&
      !this.witnessStanding(this.deliveredByDevice, this.deliveredByGenerationValue)
    ) {
      this.delivered = false;
      this.deliveredByDevice = null;
      this.deliveredByGenerationValue = null;
      this.deliveredAtMs = null;
    }

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
      // The rendered content just changed (the deadline moved), so any
      // foreground-detail delivery minted for the previous revision is now
      // stale: an ack echoing revision N must not confirm the extended
      // window. Bump so the server can reject it (apps/owner DESIGN.md §3).
      this.revisionValue += 1;
    } else {
      this.status = "held"; // unreachable owner: escalate to active approval
    }
    return this.status;
  }

  get state(): VetoStatus {
    return this.status;
  }

  /**
   * The window's showing revision — 1 at registration, +1 on extension (the
   * one event that changes what the owner would render). A delivery ack must
   * echo the revision it was minted for AND match this, so a detail fetched
   * for revision N cannot confirm the window after it has advanced.
   */
  get revision(): number {
    return this.revisionValue;
  }

  /** When silence next decides this window (ms). Moves once, on extension. */
  get deadlineAt(): number {
    return this.deadline;
  }

  /** Has an enrolled device confirmed the alert was rendered? */
  get isDelivered(): boolean {
    return this.delivered;
  }

  /** The enrolled device whose ack flipped delivered, or null. */
  get deliveredBy(): string | null {
    return this.deliveredByDevice;
  }

  /** The revocation generation the witnessing device held at ack, or null. */
  get deliveredByGeneration(): number | null {
    return this.deliveredByGenerationValue;
  }

  /** When the ack landed (ms), or null. */
  get deliveredAt(): number | null {
    return this.deliveredAtMs;
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
