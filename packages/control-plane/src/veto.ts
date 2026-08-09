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

export interface VetoOptions {
  /** initial window; default 4 min */
  windowMs?: number;
  /** extension when delivery unconfirmed; default 6 min */
  extensionMs?: number;
  now?: () => number;
}

export class VetoWindow {
  private status: VetoStatus = "pending";
  private delivered = false;
  private deadline: number;
  private readonly extensionMs: number;
  private readonly now: () => number;
  vetoedBy: string | null = null;

  constructor(
    readonly call: ToolCall,
    opts: VetoOptions = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.extensionMs = opts.extensionMs ?? 6 * 60_000;
    this.deadline = this.now() + (opts.windowMs ?? 4 * 60_000);
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

  /** Advance the state machine; call on a timer or before executing. */
  tick(): VetoStatus {
    if (this.status !== "pending" && this.status !== "extended") return this.status;
    if (this.now() < this.deadline) return this.status;

    if (this.delivered) {
      this.status = "released";
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
}
