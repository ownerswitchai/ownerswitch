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
  }

  /** Push/SMS delivery confirmed on the owner's device. */
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
