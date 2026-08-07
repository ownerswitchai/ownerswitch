/**
 * 2GO — the restore ceremony of OwnerSwitch.
 *
 * "One press to stop. Two GOs to start."
 *
 *   go1        — owner authenticates with a passkey (GO 1/2)
 *   [cooldown] — mandatory pause; the app shows the system-state summary
 *   ready      — GO 2/2 may be confirmed
 *   completed  — produces the RestoreAuthorization the KillSwitch demands
 *   expired    — ceremony not completed within its TTL; start over
 *
 * The cooldown is the anti-panic / anti-social-engineering pause:
 * nobody restores production in the heat of a "quick, turn it back on!".
 */
export interface RestoreAuthorization {
  ceremonyId: string;
  ownerId: string;
  completedAt: number;
}

export type CeremonyState = "go1" | "ready" | "completed" | "expired";

export interface TwoGoOptions {
  /** mandatory pause between GO 1/2 and GO 2/2; default 30 s */
  cooldownMs?: number;
  /** whole ceremony must finish within this; default 5 min */
  ttlMs?: number;
  now?: () => number;
}

export class RestoreCeremony {
  private status: CeremonyState = "go1";
  private readonly startedAt: number;
  private readonly cooldownMs: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(
    readonly ceremonyId: string,
    readonly ownerId: string,
    opts: TwoGoOptions = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.cooldownMs = opts.cooldownMs ?? 30_000;
    this.ttlMs = opts.ttlMs ?? 5 * 60_000;
    this.startedAt = this.now();
  }

  tick(): CeremonyState {
    if (this.status === "completed" || this.status === "expired") return this.status;
    const elapsed = this.now() - this.startedAt;
    if (elapsed >= this.ttlMs) this.status = "expired";
    else if (elapsed >= this.cooldownMs) this.status = "ready";
    return this.status;
  }

  /** GO 2/2 — only valid in "ready"; too early or too late both fail. */
  confirm(): RestoreAuthorization {
    this.tick();
    if (this.status !== "ready") {
      throw new Error(`GO 2/2 rejected in state "${this.status}"`);
    }
    this.status = "completed";
    return { ceremonyId: this.ceremonyId, ownerId: this.ownerId, completedAt: this.now() };
  }

  get state(): CeremonyState {
    return this.status;
  }
}
