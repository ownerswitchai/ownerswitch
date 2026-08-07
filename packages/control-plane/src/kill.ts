/**
 * KillSwitch — the global kill state of an OwnerSwitch deployment.
 *
 * Rules:
 *  - engaging is CHEAP: any trigger source may do it, idempotently
 *  - restoring is EXPENSIVE: only a completed 2GO ceremony authorizes it
 *  - every transition is appended to an immutable audit log
 */
export type KillSource = "button" | "honeytoken" | "app" | "voice" | "api";

export interface KillEvent {
  source: KillSource;
  reason?: string;
  at: number;
}

/** Produced by a completed 2GO restore ceremony (see feat/2go-restore). */
export interface RestoreAuthorization {
  ceremonyId: string;
  ownerId: string;
  completedAt: number;
}

export type AuditEntry =
  | { type: "kill"; event: KillEvent }
  | { type: "restore"; auth: RestoreAuthorization; at: number };

export class KillSwitch {
  private killedState = false;
  private log: AuditEntry[] = [];

  constructor(private readonly now: () => number = Date.now) {}

  /** Idempotent: repeated triggers only add audit entries, never throw. */
  engage(source: KillSource, reason?: string): void {
    this.log.push({ type: "kill", event: { source, reason, at: this.now() } });
    this.killedState = true;
  }

  get killed(): boolean {
    return this.killedState;
  }

  /**
   * Restore requires a completed ceremony. This method trusts its input's
   * SHAPE only — verifying the ceremony itself is the caller's job.
   */
  restore(auth: RestoreAuthorization): void {
    if (!this.killedState) throw new Error("not killed — nothing to restore");
    if (!auth.ceremonyId || !auth.ownerId) {
      throw new Error("restore requires a completed 2GO ceremony");
    }
    this.log.push({ type: "restore", auth, at: this.now() });
    this.killedState = false;
  }

  /** Immutable copy of the full history. */
  auditLog(): readonly AuditEntry[] {
    return [...this.log];
  }
}
