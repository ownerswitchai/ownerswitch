/**
 * Enforcement boundary: engaging KILL guarantees that no NEW authorized
 * action crosses the OwnerSwitch boundary from that moment on. It does NOT
 * instantly kill in-flight actions or revoke credentials already issued
 * downstream — those remain bounded by their TTL and by each connector's
 * revocation capability. Short TTLs are the mitigation. Don't re-introduce
 * the "kill revokes existing tokens" overclaim in docs or comments.
 */
import type { RestoreAuthorization } from "./twogo.js";

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
  /** present when the trigger carried no verifiable credential */
  unauthenticated?: true;
}

export type AuditEntry =
  | { type: "kill"; event: KillEvent }
  | { type: "restore"; auth: RestoreAuthorization; at: number };

export class KillSwitch {
  private killedState = false;
  private epochCounter = 0;
  private log: AuditEntry[] = [];
  private consumedCeremonies = new Set<string>();

  constructor(private readonly now: () => number = Date.now) {}

  /** Idempotent: repeated triggers only add audit entries, never throw. */
  engage(source: KillSource, reason?: string, opts: { unauthenticated?: boolean } = {}): void {
    this.epochCounter += 1;
    this.log.push({
      type: "kill",
      event: {
        source,
        reason,
        at: this.now(),
        ...(opts.unauthenticated ? { unauthenticated: true as const } : {}),
      },
    });
    this.killedState = true;
  }

  get killed(): boolean {
    return this.killedState;
  }

  /**
   * Every engage() starts a new kill epoch. A restore ceremony binds to the
   * epoch in force when it started; a later kill bumps the counter and
   * invalidates every ceremony in flight.
   */
  get epoch(): number {
    return this.epochCounter;
  }

  /**
   * Restore requires a RestoreAuthorization produced by a completed 2GO
   * ceremony. Verifying live ceremony state (ownership, cooldown, TTL, kill
   * epoch) is the HTTP layer's job (server.ts); the checks here — shape and
   * single-use ceremony ids — are a last line of defense, not the gate.
   */
  restore(auth: RestoreAuthorization): void {
    if (!this.killedState) throw new Error("not killed — nothing to restore");
    if (!auth.ceremonyId || !auth.ownerId) {
      throw new Error("restore requires a completed 2GO ceremony");
    }
    if (this.consumedCeremonies.has(auth.ceremonyId)) {
      throw new Error(
        `ceremony "${auth.ceremonyId}" already consumed — restore authorizations are single-use`,
      );
    }
    this.consumedCeremonies.add(auth.ceremonyId);
    this.log.push({ type: "restore", auth, at: this.now() });
    this.killedState = false;
  }

  /** Immutable copy of the full history. */
  auditLog(): readonly AuditEntry[] {
    return [...this.log];
  }
}
