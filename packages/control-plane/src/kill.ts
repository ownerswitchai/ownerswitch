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

/**
 * A flagged event that did NOT change kill state — e.g. a honeytoken FILE was
 * touched (read/backup/index), which is suspicious but has innocent
 * explanations, so it alerts instead of killing. Same shape as a KillEvent so
 * the audit trail reads uniformly.
 */
export interface AlertEvent {
  source: KillSource;
  reason?: string;
  at: number;
  /** present when the trigger carried no verifiable credential */
  unauthenticated?: true;
}

export type AuditEntry =
  | { type: "kill"; event: KillEvent }
  | { type: "restore"; auth: RestoreAuthorization; at: number }
  | { type: "alert"; event: AlertEvent };

export class KillSwitch {
  private killedState = false;
  private log: AuditEntry[] = [];
  private consumedCeremonies = new Set<string>();

  constructor(private readonly now: () => number = Date.now) {}

  /** Idempotent: repeated triggers only add audit entries, never throw. */
  engage(source: KillSource, reason?: string, opts: { unauthenticated?: boolean } = {}): void {
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

  /**
   * Record a flagged event WITHOUT engaging the kill switch. This is the
   * honeytoken file-touch tier: logged and auditable, but not a lockdown — a
   * decoy read has innocent explanations (indexing, backup, grep) and must
   * not be a one-touch denial-of-service. Idempotent and append-only.
   */
  alert(source: KillSource, reason?: string, opts: { unauthenticated?: boolean } = {}): void {
    this.log.push({
      type: "alert",
      event: {
        source,
        reason,
        at: this.now(),
        ...(opts.unauthenticated ? { unauthenticated: true as const } : {}),
      },
    });
  }

  get killed(): boolean {
    return this.killedState;
  }

  /**
   * Restore requires a completed ceremony. This method trusts its input's
   * SHAPE only — verifying the ceremony itself is the caller's job.
   * Each ceremony authorizes exactly one restore: replaying an
   * authorization whose ceremony id was already consumed throws.
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
