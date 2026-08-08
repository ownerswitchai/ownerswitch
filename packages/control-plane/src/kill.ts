/**
 * Enforcement boundary: engaging KILL guarantees that no NEW authorized
 * action crosses the OwnerSwitch boundary from that moment on. It does NOT
 * instantly kill in-flight actions or revoke credentials already issued
 * downstream — those remain bounded by their TTL and by each connector's
 * revocation capability. Short TTLs are the mitigation. Don't re-introduce
 * the "kill revokes existing tokens" overclaim in docs or comments.
 */
import type { KillStateStore } from "./kill-state.js";
import type { RestoreAuthorization } from "./twogo.js";

/**
 * KillSwitch — the global kill state of an OwnerSwitch deployment.
 *
 * Rules:
 *  - engaging is CHEAP: any trigger source may do it, idempotently
 *  - restoring is EXPENSIVE: only a completed 2GO ceremony authorizes it
 *  - every transition is appended to an immutable audit log
 *  - killed state, the epoch and the attributing event survive a process
 *    restart when a store is wired in — a restart resumes the state it went
 *    down with; it never resets it
 */
export type KillSource = "button" | "honeytoken" | "app" | "voice" | "api";

export const KILL_SOURCES: readonly KillSource[] = ["button", "honeytoken", "app", "voice", "api"];

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

export interface KillSwitchOptions {
  /**
   * Where kill state survives a process restart. Without a store the switch
   * is purely in-memory, and a restart is a fail-open path: killed comes back
   * as not-killed with no ceremony. Only omit it where forgetting the kill on
   * restart is the explicit intent (unit tests, throwaway demos) —
   * createControlPlane wires a file store by default.
   */
  store?: KillStateStore;
}

export class KillSwitch {
  private killedState = false;
  private epochCounter = 0;
  private log: AuditEntry[] = [];
  private consumedCeremonies = new Set<string>();
  private readonly store?: KillStateStore;
  private lastKillEvent?: KillEvent;
  private degradedSince?: { at: number; reason: string };

  constructor(
    private readonly now: () => number = Date.now,
    opts: KillSwitchOptions = {},
  ) {
    this.store = opts.store;
    if (this.store === undefined) return;
    // Loading happens HERE, synchronously in the constructor — before any
    // server built on this switch can accept a request.
    const loaded = this.store.load();
    if (loaded.outcome === "absent") return; // genuine first boot: armed, epoch 0
    if (loaded.outcome === "corrupt") {
      // FAIL CLOSED: kill state that exists-but-unreadable, malformed, or
      // missing-after-initialisation reads as killed. Booting free because
      // the file rotted or vanished would make disk corruption (or one
      // hostile write or delete) a silent restore.
      console.error(
        `[ownerswitch] kill state cannot be trusted (${loaded.detail}) — ` +
          `booting KILLED. Restoring requires a 2GO ceremony.`,
      );
      this.engage("api", `kill state cannot be trusted at boot — failed closed (${loaded.detail})`);
      return;
    }
    this.killedState = loaded.state.killed;
    this.epochCounter = loaded.state.epoch;
    if (loaded.state.lastKill !== undefined) {
      // Re-seat the attributing kill event so the audit surface can still
      // answer what killed the system, and when, across the restart.
      this.lastKillEvent = loaded.state.lastKill;
      this.log.push({ type: "kill", event: loaded.state.lastKill });
    }
  }

  /** Idempotent: repeated triggers only add audit entries, never throw. */
  engage(source: KillSource, reason?: string, opts: { unauthenticated?: boolean } = {}): void {
    this.epochCounter += 1;
    const event: KillEvent = {
      source,
      reason,
      at: this.now(),
      ...(opts.unauthenticated ? { unauthenticated: true as const } : {}),
    };
    this.log.push({ type: "kill", event });
    this.lastKillEvent = event;
    this.killedState = true;
    this.persist();
  }

  get killed(): boolean {
    return this.killedState;
  }

  /**
   * The newest kill event, tracked directly so the hot paths — persist on
   * every kill, /status on every gateway poll — never copy or scan the audit
   * log. Both routes are reachable without authentication (deliberately, for
   * the stop direction), so their cost must not grow with history.
   */
  get lastKill(): KillEvent | undefined {
    return this.lastKillEvent;
  }

  /**
   * True while the most recent attempt to persist a transition failed: the
   * in-memory state is authoritative and in force, but a restart may not
   * come back with it (the store has been degraded so a restart fails
   * CLOSED, never open). Cleared by the next successful persist.
   */
  get persistenceDegraded(): boolean {
    return this.degradedSince !== undefined;
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
    this.persist();
  }

  /** Immutable copy of the full history. */
  auditLog(): readonly AuditEntry[] {
    return [...this.log];
  }

  /**
   * Persistence must never block a transition — above all not a kill: if the
   * disk is the thing that's broken, the switch still flips in memory. But a
   * failed persist is never swallowed either: durability is recorded as
   * DEGRADED (surfaced by the HTTP layer on /kill and /status), the failure
   * is logged loudly, and the store is degraded — best-effort — so that a
   * later restart fails CLOSED instead of resurrecting the stale on-disk
   * state this save failed to replace.
   */
  private persist(): void {
    if (this.store === undefined) return;
    try {
      this.store.save({
        version: 1,
        killed: this.killedState,
        epoch: this.epochCounter,
        ...(this.killedState && this.lastKillEvent !== undefined
          ? { lastKill: this.lastKillEvent }
          : {}),
      });
      this.degradedSince = undefined; // durable again as of this write
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.degradedSince = { at: this.now(), reason };
      console.error(
        `[ownerswitch] FAILED to persist kill state (${reason}) — the in-memory state stands ` +
          `and durability is now reported DEGRADED; the on-disk store is being degraded so a ` +
          `restart boots killed rather than resurrecting stale state.`,
      );
      try {
        this.store.degrade();
      } catch {
        /* the contract says degrade() never throws; belt over braces */
      }
    }
  }
}
