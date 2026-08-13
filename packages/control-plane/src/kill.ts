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
 *
 * The same rules govern SCOPED (per-agent) kills — engageAgent() is as
 * cheap as engage(), restoreAgent() is as ceremonial as restore(), and the
 * two tiers are independent: a global restore does NOT restore scope-killed
 * agents (their kill was never the thing restored), and a global kill does
 * not erase them — it outranks them while it lasts.
 */
export type KillSource = "button" | "honeytoken" | "app" | "voice" | "api";

export const KILL_SOURCES: readonly KillSource[] = ["button", "honeytoken", "app", "voice", "api"];

/**
 * Bounds for SCOPED (per-agent) kills. They exist because scoped-kill
 * entries persist in the kill-state file, which load() refuses over
 * MAX_KILL_STATE_FILE_BYTES: unbounded ids, reasons or agent counts would
 * let a kill flood write a state file tomorrow's boot rejects. The counts
 * are sized so the worst-case file stays far under that ceiling.
 *
 * At the agent-count cap a scoped kill is NEVER refused — it escalates to
 * the global kill instead (see engageAgent): out of room to stop one agent,
 * stop them all. Fail-closed has no capacity limit.
 */
export const MAX_KILLED_AGENTS = 64;
export const MAX_AGENT_ID_CHARS = 128;
export const MAX_SCOPED_KILL_REASON_CHARS = 256;

/**
 * A valid agent id for scoped kills: 1–128 printable-ASCII chars with no
 * leading/trailing whitespace. It appears verbatim in the state file, the
 * unauthenticated /status body and audit surfaces, so the charset is kept
 * boring by construction — no control characters, no Unicode confusables.
 */
export function isValidAgentId(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= MAX_AGENT_ID_CHARS &&
    /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/.test(value)
  );
}

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
  | { type: "alert"; event: AlertEvent }
  | { type: "agent-kill"; agentId: string; event: KillEvent }
  | { type: "agent-restore"; agentId: string; auth: RestoreAuthorization; at: number };

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
  private quarantineFailedState = false;
  /** currently scope-killed agents and the event that killed each */
  private agentKillMap = new Map<string, KillEvent>();

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
    if (loaded.state.agentKills !== undefined) {
      // Scoped kills survive a restart exactly like the global one: a
      // scope-killed agent comes back scope-killed, event and all.
      for (const [agentId, event] of Object.entries(loaded.state.agentKills)) {
        this.agentKillMap.set(agentId, event);
        this.log.push({ type: "agent-kill", agentId, event });
      }
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

  /**
   * SCOPED kill: stop ONE agent without stopping the fleet. Same doctrine
   * as engage() — cheap, idempotent, never throws, every trigger audited —
   * but the global `killed` stays false and only calls carrying this
   * agentId are denied (gateway engine + the control plane's own approval,
   * commit and registration surfaces).
   *
   * A scoped kill BUMPS THE GLOBAL EPOCH. That is deliberate, not an
   * accident of reuse: every in-flight approval, grant, action ticket and
   * restore ceremony is epoch-bound, so bumping it makes a scoped kill
   * inherit the whole existing invalidation story — a pre-kill approval
   * (for ANY agent) cannot execute in the post-kill world without a fresh
   * owner decision. The cost, stated plainly: a scoped kill voids other
   * agents' PENDING approvals too (they re-request; the owner re-approves).
   * It does not stop them. The alternative — a per-agent epoch woven into
   * every signed format — would widen the surface this feature exists to
   * keep small.
   *
   * The caller validates the id (isValidAgentId); this method only bounds
   * what it stores. At MAX_KILLED_AGENTS the stop is not refused — it
   * escalates to the global kill, because stopping must never fail on a
   * capacity ceiling.
   */
  engageAgent(
    agentId: string,
    source: KillSource,
    reason?: string,
    opts: { unauthenticated?: boolean } = {},
  ): void {
    if (!this.agentKillMap.has(agentId) && this.agentKillMap.size >= MAX_KILLED_AGENTS) {
      this.engage(
        source,
        `scoped-kill capacity (${MAX_KILLED_AGENTS} agents) exceeded at agent "${agentId}" — ` +
          `escalated to a global kill${reason !== undefined ? `; original reason: ${reason}` : ""}`,
        opts,
      );
      return;
    }
    this.epochCounter += 1;
    const event: KillEvent = {
      source,
      // bounded because it persists per agent in the kill-state file
      ...(reason !== undefined ? { reason: reason.slice(0, MAX_SCOPED_KILL_REASON_CHARS) } : {}),
      at: this.now(),
      ...(opts.unauthenticated ? { unauthenticated: true as const } : {}),
    };
    this.log.push({ type: "agent-kill", agentId, event });
    this.agentKillMap.set(agentId, event);
    this.persist();
  }

  /** True while `agentId` is scope-killed (the global switch is separate). */
  agentKilled(agentId: string): boolean {
    return this.agentKillMap.has(agentId);
  }

  /** The scope-killed agent ids, in kill order. Served on GET /status. */
  get killedAgents(): readonly string[] {
    return [...this.agentKillMap.keys()];
  }

  /** The kill event holding `agentId` down, for attribution surfaces. */
  agentKillEvent(agentId: string): KillEvent | undefined {
    return this.agentKillMap.get(agentId);
  }

  /**
   * Scoped restore — the expensive direction, exactly like restore(): it
   * demands a completed 2GO ceremony (single-use, shared consumed-id set)
   * and un-kills ONE agent. It never touches the global switch and never
   * bumps the epoch (restores don't). Live ceremony checks — ownership,
   * cooldown, TTL, epoch, scope — are the HTTP layer's job.
   */
  restoreAgent(agentId: string, auth: RestoreAuthorization): void {
    if (!this.agentKillMap.has(agentId)) {
      throw new Error(`agent "${agentId}" is not scope-killed — nothing to restore`);
    }
    if (!auth.ceremonyId || !auth.ownerId) {
      throw new Error("restore requires a completed 2GO ceremony");
    }
    if (this.consumedCeremonies.has(auth.ceremonyId)) {
      throw new Error(
        `ceremony "${auth.ceremonyId}" already consumed — restore authorizations are single-use`,
      );
    }
    this.consumedCeremonies.add(auth.ceremonyId);
    this.log.push({ type: "agent-restore", agentId, auth, at: this.now() });
    this.agentKillMap.delete(agentId);
    this.persist();
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
   * The newest kill event, tracked directly so the hot paths — persist on
   * every kill, /status on every gateway poll — never copy or scan the audit
   * log. Both routes are reachable without authentication (deliberately, for
   * the stop direction), so their cost must not grow with history.
   */
  get lastKill(): KillEvent | undefined {
    return this.lastKillEvent;
  }

  /**
   * True while the most recent transition is not known durable: the save
   * threw, or it published but an fsync failed. The in-memory state is
   * authoritative and in force, but a restart may not come back with it.
   * Cleared by the next fully durable persist.
   */
  get persistenceDegraded(): boolean {
    return this.degradedSince !== undefined;
  }

  /**
   * True when a persist failed AND the store could not quarantine the stale
   * on-disk state it failed to replace — a restart may boot from that stale
   * state. The control plane must not present itself as fit for service
   * while this holds (the HTTP layer reports it unhealthy and keeps denying
   * restores). Cleared when a later persist writes correct state (that IS
   * the repair) or a later quarantine succeeds.
   */
  get quarantineFailed(): boolean {
    return this.quarantineFailedState;
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
   * failed persist is never swallowed either:
   *  - save threw → durability DEGRADED (surfaced on /kill and /status) and
   *    the store is asked to quarantine the stale state it failed to replace
   *  - the quarantine itself fails → the process is UNHEALTHY: a restart may
   *    boot from stale state, so the HTTP layer keeps denying restores until
   *    an owner repairs the store
   *  - save published but an fsync failed → DEGRADED too: a transition is
   *    durable only after every fsync succeeds, and a directory-fsync
   *    failure must surface, not pass in silence
   */
  private persist(): void {
    if (this.store === undefined) return;
    let result;
    try {
      result = this.store.save({
        version: 1,
        killed: this.killedState,
        epoch: this.epochCounter,
        ...(this.killedState && this.lastKillEvent !== undefined
          ? { lastKill: this.lastKillEvent }
          : {}),
        // present exactly when non-empty, so deployments that never use
        // scoped kills keep writing byte-identical state files
        ...(this.agentKillMap.size > 0
          ? { agentKills: Object.fromEntries(this.agentKillMap) }
          : {}),
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.degradedSince = { at: this.now(), reason };
      console.error(
        `[ownerswitch] FAILED to persist kill state (${reason}) — the in-memory state stands ` +
          `and durability is now reported DEGRADED; quarantining the stale on-disk state.`,
      );
      let quarantined = false;
      try {
        quarantined = this.store.degrade();
      } catch {
        quarantined = false; // the contract says degrade() never throws; belt over braces
      }
      if (quarantined) {
        // stale state is neutralised: a restart fails closed, not open
        this.quarantineFailedState = false;
      } else if (!this.quarantineFailedState) {
        this.quarantineFailedState = true;
        console.error(
          `[ownerswitch] QUARANTINE FAILED: stale kill state could not be neutralised and may ` +
            `survive a restart. The control plane is UNHEALTHY pending owner intervention — ` +
            `restores are denied until a persist succeeds.`,
        );
      }
      return;
    }
    if (result.durable) {
      // fully durable: the on-disk state is correct AND survives power loss —
      // both the degradation and any earlier quarantine failure are repaired
      this.degradedSince = undefined;
      this.quarantineFailedState = false;
    } else {
      const first = this.degradedSince === undefined;
      this.degradedSince = { at: this.now(), reason: result.detail };
      // the published state is CORRECT, so any stale-state hazard is gone
      this.quarantineFailedState = false;
      if (first) {
        console.error(
          `[ownerswitch] kill state was published but is NOT yet durable (${result.detail}) — ` +
            `persistence is reported DEGRADED.`,
        );
      }
    }
  }
}
