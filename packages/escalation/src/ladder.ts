import type {
  ChannelEvent,
  ChannelKind,
  EscalationAlert,
  LadderAction,
  LadderConfig,
  LadderRung,
  RateLimits,
} from "./types.js";

/**
 * The ladder engine — DESIGN.md §1/§6 as a pure state machine.
 *
 * House style: tick() computes, the edge (service.ts) performs. Nothing in
 * here sends, dials, or talks HTTP; the engine's entire influence on the
 * world is the LadderAction list it returns, and its entire influence on
 * the veto state machine is `relay-veto` — it has no action that extends,
 * releases, or approves, so a bug in here can at worst be noisy or silent,
 * never permissive.
 *
 * One RUN per storm (DESIGN.md §6): windows that open while a run is live
 * join it instead of starting rungs of their own, so a 1,000-window storm
 * costs one push, one SMS, one call — not a thousand. A joined window
 * re-fires nothing; the coalesced alert's headline says how many actions
 * are held and the owner app lists them all.
 */

export const DEFAULT_RUNGS: LadderRung[] = [
  { afterMs: 0, channel: "push" },
  { afterMs: 0, channel: "email" },
  { afterMs: 2.5 * 60_000, channel: "sms" },
  { afterMs: 5 * 60_000, channel: "voice" },
];

export const DEFAULT_LIMITS: RateLimits = {
  maxVoiceCallsPer10Min: 2,
  maxSmsPerHour: 6,
  maxDailySpendUsd: 5,
};

/** List-price estimates for the spend ceiling (DESIGN.md §6); config, not truth. */
export const DEFAULT_COST_USD: Record<ChannelKind, number> = {
  push: 0,
  email: 0.0001,
  sms: 0.008,
  voice: 0.014,
};

interface TrackedWindow {
  windowId: string;
  /** short human line for the alert headline; carries a tool name at most */
  headline: string;
  deadlineMs: number;
  delivered: boolean;
  closed: boolean;
}

interface Run {
  startedAtMs: number;
  /** rung indexes already fired (or skipped at a cap) this run */
  fired: Set<number>;
  windows: Map<string, TrackedWindow>;
}

export interface LadderEngineOptions {
  rungs?: LadderRung[];
  limits?: RateLimits;
  /** per-send estimates used against maxDailySpendUsd */
  costUsd?: Partial<Record<ChannelKind, number>>;
}

export class LadderEngine {
  private readonly rungs: LadderRung[];
  private readonly limits: RateLimits;
  private readonly costUsd: Record<ChannelKind, number>;
  private run: Run | null = null;
  /** unix ms of every voice send, pruned to the 10 min horizon */
  private voiceSends: number[] = [];
  /** unix ms of every SMS send, pruned to the 1 h horizon */
  private smsSends: number[] = [];
  /** { day bucket, spent } — the daily ceiling resets on the UTC day */
  private spend: { day: number; usd: number } = { day: -1, usd: 0 };
  /** actions queued by event handlers, drained by the next tick() */
  private pending: LadderAction[] = [];

  constructor(opts: LadderEngineOptions = {}) {
    this.rungs = [...(opts.rungs ?? DEFAULT_RUNGS)].sort((a, b) => a.afterMs - b.afterMs);
    this.limits = opts.limits ?? DEFAULT_LIMITS;
    this.costUsd = { ...DEFAULT_COST_USD, ...opts.costUsd };
    for (const rung of this.rungs) {
      if (rung.afterMs < 0) throw new Error("rung.afterMs must be >= 0");
    }
    for (const [name, value] of Object.entries(this.limits)) {
      if (!Number.isFinite(value) || value < 0) {
        throw new Error(`limits.${name} must be a finite non-negative number`);
      }
    }
  }

  /**
   * A veto window opened (or was discovered by the poller). Joins the live
   * run if one exists — coalescing is what keeps a storm from dialing the
   * owner's phone a thousand times — otherwise arms a fresh run whose rung
   * clock starts at the next tick.
   */
  windowOpened(windowId: string, headline: string, deadlineMs: number): void {
    const tracked: TrackedWindow = { windowId, headline, deadlineMs, delivered: false, closed: false };
    if (this.run !== null) {
      if (!this.run.windows.has(windowId)) this.run.windows.set(windowId, tracked);
      return;
    }
    this.run = { startedAtMs: -1, fired: new Set(), windows: new Map([[windowId, tracked]]) };
  }

  /** The control plane says this window's delivered bit is set. */
  windowDelivered(windowId: string): void {
    const tracked = this.run?.windows.get(windowId);
    if (tracked !== undefined) tracked.delivered = true;
  }

  /** The window left pending/extended (vetoed, released, held, killed, gone). */
  windowClosed(windowId: string): void {
    const tracked = this.run?.windows.get(windowId);
    if (tracked !== undefined) tracked.closed = true;
  }

  /** The window extended; its deadline moved. */
  windowDeadline(windowId: string, deadlineMs: number): void {
    const tracked = this.run?.windows.get(windowId);
    if (tracked !== undefined) tracked.deadlineMs = deadlineMs;
  }

  /**
   * Evidence or a veto came back from a channel. A veto queues a relay for
   * every open window the run covers — bulk stop is safe because stop is
   * the safe direction (DESIGN.md §6). Evidence is recorded by the edge
   * (it owns the control-plane client and the audit trail); the engine
   * only needs vetoes.
   */
  channelEvent(event: ChannelEvent): void {
    if (event.type !== "veto") return;
    const openIds = this.openWindowIds().filter(
      (id) => event.windowIds.length === 0 || event.windowIds.includes(id),
    );
    if (openIds.length === 0) return;
    this.pending.push({
      type: "relay-veto",
      windowIds: openIds,
      channel: event.channel,
      attribution: event.attribution,
    });
  }

  /**
   * Advance. Returns the sends to make, vetoes to relay, and stand-downs to
   * record — in that deliberate order: a queued veto relay outruns any send
   * the same tick would fire.
   */
  tick(nowMs: number): LadderAction[] {
    const actions: LadderAction[] = this.pending;
    this.pending = [];
    const run = this.run;
    if (run === null) return actions;

    // arm the rung clock on the first tick that sees the run — windowOpened
    // has no clock (house style: only tick() sees time)
    if (run.startedAtMs === -1) run.startedAtMs = nowMs;

    this.dropClosed(run, actions);
    if (this.run === null) return actions;

    // every open window confirmed -> the calm path; remaining rungs stand down
    const open = [...run.windows.values()].filter((w) => !w.closed);
    if (open.length > 0 && open.every((w) => w.delivered)) {
      const unfired = this.rungs.some((_, i) => !run.fired.has(i));
      if (unfired) {
        actions.push({
          type: "stand-down",
          windowIds: open.map((w) => w.windowId),
          reason: "confirmed",
        });
      }
      this.rungs.forEach((_, i) => run.fired.add(i));
      return actions;
    }

    for (let i = 0; i < this.rungs.length; i++) {
      if (run.fired.has(i)) continue;
      const rung = this.rungs[i];
      if (nowMs - run.startedAtMs < rung.afterMs) continue;
      const verdict = this.admit(rung.channel, nowMs);
      if (verdict === "capped") {
        // a cap converts the rung into the fail-closed ending, loudly and
        // exactly once — it may never convert into a release
        run.fired.add(i);
        actions.push({
          type: "stand-down",
          windowIds: open.map((w) => w.windowId),
          reason: "cap-hit",
        });
        continue;
      }
      run.fired.add(i);
      actions.push({ type: "send", channel: rung.channel, alert: this.alertFor(open, nowMs) });
    }
    return actions;
  }

  /** True while a run is live (windows tracked, rungs armed or firing). */
  get active(): boolean {
    return this.run !== null;
  }

  private openWindowIds(): string[] {
    return this.run === null
      ? []
      : [...this.run.windows.values()].filter((w) => !w.closed).map((w) => w.windowId);
  }

  private dropClosed(run: Run, actions: LadderAction[]): void {
    const closed = [...run.windows.values()].filter((w) => w.closed);
    if (closed.length > 0) {
      actions.push({
        type: "stand-down",
        windowIds: closed.map((w) => w.windowId),
        reason: "window-closed",
      });
      for (const w of closed) run.windows.delete(w.windowId);
    }
    if (run.windows.size === 0) this.run = null;
  }

  private alertFor(open: TrackedWindow[], nowMs: number): EscalationAlert {
    // The provider sees this text (DESIGN.md §5): a tool name and a count at
    // most, never arguments. Detail lives in the owner app.
    const earliest = Math.min(...open.map((w) => w.deadlineMs));
    const headline =
      open.length === 1
        ? `OwnerSwitch: ${open[0].headline} held for your review`
        : `OwnerSwitch: ${open.length} actions held for your review`;
    void nowMs;
    return { windowIds: open.map((w) => w.windowId), headline, deadlineMs: earliest };
  }

  /** Apply the §6 ceilings; "sent" records the spend, "capped" refuses. */
  private admit(channel: ChannelKind, nowMs: number): "sent" | "capped" {
    const cost = this.costUsd[channel];
    const day = Math.floor(nowMs / 86_400_000);
    if (this.spend.day !== day) this.spend = { day, usd: 0 };
    if (this.spend.usd + cost > this.limits.maxDailySpendUsd) return "capped";

    if (channel === "voice") {
      this.voiceSends = this.voiceSends.filter((at) => nowMs - at < 10 * 60_000);
      if (this.voiceSends.length >= this.limits.maxVoiceCallsPer10Min) return "capped";
      this.voiceSends.push(nowMs);
    }
    if (channel === "sms") {
      this.smsSends = this.smsSends.filter((at) => nowMs - at < 60 * 60_000);
      if (this.smsSends.length >= this.limits.maxSmsPerHour) return "capped";
      this.smsSends.push(nowMs);
    }
    this.spend.usd += cost;
    return "sent";
  }
}
