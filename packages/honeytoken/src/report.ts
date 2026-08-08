import { randomBytes } from "node:crypto";
import { signDeviceRequest } from "@ownerswitchai/control-plane";

/**
 * The trip reporter: deliver a tripped honeytoken to the control plane.
 *
 * Two tiers, on TWO INDEPENDENT LANES:
 *
 *  - "kill"  → POST /kill.  A decoy value about to be forwarded across the
 *    gateway has no innocent explanation; it engages the switch.
 *  - "alert" → POST /alert. A decoy file was touched, or a decoy value showed
 *    up in a call policy already refused. Suspicious, worth flagging, but not
 *    a lockdown.
 *
 * The lanes never share a queue. An earlier design put both on one strict
 * FIFO whose head retries forever — so an undeliverable alert (404, 500, a
 * hung socket, a version mismatch) could sit at the head and starve a genuine
 * kill queued behind it. Here the kill lane drains on its own; an alert that
 * never succeeds cannot delay a kill by a single millisecond.
 *
 * Within each lane the delivery discipline is the button daemon's — evidence
 * in hand must reach the control plane:
 *
 *  - a failed POST retries (200/400/800 ms, then every 2 s), logged loudly;
 *  - identical trips collapse while unconfirmed, so a replaying agent can't
 *    grow a lane without bound;
 *  - each attempt is signed fresh (single-use nonce, fresh timestamp);
 *  - flush() before shutdown blocks until both lanes drain or a bounded
 *    number of retries per trip is exhausted, so a tripped-but-unconfirmed
 *    report is not lost when the process exits.
 */

const BACKOFF_MS = [200, 400, 800] as const;
const STEADY_RETRY_MS = 2_000;

/** Attempts flush() allows per trip before giving up (loudly) so exit isn't blocked forever. */
export const DEFAULT_FLUSH_ATTEMPTS = 8;

export type TripTier = "alert" | "kill";

export interface Trip {
  /** "kill" engages the switch (POST /kill); "alert" only flags it (POST /alert). */
  tier: TripTier;
  /** Canary ids of the touched token(s); empty when none were identified. */
  canaryIds: string[];
  /** How it tripped, for the audit trail: "read of /decoys/.env.backup (atime advanced)". */
  how: string;
}

export interface DeliveryConfirmation {
  tier: TripTier;
  /** Attempts in this trip's sequence that finally landed (1 = first try). */
  attempts: number;
  status: number;
  body?: unknown;
  /** Reporter-clock time the confirmation arrived (ms since epoch). */
  at: number;
}

export interface TripReporterOptions {
  controlPlaneUrl: string;
  deviceId: string;
  /** Shared secret provisioned on the control plane (`deviceSecret`) for signing. */
  secret: string;
  /** Called once each trip's report lands. */
  onDelivered?: (trip: Trip, confirmation: DeliveryConfirmation) => void;
  now?: () => number;
  fetchImpl?: typeof fetch;
  log?: (line: string) => void;
}

export interface TripReporter {
  /** Queue a trip on its tier's lane and return immediately; delivery retries in the background. */
  report(trip: Trip): void;
  /** Block until both lanes drain, or each queued trip exhausts `maxAttempts`. */
  flush(opts?: { maxAttempts?: number }): Promise<{ delivered: boolean; pending: number }>;
  /** Trips queued but not yet confirmed, across both lanes. */
  pending(): number;
  /** Pending count on one lane. */
  pendingOn(tier: TripTier): number;
  /** Hard teardown: cancel retries now. Prefer flush() when a trip may be pending. */
  stop(): void;
}

/** The audit-trail reason a trip sends — names the token and how it tripped. */
export function tripReason(trip: Trip): string {
  const ids = trip.canaryIds.length > 0 ? trip.canaryIds.join("+") : "(id unknown)";
  return `honeytoken ${ids} tripped: ${trip.how}`;
}

/** Back-compat alias. */
export const killReason = tripReason;

interface AttemptOutcome {
  ok: boolean;
  status: number;
  body?: unknown;
  detail: string;
}

export function createTripReporter(opts: TripReporterOptions): TripReporter {
  const now = opts.now ?? Date.now;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const log = opts.log ?? ((line: string) => console.error(line));
  const endpoint: Record<TripTier, URL> = {
    kill: new URL("/kill", opts.controlPlaneUrl),
    alert: new URL("/alert", opts.controlPlaneUrl),
  };

  let active = true;

  async function attempt(trip: Trip, n: number): Promise<AttemptOutcome> {
    const url = endpoint[trip.tier];
    const timestamp = now();
    const nonce = randomBytes(16).toString("hex");
    const body = JSON.stringify({ source: "honeytoken", reason: tripReason(trip) });
    const signature = signDeviceRequest({ deviceId: opts.deviceId, timestamp, nonce }, body, opts.secret);
    log(`[honeytoken] → POST ${url} (${trip.tier}, attempt ${n}, device ${opts.deviceId})`);
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": opts.deviceId,
          "x-device-timestamp": String(timestamp),
          "x-device-nonce": nonce,
          "x-device-signature": signature,
        },
        body,
      });
      if (!res.ok) {
        return { ok: false, status: res.status, detail: `control plane answered HTTP ${res.status}` };
      }
      const parsed: unknown = await res.json().catch(() => undefined);
      return { ok: true, status: res.status, body: parsed, detail: `HTTP ${res.status}` };
    } catch (err) {
      return { ok: false, status: 0, detail: err instanceof Error ? err.message : String(err) };
    }
  }

  /** One independent delivery lane per tier — no lane can block another. */
  class Lane {
    private readonly queue: Trip[] = [];
    private retryBudget = Number.POSITIVE_INFINITY;
    private drainPromise: Promise<void> | null = null;
    private cancelWait: (() => void) | null = null;

    constructor(private readonly tier: TripTier) {}

    get size(): number {
      return this.queue.length;
    }

    private wait(ms: number): Promise<void> {
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          this.cancelWait = null;
          resolve();
        }, ms);
        this.cancelWait = () => {
          clearTimeout(timer);
          this.cancelWait = null;
          resolve();
        };
      });
    }

    enqueue(trip: Trip): void {
      const reason = tripReason(trip);
      if (this.queue.some((q) => tripReason(q) === reason)) {
        log(`[honeytoken] duplicate ${this.tier} trip already queued, report in flight — ${reason}`);
        return;
      }
      this.queue.push(trip);
      log(`[honeytoken] ⚡ TRIP (${this.tier}) — ${reason}`);
      this.ensureDraining();
    }

    private ensureDraining(): void {
      if (this.drainPromise === null) {
        this.drainPromise = this.drain().finally(() => {
          this.drainPromise = null;
        });
      }
    }

    private async drain(): Promise<void> {
      while (active && this.queue.length > 0) {
        const trip = this.queue[0];
        let landed = false;
        for (let n = 1; active && n <= this.retryBudget; n += 1) {
          const outcome = await attempt(trip, n);
          if (!active) return;
          if (outcome.ok) {
            this.queue.shift();
            landed = true;
            const verb = trip.tier === "kill" ? "KILL CONFIRMED" : "ALERT RECORDED";
            log(`[honeytoken] ■ ${verb} (${outcome.detail}, attempt ${n}) — ${tripReason(trip)}`);
            opts.onDelivered?.(trip, {
              tier: trip.tier,
              attempts: n,
              status: outcome.status,
              body: outcome.body,
              at: now(),
            });
            break;
          }
          if (n >= this.retryBudget) {
            log(
              `[honeytoken] ✗ giving up after ${n} attempt(s) — ${this.tier} trip UNCONFIRMED (${outcome.detail}); ${tripReason(trip)}`,
            );
            break;
          }
          const delayMs = n <= BACKOFF_MS.length ? BACKOFF_MS[n - 1] : STEADY_RETRY_MS;
          log(
            `[honeytoken] ✗ NOT LANDED — ${this.tier} attempt ${n} failed (${outcome.detail}); retrying in ${delayMs}ms, not giving up`,
          );
          await this.wait(delayMs);
        }
        if (!landed && this.retryBudget !== Number.POSITIVE_INFINITY) break;
      }
    }

    async flush(maxAttempts: number): Promise<void> {
      this.retryBudget = Math.max(1, Math.floor(maxAttempts));
      this.cancelWait?.(); // wake an in-progress backoff so it retries now under the bounded budget
      this.ensureDraining();
      await this.drainPromise;
      this.retryBudget = Number.POSITIVE_INFINITY;
    }

    stop(): void {
      this.cancelWait?.();
    }
  }

  const lanes: Record<TripTier, Lane> = { kill: new Lane("kill"), alert: new Lane("alert") };

  return {
    report(trip: Trip): void {
      if (!active) {
        log(`[honeytoken] ⚠ reporter is stopped — trip NOT delivered: ${tripReason(trip)}`);
        return;
      }
      lanes[trip.tier].enqueue(trip);
    },

    async flush(flushOpts: { maxAttempts?: number } = {}): Promise<{ delivered: boolean; pending: number }> {
      if (!active) return { delivered: this.pending() === 0, pending: this.pending() };
      const maxAttempts = flushOpts.maxAttempts ?? DEFAULT_FLUSH_ATTEMPTS;
      // Drain both lanes concurrently — flushing must not serialize them either.
      await Promise.all([lanes.kill.flush(maxAttempts), lanes.alert.flush(maxAttempts)]);
      const pending = this.pending();
      if (pending > 0) {
        log(
          `[honeytoken] ⚠ flush: ${pending} trip(s) still UNCONFIRMED after ${maxAttempts} attempt(s) each — evidence may be lost on exit`,
        );
      }
      return { delivered: pending === 0, pending };
    },

    pending(): number {
      return lanes.kill.size + lanes.alert.size;
    },

    pendingOn(tier: TripTier): number {
      return lanes[tier].size;
    },

    stop(): void {
      if (!active) return;
      active = false;
      lanes.kill.stop();
      lanes.alert.stop();
      const pending = lanes.kill.size + lanes.alert.size;
      if (pending > 0) {
        log(
          `[honeytoken] ⚠ stopped with ${pending} trip(s) UNCONFIRMED — the control plane may not have recorded them`,
        );
      }
    },
  };
}
