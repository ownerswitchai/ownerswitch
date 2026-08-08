import { randomBytes } from "node:crypto";
import { signDeviceRequest } from "@ownerswitchai/control-plane";

/**
 * The trip reporter: deliver a tripped honeytoken to the control plane.
 *
 * Two tiers, because a decoy FILE being read is not the same event as a decoy
 * VALUE crossing the gateway:
 *
 *  - "kill"  → POST /kill.  A decoy value in an outbound tool call has no
 *    innocent explanation; it engages the switch.
 *  - "alert" → POST /alert. A decoy file was touched (read, indexed, backed
 *    up, grepped). Suspicious and worth flagging, but reads have innocent
 *    causes and an attacker can deliberately induce one — so this records a
 *    flagged event and does NOT kill. See watch.ts for why this is the
 *    default for file tripwires.
 *
 * Delivery discipline is the button daemon's, for both tiers — evidence in
 * hand must reach the control plane:
 *
 *  - a trip that reached us must reach the control plane: a failed POST is
 *    retried (200/400/800 ms, then every 2 s) and every attempt is logged
 *    loudly — an unconfirmed report is never a silent one
 *  - trips queue: each distinct trip gets its own confirmed POST, so the
 *    audit log names every token that was touched
 *  - identical trips collapse while unconfirmed — an agent replaying the
 *    same poisoned call in a loop must not grow the queue without bound
 *  - signed fresh every attempt: nonces are single-use on the server and the
 *    timestamp must sit inside the clock-skew window, so a retry cannot
 *    reuse an earlier attempt's signature
 *  - flush() before shutdown blocks until the queue drains or a bounded
 *    number of retries per trip is exhausted, so a tripped-but-unconfirmed
 *    report is not lost when the process exits (see the button daemon's
 *    "an unconfirmed kill is an emergency" for the same stance).
 */

const BACKOFF_MS = [200, 400, 800] as const;
const STEADY_RETRY_MS = 2_000;

/** Attempts flush() allows per trip before giving up (loudly) so exit isn't blocked forever. */
export const DEFAULT_FLUSH_ATTEMPTS = 8;

export type TripTier = "alert" | "kill";

export interface Trip {
  /** "kill" engages the switch (POST /kill); "alert" only flags it (POST /alert). */
  tier: TripTier;
  /** Canary ids of the touched token(s); empty when the file held no known core. */
  canaryIds: string[];
  /** How it tripped, for the audit trail: "read of /decoys/.env.backup (atime advanced)". */
  how: string;
}

export interface DeliveryConfirmation {
  tier: TripTier;
  /** Attempts in this trip's sequence that finally landed (1 = first try). */
  attempts: number;
  /** HTTP status of the confirming response. */
  status: number;
  /** Response body, if it parsed as JSON. */
  body?: unknown;
  /** Reporter-clock time the confirmation arrived (ms since epoch). */
  at: number;
}

export interface TripReporterOptions {
  controlPlaneUrl: string;
  deviceId: string;
  /** Shared secret provisioned on the control plane (`deviceSecret`). */
  secret: string;
  /** Called once each trip's report lands. */
  onDelivered?: (trip: Trip, confirmation: DeliveryConfirmation) => void;
  now?: () => number;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** One line per event, loud by default (console.error). */
  log?: (line: string) => void;
}

export interface TripReporter {
  /** Queue a trip and return immediately; delivery retries in the background. */
  report(trip: Trip): void;
  /**
   * Block until every queued trip is confirmed, or each has exhausted
   * `maxAttempts` tries. Call before shutting the process down so an
   * unconfirmed trip is not lost. Resolves with what could not be delivered.
   */
  flush(opts?: { maxAttempts?: number }): Promise<{ delivered: boolean; pending: number }>;
  /** Trips queued but not yet confirmed by the control plane. */
  pending(): number;
  /** Hard teardown: cancel retries now. Prefer flush() when a trip may be pending. */
  stop(): void;
}

/** The audit-trail reason a trip sends — names the token and how it tripped. */
export function tripReason(trip: Trip): string {
  const ids = trip.canaryIds.length > 0 ? trip.canaryIds.join("+") : "(id unknown)";
  return `honeytoken ${ids} tripped: ${trip.how}`;
}

/** Back-compat alias — the kill reason a trip sends. */
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
  let cancelWait: (() => void) | null = null;
  /** Attempts allowed per trip. Infinity in the background; flush() lowers it. */
  let retryBudget = Number.POSITIVE_INFINITY;
  let drainPromise: Promise<void> | null = null;
  const queue: Trip[] = [];

  const wait = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => {
        cancelWait = null;
        resolve();
      }, ms);
      cancelWait = () => {
        clearTimeout(timer);
        cancelWait = null;
        resolve();
      };
    });

  async function attempt(trip: Trip, n: number): Promise<AttemptOutcome> {
    const url = endpoint[trip.tier];
    const timestamp = now();
    const nonce = randomBytes(16).toString("hex");
    const body = JSON.stringify({ source: "honeytoken", reason: tripReason(trip) });
    const signature = signDeviceRequest(
      { deviceId: opts.deviceId, timestamp, nonce },
      body,
      opts.secret,
    );
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

  async function drain(): Promise<void> {
    while (active && queue.length > 0) {
      const trip = queue[0];
      let landed = false;
      for (let n = 1; active && n <= retryBudget; n += 1) {
        const outcome = await attempt(trip, n);
        if (!active) return;
        if (outcome.ok) {
          queue.shift();
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
        if (n >= retryBudget) {
          // Bounded flush gave up on this trip. Leave it queued (pending()
          // still counts it) and stop draining so we don't spin on queue[0].
          log(
            `[honeytoken] ✗ giving up after ${n} attempt(s) — trip UNCONFIRMED (${outcome.detail}); ${tripReason(trip)}`,
          );
          break;
        }
        const delayMs = n <= BACKOFF_MS.length ? BACKOFF_MS[n - 1] : STEADY_RETRY_MS;
        log(
          `[honeytoken] ✗ NOT LANDED — attempt ${n} failed (${outcome.detail}); retrying in ${delayMs}ms, not giving up`,
        );
        await wait(delayMs);
      }
      // A bounded budget that didn't land must not loop forever on the head.
      if (!landed && retryBudget !== Number.POSITIVE_INFINITY) break;
    }
  }

  function ensureDraining(): void {
    if (drainPromise === null) {
      drainPromise = drain().finally(() => {
        drainPromise = null;
      });
    }
  }

  return {
    report(trip: Trip): void {
      const reason = tripReason(trip);
      if (!active) {
        // Stopped reporters must not swallow evidence silently.
        log(`[honeytoken] ⚠ reporter is stopped — trip NOT delivered: ${reason}`);
        return;
      }
      if (queue.some((queued) => queued.tier === trip.tier && tripReason(queued) === reason)) {
        log(`[honeytoken] duplicate trip already queued, report in flight — ${reason}`);
        return;
      }
      queue.push(trip);
      log(`[honeytoken] ⚡ TRIP (${trip.tier}) — ${reason}`);
      ensureDraining();
    },

    async flush(flushOpts: { maxAttempts?: number } = {}): Promise<{ delivered: boolean; pending: number }> {
      if (!active) return { delivered: queue.length === 0, pending: queue.length };
      const maxAttempts = flushOpts.maxAttempts ?? DEFAULT_FLUSH_ATTEMPTS;
      retryBudget = Math.max(1, Math.floor(maxAttempts));
      cancelWait?.(); // wake any in-progress backoff so it retries now under the bounded budget
      ensureDraining();
      await drainPromise;
      const delivered = queue.length === 0;
      if (!delivered) {
        log(
          `[honeytoken] ⚠ flush: ${queue.length} trip(s) still UNCONFIRMED after ${retryBudget} attempt(s) each — evidence may be lost on exit`,
        );
      }
      retryBudget = Number.POSITIVE_INFINITY;
      return { delivered, pending: queue.length };
    },

    pending(): number {
      return queue.length;
    },

    stop(): void {
      if (!active) return;
      active = false;
      cancelWait?.();
      if (queue.length > 0) {
        log(
          `[honeytoken] ⚠ stopped with ${queue.length} trip(s) UNCONFIRMED — the control plane may not have recorded them`,
        );
      }
    },
  };
}
