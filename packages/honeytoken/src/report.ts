import { randomBytes } from "node:crypto";
import { signDeviceRequest } from "@ownerswitchai/control-plane";

/**
 * The trip reporter: turn a tripped honeytoken into a CONFIRMED kill.
 *
 * Same contract as the button daemon, because a trip is the same class of
 * event as a press — evidence in hand that must reach the control plane:
 *
 *  - a trip that reached us must reach the control plane: a failed POST is
 *    retried forever (200/400/800 ms, then every 2 s) and every attempt is
 *    logged loudly — an unconfirmed kill is an emergency, never a silent one
 *  - trips queue: each distinct trip gets its own confirmed POST /kill, so
 *    the audit log names every token that was touched (kill is idempotent
 *    on the control plane; extra entries are audit, not risk)
 *  - identical trips collapse while unconfirmed — an agent replaying the
 *    same poisoned call in a loop must not grow the queue without bound
 *  - signed fresh every attempt: nonces are single-use on the server and the
 *    timestamp must sit inside the clock-skew window, so a retry cannot
 *    reuse an earlier attempt's signature.
 */

const BACKOFF_MS = [200, 400, 800] as const;
const STEADY_RETRY_MS = 2_000;

export interface Trip {
  /** Canary ids of the touched token(s); empty when the file held no known core. */
  canaryIds: string[];
  /** How it tripped, for the audit trail: "read of /decoys/.env.backup (atime advanced)". */
  how: string;
}

export interface KillConfirmation {
  /** Attempts in this trip's sequence that finally landed (1 = first try). */
  attempts: number;
  /** HTTP status of the confirming response. */
  status: number;
  /** Response body of POST /kill, if it parsed as JSON. */
  body?: unknown;
  /** Reporter-clock time the confirmation arrived (ms since epoch). */
  at: number;
}

export interface TripReporterOptions {
  controlPlaneUrl: string;
  deviceId: string;
  /** Shared secret provisioned on the control plane (`deviceSecret`). */
  secret: string;
  /** Called once each trip's kill lands. */
  onKill?: (trip: Trip, confirmation: KillConfirmation) => void;
  now?: () => number;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** One line per event, loud by default (console.error). */
  log?: (line: string) => void;
}

export interface TripReporter {
  /** Queue a trip and return immediately; delivery retries forever in the background. */
  report(trip: Trip): void;
  /** Trips queued but not yet confirmed by the control plane. */
  pending(): number;
  stop(): void;
}

/** The audit-trail reason a trip sends with its kill — names the token and how it tripped. */
export function killReason(trip: Trip): string {
  const ids = trip.canaryIds.length > 0 ? trip.canaryIds.join("+") : "(id unknown)";
  return `honeytoken ${ids} tripped: ${trip.how}`;
}

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
  const killUrl = new URL("/kill", opts.controlPlaneUrl);

  let active = true;
  let draining = false;
  let cancelWait: (() => void) | null = null;
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

  async function attemptKill(trip: Trip, attempt: number): Promise<AttemptOutcome> {
    const timestamp = now();
    const nonce = randomBytes(16).toString("hex");
    const body = JSON.stringify({ source: "honeytoken", reason: killReason(trip) });
    const signature = signDeviceRequest(
      { deviceId: opts.deviceId, timestamp, nonce },
      body,
      opts.secret,
    );
    log(`[honeytoken] → POST ${killUrl} (attempt ${attempt}, device ${opts.deviceId})`);
    try {
      const res = await fetchImpl(killUrl, {
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
    draining = true;
    while (active && queue.length > 0) {
      const trip = queue[0];
      for (let attempt = 1; active; attempt += 1) {
        const outcome = await attemptKill(trip, attempt);
        if (!active) break;
        if (outcome.ok) {
          queue.shift();
          log(`[honeytoken] ■ KILL CONFIRMED (${outcome.detail}, attempt ${attempt}) — ${killReason(trip)}`);
          opts.onKill?.(trip, { attempts: attempt, status: outcome.status, body: outcome.body, at: now() });
          break;
        }
        const delayMs = attempt <= BACKOFF_MS.length ? BACKOFF_MS[attempt - 1] : STEADY_RETRY_MS;
        log(
          `[honeytoken] ✗ KILL NOT LANDED — attempt ${attempt} failed (${outcome.detail}); retrying in ${delayMs}ms, not giving up`,
        );
        await wait(delayMs);
      }
    }
    draining = false;
  }

  return {
    report(trip: Trip): void {
      const reason = killReason(trip);
      if (!active) {
        // Stopped reporters must not swallow evidence silently.
        log(`[honeytoken] ⚠ reporter is stopped — trip NOT delivered: ${reason}`);
        return;
      }
      if (queue.some((queued) => killReason(queued) === reason)) {
        log(`[honeytoken] duplicate trip already queued, kill in flight — ${reason}`);
        return;
      }
      queue.push(trip);
      log(`[honeytoken] ⚡ TRIP — ${reason}`);
      if (!draining) void drain();
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
          `[honeytoken] ⚠ stopped with ${queue.length} trip(s) UNCONFIRMED — the control plane may not be killed`,
        );
      }
    },
  };
}
