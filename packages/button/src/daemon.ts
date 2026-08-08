import { randomBytes } from "node:crypto";
import { signDeviceRequest } from "@ownerswitchai/control-plane";
import type { OnPress } from "./input.js";

/**
 * The button daemon: turn a physical press into a CONFIRMED kill.
 *
 * Rules, in priority order:
 *  - a press that reached us must reach the control plane: a failed POST is
 *    retried forever (200/400/800 ms, then every 2 s) and every attempt is
 *    logged loudly — an unconfirmed kill is an emergency, never a silent one
 *  - hardware bounce is not intent: presses within `debounceMs` of the last
 *    one collapse into a single kill…
 *  - …unless an attempt has already failed — then a press always re-fires
 *    immediately with the backoff reset. When in doubt, send again:
 *    POST /kill is idempotent on the control plane.
 */

const BACKOFF_MS = [200, 400, 800] as const;
const STEADY_RETRY_MS = 2_000;
const DEFAULT_DEBOUNCE_MS = 1_000;

export interface KillConfirmation {
  /** Attempts in the sequence that finally landed (1 = first try). */
  attempts: number;
  /** HTTP status of the confirming response. */
  status: number;
  /** Response body of POST /kill, if it parsed as JSON. */
  body?: unknown;
  /** Daemon-clock time the confirmation arrived (ms since epoch). */
  at: number;
}

export interface ButtonDaemonOptions {
  controlPlaneUrl: string;
  deviceId: string;
  /** Shared secret provisioned on the control plane (`deviceSecret`). */
  secret: string;
  /** Where presses come from — a source's `onPress` (see input.ts) or a stub. */
  onPress: OnPress;
  /** Called once a kill lands; the CLI prints the audit confirmation here. */
  onKill?: (confirmation: KillConfirmation) => void;
  /** Audit-trail reason sent with the kill. Default: `physical button <deviceId>`. */
  reason?: string;
  /** Bounce window; default 1000 ms. */
  debounceMs?: number;
  now?: () => number;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** One line per event, loud by default (console.error). */
  log?: (line: string) => void;
}

export interface ButtonDaemon {
  start(): void;
  stop(): void;
}

interface AttemptOutcome {
  ok: boolean;
  status: number;
  body?: unknown;
  detail: string;
}

export function createButtonDaemon(opts: ButtonDaemonOptions): ButtonDaemon {
  const now = opts.now ?? Date.now;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const log = opts.log ?? ((line: string) => console.error(line));
  const debounceMs = opts.debounceMs ?? DEFAULT_DEBOUNCE_MS;
  const reason = opts.reason ?? `physical button ${opts.deviceId}`;
  const killUrl = new URL("/kill", opts.controlPlaneUrl);

  let active = false;
  let unsubscribe: (() => void) | null = null;
  /** Bumped whenever a sequence is superseded; stale loops check and exit. */
  let generation = 0;
  let lastPressAt = Number.NEGATIVE_INFINITY;
  /** A sequence is running and the kill has not been acknowledged yet. */
  let unconfirmed = false;
  /** Failed attempts in the current sequence; >0 disables the debounce. */
  let failedInSequence = 0;
  let cancelWait: (() => void) | null = null;

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

  const handlePress = (): void => {
    if (!active) return;
    const at = now();
    const bounce = at - lastPressAt < debounceMs;
    lastPressAt = at;
    if (bounce && failedInSequence === 0) {
      log(`[button] press within ${debounceMs}ms of the last — treated as bounce, kill already in hand`);
      return;
    }
    if (failedInSequence > 0) {
      log("[button] press while the kill is UNCONFIRMED — re-firing now, backoff reset");
    }
    startSequence();
  };

  const startSequence = (): void => {
    generation += 1;
    failedInSequence = 0;
    unconfirmed = true;
    cancelWait?.(); // wake a loop stuck in backoff so it can see it was superseded
    void runSequence(generation);
  };

  async function runSequence(gen: number): Promise<void> {
    for (let attempt = 1; active && gen === generation; attempt += 1) {
      const outcome = await attemptKill(attempt);
      if (!active || gen !== generation) return; // superseded — the newer sequence owns the retries
      if (outcome.ok) {
        unconfirmed = false;
        failedInSequence = 0;
        log(`[button] ■ KILL CONFIRMED (${outcome.detail}, attempt ${attempt})`);
        opts.onKill?.({ attempts: attempt, status: outcome.status, body: outcome.body, at: now() });
        return;
      }
      failedInSequence += 1;
      const delayMs = attempt <= BACKOFF_MS.length ? BACKOFF_MS[attempt - 1] : STEADY_RETRY_MS;
      log(
        `[button] ✗ KILL NOT LANDED — attempt ${attempt} failed (${outcome.detail}); retrying in ${delayMs}ms, not giving up`,
      );
      await wait(delayMs);
    }
  }

  async function attemptKill(attempt: number): Promise<AttemptOutcome> {
    // Signed fresh every attempt: nonces are single-use on the server and the
    // timestamp must sit inside the clock-skew window, so a retry cannot
    // reuse the original press's signature.
    const timestamp = now();
    const nonce = randomBytes(16).toString("hex");
    const body = JSON.stringify({ source: "button", reason });
    const signature = signDeviceRequest(
      { deviceId: opts.deviceId, timestamp, nonce },
      body,
      opts.secret,
    );
    log(`[button] → POST ${killUrl} (attempt ${attempt}, device ${opts.deviceId})`);
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

  return {
    start(): void {
      if (active) return;
      active = true;
      unsubscribe = opts.onPress(handlePress);
    },
    stop(): void {
      if (!active) return;
      active = false;
      generation += 1;
      cancelWait?.();
      unsubscribe?.();
      unsubscribe = null;
      if (unconfirmed) {
        log("[button] ⚠ stopped while a kill was still UNCONFIRMED — the control plane may not be killed");
      }
    },
  };
}
