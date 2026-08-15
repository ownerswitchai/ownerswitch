import { randomBytes } from "node:crypto";
import { signDeviceRequest } from "@ownerswitchai/control-plane";

/**
 * Fault reporting — the daemon-side half of dual-channel e-stop monitoring
 * (issue #40, hardware/pico). The firmware re-asserts "FAULT" every few
 * seconds while its NC/NO cross-check disagrees; this reporter collapses
 * that stream into EPISODES and reports each episode once, as a
 * device-signed `POST /alert` — the control plane's flagged-event surface
 * that records and surfaces without touching kill state.
 *
 * Doctrine, restated where it is enforced: a hardware fault is NOT a
 * press. It must reach the owner (a button whose wiring is broken might
 * not carry the next real press), but it must never forge a kill and
 * never mask one — the firmware's KILL rule runs independently, and this
 * reporter has no kill verb at all.
 *
 * Unlike a kill (retried forever), an alert retries a bounded number of
 * times: the firmware keeps re-asserting while the fault persists, so the
 * NEXT episode signal is the durable retry — and an unreachable control
 * plane is already being screamed about by every fail-closed client.
 */

const RETRY_BACKOFF_MS = [500, 1_000, 2_000] as const;
const DEFAULT_EPISODE_GAP_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 1_500;

export interface FaultReporterOptions {
  controlPlaneUrl: string;
  deviceId: string;
  /** Shared secret provisioned on the control plane (`deviceSecret`). */
  secret: string;
  /**
   * Silence longer than this ends the episode; the next fault signal is a
   * NEW episode and re-alerts. Must exceed the firmware's re-assert
   * cadence (5 s). Default 30 s.
   */
  episodeGapMs?: number;
  /** Audit reason; default names the device and the cross-check. */
  reason?: string;
  now?: () => number;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  log?: (line: string) => void;
}

export interface FaultReporter {
  /** Feed every received FAULT line here; episodes and posting are internal. */
  faultSignal(): void;
}

export function createFaultReporter(opts: FaultReporterOptions): FaultReporter {
  const now = opts.now ?? Date.now;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const log = opts.log ?? ((line: string) => console.error(line));
  const episodeGapMs = opts.episodeGapMs ?? DEFAULT_EPISODE_GAP_MS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const reason =
    opts.reason ??
    `e-stop hardware fault: NC/NO cross-check disagreement on button ${opts.deviceId} — ` +
      "wiring break or welded contact; the button needs service and may not carry the next press";
  const alertUrl = new URL("/alert", opts.controlPlaneUrl);

  let lastSignalAt = Number.NEGATIVE_INFINITY;
  let reporting = false;

  async function postAlert(): Promise<void> {
    for (let attempt = 1; attempt <= RETRY_BACKOFF_MS.length + 1; attempt += 1) {
      // Signed fresh every attempt: server nonces are single-use and the
      // timestamp must sit inside the skew window.
      const timestamp = now();
      const nonce = randomBytes(16).toString("hex");
      const body = JSON.stringify({ source: "button", reason });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(alertUrl, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-device-id": opts.deviceId,
            "x-device-timestamp": String(timestamp),
            "x-device-nonce": nonce,
            "x-device-signature": signDeviceRequest(
              { deviceId: opts.deviceId, timestamp, nonce },
              body,
              opts.secret,
              { method: "POST", pathAndQuery: alertUrl.pathname + alertUrl.search },
            ),
          },
          body,
          signal: controller.signal,
        });
        if (res.ok) {
          log(`[button] ⚠ HARDWARE FAULT reported to the control plane (attempt ${attempt})`);
          return;
        }
        log(`[button] fault alert attempt ${attempt} refused: HTTP ${res.status}`);
      } catch (err) {
        const detail = controller.signal.aborted
          ? `no response within ${timeoutMs}ms`
          : err instanceof Error
            ? err.message
            : String(err);
        log(`[button] fault alert attempt ${attempt} failed: ${detail}`);
      } finally {
        clearTimeout(timer);
      }
      if (attempt <= RETRY_BACKOFF_MS.length) {
        await new Promise((resolve) => setTimeout(resolve, RETRY_BACKOFF_MS[attempt - 1]));
      }
    }
    log(
      "[button] ⚠ HARDWARE FAULT could not be reported — giving up on this episode; " +
        "the firmware keeps re-asserting while the fault persists",
    );
  }

  return {
    faultSignal(): void {
      const at = now();
      const newEpisode = at - lastSignalAt > episodeGapMs;
      lastSignalAt = at;
      if (!newEpisode || reporting) return;
      reporting = true;
      log("[button] ⚠ HARDWARE FAULT: the e-stop's NC/NO channels agree — wiring break or welded contact");
      void postAlert().finally(() => {
        reporting = false;
      });
    },
  };
}
