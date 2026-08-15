import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createButtonDaemon, type KillConfirmation } from "./daemon.js";

const KILL_CTX = { method: "POST", pathAndQuery: "/kill" };
const SECRET = "button-test-secret";

const okResponse = () =>
  new Response(JSON.stringify({ killed: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

interface FetchCall {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: string;
}

/** Daemon wired to a manual press trigger and a scripted fetch — no network. */
function harness(behavior: (call: number) => Response) {
  const calls: FetchCall[] = [];
  const logs: string[] = [];
  const kills: KillConfirmation[] = [];
  let fire: (() => void) | null = null;
  let unsubscribed = false;

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method,
      headers: { ...(init?.headers as Record<string, string>) },
      body: String(init?.body),
    });
    return behavior(calls.length);
  }) as typeof fetch;

  const daemon = createButtonDaemon({
    controlPlaneUrl: "http://127.0.0.1:4999",
    deviceId: "btn-test",
    secret: SECRET,
    onPress: (listener) => {
      fire = listener;
      return () => {
        fire = null;
        unsubscribed = true;
      };
    },
    fetchImpl,
    log: (line) => logs.push(line),
    onKill: (confirmation) => kills.push(confirmation),
  });
  daemon.start();

  return {
    daemon,
    calls,
    logs,
    kills,
    press: () => {
      if (fire === null) throw new Error("daemon has no press listener");
      fire();
    },
    wasUnsubscribed: () => unsubscribed,
  };
}

/** Let pending promise chains settle without moving the fake clock. */
const settle = () => vi.advanceTimersByTimeAsync(0);

describe("button daemon", () => {
  beforeEach(() => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
    });
    vi.setSystemTime(new Date("2026-08-07T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('a press sends one signed POST /kill with source "button"', async () => {
    const h = harness(() => okResponse());

    h.press();
    await settle();

    expect(h.calls).toHaveLength(1);
    const call = h.calls[0];
    expect(call.url).toBe("http://127.0.0.1:4999/kill");
    expect(call.method).toBe("POST");
    expect(JSON.parse(call.body)).toEqual({ source: "button", reason: "physical button btn-test" });
    expect(call.headers["x-device-id"]).toBe("btn-test");
    expect(call.headers["x-device-timestamp"]).toBe(String(Date.now()));
    expect(call.headers["x-device-nonce"]).toMatch(/^[0-9a-f]{32}$/);
    expect(call.headers["x-device-signature"]).toMatch(/^[0-9a-f]{64}$/);

    expect(h.kills).toEqual([
      { attempts: 1, status: 200, body: { killed: true }, at: Date.now() },
    ]);
  });

  it("the signature it sends verifies with verifyDeviceSignature", async () => {
    const h = harness(() => okResponse());

    h.press();
    await settle();

    const { headers, body } = h.calls[0];
    const credential = {
      deviceId: headers["x-device-id"],
      timestamp: Number(headers["x-device-timestamp"]),
      nonce: headers["x-device-nonce"],
      signature: headers["x-device-signature"],
    };
    const at = () => credential.timestamp;

    expect(
      verifyDeviceSignature(credential, body, SECRET, KILL_CTX, { now: at, seenNonces: new Map() }),
    ).toBe(true);
    // …and only over the exact bytes it sent, with the exact secret:
    expect(
      verifyDeviceSignature(credential, body + " ", SECRET, KILL_CTX, { now: at, seenNonces: new Map() }),
    ).toBe(false);
    expect(
      verifyDeviceSignature(credential, body, "wrong-secret", KILL_CTX, { now: at, seenNonces: new Map() }),
    ).toBe(false);
  });

  it("a failed POST retries on the 200/400/800/2000ms schedule and never goes quiet", async () => {
    let succeedFrom = Number.POSITIVE_INFINITY;
    const h = harness((n) => {
      if (n >= succeedFrom) return okResponse();
      throw new Error("connect ECONNREFUSED");
    });

    h.press();
    await settle();
    expect(h.calls).toHaveLength(1); // t=0

    await vi.advanceTimersByTimeAsync(199);
    expect(h.calls).toHaveLength(1); // backoff not elapsed yet
    await vi.advanceTimersByTimeAsync(1);
    expect(h.calls).toHaveLength(2); // t=200
    await vi.advanceTimersByTimeAsync(400);
    expect(h.calls).toHaveLength(3); // t=600
    await vi.advanceTimersByTimeAsync(800);
    expect(h.calls).toHaveLength(4); // t=1400
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(5); // t=3400 — steady 2s cadence from here
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(6); // t=5400

    // every failure is logged loudly; nothing has been confirmed
    expect(h.logs.filter((line) => line.includes("KILL NOT LANDED"))).toHaveLength(6);
    expect(h.kills).toHaveLength(0);

    // every attempt is signed fresh — no nonce is ever reused
    const nonces = h.calls.map((c) => c.headers["x-device-nonce"]);
    expect(new Set(nonces).size).toBe(nonces.length);

    // the control plane comes back: the next retry lands and retries stop
    succeedFrom = 7;
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(7);
    expect(h.kills).toMatchObject([{ attempts: 7, status: 200 }]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(7);
  });

  it("presses within the 1s debounce window collapse into one kill", async () => {
    const h = harness(() => okResponse());

    h.press();
    await settle();
    await vi.advanceTimersByTimeAsync(100);
    h.press();
    await vi.advanceTimersByTimeAsync(300);
    h.press();
    await vi.advanceTimersByTimeAsync(300);
    h.press();
    await settle();

    expect(h.calls).toHaveLength(1);
    expect(h.kills).toHaveLength(1);
    expect(h.logs.filter((line) => line.includes("bounce"))).toHaveLength(3);

    // a press outside the window is a real press again (kill is idempotent)
    await vi.advanceTimersByTimeAsync(1000);
    h.press();
    await settle();
    expect(h.calls).toHaveLength(2);
    expect(h.kills).toHaveLength(2);
  });

  it("a press after a failed attempt re-fires immediately, debounce or not", async () => {
    let succeedFrom = Number.POSITIVE_INFINITY;
    const h = harness((n) => {
      if (n >= succeedFrom) return okResponse();
      throw new Error("control plane down");
    });

    h.press();
    await settle();
    expect(h.calls).toHaveLength(1); // attempt 1 failed; retry due at t=200

    // 50ms later — deep inside the debounce window AND before the backoff fires
    await vi.advanceTimersByTimeAsync(50);
    h.press();
    await settle();
    expect(h.calls).toHaveLength(2); // re-fired immediately

    // the backoff restarted from 200ms after the re-press…
    await vi.advanceTimersByTimeAsync(199);
    expect(h.calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.calls).toHaveLength(3);

    // …and the re-fired sequence keeps retrying until it lands
    succeedFrom = 4;
    await vi.advanceTimersByTimeAsync(400);
    expect(h.calls).toHaveLength(4);
    expect(h.kills).toMatchObject([{ attempts: 3 }]);
  });

  it("stop() unsubscribes, cancels retries, and warns about an unconfirmed kill", async () => {
    const h = harness(() => {
      throw new Error("control plane down");
    });

    h.press();
    await settle();
    expect(h.calls).toHaveLength(1);

    h.daemon.stop();
    expect(h.wasUnsubscribed()).toBe(true);
    expect(h.logs.some((line) => line.includes("UNCONFIRMED"))).toBe(true);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(1);
  });
});

describe("attemptKill timeout", () => {
  beforeEach(() => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
    });
    vi.setSystemTime(new Date("2026-08-07T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** A fetch that hangs forever unless the caller's AbortSignal fires. */
  function hangingFetch(calls: { signal: AbortSignal | undefined }[]) {
    return (async (_url: URL | RequestInfo, init?: RequestInit) => {
      calls.push({ signal: init?.signal ?? undefined });
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      });
    }) as typeof fetch;
  }

  it("a hung POST /kill aborts on the per-attempt timeout instead of stalling silently, and counts as an ordinary failed attempt", async () => {
    const calls: { signal: AbortSignal | undefined }[] = [];
    const logs: string[] = [];
    const kills: KillConfirmation[] = [];
    let fire: (() => void) | null = null;

    const daemon = createButtonDaemon({
      controlPlaneUrl: "http://127.0.0.1:4999",
      deviceId: "btn-test",
      secret: SECRET,
      timeoutMs: 1_000,
      onPress: (listener) => {
        fire = listener;
        return () => {
          fire = null;
        };
      },
      fetchImpl: hangingFetch(calls),
      log: (line) => logs.push(line),
      onKill: (confirmation) => kills.push(confirmation),
    });
    daemon.start();

    const press = (): void => {
      if (fire === null) throw new Error("no press listener registered");
      fire();
    };
    press();
    await settle();
    expect(calls).toHaveLength(1); // attempt 1 in flight, hung
    expect(calls[0].signal?.aborted).toBe(false);

    // not yet timed out — nothing has failed or landed
    await vi.advanceTimersByTimeAsync(999);
    expect(logs.filter((l) => l.includes("KILL NOT LANDED"))).toHaveLength(0);
    expect(kills).toHaveLength(0);

    // the 1000ms per-attempt timeout fires: the fetch aborts, which is
    // reported as an ordinary failed attempt — loud, not a silent stall
    await vi.advanceTimersByTimeAsync(1);
    expect(calls[0].signal?.aborted).toBe(true);
    expect(logs.filter((l) => l.includes("KILL NOT LANDED"))).toHaveLength(1);
    expect(logs.some((l) => l.includes("aborted"))).toBe(true);
    expect(kills).toHaveLength(0);
  });

  it("the retry schedule still holds after an abort — the next attempt fires on the normal backoff, not after another full timeout", async () => {
    const calls: { signal: AbortSignal | undefined }[] = [];
    let fire: (() => void) | null = null;

    const daemon = createButtonDaemon({
      controlPlaneUrl: "http://127.0.0.1:4999",
      deviceId: "btn-test",
      secret: SECRET,
      timeoutMs: 1_000,
      onPress: (listener) => {
        fire = listener;
        return () => {
          fire = null;
        };
      },
      fetchImpl: hangingFetch(calls),
      log: () => {},
    });
    daemon.start();

    const press = (): void => {
      if (fire === null) throw new Error("no press listener registered");
      fire();
    };
    press();
    await settle();
    expect(calls).toHaveLength(1);

    // attempt 1 times out at t=1000
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(1);

    // schedule after a failed attempt 1 is the normal 200ms backoff — not
    // another 1000ms wait for a second timeout
    await vi.advanceTimersByTimeAsync(199);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(2); // t=1200

    // attempt 2 also hangs and times out at t=2200; attempt 3 follows the
    // 400ms backoff from there, at t=2600 — the schedule never resets or
    // stalls because of the abort
    await vi.advanceTimersByTimeAsync(1_000);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(399);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(3); // t=2600
  });
});
