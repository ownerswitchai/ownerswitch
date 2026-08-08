import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createTripReporter,
  killReason,
  tripReason,
  type DeliveryConfirmation,
  type Trip,
} from "./report.js";

const SECRET = "honeytoken-test-secret";

const KILL_TRIP: Trip = {
  tier: "kill",
  canaryIds: ["ABCDEFGH2A"],
  how: 'decoy value appeared in tool-call arguments (tool "write_file", agent "a1")',
};

const ALERT_TRIP: Trip = {
  tier: "alert",
  canaryIds: ["ZZZZZZZZ2B"],
  how: "read of /srv/decoys/.env.backup (atime advanced)",
};

const okResponse = (body: unknown = { killed: true }) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

interface FetchCall {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: string;
}

/** Reporter wired to a scripted fetch — no network. */
function harness(behavior: (call: number, url: string) => Response) {
  const calls: FetchCall[] = [];
  const logs: string[] = [];
  const delivered: Array<{ trip: Trip; confirmation: DeliveryConfirmation }> = [];

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    const u = String(url);
    calls.push({
      url: u,
      method: init?.method,
      headers: { ...(init?.headers as Record<string, string>) },
      body: String(init?.body),
    });
    return behavior(calls.length, u);
  }) as typeof fetch;

  const reporter = createTripReporter({
    controlPlaneUrl: "http://127.0.0.1:4999",
    deviceId: "honeytoken-host",
    secret: SECRET,
    fetchImpl,
    log: (line) => logs.push(line),
    onDelivered: (trip, confirmation) => delivered.push({ trip, confirmation }),
  });

  return { reporter, calls, logs, delivered };
}

/** Let pending promise chains settle without moving the fake clock. */
const settle = () => vi.advanceTimersByTimeAsync(0);

describe("trip reporter", () => {
  beforeEach(() => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
    });
    vi.setSystemTime(new Date("2026-08-07T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('a kill trip POSTs /kill with source "honeytoken", naming the token and how it tripped', async () => {
    const h = harness(() => okResponse());

    h.reporter.report(KILL_TRIP);
    await settle();

    expect(h.calls).toHaveLength(1);
    const call = h.calls[0];
    expect(call.url).toBe("http://127.0.0.1:4999/kill");
    expect(call.method).toBe("POST");
    expect(JSON.parse(call.body)).toEqual({ source: "honeytoken", reason: tripReason(KILL_TRIP) });
    expect(call.headers["x-device-id"]).toBe("honeytoken-host");
    expect(call.headers["x-device-nonce"]).toMatch(/^[0-9a-f]{32}$/);
    expect(call.headers["x-device-signature"]).toMatch(/^[0-9a-f]{64}$/);

    expect(h.delivered).toEqual([
      {
        trip: KILL_TRIP,
        confirmation: { tier: "kill", attempts: 1, status: 200, body: { killed: true }, at: Date.now() },
      },
    ]);
    expect(h.reporter.pending()).toBe(0);
  });

  it("an alert trip POSTs /alert instead — a file touch flags, it does not kill", async () => {
    const h = harness(() => okResponse({ alerted: true, killed: false }));

    h.reporter.report(ALERT_TRIP);
    await settle();

    expect(h.calls).toHaveLength(1);
    expect(h.calls[0].url).toBe("http://127.0.0.1:4999/alert");
    expect(JSON.parse(h.calls[0].body)).toEqual({ source: "honeytoken", reason: tripReason(ALERT_TRIP) });
    expect(h.delivered[0].confirmation.tier).toBe("alert");
  });

  it("killReason is a back-compat alias of tripReason", () => {
    expect(killReason(KILL_TRIP)).toBe(tripReason(KILL_TRIP));
  });

  it("the signature it sends verifies with verifyDeviceSignature", async () => {
    const h = harness(() => okResponse());

    h.reporter.report(KILL_TRIP);
    await settle();

    const { headers, body } = h.calls[0];
    const credential = {
      deviceId: headers["x-device-id"],
      timestamp: Number(headers["x-device-timestamp"]),
      nonce: headers["x-device-nonce"],
      signature: headers["x-device-signature"],
    };
    const at = () => credential.timestamp;

    expect(verifyDeviceSignature(credential, body, SECRET, { now: at, seenNonces: new Map() })).toBe(true);
    expect(verifyDeviceSignature(credential, body + " ", SECRET, { now: at, seenNonces: new Map() })).toBe(false);
    expect(verifyDeviceSignature(credential, body, "wrong", { now: at, seenNonces: new Map() })).toBe(false);
  });

  it("a failed POST retries on the 200/400/800/2000ms schedule and never gives up in the background", async () => {
    let succeedFrom = Number.POSITIVE_INFINITY;
    const h = harness((n) => {
      if (n >= succeedFrom) return okResponse();
      throw new Error("connect ECONNREFUSED");
    });

    h.reporter.report(KILL_TRIP);
    await settle();
    expect(h.calls).toHaveLength(1); // t=0

    await vi.advanceTimersByTimeAsync(199);
    expect(h.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(h.calls).toHaveLength(2); // t=200
    await vi.advanceTimersByTimeAsync(400);
    expect(h.calls).toHaveLength(3); // t=600
    await vi.advanceTimersByTimeAsync(800);
    expect(h.calls).toHaveLength(4); // t=1400
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(5); // t=3400
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(6); // t=5400

    expect(h.logs.filter((line) => line.includes("NOT LANDED"))).toHaveLength(6);
    expect(h.delivered).toHaveLength(0);
    expect(h.reporter.pending()).toBe(1);

    const nonces = h.calls.map((c) => c.headers["x-device-nonce"]);
    expect(new Set(nonces).size).toBe(nonces.length);

    succeedFrom = 7;
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(7);
    expect(h.delivered).toMatchObject([{ confirmation: { attempts: 7, status: 200 } }]);
    expect(h.reporter.pending()).toBe(0);
  });

  it("a non-2xx answer counts as failure and retries too", async () => {
    let calls = 0;
    const h = harness(() => {
      calls += 1;
      return calls === 1 ? new Response("{}", { status: 500 }) : okResponse();
    });

    h.reporter.report(KILL_TRIP);
    await settle();
    expect(h.logs.some((line) => line.includes("HTTP 500"))).toBe(true);

    await vi.advanceTimersByTimeAsync(200);
    expect(h.delivered).toHaveLength(1);
  });

  it("distinct trips queue and each gets its own confirmed delivery, in order", async () => {
    const h = harness(() => okResponse());

    h.reporter.report(KILL_TRIP);
    h.reporter.report(ALERT_TRIP);
    expect(h.reporter.pending()).toBe(2);
    await settle();

    expect(h.calls.map((c) => c.url)).toEqual([
      "http://127.0.0.1:4999/kill",
      "http://127.0.0.1:4999/alert",
    ]);
    expect(h.delivered).toHaveLength(2);
    expect(h.reporter.pending()).toBe(0);
  });

  it("identical trips collapse while the first is unconfirmed — a replaying agent cannot grow the queue", async () => {
    const h = harness(() => {
      throw new Error("control plane down");
    });

    h.reporter.report(KILL_TRIP);
    await settle();
    h.reporter.report({ ...KILL_TRIP });
    h.reporter.report({ ...KILL_TRIP });

    expect(h.reporter.pending()).toBe(1);
    expect(h.logs.filter((line) => line.includes("duplicate trip already queued"))).toHaveLength(2);
  });

  describe("flush() — fix #3, evidence is not lost on shutdown", () => {
    it("blocks until a pending trip is confirmed, then resolves delivered", async () => {
      let up = false;
      const h = harness(() => {
        if (!up) throw new Error("control plane down");
        return okResponse();
      });

      h.reporter.report(KILL_TRIP);
      await settle();
      expect(h.reporter.pending()).toBe(1);

      // the control plane comes back while a flush is in progress
      const flushing = h.reporter.flush();
      up = true;
      await vi.advanceTimersByTimeAsync(200); // wake the pending backoff → retry lands
      const result = await flushing;

      expect(result).toEqual({ delivered: true, pending: 0 });
      expect(h.delivered).toHaveLength(1);
    });

    it("gives up loudly after a bounded number of attempts so exit is never blocked forever", async () => {
      const h = harness(() => {
        throw new Error("control plane down");
      });

      h.reporter.report(KILL_TRIP);
      await settle();

      const flushing = h.reporter.flush({ maxAttempts: 3 });
      // drive the bounded retries to completion: attempts at t0(already), +200, +400
      await vi.advanceTimersByTimeAsync(200);
      await vi.advanceTimersByTimeAsync(400);
      const result = await flushing;

      expect(result).toEqual({ delivered: false, pending: 1 });
      expect(h.calls).toHaveLength(3); // exactly maxAttempts, no more
      expect(h.logs.some((line) => line.includes("giving up after 3"))).toBe(true);
      expect(h.logs.some((line) => line.includes("still UNCONFIRMED"))).toBe(true);
    });

    it("with nothing queued resolves immediately as delivered", async () => {
      const h = harness(() => okResponse());
      await expect(h.reporter.flush()).resolves.toEqual({ delivered: true, pending: 0 });
      expect(h.calls).toHaveLength(0);
    });
  });

  it("stop() cancels retries and warns loudly about unconfirmed trips", async () => {
    const h = harness(() => {
      throw new Error("control plane down");
    });

    h.reporter.report(KILL_TRIP);
    await settle();
    expect(h.calls).toHaveLength(1);

    h.reporter.stop();
    expect(h.logs.some((line) => line.includes("UNCONFIRMED"))).toBe(true);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(1);

    h.reporter.report({ ...KILL_TRIP, canaryIds: ["LATE12345A"] });
    expect(h.logs.some((line) => line.includes("NOT delivered"))).toBe(true);
    await settle();
    expect(h.calls).toHaveLength(1);
  });
});
