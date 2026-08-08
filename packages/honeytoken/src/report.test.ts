import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTripReporter, killReason, type KillConfirmation, type Trip } from "./report.js";

const SECRET = "honeytoken-test-secret";

const READ_TRIP: Trip = {
  canaryIds: ["ABCDEFGH2A"],
  how: "read of /srv/decoys/.env.backup (atime advanced)",
};

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

/** Reporter wired to a scripted fetch — no network. */
function harness(behavior: (call: number) => Response) {
  const calls: FetchCall[] = [];
  const logs: string[] = [];
  const kills: Array<{ trip: Trip; confirmation: KillConfirmation }> = [];

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method,
      headers: { ...(init?.headers as Record<string, string>) },
      body: String(init?.body),
    });
    return behavior(calls.length);
  }) as typeof fetch;

  const reporter = createTripReporter({
    controlPlaneUrl: "http://127.0.0.1:4999",
    deviceId: "honeytoken-host",
    secret: SECRET,
    fetchImpl,
    log: (line) => logs.push(line),
    onKill: (trip, confirmation) => kills.push({ trip, confirmation }),
  });

  return { reporter, calls, logs, kills };
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

  it('a trip POSTs a signed kill with source "honeytoken" naming the token and how it tripped', async () => {
    const h = harness(() => okResponse());

    h.reporter.report(READ_TRIP);
    await settle();

    expect(h.calls).toHaveLength(1);
    const call = h.calls[0];
    expect(call.url).toBe("http://127.0.0.1:4999/kill");
    expect(call.method).toBe("POST");
    expect(JSON.parse(call.body)).toEqual({
      source: "honeytoken",
      reason: "honeytoken ABCDEFGH2A tripped: read of /srv/decoys/.env.backup (atime advanced)",
    });
    expect(call.headers["x-device-id"]).toBe("honeytoken-host");
    expect(call.headers["x-device-timestamp"]).toBe(String(Date.now()));
    expect(call.headers["x-device-nonce"]).toMatch(/^[0-9a-f]{32}$/);
    expect(call.headers["x-device-signature"]).toMatch(/^[0-9a-f]{64}$/);

    expect(h.kills).toEqual([
      {
        trip: READ_TRIP,
        confirmation: { attempts: 1, status: 200, body: { killed: true }, at: Date.now() },
      },
    ]);
    expect(h.reporter.pending()).toBe(0);
  });

  it("the signature it sends verifies with verifyDeviceSignature", async () => {
    const h = harness(() => okResponse());

    h.reporter.report(READ_TRIP);
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
      verifyDeviceSignature(credential, body, SECRET, { now: at, seenNonces: new Map() }),
    ).toBe(true);
    // …and only over the exact bytes it sent, with the exact secret:
    expect(
      verifyDeviceSignature(credential, body + " ", SECRET, { now: at, seenNonces: new Map() }),
    ).toBe(false);
    expect(
      verifyDeviceSignature(credential, body, "wrong-secret", { now: at, seenNonces: new Map() }),
    ).toBe(false);
  });

  it("a failed POST retries on the 200/400/800/2000ms schedule and never gives up", async () => {
    let succeedFrom = Number.POSITIVE_INFINITY;
    const h = harness((n) => {
      if (n >= succeedFrom) return okResponse();
      throw new Error("connect ECONNREFUSED");
    });

    h.reporter.report(READ_TRIP);
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

    // every failure is logged loudly; the trip is still pending, never dropped
    expect(h.logs.filter((line) => line.includes("KILL NOT LANDED"))).toHaveLength(6);
    expect(h.kills).toHaveLength(0);
    expect(h.reporter.pending()).toBe(1);

    // every attempt is signed fresh — no nonce is ever reused
    const nonces = h.calls.map((c) => c.headers["x-device-nonce"]);
    expect(new Set(nonces).size).toBe(nonces.length);

    // the control plane comes back: the next retry lands and retries stop
    succeedFrom = 7;
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(7);
    expect(h.kills).toMatchObject([{ confirmation: { attempts: 7, status: 200 } }]);
    expect(h.reporter.pending()).toBe(0);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(7);
  });

  it("a non-2xx answer counts as failure and retries too", async () => {
    let calls = 0;
    const h = harness(() => {
      calls += 1;
      return calls === 1 ? new Response("{}", { status: 500 }) : okResponse();
    });

    h.reporter.report(READ_TRIP);
    await settle();
    expect(h.logs.some((line) => line.includes("HTTP 500"))).toBe(true);

    await vi.advanceTimersByTimeAsync(200);
    expect(h.kills).toHaveLength(1);
  });

  it("distinct trips queue and each gets its own confirmed kill, in order", async () => {
    const h = harness(() => okResponse());
    const second: Trip = { canaryIds: ["ZZZZZZZZ2B"], how: "write to /srv/decoys/credentials.json" };

    h.reporter.report(READ_TRIP);
    h.reporter.report(second);
    expect(h.reporter.pending()).toBe(2);
    await settle();

    expect(h.calls).toHaveLength(2);
    expect(h.calls.map((c) => (JSON.parse(c.body) as { reason: string }).reason)).toEqual([
      killReason(READ_TRIP),
      killReason(second),
    ]);
    expect(h.kills).toHaveLength(2);
    expect(h.reporter.pending()).toBe(0);
  });

  it("identical trips collapse while the first is unconfirmed — a replaying agent cannot grow the queue", async () => {
    const h = harness(() => {
      throw new Error("control plane down");
    });

    h.reporter.report(READ_TRIP);
    await settle();
    h.reporter.report({ ...READ_TRIP });
    h.reporter.report({ ...READ_TRIP });

    expect(h.reporter.pending()).toBe(1);
    expect(h.logs.filter((line) => line.includes("duplicate trip already queued"))).toHaveLength(2);
  });

  it("stop() cancels retries and warns loudly about unconfirmed trips", async () => {
    const h = harness(() => {
      throw new Error("control plane down");
    });

    h.reporter.report(READ_TRIP);
    await settle();
    expect(h.calls).toHaveLength(1);

    h.reporter.stop();
    expect(h.logs.some((line) => line.includes("UNCONFIRMED"))).toBe(true);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(1);

    // a trip after stop() is refused loudly, never silently swallowed
    h.reporter.report({ canaryIds: ["ABCDEFGH2A"], how: "late trip" });
    expect(h.logs.some((line) => line.includes("NOT delivered"))).toBe(true);
    await settle();
    expect(h.calls).toHaveLength(1);
  });
});
