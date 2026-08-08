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
  canaryIds: ["ABCDEFGH2A3B"],
  how: 'decoy value about to be forwarded (tool "write_file", agent "a1")',
};
const ALERT_TRIP: Trip = {
  tier: "alert",
  canaryIds: ["ZZZZZZZZ2B3C"],
  how: "read of /srv/decoys/.env.backup (atime advanced)",
};

const okResponse = (body: unknown = { killed: true }) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

interface FetchCall {
  url: string;
  headers: Record<string, string>;
  body: string;
}

function harness(behavior: (call: number, url: string) => Response) {
  const calls: FetchCall[] = [];
  const logs: string[] = [];
  const delivered: Array<{ trip: Trip; confirmation: DeliveryConfirmation }> = [];

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body) });
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

const settle = () => vi.advanceTimersByTimeAsync(0);
const callsTo = (calls: FetchCall[], suffix: string) => calls.filter((c) => c.url.endsWith(suffix));

describe("trip reporter", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
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
    expect(h.calls[0].url).toBe("http://127.0.0.1:4999/kill");
    expect(JSON.parse(h.calls[0].body)).toEqual({ source: "honeytoken", reason: tripReason(KILL_TRIP) });
    expect(h.calls[0].headers["x-device-nonce"]).toMatch(/^[0-9a-f]{32}$/);
    expect(h.delivered).toEqual([
      { trip: KILL_TRIP, confirmation: { tier: "kill", attempts: 1, status: 200, body: { killed: true }, at: Date.now() } },
    ]);
  });

  it("an alert trip POSTs /alert instead — a file touch flags, it does not kill", async () => {
    const h = harness(() => okResponse({ alerted: true, killed: false }));
    h.reporter.report(ALERT_TRIP);
    await settle();
    expect(h.calls[0].url).toBe("http://127.0.0.1:4999/alert");
    expect(h.delivered[0].confirmation.tier).toBe("alert");
  });

  it("killReason aliases tripReason", () => {
    expect(killReason(KILL_TRIP)).toBe(tripReason(KILL_TRIP));
  });

  it("the signature verifies with verifyDeviceSignature over the exact bytes", async () => {
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
  });

  it("a failed POST retries on the 200/400/800/2000ms schedule and never gives up in the background", async () => {
    let succeedFrom = Number.POSITIVE_INFINITY;
    const h = harness((n) => {
      if (n >= succeedFrom) return okResponse();
      throw new Error("connect ECONNREFUSED");
    });
    h.reporter.report(KILL_TRIP);
    await settle();
    expect(h.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(h.calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(400);
    expect(h.calls).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(800);
    expect(h.calls).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(5);
    expect(h.reporter.pending()).toBe(1);

    succeedFrom = 6;
    await vi.advanceTimersByTimeAsync(2000);
    expect(h.calls).toHaveLength(6);
    expect(h.delivered).toMatchObject([{ confirmation: { attempts: 6 } }]);
    expect(h.reporter.pending()).toBe(0);
  });

  it("identical trips collapse while unconfirmed — a replaying agent cannot grow a lane", async () => {
    const h = harness(() => {
      throw new Error("down");
    });
    h.reporter.report(KILL_TRIP);
    await settle();
    h.reporter.report({ ...KILL_TRIP });
    h.reporter.report({ ...KILL_TRIP });
    expect(h.reporter.pending()).toBe(1);
    expect(h.logs.filter((l) => l.includes("duplicate kill trip already queued"))).toHaveLength(2);
  });

  describe("independent lanes — fix #4, an alert never blocks a kill", () => {
    it("a permanently-failing alert does not delay a kill queued after it", async () => {
      const h = harness((_n, url) => {
        if (url.endsWith("/alert")) throw new Error("alert endpoint wedged (404/500/hang)");
        return okResponse(); // /kill succeeds
      });

      h.reporter.report(ALERT_TRIP); // wedges at the head of the ALERT lane forever
      await settle();
      expect(h.reporter.pendingOn("alert")).toBe(1);

      h.reporter.report(KILL_TRIP); // must land despite the stuck alert
      await settle();

      expect(h.delivered.filter((d) => d.confirmation.tier === "kill")).toHaveLength(1);
      expect(h.reporter.pendingOn("kill")).toBe(0);
      expect(h.reporter.pendingOn("alert")).toBe(1); // alert still stuck, but harmless
      expect(callsTo(h.calls, "/kill")).toHaveLength(1);
    });
  });

  describe("flush() — fix #3 round, evidence is not lost on shutdown", () => {
    it("blocks until a pending trip is confirmed, then resolves delivered", async () => {
      let up = false;
      const h = harness((_n, url) => {
        if (!up && url.endsWith("/kill")) throw new Error("down");
        return okResponse();
      });
      h.reporter.report(KILL_TRIP);
      await settle();
      const flushing = h.reporter.flush();
      up = true;
      await vi.advanceTimersByTimeAsync(200);
      expect(await flushing).toEqual({ delivered: true, pending: 0 });
    });

    it("gives up loudly after a bounded number of attempts so exit is never blocked forever", async () => {
      const h = harness(() => {
        throw new Error("down");
      });
      h.reporter.report(KILL_TRIP);
      await settle();

      const flushing = h.reporter.flush({ maxAttempts: 3 });
      await vi.advanceTimersByTimeAsync(200);
      await vi.advanceTimersByTimeAsync(400);
      expect(await flushing).toEqual({ delivered: false, pending: 1 });
      expect(callsTo(h.calls, "/kill")).toHaveLength(3);
      expect(h.logs.some((l) => l.includes("giving up after 3"))).toBe(true);
    });

    it("flushes both lanes concurrently — a stuck alert does not stop the kill lane draining", async () => {
      const h = harness((_n, url) => {
        if (url.endsWith("/alert")) throw new Error("down");
        return okResponse();
      });
      h.reporter.report(ALERT_TRIP);
      h.reporter.report(KILL_TRIP);
      await settle();

      const flushing = h.reporter.flush({ maxAttempts: 2 });
      await vi.advanceTimersByTimeAsync(200);
      const result = await flushing;
      // the kill delivered; only the wedged alert remains
      expect(result).toEqual({ delivered: false, pending: 1 });
      expect(h.reporter.pendingOn("kill")).toBe(0);
      expect(h.reporter.pendingOn("alert")).toBe(1);
    });

    it("with nothing queued resolves immediately", async () => {
      const h = harness(() => okResponse());
      await expect(h.reporter.flush()).resolves.toEqual({ delivered: true, pending: 0 });
      expect(h.calls).toHaveLength(0);
    });
  });

  it("stop() cancels retries and warns about unconfirmed trips", async () => {
    const h = harness(() => {
      throw new Error("down");
    });
    h.reporter.report(KILL_TRIP);
    await settle();
    h.reporter.stop();
    expect(h.logs.some((l) => l.includes("UNCONFIRMED"))).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.calls).toHaveLength(1);

    h.reporter.report({ ...ALERT_TRIP, canaryIds: ["LATE12345678"] });
    expect(h.logs.some((l) => l.includes("NOT delivered"))).toBe(true);
  });
});
