import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createTripReporter,
  killReason,
  tripReason,
  type DeliveryConfirmation,
  type Trip,
} from "./report.js";

const KILL_CTX = { method: "POST", pathAndQuery: "/kill" };
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
  const inits: RequestInit[] = [];
  const logs: string[] = [];
  const delivered: Array<{ trip: Trip; confirmation: DeliveryConfirmation }> = [];

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, headers: { ...(init?.headers as Record<string, string>) }, body: String(init?.body) });
    inits.push(init ?? {});
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

  return { reporter, calls, inits, logs, delivered };
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
    expect(
      verifyDeviceSignature(credential, body, SECRET, KILL_CTX, { now: at, seenNonces: new Map() }),
    ).toBe(true);
    expect(
      verifyDeviceSignature(credential, body + " ", SECRET, KILL_CTX, { now: at, seenNonces: new Map() }),
    ).toBe(false);
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

  describe("attempt timeout — a hung request is bounded, not infinite", () => {
    /** A fetchImpl whose Promise never settles unless its AbortSignal fires. */
    function hangingFetchImpl(calls: Array<{ signal: AbortSignal | null | undefined }> = []) {
      return ((_url: URL | RequestInfo, init?: RequestInit) => {
        calls.push({ signal: init?.signal });
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("The operation was aborted");
            err.name = "AbortError";
            reject(err);
          });
        });
      }) as typeof fetch;
    }

    it("aborts after attemptTimeoutMs and counts as a failed attempt — a /kill still lands once the hang clears", async () => {
      const calls: Array<{ signal: AbortSignal | null | undefined }> = [];
      let mode: "hang" | "succeed" = "hang";
      const fetchImpl = ((url: URL | RequestInfo, init?: RequestInit) => {
        if (mode === "succeed") return Promise.resolve(okResponse());
        return hangingFetchImpl(calls)(url, init);
      }) as typeof fetch;
      const logs: string[] = [];
      const delivered: Array<{ trip: Trip; confirmation: DeliveryConfirmation }> = [];
      const reporter = createTripReporter({
        controlPlaneUrl: "http://127.0.0.1:4999",
        deviceId: "honeytoken-host",
        secret: SECRET,
        fetchImpl,
        attemptTimeoutMs: 1_000,
        log: (l) => logs.push(l),
        onDelivered: (trip, confirmation) => delivered.push({ trip, confirmation }),
      });

      reporter.report(KILL_TRIP);
      await settle();
      expect(calls).toHaveLength(1); // the request is in flight, and hanging
      expect(reporter.pending()).toBe(1);

      // cancelWait (the backoff canceller) has NO reach into this — only the
      // per-attempt AbortController timeout can move it past a genuine hang.
      await vi.advanceTimersByTimeAsync(999);
      expect(delivered).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(1);
      expect(logs.some((l) => l.includes("timed out after 1000ms"))).toBe(true);
      expect(reporter.pending()).toBe(1); // not lost — queued for the next attempt

      // the hang clears; the very next attempt (after the normal 200ms backoff) lands
      mode = "succeed";
      await vi.advanceTimersByTimeAsync(200);
      expect(delivered).toHaveLength(1);
      expect(delivered[0].confirmation.attempts).toBe(2);
      expect(reporter.pending()).toBe(0);
    });

    it("flush() completes in BOUNDED time even when every attempt hangs until aborted", async () => {
      const logs: string[] = [];
      const reporter = createTripReporter({
        controlPlaneUrl: "http://127.0.0.1:4999",
        deviceId: "honeytoken-host",
        secret: SECRET,
        fetchImpl: hangingFetchImpl(),
        attemptTimeoutMs: 500,
        log: (l) => logs.push(l),
      });

      reporter.report(KILL_TRIP);
      await settle();

      const flushing = reporter.flush({ maxAttempts: 3 });
      let settled = false;
      void flushing.then(() => (settled = true));

      // attempt 1: hangs 500ms then aborts; 200ms backoff; attempt 2: hangs
      // 500ms then aborts; 400ms backoff; attempt 3: hangs 500ms then aborts
      // and gives up (maxAttempts reached) — 2100ms total, not "forever".
      await vi.advanceTimersByTimeAsync(500);
      expect(settled).toBe(false); // still bounded work in progress, not resolved early
      await vi.advanceTimersByTimeAsync(200);
      await vi.advanceTimersByTimeAsync(500);
      await vi.advanceTimersByTimeAsync(400);
      await vi.advanceTimersByTimeAsync(500);

      const result = await flushing;
      expect(result).toEqual({ delivered: false, pending: 1 });
      expect(logs.filter((l) => l.includes("timed out after 500ms"))).toHaveLength(3);
      expect(logs.some((l) => l.includes("giving up after 3"))).toBe(true);
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

  it("override trips (source, agentId, reason) ride the same lanes with a SCOPED, attributed body", async () => {
    const h = harness(() => okResponse());
    const trip: Trip = {
      tier: "kill",
      canaryIds: [],
      how: "",
      source: "limit",
      agentId: "agent-7",
      reason: 'limit "spend" tripped for agent "agent-7": total 1200 exceeded max 1000',
    };
    h.reporter.report(trip);
    // duplicate collapses on the OVERRIDE reason, not the honeytoken phrasing
    h.reporter.report({ ...trip });
    await settle();
    const kills = callsTo(h.calls, "/kill");
    expect(kills).toHaveLength(1);
    const body = JSON.parse(kills[0].body) as Record<string, unknown>;
    expect(body).toEqual({
      source: "limit",
      agentId: "agent-7", // scoped: stops one agent, not the fleet
      reason: 'limit "spend" tripped for agent "agent-7": total 1200 exceeded max 1000',
    });
    // still device-signed over the exact bytes on the wire
    expect(
      verifyDeviceSignature(
        {
          deviceId: kills[0].headers["x-device-id"],
          timestamp: Number(kills[0].headers["x-device-timestamp"]),
          nonce: kills[0].headers["x-device-nonce"],
          signature: kills[0].headers["x-device-signature"],
        },
        kills[0].body,
        SECRET,
        KILL_CTX,
      ),
    ).toBe(true);
    expect(h.logs.some((l) => l.includes("[limit]"))).toBe(true);
  });

  it("confirmDelivery gates a 2xx: a non-conforming body is a FAILED attempt that retries", async () => {
    // first answer: 200 with a body no real scoped-kill confirmation has;
    // second answer: the genuine echo — only that one confirms
    const h = harness((n) =>
      n === 1
        ? okResponse({ killed: false }) // 200, but no killedAgent echo
        : okResponse({ killed: false, killedAgent: "agent-7" }),
    );
    const trip: Trip = {
      tier: "kill",
      canaryIds: [],
      how: "",
      source: "limit",
      agentId: "agent-7",
      reason: "limit tripped",
      confirmDelivery: (body) =>
        typeof body === "object" && body !== null &&
        (body as Record<string, unknown>).killedAgent === "agent-7",
    };
    h.reporter.report(trip);
    await settle();
    expect(h.delivered).toHaveLength(0); // the lying 200 did not confirm
    await vi.advanceTimersByTimeAsync(250); // first backoff elapses → retry
    expect(callsTo(h.calls, "/kill")).toHaveLength(2);
    expect(h.delivered).toHaveLength(1); // the real echo did
  });

  it("a per-report onDelivered fires for ITS report only, before the reporter-wide hook", async () => {
    // What the limit latch needs: the reporter-wide hook cannot tell two
    // kill reports apart, so the confirmation that advances ONE trip's
    // lifecycle has to travel with that trip.
    const h = harness(() => okResponse({ killed: false, killedAgent: "agent-7" }));
    const first: number[] = [];
    const second: number[] = [];
    const trip = (reason: string, seen: number[]): Trip => ({
      tier: "kill",
      canaryIds: [],
      how: "",
      source: "limit",
      agentId: "agent-7",
      reason,
      onDelivered: (confirmation) => seen.push(confirmation.status),
    });
    h.reporter.report(trip("budget A", first));
    h.reporter.report(trip("budget B", second));
    await settle();

    expect(first).toEqual([200]);
    expect(second).toEqual([200]);
    // the reporter-wide hook still sees both, and each per-report hook ran
    // before its own reporter-wide call
    expect(h.delivered).toHaveLength(2);
    expect(h.delivered.map((d) => d.trip.reason)).toEqual(["budget A", "budget B"]);
  });

  it("a degraded-persistence 200 keeps retrying instead of confirming a kill that may not survive", async () => {
    const h = harness((n) =>
      n === 1
        ? okResponse({ killed: false, killedAgent: "agent-7", persistenceDegraded: true })
        : okResponse({ killed: false, killedAgent: "agent-7" }),
    );
    const degradedAware: Trip = {
      tier: "kill",
      canaryIds: [],
      how: "",
      source: "limit",
      agentId: "agent-7",
      reason: "limit tripped",
      confirmDelivery: (body) => {
        const b = body as Record<string, unknown> | null;
        return (
          b !== null && b.persistenceDegraded === undefined && b.killedAgent === "agent-7"
        );
      },
    };
    h.reporter.report(degradedAware);
    await settle();
    expect(h.delivered).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(250);
    expect(h.delivered).toHaveLength(1); // retry re-killed and re-persisted cleanly
  });

  it("requests refuse redirects — some other origin's 200 must never read as the control plane's", async () => {
    const h = harness(() => okResponse());
    h.reporter.report(KILL_TRIP);
    await settle();
    expect(h.inits).toHaveLength(1);
    expect(h.inits[0].redirect).toBe("error"); // the actual request init
  });
});
