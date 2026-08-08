import { randomUUID } from "node:crypto";
import { chmodSync, chownSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOwnerSession, signDeviceRequest } from "./auth.js";
import {
  createControlPlane,
  MAX_CEREMONY_RECORDS,
  type ControlPlane,
  type ControlPlaneOptions,
} from "./server.js";
import { VetoWindow } from "./veto.js";

const clock = (start = 0) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

const DEVICE_SECRET = "button-secret";

/** Headers for a device-signed request over `body`, signed "now". */
const deviceHeaders = (body: string, at: number, nonce = `n-${at}-${Math.random().toString(36).slice(2)}`) => ({
  "content-type": "application/json",
  "x-device-id": "btn-1",
  "x-device-timestamp": String(at),
  "x-device-nonce": nonce,
  "x-device-signature": signDeviceRequest(
    { deviceId: "btn-1", timestamp: at, nonce },
    body,
    DEVICE_SECRET,
  ),
});

const bearer = (token: string) => ({
  "content-type": "application/json",
  authorization: `Bearer ${token}`,
});

/**
 * A control plane with persistence explicitly OFF (dev mode): each test gets
 * fresh kill state and leaves no file behind. The restart tests below are the
 * ones that exercise persistence, and they construct their own with a real
 * state file — in production mode, so the boot-time path guard runs too. The
 * one-line DEV MODE warning is silenced here so it doesn't drown test output;
 * a dedicated test asserts it fires.
 */
const ephemeral = (opts: Omit<ControlPlaneOptions, "killStateFile" | "dev"> = {}) => {
  const original = console.error;
  console.error = () => {};
  try {
    return createControlPlane({ ...opts, dev: true, killStateFile: null });
  } finally {
    console.error = original;
  }
};

/** A kill-state path inside a fresh private temp dir. */
const tempStateFile = () => join(mkdtempSync(join(tmpdir(), "ownerswitch-test-")), "kill-state.json");

describe("control-plane HTTP API", () => {
  let server: Server | undefined;

  const start = (cp: ControlPlane): Promise<string> => {
    server = createServer(cp.handler);
    return new Promise((resolve) => {
      server!.listen(0, "127.0.0.1", () => {
        const addr = server!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  };

  /** Like start(), but every request appears to come from `remoteAddress`. */
  const startAs = (cp: ControlPlane, remoteAddress: string): Promise<string> => {
    server = createServer((req, res) => {
      Object.defineProperty(req.socket, "remoteAddress", {
        value: remoteAddress,
        configurable: true,
      });
      cp.handler(req, res);
    });
    return new Promise((resolve) => {
      server!.listen(0, "127.0.0.1", () => {
        const addr = server!.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  };

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it("GET /status before and after kill", async () => {
    const c = clock(1_000);
    const url = await start(ephemeral({ now: c.now }));

    let res = await fetch(`${url}/status`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: false, epoch: 0 });

    await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "button", reason: "red button pressed" }),
    });

    res = await fetch(`${url}/status`);
    expect(await res.json()).toEqual({
      killed: true,
      reason: "red button pressed",
      at: 1_000,
      epoch: 1,
    });
  });

  it("GET /status exposes the epoch so a client can tell a stale approval from a current one", async () => {
    const cp = ephemeral({ now: clock().now });
    const url = await start(cp);

    expect((await (await fetch(`${url}/status`)).json()).epoch).toBe(0);

    await fetch(`${url}/kill`, { method: "POST" });
    expect((await (await fetch(`${url}/status`)).json()).epoch).toBe(1);

    // a second kill (still killed) bumps the epoch again — it counts every
    // engagement, not just "is currently killed"
    await fetch(`${url}/kill`, { method: "POST" });
    expect((await (await fetch(`${url}/status`)).json()).epoch).toBe(2);
    expect(cp.killSwitch.epoch).toBe(2);
  });

  it("POST /kill with an empty body still engages (default source 'api')", async () => {
    const cp = ephemeral({ now: clock().now });
    const url = await start(cp);

    const res = await fetch(`${url}/kill`, { method: "POST" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: true });

    expect(cp.killSwitch.killed).toBe(true);
    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type === "kill" && entry.event.source).toBe("api");
  });

  it("POST /kill with a valid device signature records the claimed source", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const body = JSON.stringify({ source: "button", reason: "red button pressed" });
    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(200);

    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type).toBe("kill");
    if (entry.type === "kill") {
      expect(entry.event.source).toBe("button");
      expect(entry.event.unauthenticated).toBeUndefined();
    }
  });

  it("loopback kill without credentials works, but is audited as unauthenticated 'api'", async () => {
    const cp = ephemeral({ now: clock().now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    // claims to be the button, but cannot prove it
    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "button", reason: "who knows" }),
    });
    expect(res.status).toBe(200);
    expect(cp.killSwitch.killed).toBe(true);

    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type).toBe("kill");
    if (entry.type === "kill") {
      expect(entry.event.source).toBe("api"); // unverified claim is not trusted
      expect(entry.event.unauthenticated).toBe(true);
      expect(entry.event.reason).toBe("who knows");
    }
  });

  it("loopback kill with an INVALID signature still kills — stopping never fails on bad auth", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const body = JSON.stringify({ source: "button" });
    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: { ...deviceHeaders(body, c.now()), "x-device-signature": "deadbeef" },
      body,
    });
    expect(res.status).toBe(200);
    expect(cp.killSwitch.killed).toBe(true);

    const [entry] = cp.killSwitch.auditLog();
    if (entry.type === "kill") {
      expect(entry.event.source).toBe("api");
      expect(entry.event.unauthenticated).toBe(true);
    }
  });

  it("non-loopback kill without credentials -> 401, generic body, not killed", async () => {
    const cp = ephemeral({ now: clock().now, deviceSecret: DEVICE_SECRET });
    const url = await startAs(cp, "203.0.113.7");

    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "button", reason: "not the button" }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("non-loopback kill WITH a valid device signature works", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await startAs(cp, "203.0.113.7");

    const body = JSON.stringify({ source: "button" });
    const headers = deviceHeaders(body, c.now());
    const res = await fetch(`${url}/kill`, { method: "POST", headers, body });
    expect(res.status).toBe(200);
    expect(cp.killSwitch.killed).toBe(true);

    // replaying the exact same signed request from outside loopback -> 401
    const replay = await fetch(`${url}/kill`, { method: "POST", headers, body });
    expect(replay.status).toBe(401);
  });

  it("non-loopback kill with an owner session works and honors the claimed source", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await startAs(cp, "203.0.113.7");
    const session = createOwnerSession("adam", { now: c.now });

    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ source: "app", reason: "owner tapped stop" }),
    });
    expect(res.status).toBe(200);
    expect(cp.killSwitch.killed).toBe(true);

    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type).toBe("kill");
    if (entry.type === "kill") {
      expect(entry.event.source).toBe("app");
      expect(entry.event.unauthenticated).toBeUndefined();
    }
  });

  it("POST /alert records a flagged event and does NOT kill (the DoS fix)", async () => {
    const c = clock(7_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const body = JSON.stringify({ source: "honeytoken", reason: "read of /decoys/.env.backup" });
    const res = await fetch(`${url}/alert`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ alerted: true, killed: false });

    // status stays not-killed — a decoy read alerts, it does not lock down
    expect(cp.killSwitch.killed).toBe(false);
    expect((await (await fetch(`${url}/status`)).json())).toEqual({ killed: false, epoch: 0 });

    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type).toBe("alert");
    if (entry.type === "alert") {
      expect(entry.event.source).toBe("honeytoken");
      expect(entry.event.reason).toBe("read of /decoys/.env.backup");
      expect(entry.event.unauthenticated).toBeUndefined();
    }
  });

  it("non-loopback /alert without credentials -> 401, nothing recorded", async () => {
    const cp = ephemeral({ now: clock().now, deviceSecret: DEVICE_SECRET });
    const url = await startAs(cp, "203.0.113.9");

    const res = await fetch(`${url}/alert`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "honeytoken", reason: "x" }),
    });
    expect(res.status).toBe(401);
    expect(cp.killSwitch.auditLog()).toHaveLength(0);
  });

  it("loopback /alert without credentials records an unauthenticated 'api' alert", async () => {
    const cp = ephemeral({ now: clock().now });
    const url = await start(cp);

    const res = await fetch(`${url}/alert`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: "honeytoken", reason: "loopback read" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ alerted: true, killed: false });

    const [entry] = cp.killSwitch.auditLog();
    expect(entry.type).toBe("alert");
    if (entry.type === "alert") {
      expect(entry.event.source).toBe("api"); // unverified source claim not trusted
      expect(entry.event.unauthenticated).toBe(true);
    }
  });

  it("the Bearer auth-scheme is case-insensitive (RFC 9110)", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, { now: c.now });
    cp.vetoWindows.set("v-1", window);
    const session = createOwnerSession("adam", { now: c.now });

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `bearer ${session.token}` },
    });
    expect(res.status).toBe(200);
    expect(window.vetoedBy).toBe("adam");
  });

  /** GO 1/2 over HTTP; returns the ceremony id the server minted. */
  const startCeremony = async (url: string, token: string): Promise<string> => {
    const res = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(token),
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  };

  /** GO 2/2 over HTTP. */
  const postRestore = (url: string, token: string, ceremonyId: string) =>
    fetch(`${url}/restore`, {
      method: "POST",
      headers: bearer(token),
      body: JSON.stringify({ ceremonyId }),
    });

  it("POST /restore/ceremony without a session -> 401 generic, even from loopback", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    const res = await fetch(`${url}/restore/ceremony`, { method: "POST" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("POST /restore/ceremony while not killed -> 409", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    const res = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/nothing to restore/);
  });

  it("GET /restore/ceremony/:id tracks go1 -> ready and counts the cooldown down", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("button");
    const id = await startCeremony(url, session.token);

    const read = async () =>
      (await (await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(session.token) })).json()) as {
        state: string;
        cooldownRemainingMs: number;
        expiresAt: number;
      };

    expect(await read()).toEqual({ state: "go1", cooldownRemainingMs: 30_000, expiresAt: 300_000 });
    c.advance(10_000);
    expect(await read()).toEqual({ state: "go1", cooldownRemainingMs: 20_000, expiresAt: 300_000 });
    c.advance(20_000);
    expect(await read()).toEqual({ state: "ready", cooldownRemainingMs: 0, expiresAt: 300_000 });
  });

  it("GET /restore/ceremony/:id needs a session; unknown and foreign ids read as absent", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const owner = createOwnerSession("adam", { now: c.now });
    const other = createOwnerSession("eve", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, owner.token);

    expect((await fetch(`${url}/restore/ceremony/${id}`)).status).toBe(401);
    const foreign = await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(other.token) });
    expect(foreign.status).toBe(404); // existence is not revealed across owners
    const unknown = await fetch(`${url}/restore/ceremony/cer_missing`, {
      headers: bearer(owner.token),
    });
    expect(unknown.status).toBe(404);
  });

  it("GO 2/2 before the cooldown -> 409 and still killed; after the cooldown -> restores", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("honeytoken", "decoy key touched");
    const id = await startCeremony(url, session.token);

    const early = await postRestore(url, session.token, id);
    expect(early.status).toBe(409);
    expect(await early.json()).toEqual({ error: "restore rejected" }); // generic — no timing details
    expect(cp.killSwitch.killed).toBe(true);

    c.advance(30_000); // past the cooldown
    const res = await postRestore(url, session.token, id);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: false });
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("the same ceremony twice -> second attempt rejected, system stays killed", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, session.token);
    c.advance(30_000);
    expect((await postRestore(url, session.token, id)).status).toBe(200);

    cp.killSwitch.engage("api"); // killed again — the spent ceremony must not restore twice
    const replay = await postRestore(url, session.token, id);
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual({ error: "restore rejected" });
    expect(cp.killSwitch.killed).toBe(true);

    // the spent ceremony reads as consumed on the status surface
    const status = await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(session.token) });
    expect(((await status.json()) as { state: string }).state).toBe("consumed");
  });

  it("a ceremony from a different owner -> 409, system stays killed", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const owner = createOwnerSession("adam", { now: c.now });
    const other = createOwnerSession("eve", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, owner.token);
    c.advance(30_000);

    const res = await postRestore(url, other.token, id);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(cp.killSwitch.killed).toBe(true);

    // the ceremony is intact — its owner can still spend it
    expect((await postRestore(url, owner.token, id)).status).toBe(200);
  });

  it("a valid-but-foreign id and a random nonexistent id reject with an identical response shape", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const owner = createOwnerSession("adam", { now: c.now });
    const other = createOwnerSession("eve", { now: c.now });

    cp.killSwitch.engage("api");
    const real = await startCeremony(url, owner.token); // live and adam's — just not eve's
    c.advance(30_000); // fully ready, so not even ceremony timing can show through

    const foreign = await postRestore(url, other.token, real);
    const missing = await postRestore(url, other.token, `cer_${randomUUID()}`);

    // "no such id", "wrong owner" and "expired" must share one response
    // SHAPE: same status, same content-type, byte-identical body. This pins
    // the shape only — timing and evaluation order are NOT normalised, so it
    // is not a constant-time guarantee.
    expect(foreign.status).toBe(409);
    expect(missing.status).toBe(409);
    const [foreignBody, missingBody] = [await foreign.text(), await missing.text()];
    expect(foreignBody).toBe(missingBody);
    expect(foreignBody).toBe(JSON.stringify({ error: "restore rejected" }));
    expect(foreign.headers.get("content-type")).toBe(missing.headers.get("content-type"));
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("a second kill invalidates a ceremony in flight (kill epoch)", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("button", "first kill");
    const id = await startCeremony(url, session.token);
    c.advance(30_000);
    cp.killSwitch.engage("honeytoken", "second kill mid-ceremony");

    const res = await postRestore(url, session.token, id);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(cp.killSwitch.killed).toBe(true);

    // the superseded ceremony reads as dead, and a fresh one under the new
    // epoch restores normally
    const status = await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(session.token) });
    expect(((await status.json()) as { state: string }).state).toBe("expired");
    const fresh = await startCeremony(url, session.token);
    c.advance(30_000);
    expect((await postRestore(url, session.token, fresh)).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("an expired ceremony -> 409, system stays killed", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, session.token);
    c.advance(5 * 60_000); // the whole TTL elapses

    const status = await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(session.token) });
    expect(((await status.json()) as { state: string }).state).toBe("expired");

    const res = await postRestore(url, session.token, id);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("two concurrent /restore calls with one ceremony -> exactly one succeeds", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, session.token);
    c.advance(30_000);

    const [a, b] = await Promise.all([
      postRestore(url, session.token, id),
      postRestore(url, session.token, id),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("POST /restore without a session -> 401 generic, even from loopback", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, session.token); // a genuinely ready ceremony...
    c.advance(30_000);

    const res = await fetch(`${url}/restore`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ceremonyId: id }), // ...does not help without a session
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" }); // no domain details leak
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("POST /restore with an expired session -> 401", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    const session = createOwnerSession("adam", { now: c.now });
    c.advance(16 * 60_000); // past the 15 min TTL

    const res = await postRestore(url, session.token, "cer_whatever");
    expect(res.status).toBe(401);
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("an authorization-shaped body without server-side ceremony state -> 409", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    // the exact shape the old code trusted — a valid-looking RestoreAuthorization
    const res = await fetch(`${url}/restore`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ ceremonyId: "cer-forged", ownerId: "adam", completedAt: c.now() }),
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(cp.killSwitch.killed).toBe(true);
  });

  it("a restart mid-ceremony fails closed: the kill survives, the ceremony does not", async () => {
    const c = clock();
    const stateFile = tempStateFile();
    const before = createControlPlane({ now: c.now, killStateFile: stateFile });
    const url = await start(before);
    const session = createOwnerSession("adam", { now: c.now });

    before.killSwitch.engage("button");
    const id = await startCeremony(url, session.token);
    c.advance(30_000); // ready — and then the process dies
    server?.close();
    server = undefined;

    // NOTHING re-engages here: the persisted state alone keeps the new
    // process killed. (An earlier version of this test called engage() on the
    // new process, which hid a restart that booted not-killed.)
    const after = createControlPlane({ now: c.now, killStateFile: stateFile });
    expect(after.killSwitch.killed).toBe(true);
    const url2 = await start(after);

    const res = await postRestore(url2, session.token, id);
    expect(res.status).toBe(409); // the ceremony did not survive — start over
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(after.killSwitch.killed).toBe(true);
  });

  it("a restart WITHOUT re-engaging comes back killed, with the same epoch and reason", async () => {
    const c = clock(1_000);
    const stateFile = tempStateFile();
    const before = createControlPlane({ now: c.now, killStateFile: stateFile });
    before.killSwitch.engage("button", "red button pressed");
    const epoch = before.killSwitch.epoch;

    // a brand-new process over the same state file — nobody calls engage()
    const after = createControlPlane({ now: c.now, killStateFile: stateFile });
    expect(after.killSwitch.killed).toBe(true);
    expect(after.killSwitch.epoch).toBe(epoch);

    // the attribution survives too: /status still answers what killed us, when
    const url = await start(after);
    expect(await (await fetch(`${url}/status`)).json()).toEqual({
      killed: true,
      reason: "red button pressed",
      at: 1_000,
      epoch,
    });
  });

  it("a corrupt kill-state file boots FAIL-CLOSED: killed, and loudly", async () => {
    const stateFile = tempStateFile();
    writeFileSync(stateFile, "{definitely not json", "utf8");
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const cp = createControlPlane({ now: clock().now, killStateFile: stateFile });
      expect(cp.killSwitch.killed).toBe(true);
      expect(errors).toHaveBeenCalled(); // the why is logged, not swallowed
      const [entry] = cp.killSwitch.auditLog();
      expect(entry.type).toBe("kill");
      if (entry.type === "kill") expect(entry.event.reason).toMatch(/failed closed/);
    } finally {
      errors.mockRestore();
    }
  });

  it("a restart after a legitimate 2GO restore comes back NOT killed", async () => {
    const c = clock();
    const stateFile = tempStateFile();
    const before = createControlPlane({ now: c.now, killStateFile: stateFile });
    const url = await start(before);
    const session = createOwnerSession("adam", { now: c.now });

    before.killSwitch.engage("button");
    const id = await startCeremony(url, session.token);
    c.advance(30_000);
    expect((await postRestore(url, session.token, id)).status).toBe(200);
    server?.close();
    server = undefined;

    const after = createControlPlane({ now: c.now, killStateFile: stateFile });
    expect(after.killSwitch.killed).toBe(false);
    expect(after.killSwitch.epoch).toBe(before.killSwitch.epoch); // the epoch survives the restore
    const url2 = await start(after);
    expect(await (await fetch(`${url2}/status`)).json()).toEqual({
      killed: false,
      epoch: after.killSwitch.epoch,
    });
  });

  it("deleting the state file of an initialised store boots FAIL-CLOSED, not fresh", async () => {
    const c = clock();
    const stateFile = tempStateFile();
    const before = createControlPlane({ now: c.now, killStateFile: stateFile });
    before.killSwitch.engage("button", "incident");

    rmSync(stateFile); // the file vanishes — deletion, tampering, wrong volume

    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const after = createControlPlane({ now: c.now, killStateFile: stateFile });
      expect(after.killSwitch.killed).toBe(true); // NOT a first boot: the marker says this store has history
      expect(errors).toHaveBeenCalled();
      const [entry] = after.killSwitch.auditLog();
      expect(entry.type === "kill" && entry.event.reason).toMatch(/missing/);
    } finally {
      errors.mockRestore();
    }
  });

  it("a never-initialised store is a genuine first boot: not killed", () => {
    const cp = createControlPlane({ now: clock().now, killStateFile: tempStateFile() });
    expect(cp.killSwitch.killed).toBe(false);
    expect(cp.killSwitch.epoch).toBe(0);
  });

  /** Expect createControlPlane to refuse to start, with the reason in the error. */
  const expectRefusal = (opts: ControlPlaneOptions, match: RegExp) => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(() => createControlPlane(opts)).toThrow(match);
      expect(errors).toHaveBeenCalled(); // the refusal is also logged, with the fix
    } finally {
      errors.mockRestore();
    }
  };

  it("production refuses to start without a killStateFile", () => {
    expectRefusal({ now: clock().now }, /no killStateFile configured/);
  });

  it("production refuses killStateFile: null — ephemeral is dev-only", () => {
    expectRefusal({ now: clock().now, killStateFile: null }, /ephemeral/);
  });

  it("production refuses a relative killStateFile", () => {
    expectRefusal({ now: clock().now, killStateFile: "state/kill.json" }, /relative path/);
  });

  it("production refuses a killStateFile inside the working directory", () => {
    expectRefusal(
      { now: clock().now, killStateFile: join(process.cwd(), "state", "kill.json") },
      /inside the working directory/,
    );
  });

  it("production refuses a state directory that does not exist, and says how to create it", () => {
    const missing = join(mkdtempSync(join(tmpdir(), "ownerswitch-test-")), "missing", "kill.json");
    expectRefusal({ now: clock().now, killStateFile: missing }, /cannot be inspected.*mkdir -p/s);
  });

  it("production refuses a group- or world-writable state directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-test-"));
    chmodSync(dir, 0o770); // group-writable
    expectRefusal({ now: clock().now, killStateFile: join(dir, "kill.json") }, /group- or world-writable/);
    chmodSync(dir, 0o777); // world-writable
    expectRefusal({ now: clock().now, killStateFile: join(dir, "kill.json") }, /group- or world-writable/);
  });

  it("production refuses a state directory owned by another user", () => {
    let path: string;
    if (process.getuid?.() === 0) {
      // running as root: hand the directory to another uid
      const dir = mkdtempSync(join(tmpdir(), "ownerswitch-test-"));
      chownSync(dir, 12345, 12345);
      path = join(dir, "kill.json");
    } else {
      // not root: "/" exists, is not writable by us, and is owned by root
      path = "/ownerswitch-kill-state.json";
    }
    expectRefusal({ now: clock().now, killStateFile: path }, /owned by uid/);
  });

  it("dev: true skips the path checks, with a loud one-line warning", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const cp = createControlPlane({ now: clock().now, dev: true, killStateFile: null });
      expect(cp.killSwitch.killed).toBe(false); // ephemeral dev plane boots armed
      expect(errors).toHaveBeenCalledWith(expect.stringContaining("DEV MODE"));
    } finally {
      errors.mockRestore();
    }
  });

  it("failed persistence is admitted on the wire: /kill and /status report degraded durability", async () => {
    const c = clock(500);
    // A DIRECTORY where the state file should be: loading fails closed
    // (not a regular file), every save fails (rename onto a directory), and
    // the quarantine fails too (a directory cannot be unlinked) — a
    // deterministic, real-filesystem persistence failure. dev: true because
    // the path guard would (rightly) refuse a state file inside the
    // world-writable os tmpdir.
    const stateDir = mkdtempSync(join(tmpdir(), "ownerswitch-test-"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const cp = createControlPlane({ now: c.now, killStateFile: stateDir, dev: true });
      expect(cp.killSwitch.killed).toBe(true); // fail-closed boot...
      expect(cp.killSwitch.persistenceDegraded).toBe(true); // ...whose own persist already failed
      expect(cp.killSwitch.quarantineFailed).toBe(true); // ...and whose stale state is stuck in place

      const url = await start(cp);
      const kill = await fetch(`${url}/kill`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reason: "manual stop" }),
      });
      // the kill is in force, but the response does not claim durability it lacks
      expect(await kill.json()).toEqual({
        killed: true,
        persistenceDegraded: true,
        unhealthy: expect.stringContaining("owner intervention"),
      });
      expect(await (await fetch(`${url}/status`)).json()).toEqual({
        killed: true,
        reason: "manual stop",
        at: 500,
        epoch: cp.killSwitch.epoch,
        persistenceDegraded: true,
        unhealthy: expect.stringContaining("owner intervention"),
      });
    } finally {
      errors.mockRestore();
    }
  });

  it("a failed quarantine keeps the plane out of service: restores are denied until the store is repaired", async () => {
    const c = clock();
    const stateFile = tempStateFile();
    const cp = createControlPlane({ now: c.now, killStateFile: stateFile }); // production mode, first boot
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    // sabotage the store before the first transition: a NON-EMPTY directory
    // at the state path makes save fail (rename) AND quarantine fail (unlink)
    mkdirSync(stateFile);
    writeFileSync(join(stateFile, "occupied"), "", "utf8");

    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await fetch(`${url}/kill`, { method: "POST" });
      expect(cp.killSwitch.killed).toBe(true); // the kill itself always lands
      expect(cp.killSwitch.quarantineFailed).toBe(true);

      // a full, patient 2GO ceremony still cannot restore while the stale
      // store is unquarantined — flipping the in-memory switch is the only
      // working stop left, so the plane keeps denying
      const id = await startCeremony(url, session.token);
      c.advance(30_000);
      const denied = await postRestore(url, session.token, id);
      expect(denied.status).toBe(409);
      expect(await denied.json()).toEqual({ error: "restore rejected" }); // same generic shape
      expect(cp.killSwitch.killed).toBe(true);

      // owner intervention: repair the store, then a successful persist (the
      // next kill) clears the condition and restore works again
      rmSync(stateFile, { recursive: true });
      await fetch(`${url}/kill`, { method: "POST" }); // persists cleanly -> healthy
      expect(cp.killSwitch.quarantineFailed).toBe(false);
      const fresh = await startCeremony(url, session.token);
      c.advance(30_000);
      expect((await postRestore(url, session.token, fresh)).status).toBe(200);
      expect(cp.killSwitch.killed).toBe(false);
    } finally {
      errors.mockRestore();
    }
  });

  /** GO 1/2 for `count` DISTINCT owners; returns their sessions and ceremony ids. */
  const fillCeremonies = async (url: string, now: () => number, count: number) => {
    const sessions = [];
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      const s = createOwnerSession(`owner-${i}`, { now });
      sessions.push(s);
      ids.push(await startCeremony(url, s.token));
    }
    return { sessions, ids };
  };

  it("GO 1/2 is idempotent: a repeat returns the SAME ceremony — same id, same expiry, cooldown NOT reset", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const firstRes = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(firstRes.status).toBe(201);
    const first = (await firstRes.json()) as { id: string; cooldownRemainingMs: number; expiresAt: number };
    expect(first.cooldownRemainingMs).toBe(30_000);

    c.advance(10_000); // a retry, a double-click, a second tab — 10 s later
    const repeatRes = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(repeatRes.status).toBe(200); // returned, not created
    const repeat = (await repeatRes.json()) as { id: string; cooldownRemainingMs: number; expiresAt: number };
    expect(repeat.id).toBe(first.id); // same ceremony...
    expect(repeat.expiresAt).toBe(first.expiresAt); // ...same expiry...
    expect(repeat.cooldownRemainingMs).toBe(20_000); // ...and the cooldown kept counting — NOT reset

    // the id the owner has been holding all along still spends
    c.advance(20_000); // 30 s since GO 1/2
    expect((await postRestore(url, session.token, first.id)).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("there is NO cancel verb: DELETE /restore/ceremony/:id is not a route, and the ceremony survives it", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const owner = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const id = await startCeremony(url, owner.token);

    // a cancel would hand the same bearer token a repeatable way to destroy
    // the owner's pending ceremony — the lockout idempotent GO 1/2 closed
    const attempt = await fetch(`${url}/restore/ceremony/${id}`, {
      method: "DELETE",
      headers: bearer(owner.token),
    });
    expect(attempt.status).toBe(404); // not a route

    // the pending ceremony is untouched and still spends
    c.advance(30_000);
    expect((await postRestore(url, owner.token, id)).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("a consumed ceremony plus a fresh kill cannot lock out restore", { timeout: 20_000 }, async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);
    const adam = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    await fillCeremonies(url, c.now, MAX_CEREMONY_RECORDS - 1); // other owners hold every slot but one
    const id = await startCeremony(url, adam.token); // adam takes the last one — the map is at its ceiling
    c.advance(30_000);
    expect((await postRestore(url, adam.token, id)).status).toBe(200); // an ordinary restore...
    cp.killSwitch.engage("honeytoken", "fresh incident"); // ...followed by a NEW kill

    // every record in the map is now dead (superseded epoch; adam's also
    // consumed) — and a new ceremony must still start, because dead records
    // are purged before any capacity decision
    const res = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(adam.token),
    });
    expect(res.status).toBe(201);
  });

  it("a map full of superseded-epoch ceremonies does not block one under the current epoch", { timeout: 20_000 }, async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api"); // epoch 1
    await fillCeremonies(url, c.now, MAX_CEREMONY_RECORDS); // ceiling reached, all bound to epoch 1
    cp.killSwitch.engage("api", "killed again"); // epoch 2 — every record above is now dead

    const adam = createOwnerSession("adam", { now: c.now });
    const id = await startCeremony(url, adam.token); // asserts 201: the corpses were purged first
    c.advance(30_000);
    expect((await postRestore(url, adam.token, id)).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("the record ceiling is a pure backstop: full of LIVE ceremonies -> 409, none evicted", { timeout: 20_000 }, async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    const { sessions, ids } = await fillCeremonies(url, c.now, MAX_CEREMONY_RECORDS);

    // every record is live and current-epoch, so nothing is purgeable: a NEW
    // owner is refused with the generic 409 and nothing else changes
    const overflow = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(createOwnerSession("one-too-many", { now: c.now }).token),
    });
    expect(overflow.status).toBe(409);
    expect(await overflow.json()).toEqual({ error: "ceremony rejected" });
    expect(cp.killSwitch.killed).toBe(true);

    // an owner already holding a slot is never refused at the ceiling: the
    // idempotent GO 1/2 hands back their own pending ceremony (200, same id)
    const repeat = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(sessions[5].token),
    });
    expect(repeat.status).toBe(200);
    expect(((await repeat.json()) as { id: string }).id).toBe(ids[5]);

    // and no other live ceremony was evicted: the very first is still spendable
    c.advance(30_000);
    expect((await postRestore(url, sessions[0].token, ids[0])).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("TTL-expired ceremonies are purged before the ceiling rejects: a map full of dead ones frees itself", { timeout: 20_000 }, async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    await fillCeremonies(url, c.now, MAX_CEREMONY_RECORDS);
    c.advance(5 * 60_000); // every ceremony's TTL elapses; owner sessions (15 min) live on

    // the purge runs before the ceiling check, so a fresh ceremony fits again
    const res = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(createOwnerSession("late-owner", { now: c.now }).token),
    });
    expect(res.status).toBe(201);
  });

  it("POST /veto/:id without a session -> 401, window untouched", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, { now: c.now });
    cp.vetoWindows.set("v-1", window);

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ by: "adam" }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(window.state).toBe("pending");

    // and an unknown id also gets 401, not 404 — existence is not revealed
    const unknown = await fetch(`${url}/veto/missing`, { method: "POST" });
    expect(unknown.status).toBe(401);
  });

  it("POST /veto/:id with a session vetoes; the session names the vetoer", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, { now: c.now });
    cp.vetoWindows.set("v-1", window);
    const session = createOwnerSession("adam", { now: c.now });

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ by: "someone-else" }), // ignored: the session says who
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "vetoed" });
    expect(window.vetoedBy).toBe("adam");

    const status = await fetch(`${url}/veto/v-1`);
    expect(await status.json()).toEqual({ status: "vetoed" });
  });

  it("POST /veto/:id on a released window -> 409 (authenticated)", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow(
      { agentId: "agent-1", tool: "bash" },
      { now: c.now, windowMs: 4 * 60_000 },
    );
    window.markDelivered();
    cp.vetoWindows.set("v-1", window);

    c.advance(4 * 60_000); // deadline passes with delivery confirmed -> released
    const status = await fetch(`${url}/veto/v-1`);
    expect(await status.json()).toEqual({ status: "released" });

    const session = createOwnerSession("adam", { now: c.now });
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ by: "adam" }),
    });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/released/);
  });

  it("POST /veto with a valid device signature registers a window the owner can veto", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const body = JSON.stringify({
      call: { agentId: "mcp-proxy", tool: "write_file", args: { path: "/tmp/x" } },
    });
    const res = await fetch(`${url}/veto`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(201);
    const { id, status } = (await res.json()) as { id: string; status: string };
    expect(id).toMatch(/^veto_/);
    expect(status).toBe("pending");

    const window = cp.vetoWindows.get(id);
    expect(window?.call).toEqual({
      agentId: "mcp-proxy",
      tool: "write_file",
      args: { path: "/tmp/x" },
    });

    // the registered window is live on the owner surface: readable and vetoable
    expect(await (await fetch(`${url}/veto/${id}`)).json()).toEqual({ status: "pending" });
    const session = createOwnerSession("adam", { now: c.now });
    const veto = await fetch(`${url}/veto/${id}`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(await veto.json()).toEqual({ status: "vetoed" });
    expect(window?.vetoedBy).toBe("adam");
  });

  it("POST /veto without a valid signature -> 401, even from loopback, nothing registered", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const body = JSON.stringify({ call: { agentId: "mcp-proxy", tool: "write_file" } });
    const bare = await fetch(`${url}/veto`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(bare.status).toBe(401);
    expect(await bare.json()).toEqual({ error: "unauthorized" });

    const forged = await fetch(`${url}/veto`, {
      method: "POST",
      headers: { ...deviceHeaders(body, c.now()), "x-device-signature": "deadbeef" },
      body,
    });
    expect(forged.status).toBe(401);
    expect(cp.vetoWindows.size).toBe(0);
  });

  it("POST /veto with no device secret configured -> 401 (registration has no open mode)", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now }); // deviceSecret absent
    const url = await start(cp);

    const body = JSON.stringify({ call: { agentId: "mcp-proxy", tool: "write_file" } });
    const res = await fetch(`${url}/veto`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(401);
    expect(cp.vetoWindows.size).toBe(0);
  });

  it("POST /veto with a malformed call -> 400", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    for (const bad of [{}, { call: "write_file" }, { call: { tool: "write_file" } }]) {
      const body = JSON.stringify(bad);
      const res = await fetch(`${url}/veto`, {
        method: "POST",
        headers: deviceHeaders(body, c.now()),
        body,
      });
      expect(res.status).toBe(400);
    }
    expect(cp.vetoWindows.size).toBe(0);
  });

  it("unknown route -> 404", async () => {
    const url = await start(ephemeral({ now: clock().now }));

    expect((await fetch(`${url}/nope`)).status).toBe(404);
    expect((await fetch(`${url}/status`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${url}/veto/missing`)).status).toBe(404);
  });

  it("malformed JSON -> 400, and the process survives", async () => {
    const cp = ephemeral({ now: clock().now });
    const url = await start(cp);

    const res = await fetch(`${url}/kill`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);

    // the server is still alive and well
    expect((await fetch(`${url}/status`)).status).toBe(200);
  });
});
