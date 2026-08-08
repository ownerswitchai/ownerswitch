import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createOwnerSession, signDeviceRequest } from "./auth.js";
import { createControlPlane, MAX_LIVE_CEREMONIES, type ControlPlane } from "./server.js";
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
    const url = await start(createControlPlane({ now: c.now }));

    let res = await fetch(`${url}/status`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ killed: false });

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
    });
  });

  it("POST /kill with an empty body still engages (default source 'api')", async () => {
    const cp = createControlPlane({ now: clock().now });
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: clock().now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: clock().now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: c.now });
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

  it("the Bearer auth-scheme is case-insensitive (RFC 9110)", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);

    cp.killSwitch.engage("api");
    const res = await fetch(`${url}/restore/ceremony`, { method: "POST" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("POST /restore/ceremony while not killed -> 409", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("button");
    const id = await startCeremony(url, session.token);

    const read = async () =>
      (await (await fetch(`${url}/restore/ceremony/${id}`, { headers: bearer(session.token) })).json()) as {
        state: string;
        cooldownRemainingMs: number;
      };

    expect(await read()).toEqual({ state: "go1", cooldownRemainingMs: 30_000 });
    c.advance(10_000);
    expect(await read()).toEqual({ state: "go1", cooldownRemainingMs: 20_000 });
    c.advance(20_000);
    expect(await read()).toEqual({ state: "ready", cooldownRemainingMs: 0 });
  });

  it("GET /restore/ceremony/:id needs a session; unknown and foreign ids read as absent", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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

  it("a valid-but-foreign id and a random nonexistent id reject byte-identically", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);
    const owner = createOwnerSession("adam", { now: c.now });
    const other = createOwnerSession("eve", { now: c.now });

    cp.killSwitch.engage("api");
    const real = await startCeremony(url, owner.token); // live and adam's — just not eve's
    c.advance(30_000); // fully ready, so not even ceremony timing can show through

    const foreign = await postRestore(url, other.token, real);
    const missing = await postRestore(url, other.token, `cer_${randomUUID()}`);

    // "no such id", "wrong owner" and "expired" must be one indistinguishable
    // answer: same status, same headers, byte-identical body
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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

  it("a control-plane restart mid-ceremony fails closed: the ceremony does not survive", async () => {
    const c = clock();
    const before = createControlPlane({ now: c.now });
    const url = await start(before);
    const session = createOwnerSession("adam", { now: c.now });

    before.killSwitch.engage("button");
    const id = await startCeremony(url, session.token);
    c.advance(30_000); // ready — and then the process dies
    server?.close();

    const after = createControlPlane({ now: c.now }); // fresh process, fresh state
    const url2 = await start(after);
    after.killSwitch.engage("button"); // the kill is re-asserted on the new process

    const res = await postRestore(url2, session.token, id);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "restore rejected" });
    expect(after.killSwitch.killed).toBe(true);
  });

  it("the ceremonies map is capped: full -> generic 409, and no live ceremony is evicted", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    const ids: string[] = [];
    for (let i = 0; i < MAX_LIVE_CEREMONIES; i++) {
      ids.push(await startCeremony(url, session.token));
    }

    // full: minting fails closed with a generic 409 and changes nothing else
    const overflow = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(overflow.status).toBe(409);
    expect(await overflow.json()).toEqual({ error: "ceremony rejected" });
    expect(cp.killSwitch.killed).toBe(true);

    // no eviction to make room: the very first ceremony is still spendable
    c.advance(30_000);
    expect((await postRestore(url, session.token, ids[0])).status).toBe(200);
    expect(cp.killSwitch.killed).toBe(false);
  });

  it("expired ceremonies are swept before the cap rejects: a map full of dead ones frees itself", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
    const url = await start(cp);
    const session = createOwnerSession("adam", { now: c.now });

    cp.killSwitch.engage("api");
    for (let i = 0; i < MAX_LIVE_CEREMONIES; i++) {
      await startCeremony(url, session.token);
    }
    c.advance(5 * 60_000); // every ceremony's TTL elapses; the owner session (15 min) lives on

    // the sweep runs before the cap check, so a fresh ceremony fits again
    const res = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
    });
    expect(res.status).toBe(201);
  });

  it("POST /veto/:id without a session -> 401, window untouched", async () => {
    const c = clock();
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now });
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const cp = createControlPlane({ now: c.now }); // deviceSecret absent
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
    const cp = createControlPlane({ now: c.now, deviceSecret: DEVICE_SECRET });
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
    const url = await start(createControlPlane({ now: clock().now }));

    expect((await fetch(`${url}/nope`)).status).toBe(404);
    expect((await fetch(`${url}/status`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${url}/veto/missing`)).status).toBe(404);
  });

  it("malformed JSON -> 400, and the process survives", async () => {
    const cp = createControlPlane({ now: clock().now });
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
