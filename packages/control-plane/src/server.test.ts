import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomUUID,
  sign as ecSign,
} from "node:crypto";
import { chmodSync, chownSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJson, ownerDeviceSigPreimage, verifyMergeGrant } from "@ownerswitchai/shared";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOwnerSession, signDeviceRequest } from "./auth.js";
import { generateLicenseKeys, mintLicense } from "./license.js";
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

// The owner app's asymmetric device key: a non-extractable P-256 key on the
// phone in production; here a test keypair whose SPKI is enrolled and whose
// private half signs the delivery ack (owner-device.ts).
const ownerKeypair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const OWNER_DEVICE_SPKI = ownerKeypair.publicKey.export({ format: "pem", type: "spki" }).toString();
const OWNER_DEVICE_KEYS: Record<string, string> = { "owner-app": OWNER_DEVICE_SPKI };

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

/**
 * Headers signed with the OWNER APP's asymmetric device key — the delivery-ack
 * credential (ECDSA P-256, r||s, over the method+path+body preimage). The
 * signed path must be the exact request target, so the caller passes it.
 */
const ownerAppHeaders = (
  method: string,
  pathAndQuery: string,
  body: string,
  at: number,
  nonce = `oa-${at}-${Math.random().toString(36).slice(2)}`,
) => {
  const preimage = ownerDeviceSigPreimage({
    deviceId: "owner-app",
    method,
    pathAndQuery,
    bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
    timestamp: at,
    nonce,
  });
  const signature = ecSign("sha256", preimage, {
    key: ownerKeypair.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  return {
    "content-type": "application/json",
    "x-device-id": "owner-app",
    "x-device-timestamp": String(at),
    "x-device-nonce": nonce,
    "x-device-signature": signature,
  };
};

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
    // dev instances here approve session-only by design; acknowledge it so
    // the startup guard (which the WebAuthn suite exercises) stays out of
    // the way of the non-passkey tests
    return createControlPlane({
      acceptSessionOnlyApprovalRisk: true,
      ...opts,
      dev: true,
      killStateFile: null,
    });
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

  it("GET /status is served uncacheable — a stale killed:false must be impossible to replay", async () => {
    const url = await start(ephemeral({ now: clock().now }));
    const res = await fetch(`${url}/status`);
    expect(res.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(res.headers.get("pragma")).toBe("no-cache");
    // the veto status surface carries the same live-state weight: a cached
    // "released" would resurrect a spent release across a kill
    const veto = await fetch(`${url}/veto/nope`);
    expect(veto.headers.get("cache-control")).toBe("no-store, max-age=0");
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

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, 0, { now: c.now });
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

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, 0, { now: c.now });
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

    const window = new VetoWindow({ agentId: "agent-1", tool: "stripe.payout" }, 0, { now: c.now });
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
      0,
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

  it("a released window from a previous kill epoch reports spent — a veto release does not survive a kill", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow(
      { agentId: "agent-1", tool: "github.merge_pr" },
      cp.killSwitch.epoch,
      { now: c.now, windowMs: 1000 },
    );
    window.markDelivered();
    cp.vetoWindows.set("v-1", window);
    c.advance(1001); // silence with confirmed delivery: the window would release

    // a kill lands after registration, and the owner completes a restore
    // before the retry — killed is false again, but the epoch moved, and a
    // pre-kill release must not authorize a post-kill run
    cp.killSwitch.engage("button", "incident mid-window");
    cp.killSwitch.restore({ ceremonyId: "cer-spent", ownerId: "adam", completedAt: c.now() });

    expect(await (await fetch(`${url}/veto/v-1`)).json()).toEqual({ status: "spent" });
    // and it stays spent — the epoch never goes back
    expect(await (await fetch(`${url}/veto/v-1`)).json()).toEqual({ status: "spent" });
  });

  it("no endpoint reports 'released' for an epoch-dead window — the binding has no bypass", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow({ agentId: "agent-1", tool: "github.merge_pr" }, cp.killSwitch.epoch, {
      now: c.now,
      windowMs: 1000,
    });
    window.markDelivered();
    cp.vetoWindows.set("v-1", window);
    c.advance(1001);
    cp.killSwitch.engage("api", "incident");
    cp.killSwitch.restore({ ceremonyId: "cer-nobypass", ownerId: "adam", completedAt: c.now() });

    // GET /veto/:id — the ONLY status surface the gateway reads — says spent
    expect(await (await fetch(`${url}/veto/v-1`)).json()).toEqual({ status: "spent" });

    // POST /veto/:id (the owner surface) cannot be used to read a release
    // out of it either: the window is internally past pending/extended, so
    // the veto attempt 409s — an error, not an authorization
    const session = createOwnerSession("adam", { now: c.now });
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(409);
    const body = (await res.json()) as { status?: string };
    expect(body.status).toBeUndefined(); // no status field at all on the error path
  });

  it("a vetoed window stays vetoed across a kill — 'no' survives everything", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now });
    const url = await start(cp);

    const window = new VetoWindow({ agentId: "agent-1", tool: "bash" }, cp.killSwitch.epoch, {
      now: c.now,
    });
    window.veto("adam");
    cp.vetoWindows.set("v-1", window);

    cp.killSwitch.engage("api");
    cp.killSwitch.restore({ ceremonyId: "cer-veto-holds", ownerId: "adam", completedAt: c.now() });

    expect(await (await fetch(`${url}/veto/v-1`)).json()).toEqual({ status: "vetoed" });
  });

  it("POST /veto binds the window to the kill epoch in force at registration", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);
    // two kill/restore cycles before registration: the record must bind to
    // the CURRENT epoch, not to zero
    cp.killSwitch.engage("api");
    cp.killSwitch.restore({ ceremonyId: "cer-b1", ownerId: "adam", completedAt: c.now() });
    cp.killSwitch.engage("api");
    cp.killSwitch.restore({ ceremonyId: "cer-b2", ownerId: "adam", completedAt: c.now() });

    const body = JSON.stringify({ call: { agentId: "mcp-proxy", tool: "write_file" } });
    const res = await fetch(`${url}/veto`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(201);
    const { id } = (await res.json()) as { id: string };
    expect(cp.vetoWindows.get(id)?.killEpoch).toBe(2);
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

  it("POST /veto records the declared PURPOSE and signs it into the grant on active approval", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, grantKey: "grant-key-cp-and-broker-padded-256bit" });
    const url = await start(cp);

    const mergeArgs = {
      owner: "o",
      repo: "r",
      pullNumber: 7,
      expectedHeadSha: "a".repeat(40),
      expectedBaseRef: "main",
    };
    const body = JSON.stringify({
      call: { agentId: "mcp-proxy", tool: "github.merge_pr", args: mergeArgs },
      purpose: { connector: "github", operation: "merge_pull_request", policyVersion: "sha256:pv" },
    });
    const res = await fetch(`${url}/veto`, { method: "POST", headers: deviceHeaders(body, c.now()), body });
    expect(res.status).toBe(201);
    const { id } = (await res.json()) as { id: string };
    expect(cp.vetoWindows.get(id)?.purpose).toEqual({
      connector: "github",
      operation: "merge_pull_request",
      policyVersion: "sha256:pv",
    });

    // the owner actively approves (owner session) — the only path to a grant
    const session = createOwnerSession("adam", { now: c.now });
    await fetch(`${url}/veto/${id}`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "approve" }),
    });
    const released = (await (await fetch(`${url}/veto/${id}`)).json()) as {
      status: string;
      grant?: { connector: string; operation: string; policyVersion: string };
    };
    expect(released.status).toBe("released");
    expect(released.grant).toMatchObject({
      connector: "github",
      operation: "merge_pull_request",
      policyVersion: "sha256:pv",
    });
  });

  it("POST /veto refuses a malformed purpose, and a merge purpose whose args fail the closed schema", async () => {
    const c = clock(100_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const send = async (payload: unknown): Promise<Response> => {
      const body = JSON.stringify(payload);
      return fetch(`${url}/veto`, { method: "POST", headers: deviceHeaders(body, c.now()), body });
    };
    const call = { agentId: "a", tool: "t", args: { owner: "o", repo: "r", pullNumber: 7 } };

    // closed purpose schema: unknown field, missing/empty operation
    for (const purpose of [
      { connector: "github", operation: "merge_pull_request", extra: 1 },
      { connector: "github" },
      { connector: "github", operation: "" },
    ]) {
      const res = await send({ call, purpose });
      expect(res.status).toBe(400);
    }
    // a merge-purpose window whose args are NOT exactly one merge
    // (expectedHeadSha missing) must never be put in front of the owner
    const res = await send({
      call, // no expectedHeadSha in args
      purpose: { connector: "github", operation: "merge_pull_request" },
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toMatch(/closed merge schema/);
    expect(cp.vetoWindows.size).toBe(0);
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

  it("GET /kill-state returns a nonce-bound signed envelope (and 501 without a key)", async () => {
    const c = clock(100_000);
    const KILL_KEY = "kill-state-key-cp-and-broker-256bit";
    const withKey = ephemeral({ now: c.now, killStateKey: KILL_KEY });
    const url = await start(withKey);

    const nonce = "nonce-abc123";
    const body = (await (await fetch(`${url}/kill-state?nonce=${nonce}`)).json()) as {
      killed: boolean;
      epoch: number;
      nonce: string;
      expiresAt: number;
      sig: string;
    };
    expect(body.killed).toBe(false);
    expect(body.nonce).toBe(nonce);
    expect(body.expiresAt).toBe(c.now() + 5_000);
    // the signature verifies over exactly {killed, epoch, nonce, expiresAt}
    const expected = createHmac("sha256", KILL_KEY)
      .update(
        canonicalJson({ killed: body.killed, epoch: body.epoch, nonce, expiresAt: body.expiresAt }),
      )
      .digest("hex");
    expect(body.sig).toBe(expected);
    // no nonce → 400
    expect((await fetch(`${url}/kill-state`)).status).toBe(400);

    server?.close();
    // without a kill-state key configured → 501
    const noKey = ephemeral({ now: c.now });
    const url2 = await start(noKey);
    expect((await fetch(`${url2}/kill-state?nonce=x`)).status).toBe(501);
  });

  it("VETO REVOKES an issued grant: the signed grant-liveness probe flips to false", async () => {
    const c = clock(100_000);
    const KILL_KEY = "kill-state-key-cp-and-broker-256bit";
    const GRANT_KEY2 = "grant-key-cp-and-broker-padded-256bit";
    const cp = ephemeral({ now: c.now, killStateKey: KILL_KEY, grantKey: GRANT_KEY2 });
    const url = await start(cp);

    // an approved merge window whose grant is fetched (the broker's evidence)
    const window = new VetoWindow(
      {
        agentId: "a1",
        tool: "github.merge_pr",
        args: {
          owner: "o",
          repo: "r",
          pullNumber: 7,
          expectedHeadSha: "a".repeat(40),
          expectedBaseRef: "main",
        },
      },
      0,
      {
        now: c.now,
        purpose: { connector: "github", operation: "merge_pull_request", policyVersion: "" },
      },
    );
    window.markDelivered();
    window.approve("owner-1", 0);
    cp.vetoWindows.set("v-live", window);
    const released = (await (await fetch(`${url}/veto/v-live`)).json()) as {
      grant?: { jti: string };
    };
    const jti = released.grant!.jti;

    const probe = async (): Promise<{ jti?: string; grantLive?: boolean; sig: string; killed: boolean; epoch: number; nonce: string; expiresAt: number }> =>
      (await (await fetch(`${url}/kill-state?nonce=n1&jti=${encodeURIComponent(jti)}`)).json()) as never;

    // before the veto: the plane vouches, and the answer is SIGNED over the probe fields
    const live = await probe();
    expect(live.grantLive).toBe(true);
    expect(live.jti).toBe(jti);
    const expectedSig = createHmac("sha256", KILL_KEY)
      .update(
        canonicalJson({
          killed: live.killed,
          epoch: live.epoch,
          nonce: live.nonce,
          expiresAt: live.expiresAt,
          jti: live.jti,
          grantLive: live.grantLive,
        }),
      )
      .digest("hex");
    expect(live.sig).toBe(expectedSig);

    // the owner vetoes AFTER issuance — allowed for a purposed window, and
    // it revokes the outstanding grant
    const session = createOwnerSession("adam", { now: c.now });
    const veto = await fetch(`${url}/veto/v-live`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "veto" }),
    });
    expect(veto.status).toBe(200);
    expect((await probe()).grantLive).toBe(false);

    // an unknown jti (or a restarted plane) is never vouched for
    const unknown = (await (
      await fetch(`${url}/kill-state?nonce=n2&jti=grant_never_minted`)
    ).json()) as { grantLive?: boolean };
    expect(unknown.grantLive).toBe(false);
  });

  it("ATOMIC COMMIT: a committed grant blocks a later veto (in-flight), and a vetoed grant blocks commit", async () => {
    const c = clock(100_000);
    const KILL_KEY = "kill-state-key-cp-and-broker-256bit";
    const GRANT_KEY2 = "grant-key-cp-and-broker-padded-256bit";

    // helper: build a signed broker commit request for a jti
    const commit = async (base: string, jti: string, nonce: string) => {
      const ts = c.now();
      const sig = createHmac("sha256", KILL_KEY)
        .update(canonicalJson({ jti, nonce, ts }))
        .digest("hex");
      return (await (
        await fetch(`${base}/kill-state/commit`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jti, nonce, ts, sig }),
        })
      ).json()) as { committed?: boolean };
    };

    const makeGrant = async (base: string, cp: ControlPlane, id: string): Promise<string> => {
      const window = new VetoWindow(
        {
          agentId: "a1",
          tool: "github.merge_pr",
          args: { owner: "o", repo: "r", pullNumber: 7, expectedHeadSha: "a".repeat(40), expectedBaseRef: "main" },
        },
        0,
        { now: c.now, purpose: { connector: "github", operation: "merge_pull_request", policyVersion: "" } },
      );
      window.markDelivered();
      window.approve("owner-1", 0);
      cp.vetoWindows.set(id, window);
      const released = (await (await fetch(`${base}/veto/${id}`)).json()) as { grant?: { jti: string } };
      return released.grant!.jti;
    };

    // Case A: COMMIT wins → a later veto is 409 in-flight
    {
      const cp = ephemeral({ now: c.now, killStateKey: KILL_KEY, grantKey: GRANT_KEY2 });
      const url = await start(cp);
      const jti = await makeGrant(url, cp, "v-a");
      expect((await commit(url, jti, "cn1")).committed).toBe(true);
      const session = createOwnerSession("adam", { now: c.now });
      const late = await fetch(`${url}/veto/v-a`, {
        method: "POST",
        headers: bearer(session.token),
        body: JSON.stringify({ decision: "veto" }),
      });
      expect(late.status).toBe(409);
      expect(((await late.json()) as { error: string }).error).toMatch(/in flight/);
      server?.close();
    }

    // Case B: VETO wins → the commit that follows returns committed:false
    {
      const cp = ephemeral({ now: c.now, killStateKey: KILL_KEY, grantKey: GRANT_KEY2 });
      const url = await start(cp);
      const jti = await makeGrant(url, cp, "v-b");
      const session = createOwnerSession("adam", { now: c.now });
      const veto = await fetch(`${url}/veto/v-b`, {
        method: "POST",
        headers: bearer(session.token),
        body: JSON.stringify({ decision: "veto" }),
      });
      expect(veto.status).toBe(200);
      expect((await commit(url, jti, "cn2")).committed).toBe(false);
    }
  });

  it("the commit endpoint refuses an UNSIGNED (agent-forged) request — only the broker may commit", async () => {
    const c = clock(100_000);
    const KILL_KEY = "kill-state-key-cp-and-broker-256bit";
    const GRANT_KEY2 = "grant-key-cp-and-broker-padded-256bit";
    const cp = ephemeral({ now: c.now, killStateKey: KILL_KEY, grantKey: GRANT_KEY2 });
    const url = await start(cp);
    const window = new VetoWindow(
      {
        agentId: "a1",
        tool: "github.merge_pr",
        args: { owner: "o", repo: "r", pullNumber: 7, expectedHeadSha: "a".repeat(40), expectedBaseRef: "main" },
      },
      0,
      { now: c.now, purpose: { connector: "github", operation: "merge_pull_request", policyVersion: "" } },
    );
    window.markDelivered();
    window.approve("owner-1", 0);
    cp.vetoWindows.set("v-1", window);
    const jti = ((await (await fetch(`${url}/veto/v-1`)).json()) as { grant: { jti: string } }).grant.jti;

    // no valid signature → 401, and the grant stays vetoable
    const forged = await fetch(`${url}/kill-state/commit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jti, nonce: "x", ts: c.now(), sig: "00" }),
    });
    expect(forged.status).toBe(401);
    const session = createOwnerSession("adam", { now: c.now });
    const veto = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "veto" }),
    });
    expect(veto.status).toBe(200); // still vetoable — the forged commit did nothing
  });
});

describe("MergeGrant issuance on ACTIVE owner approval", () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server = undefined;
  });
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

  const GRANT_KEY = "grant-key-cp-and-broker-padded-256bit";
  const MERGE_ARGS = {
    owner: "ownerswitchai",
    repo: "ownerswitch",
    pullNumber: 7,
    expectedHeadSha: "a".repeat(40),
    expectedBaseRef: "main",
  };

  const MERGE_PURPOSE = {
    connector: "github",
    operation: "merge_pull_request",
    policyVersion: "sha256:authzworld",
  };

  /** A grant-eligible window, delivered but NOT yet approved. */
  const mergeWindow = (
    c: ReturnType<typeof clock>,
    purpose: { connector: string; operation: string; policyVersion: string } | null = MERGE_PURPOSE,
    args: Record<string, unknown> = MERGE_ARGS,
  ) => {
    const window = new VetoWindow({ agentId: "agent-1", tool: "github.merge_pr", args }, 0, {
      now: c.now,
      windowMs: 4 * 60_000,
      ...(purpose !== null ? { purpose } : {}),
    });
    window.markDelivered();
    return window;
  };

  /** A window the owner has ACTIVELY approved at the current clock/epoch. */
  const approvedWindow = (c: ReturnType<typeof clock>, epoch = 0) => {
    const window = mergeWindow(c);
    window.approve("owner-1", epoch);
    return window;
  };

  it("mints a single-use signed grant over the APPROVED call — silence alone mints nothing", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    // delivered + past deadline (would 'release' on the veto lane) but NOT
    // approved: a merge must NOT mint on silence
    cp.vetoWindows.set("v-silent", mergeWindow(c));
    c.advance(4 * 60_000);
    const silent = (await (await fetch(`${url}/veto/v-silent`)).json()) as {
      status: string;
      grant?: unknown;
    };
    expect(silent.status).toBe("pending");
    expect(silent.grant).toBeUndefined();

    // now an actively approved window mints the grant
    cp.vetoWindows.set("v-ok", approvedWindow(c));
    const body = (await (await fetch(`${url}/veto/v-ok`)).json()) as {
      status: string;
      grant?: { killEpoch: number };
    };
    expect(body.status).toBe("released");
    const verified = verifyMergeGrant(body.grant, GRANT_KEY, { now: c.now });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.grant.tool).toBe("github.merge_pr");
      expect(verified.grant.canonicalArgs).toBe(canonicalJson(MERGE_ARGS));
      expect(verified.grant.killEpoch).toBe(0);
      expect(verified.grant.connector).toBe("github");
      expect(verified.grant.operation).toBe("merge_pull_request");
      expect(verified.grant.policyVersion).toBe("sha256:authzworld");
    }
    expect(verifyMergeGrant(body.grant, "wrong-key", { now: c.now }).ok).toBe(false);
  });

  it("anchors the grant's expiry to the APPROVAL moment, not the read that fetched it", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    const approvedAt = c.now();
    cp.vetoWindows.set("v-1", approvedWindow(c));
    // first read 90s AFTER approval — no fresh 2 minutes
    c.advance(90_000);

    const body = (await (await fetch(`${url}/veto/v-1`)).json()) as {
      status: string;
      grant?: { expiresAt: number };
    };
    expect(body.status).toBe("released");
    expect(body.grant?.expiresAt).toBe(approvedAt + 2 * 60_000);
  });

  it("an approval that sat unread past the grant window is SPENT — never a late fresh capability", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", approvedWindow(c));
    c.advance(3 * 60_000); // grants live 2 min from approval; one minute late

    const body = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(body.status).toBe("spent");
    expect(body.grant).toBeUndefined();
  });

  it("issues the grant AT MOST ONCE — a second read is 'spent', no second grant", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", approvedWindow(c));

    const first = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(first.status).toBe("released");
    expect(first.grant).toBeDefined();
    const second = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(second.status).toBe("spent");
    expect(second.grant).toBeUndefined();
  });

  it("a kill AFTER approval spends the grant (epoch moved) and mints nothing", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", approvedWindow(c, 0)); // approved at epoch 0

    const killBody = JSON.stringify({ source: "button" });
    await fetch(`${url}/kill`, { method: "POST", headers: deviceHeaders(killBody, c.now()), body: killBody });

    const body = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(body.status).toBe("spent");
    expect(body.grant).toBeUndefined();
  });

  it("POST /veto/:id decision=approve is owner-authenticated, and refused while killed", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", mergeWindow(c));

    // no owner session → 401, nothing approved
    const bare = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(bare.status).toBe(401);
    expect(cp.vetoWindows.get("v-1")?.approvedBy).toBeNull();

    // engage the kill, then an owner approval must be REFUSED (409) — no
    // approval may be minted while killed
    const killBody = JSON.stringify({ source: "button" });
    await fetch(`${url}/kill`, { method: "POST", headers: deviceHeaders(killBody, c.now()), body: killBody });
    const session = createOwnerSession("adam", { now: c.now });
    const whileKilled = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(whileKilled.status).toBe(409);
    expect(cp.vetoWindows.get("v-1")?.approvedBy).toBeNull();
  });

  it("POST /veto/:id decision=approve refuses a non-grant-eligible window (400)", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-plain", mergeWindow(c, null)); // no purpose
    const session = createOwnerSession("adam", { now: c.now });
    const res = await fetch(`${url}/veto/v-plain`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(res.status).toBe(400);
  });

  it("the full loop: approve over HTTP, then the next read mints the grant", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", mergeWindow(c));

    // before approval, a read is 'pending'
    expect(((await (await fetch(`${url}/veto/v-1`)).json()) as { status: string }).status).toBe(
      "pending",
    );
    const session = createOwnerSession("adam", { now: c.now });
    const approve = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(approve.status).toBe(200);
    expect(await approve.json()).toEqual({ status: "approved" });

    const released = (await (await fetch(`${url}/veto/v-1`)).json()) as {
      status: string;
      grant?: unknown;
    };
    expect(released.status).toBe("released");
    expect(released.grant).toBeDefined();
  });

  it("mints NO grant for a merge-purpose window whose args fail the closed schema", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now, grantKey: GRANT_KEY });
    const url = await start(cp);
    const window = mergeWindow(c, MERGE_PURPOSE, { ...MERGE_ARGS, dryRun: true });
    // even if somehow approved, args that fail the closed schema are not
    // grant-eligible, so no grant is ever minted
    window.approve("owner-1", 0);
    cp.vetoWindows.set("v-bad", window);

    const body = (await (await fetch(`${url}/veto/v-bad`)).json()) as { status: string; grant?: unknown };
    expect(body.grant).toBeUndefined();
  });

  it("no grant key configured → a merge window is never grant-eligible", async () => {
    const c = clock();
    const cp = ephemeral({ now: c.now }); // no grantKey
    const url = await start(cp);
    cp.vetoWindows.set("v-1", approvedWindow(c));
    c.advance(4 * 60_000);

    const body = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(body.grant).toBeUndefined();
  });
});

describe("the escalation surface — seen acks, device veto relay, pending listing", () => {
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

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  const openWindow = (cp: ControlPlane, c: { now: () => number }, id = "v-1", windowMs = 4 * 60_000) => {
    const window = new VetoWindow({ agentId: "agent-1", tool: "bash" }, cp.killSwitch.epoch, {
      now: c.now,
      windowMs,
    });
    cp.vetoWindows.set(id, window);
    return window;
  };

  /** Fetch the foreground detail (owner-app-signed) and return its delivery echo. */
  const fetchDetail = async (url: string, windowId: string, c: { now: () => number }) => {
    const p = `/veto/${windowId}/detail`;
    const res = await fetch(`${url}${p}`, { headers: ownerAppHeaders("GET", p, "", c.now()) });
    return { res, detail: (await res.json()) as Record<string, unknown> };
  };

  /** Full versioned ack: fetch detail, echo {deliveryId, revision, renderContentHash}, POST /seen. */
  const ackWindow = async (url: string, windowId: string, c: { now: () => number }) => {
    const { detail } = await fetchDetail(url, windowId, c);
    const p = `/veto/${windowId}/seen`;
    const ackBody = JSON.stringify({
      deliveryId: detail.deliveryId,
      revision: detail.revision,
      renderContentHash: detail.renderContentHash,
    });
    return fetch(`${url}${p}`, { method: "POST", headers: ownerAppHeaders("POST", p, ackBody, c.now()), body: ackBody });
  };

  it("GET /veto/:id/detail returns the renderable + a delivery; the echoed ack flips delivered and silence releases", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const { detail } = await fetchDetail(url, "v-1", c);
    expect(detail.agentId).toBe("agent-1");
    expect(detail.tool).toBe("bash");
    expect(detail.revision).toBe(1);
    expect(typeof detail.deliveryId).toBe("string");
    expect(typeof detail.renderContentHash).toBe("string");

    const res = await ackWindow(url, "v-1", c);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { delivered: boolean }).delivered).toBe(true);
    expect(window.isDelivered).toBe(true);
    expect(window.deliveredBy).toBe("owner-app");

    c.advance(4 * 60_000);
    expect(await (await fetch(`${url}/veto/v-1`)).json()).toEqual({ status: "released" });
  });

  it("an ack with no delivery echo (blank ack) is refused — a blank render cannot confirm", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const res = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-1/seen", "", c.now()),
      body: "",
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toMatch(/delivery/);
    expect(window.isDelivered).toBe(false);
  });

  it("a delivery minted for revision N cannot confirm the window after it extends (stale delivery)", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c, "v-1", 60_000); // short 1-min window (< 2-min delivery TTL)

    const { detail } = await fetchDetail(url, "v-1", c); // revision 1
    // window extends undelivered → revision bumps to 2, but the delivery is
    // still UNEXPIRED (fetched <2 min ago), so it is REVISION that rejects it
    c.advance(60_001);
    expect(window.tick()).toBe("extended");
    expect(window.revision).toBe(2);

    const p = "/veto/v-1/seen";
    const ackBody = JSON.stringify({
      deliveryId: detail.deliveryId,
      revision: detail.revision, // stale revision 1
      renderContentHash: detail.renderContentHash,
    });
    const res = await fetch(`${url}${p}`, {
      method: "POST",
      headers: ownerAppHeaders("POST", p, ackBody, c.now()),
      body: ackBody,
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toMatch(/stale|advanced/);
    expect(window.isDelivered).toBe(false);
  });

  it("an expired delivery cannot confirm (2 min TTL), even while the window is still open", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c); // 4 min window
    const { detail } = await fetchDetail(url, "v-1", c);

    c.advance(2 * 60_000 + 1); // past DELIVERY_TTL_MS, still before the 4-min deadline (revision unchanged)
    const p = "/veto/v-1/seen";
    const ackBody = JSON.stringify({
      deliveryId: detail.deliveryId,
      revision: detail.revision,
      renderContentHash: detail.renderContentHash,
    });
    const res = await fetch(`${url}${p}`, {
      method: "POST",
      headers: ownerAppHeaders("POST", p, ackBody, c.now()),
      body: ackBody,
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toMatch(/expired/);
    expect(window.isDelivered).toBe(false);
  });

  it("the FLEET device secret cannot flip the permissive bit — only the owner-app secret", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    // a valid FLEET-signed request (the gateway's / a same-uid agent's
    // credential) is rejected: it may stop, never confirm-delivered
    const viaFleet = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: deviceHeaders("", c.now()),
      body: "",
    });
    expect(viaFleet.status).toBe(401);
    expect(window.isDelivered).toBe(false);
  });

  it("with no owner-app secret enrolled, /veto/:id/seen is 501 and delivery stays unwired (fail closed)", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET }); // no ownerAppSecret
    const url = await start(cp);
    const window = openWindow(cp, c);

    const res = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-1/seen", "", c.now()),
      body: "",
    });
    expect(res.status).toBe(501);
    expect(((await res.json()) as { error: string }).error).toMatch(/not wired/);
    expect(window.isDelivered).toBe(false);

    // and the window then walks to held, never released, on silence
    c.advance(4 * 60_000);
    expect(window.tick()).toBe("extended");
    c.advance(6 * 60_000);
    expect(window.tick()).toBe("held");
  });

  it("POST /veto/:id/seen without a valid signature -> 401; no session variant exists", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const bare = await fetch(`${url}/veto/v-1/seen`, { method: "POST", body: "" });
    expect(bare.status).toBe(401);

    // an owner SESSION must not flip the permissive bit — the ack is
    // enrolled-device evidence, not a session assertion
    const session = createOwnerSession("adam", { now: c.now });
    const viaSession = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: bearer(session.token),
      body: "",
    });
    expect(viaSession.status).toBe(401);
    expect(window.isDelivered).toBe(false);
  });

  it("an ack inside the 60 s response floor is refused and the window extends, never releases", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    // fetch a fresh detail close to the floor (so the delivery is unexpired
    // when the ack lands inside the floor), then advance into the floor
    c.advance(4 * 60_000 - 90_000); // 2:30 in — delivery TTL runs to 4:30
    const { detail } = await fetchDetail(url, "v-1", c);
    c.advance(60_000); // now 30 s before the deadline — inside the floor
    const p = "/veto/v-1/seen";
    const floorBody = JSON.stringify({
      deliveryId: detail.deliveryId,
      revision: detail.revision,
      renderContentHash: detail.renderContentHash,
    });
    const res = await fetch(`${url}${p}`, {
      method: "POST",
      headers: ownerAppHeaders("POST", p, floorBody, c.now()),
      body: floorBody,
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toMatch(/response floor/);
    expect(window.isDelivered).toBe(false);

    c.advance(30_000); // deadline passes undelivered -> extended, not released
    expect(window.tick()).toBe("extended");

    // against the NEW deadline there is time again; a FRESH detail's ack counts
    const again = await ackWindow(url, "v-1", c);
    expect(again.status).toBe(200);
    expect(window.isDelivered).toBe(true);
  });

  it("re-acking a delivered window is an idempotent success; a terminal window refuses", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);
    window.markDelivered("owner-app");

    // an already-delivered window re-acks idempotently, no fresh delivery needed
    const res = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-1/seen", "", c.now()),
      body: "",
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { delivered: boolean }).delivered).toBe(true);

    // a delivered window stays ack-able even after it turns terminal — the
    // bit cannot un-flip, so the retry stays a no-op success
    window.veto("adam");
    const deliveredTerminal = await fetch(`${url}/veto/v-1/seen`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-1/seen", "", c.now()),
      body: "",
    });
    expect(deliveredTerminal.status).toBe(200);

    // but a FIRST ack on a terminal window refuses: there is nothing left
    // for the permissive bit to permit
    openWindow(cp, c, "v-2").veto("adam");
    const terminal = await fetch(`${url}/veto/v-2/seen`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-2/seen", "", c.now()),
      body: "",
    });
    expect(terminal.status).toBe(409);
    expect(((await terminal.json()) as { error: string }).error).toMatch(/vetoed/);
  });

  it("device-signed POST /veto/:id relays a channel stop with honest attribution, idempotently", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const body = JSON.stringify({ decision: "veto", attribution: "channel:sms-reply" });
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: deviceHeaders(body, c.now()),
      body,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "vetoed" });
    expect(window.vetoedBy).toBe("channel:sms-reply");

    // blind retry (the relay could not prove the first arrived) -> no-op success
    const retryBody = JSON.stringify({ attribution: "channel:sms-reply" });
    const retry = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: deviceHeaders(retryBody, c.now()),
      body: retryBody,
    });
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ status: "vetoed" });
    expect(window.vetoedBy).toBe("channel:sms-reply"); // first attribution stands
  });

  it("the owner app's ECDSA device signature vetoes on POST /veto/:id (deny-only, E2E)", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET, ownerDeviceKeys: OWNER_DEVICE_KEYS });
    const url = await start(cp);
    const window = openWindow(cp, c);

    // the same owner-device key that acks delivery signs the one-tap veto
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-1", "", c.now()),
      body: "",
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "vetoed" });
    expect(window.vetoedBy).toBe("owner-device:owner-app");

    // but that same credential can NEVER approve
    const approveBody = JSON.stringify({ decision: "approve" });
    openWindow(cp, c, "v-appr");
    const approve = await fetch(`${url}/veto/v-appr`, {
      method: "POST",
      headers: ownerAppHeaders("POST", "/veto/v-appr", approveBody, c.now()),
      body: approveBody,
    });
    expect(approve.status).toBe(403);
    expect(((await approve.json()) as { error: string }).error).toMatch(/one verb/);
  });

  it("without an attribution a device stop is recorded against the signing device", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: deviceHeaders("", c.now()),
      body: "",
    });
    expect(res.status).toBe(200);
    expect(window.vetoedBy).toBe("device:btn-1");
  });

  it("a device credential can never approve, and a malformed attribution is refused", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const approve = JSON.stringify({ decision: "approve" });
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: deviceHeaders(approve, c.now()),
      body: approve,
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toMatch(/one verb/);
    expect(window.state).toBe("pending");
    expect(window.approvedBy).toBeNull();

    const forged = JSON.stringify({ attribution: "owner:adam" }); // not a channel:* label
    const bad = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: deviceHeaders(forged, c.now()),
      body: forged,
    });
    expect(bad.status).toBe(400);
    expect(window.state).toBe("pending");
  });

  it("GET /veto/pending is device-signed and lists only open windows, with pacing fields", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);

    const open = openWindow(cp, c, "v-open");
    openWindow(cp, c, "v-vetoed").veto("adam");
    const delivered = openWindow(cp, c, "v-delivered");
    delivered.markDelivered("app-1");

    expect((await fetch(`${url}/veto/pending`)).status).toBe(401);

    const res = await fetch(`${url}/veto/pending`, { headers: deviceHeaders("", c.now()) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { windows: Array<Record<string, unknown>> };
    expect(body.windows).toHaveLength(2);
    expect(body.windows).toContainEqual({
      id: "v-open",
      status: "pending",
      agentId: "agent-1",
      tool: "bash",
      deadline: open.deadlineAt,
      delivered: false,
    });
    expect(body.windows).toContainEqual({
      id: "v-delivered",
      status: "pending",
      agentId: "agent-1",
      tool: "bash",
      deadline: delivered.deadlineAt,
      delivered: true,
    });
  });

  it("GET /veto/:id stays status-only for the open read; a device-signed read adds the pacing fields", async () => {
    const c = clock(1_000);
    const cp = ephemeral({ now: c.now, deviceSecret: DEVICE_SECRET });
    const url = await start(cp);
    const window = openWindow(cp, c);

    const open = (await (await fetch(`${url}/veto/v-1`)).json()) as Record<string, unknown>;
    expect(open).toEqual({ status: "pending" }); // no clock leak to id holders

    const signed = await fetch(`${url}/veto/v-1`, { headers: deviceHeaders("", c.now()) });
    expect(await signed.json()).toEqual({
      status: "pending",
      deadline: window.deadlineAt,
      delivered: false,
    });
  });
});

describe("2GO licensing — the ONE paid gate; every stop path stays free", () => {
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

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  const keys = generateLicenseKeys();
  const YEAR = 365 * 86_400_000;
  const license = (expiresAt: number, issuedAt = 0) =>
    mintLicense(
      { v: 1, jti: "lic_test", plan: "team", licensee: "Test Co", issuedAt, expiresAt },
      keys.privateKeyPem,
    );

  const startCeremony = async (url: string, c: { now: () => number }) => {
    const session = createOwnerSession("adam", { now: c.now });
    return fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({}),
    });
  };

  it("a valid license mints ceremonies; expiry falls into the 72 h grace, then 402", async () => {
    const c = clock(1_000);
    const cp = ephemeral({
      now: c.now,
      licensing: { vendorPublicKeyPem: keys.publicKeyPem, token: license(YEAR) },
    });
    const url = await start(cp);
    await fetch(`${url}/kill`, { method: "POST", body: JSON.stringify({ source: "api" }) });

    expect((await startCeremony(url, c)).status).toBe(201);

    // license expires; the ceremony above ages out; grace holds the door open
    c.advance(YEAR + 3_600_000); // 1 h past expiry — inside grace
    const inGrace = await startCeremony(url, c);
    expect(inGrace.status).toBe(201);

    c.advance(72 * 3_600_000); // now past expiry + 72 h
    const dead = await startCeremony(url, c);
    expect(dead.status).toBe(402);
    const body = (await dead.json()) as { error: string };
    expect(body.error).toMatch(/license/);
    expect(body.error).toMatch(/free forever/);
  });

  it("an UNLICENSED plane refuses new ceremonies with 402 — and every stop path still works", async () => {
    const c = clock(1_000);
    const original = console.error;
    console.error = () => {}; // boot warning is loud by design; silence for the test
    let cp: ControlPlane;
    try {
      cp = ephemeral({
        now: c.now,
        deviceSecret: DEVICE_SECRET,
        ownerDeviceKeys: OWNER_DEVICE_KEYS,
        licensing: { vendorPublicKeyPem: keys.publicKeyPem }, // no token
      });
    } finally {
      console.error = original;
    }
    const url = await start(cp);

    // stopping is free: the kill engages without any license
    const kill = await fetch(`${url}/kill`, { method: "POST", body: JSON.stringify({ source: "api" }) });
    expect(kill.status).toBe(200);
    expect(cp.killSwitch.killed).toBe(true);

    // the deny direction is free: the device veto relay works with no license
    const window = new VetoWindow({ agentId: "a", tool: "bash" }, cp.killSwitch.epoch, { now: c.now });
    cp.vetoWindows.set("v-free", window);
    const veto = await fetch(`${url}/veto/v-free`, {
      method: "POST",
      headers: deviceHeaders("", c.now()),
      body: "",
    });
    expect(veto.status).toBe(200);
    expect(window.state).toBe("vetoed");

    // status stays open and honest
    expect((await (await fetch(`${url}/status`)).json() as { killed: boolean }).killed).toBe(true);

    // only the paid act — minting a NEW 2GO ceremony — answers 402
    const refused = await startCeremony(url, c);
    expect(refused.status).toBe(402);

    // and without the licensing option at all (dev/quickstart), 2GO is ungated
    const free = ephemeral({ now: c.now });
    const freeUrl = await start(free);
    await fetch(`${freeUrl}/kill`, { method: "POST", body: JSON.stringify({ source: "api" }) });
    expect((await startCeremony(freeUrl, c)).status).toBe(201);
  });

  it("an owner already HOLDING a ceremony keeps it through a license lapse (idempotent return outruns the gate)", async () => {
    const c = clock(1_000);
    const cpLive = ephemeral({
      now: c.now,
      licensing: { vendorPublicKeyPem: keys.publicKeyPem, token: license(2_000) },
    });
    const url = await start(cpLive);
    await fetch(`${url}/kill`, { method: "POST", body: JSON.stringify({ source: "api" }) });

    const session = createOwnerSession("adam", { now: c.now });
    const mint = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({}),
    });
    expect(mint.status).toBe(201); // license valid at t=1s (expires t=2s, grace 72h — still ok)
    const { id } = (await mint.json()) as { id: string };

    // same owner asks again — idempotent return, no fresh license judgment
    const again = await fetch(`${url}/restore/ceremony`, {
      method: "POST",
      headers: bearer(session.token),
      body: JSON.stringify({}),
    });
    expect(again.status).toBe(200);
    expect(((await again.json()) as { id: string }).id).toBe(id);
  });
});
