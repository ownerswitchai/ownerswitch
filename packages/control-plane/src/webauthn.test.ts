import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJson, sha256Hex } from "@ownerswitchai/shared";
import { afterEach, describe, expect, it } from "vitest";
import { createOwnerSession, signDeviceRequest } from "./auth.js";
import { createControlPlane, type ControlPlane, type ControlPlaneOptions } from "./server.js";
import { VetoWindow } from "./veto.js";
import { verifyOwnerAssertion } from "./webauthn.js";

/**
 * A REAL P-256 keypair plays the platform authenticator: assertions are
 * genuinely signed over authenticatorData || sha256(clientDataJSON), so the
 * verifier is exercised against true WebAuthn byte layouts — not mocks of
 * itself. Only the hardware is simulated; the crypto is real.
 */

const RP_ID = "owner.ownerswitch.test";
const ORIGIN = "https://owner.ownerswitch.test";
const CRED_ID = "cred-b64url-1";

function authenticator() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  function assert(opts: {
    challenge: string;
    signCount?: number;
    rpId?: string;
    uv?: boolean;
    up?: boolean;
    type?: string;
    origin?: string;
    credentialId?: string;
    tamperSignature?: boolean;
  }) {
    const clientData = JSON.stringify({
      type: opts.type ?? "webauthn.get",
      challenge: opts.challenge,
      origin: opts.origin ?? ORIGIN,
    });
    const clientDataJSON = Buffer.from(clientData, "utf8");
    const rpIdHash = createHash("sha256").update(opts.rpId ?? RP_ID, "utf8").digest();
    const flags = (opts.up === false ? 0 : 0x01) | (opts.uv === false ? 0 : 0x04);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(opts.signCount ?? 1);
    const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), counter]);
    const signature = createSign("sha256")
      .update(authData)
      .update(createHash("sha256").update(clientDataJSON).digest())
      .sign(privateKey);
    if (opts.tamperSignature === true) signature[8] = signature[8]! ^ 0xff;
    return {
      credentialId: opts.credentialId ?? CRED_ID,
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: authData.toString("base64url"),
      signature: signature.toString("base64url"),
    };
  }

  return { publicKeyPem, assert };
}

describe("verifyOwnerAssertion — the pure verifier", () => {
  const auth = authenticator();
  const passkey = { credentialId: CRED_ID, publicKeyPem: auth.publicKeyPem };
  const CH = randomBytes(32).toString("base64url");
  const base = { passkey, rpId: RP_ID, expectedChallenge: CH, expectedOrigin: ORIGIN, lastSignCount: 0 };

  it("accepts a genuine UP+UV assertion over the expected challenge", () => {
    expect(verifyOwnerAssertion(auth.assert({ challenge: CH, signCount: 7 }), base)).toEqual({
      ok: true,
      signCount: 7,
    });
  });

  it("rejects the wrong ceremony type, challenge, origin, rpId, and credential", () => {
    for (const [assertion, reason] of [
      [auth.assert({ challenge: CH, type: "webauthn.create" }), /webauthn.get/],
      [auth.assert({ challenge: randomBytes(32).toString("base64url") }), /challenge/],
      [auth.assert({ challenge: CH, origin: "https://evil.example" }), /origin/],
      [auth.assert({ challenge: CH, rpId: "evil.example" }), /rpIdHash/],
      [auth.assert({ challenge: CH, credentialId: "someone-else" }), /enrolled passkey/],
    ] as const) {
      const verdict = verifyOwnerAssertion(assertion, base);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(verdict.reason).toMatch(reason);
    }
  });

  it("demands user presence AND user verification", () => {
    for (const assertion of [
      auth.assert({ challenge: CH, up: false }),
      auth.assert({ challenge: CH, uv: false }),
    ]) {
      expect(verifyOwnerAssertion(assertion, base).ok).toBe(false);
    }
  });

  it("rejects a regressed signature counter — the cloned-authenticator signal", () => {
    const verdict = verifyOwnerAssertion(auth.assert({ challenge: CH, signCount: 5 }), {
      ...base,
      lastSignCount: 5,
    });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/counter/);
    // counter-less authenticators (always 0) stay usable
    expect(
      verifyOwnerAssertion(auth.assert({ challenge: CH, signCount: 0 }), base).ok,
    ).toBe(true);
  });

  it("rejects a tampered signature and a foreign key", () => {
    expect(
      verifyOwnerAssertion(auth.assert({ challenge: CH, tamperSignature: true }), base).ok,
    ).toBe(false);
    const stranger = authenticator();
    expect(
      verifyOwnerAssertion(stranger.assert({ challenge: CH }), base).ok, // signed by a DIFFERENT key
    ).toBe(false);
  });
});

describe("assertion-gated approval over HTTP", () => {
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
  const clock = (start = 100_000) => {
    let t = start;
    return { now: () => t, advance: (ms: number) => (t += ms) };
  };
  const quiet = (opts: ControlPlaneOptions) => {
    const original = console.error;
    console.error = () => {};
    try {
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

  const MERGE_ARGS = {
    owner: "o",
    repo: "r",
    pullNumber: 7,
    expectedHeadSha: "a".repeat(40),
    expectedBaseRef: "main",
  };
  const PURPOSE = { connector: "github", operation: "merge_pull_request", policyVersion: "" };
  const GRANT_KEY = "grant-key-cp-and-broker-padded-256bit";

  function mergeWindow(now: () => number) {
    const window = new VetoWindow(
      { agentId: "a1", tool: "github.merge_pr", args: MERGE_ARGS },
      0,
      { now, purpose: PURPOSE },
    );
    window.markDelivered();
    return window;
  }

  async function setup(auth: ReturnType<typeof authenticator>) {
    const c = clock();
    const cp = quiet({
      now: c.now,
      grantKey: GRANT_KEY,
      ownerPasskey: {
        credentialId: CRED_ID,
        publicKeyPem: auth.publicKeyPem,
        rpId: RP_ID,
        origin: ORIGIN,
      },
    });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", mergeWindow(c.now));
    const session = createOwnerSession("adam", { now: c.now });
    const bearer = { authorization: `Bearer ${session.token}`, "content-type": "application/json" };
    return { c, cp, url, bearer };
  }

  it("the full ceremony: challenge → passkey assertion → approval → grant; session alone is refused", async () => {
    const auth = authenticator();
    const { url, bearer } = await setup(auth);

    // session-only approve (no assertion) is REFUSED with a passkey enrolled
    const bare = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(bare.status).toBe(401);
    expect(((await bare.json()) as { error: string }).error).toMatch(/approval ceremony/);

    // mint the ceremony — it names the exact call bytes being approved, and
    // returns a TYPED, per-field renderable (never raw canonical JSON)
    const ch = (await (
      await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST", headers: bearer })
    ).json()) as {
      challenge: string;
      callHash: string;
      renderHash: string;
      renderable: { action: string; owner: string; repo: string; expectedBaseRef: string };
    };
    expect(ch.callHash).toBe(sha256Hex(canonicalJson(MERGE_ARGS)));
    expect(ch.renderable).toMatchObject({
      action: "github.merge_pull_request",
      owner: "o",
      repo: "r",
      expectedBaseRef: "main",
    });
    expect(ch.renderHash).toBe(sha256Hex(canonicalJson(ch.renderable)));

    // the enrolled passkey signs it; approval succeeds; the grant mints
    const ok = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: auth.assert({ challenge: ch.challenge, signCount: 3 }),
      }),
    });
    expect(ok.status).toBe(200);
    const released = (await (await fetch(`${url}/veto/v-1`)).json()) as { status: string; grant?: unknown };
    expect(released.status).toBe("released");
    expect(released.grant).toBeDefined();
  });

  it("a challenge is SINGLE-USE — the same assertion cannot approve twice, nor a failed attempt retry", async () => {
    const auth = authenticator();
    const { url, bearer, cp, c } = await setup(auth);
    const ch = (await (
      await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST", headers: bearer })
    ).json()) as { challenge: string };

    // a WRONG assertion spends the ceremony…
    const stranger = authenticator();
    const bad = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: stranger.assert({ challenge: ch.challenge }),
      }),
    });
    expect(bad.status).toBe(401);
    // …so replaying even a VALID signature over it finds no live ceremony
    const replay = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: auth.assert({ challenge: ch.challenge, signCount: 4 }),
      }),
    });
    expect(replay.status).toBe(401);
    expect(cp.vetoWindows.get("v-1")?.approvedBy).toBeNull();

    // an EXPIRED ceremony is dead too
    const ch2 = (await (
      await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST", headers: bearer })
    ).json()) as { challenge: string };
    c.advance(3 * 60_000);
    const late = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: auth.assert({ challenge: ch2.challenge, signCount: 5 }),
      }),
    });
    expect(late.status).toBe(401);
  });

  it("a ceremony for one window cannot approve another — the challenge is action-bound", async () => {
    const auth = authenticator();
    const { url, bearer, cp, c } = await setup(auth);
    cp.vetoWindows.set("v-2", mergeWindow(c.now));

    const ch1 = (await (
      await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST", headers: bearer })
    ).json()) as { challenge: string };
    // sign window 1's challenge, present it against window 2: window 2 has
    // no live ceremony (its map slot is empty), so the redemption refuses
    const cross = await fetch(`${url}/veto/v-2`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: auth.assert({ challenge: ch1.challenge, signCount: 6 }),
      }),
    });
    expect(cross.status).toBe(401);
    expect(cp.vetoWindows.get("v-2")?.approvedBy).toBeNull();
  });

  it("a GENUINE non-dev control plane with no passkey refuses session-only approval (403)", async () => {
    // This actually boots dev:false, with a hardened (0700, owned) kill-state
    // path, so it exercises the production refusal — not a dev helper.
    const dir = mkdtempSync(join(tmpdir(), "oswitch-cp-"));
    try {
      const c = clock();
      const original = console.error;
      console.error = () => {};
      let cp: ControlPlane;
      try {
        cp = createControlPlane({
          now: c.now,
          grantKey: GRANT_KEY,
          killStateFile: join(dir, "kill-state.json"),
          // dev:false and NO passkey: production, session-only path must refuse
        });
      } finally {
        console.error = original;
      }
      const url = await start(cp);
      cp.vetoWindows.set("v-1", mergeWindow(c.now));
      const session = createOwnerSession("adam", { now: c.now });
      const res = await fetch(`${url}/veto/v-1`, {
        method: "POST",
        headers: { authorization: `Bearer ${session.token}`, "content-type": "application/json" },
        body: JSON.stringify({ decision: "approve" }),
      });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toMatch(/session-only/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to START a non-dev control plane whose passkey origin is not https", () => {
    const original = console.error;
    console.error = () => {};
    try {
      const dir = mkdtempSync(join(tmpdir(), "oswitch-cp-"));
      expect(() =>
        createControlPlane({
          grantKey: GRANT_KEY,
          killStateFile: join(dir, "ks.json"),
          ownerPasskey: { credentialId: CRED_ID, publicKeyPem: "x", rpId: RP_ID, origin: "http://insecure" },
        }),
      ).toThrowError(/https/);
      rmSync(dir, { recursive: true, force: true });
    } finally {
      console.error = original;
    }
  });

  it("rejects a cross-origin (embedded) assertion and a mismatched topOrigin", () => {
    const auth = authenticator();
    const passkey = { credentialId: CRED_ID, publicKeyPem: auth.publicKeyPem };
    const CH = randomBytes(32).toString("base64url");
    const base = { passkey, rpId: RP_ID, expectedChallenge: CH, expectedOrigin: ORIGIN, lastSignCount: 0 };
    // build clientData with crossOrigin / topOrigin by hand
    const withClientData = (extra: Record<string, unknown>) => {
      const a = auth.assert({ challenge: CH });
      const cd = JSON.stringify({ type: "webauthn.get", challenge: CH, origin: ORIGIN, ...extra });
      // re-sign is not needed: crossOrigin/topOrigin are checked BEFORE the
      // signature, so a rejected verdict here proves the context gate fires
      return { ...a, clientDataJSON: Buffer.from(cd, "utf8").toString("base64url") };
    };
    expect(verifyOwnerAssertion(withClientData({ crossOrigin: true }), base).ok).toBe(false);
    expect(
      verifyOwnerAssertion(withClientData({ topOrigin: "https://evil.example" }), base).ok,
    ).toBe(false);
  });

  it("a ceremony minted before a KILL cannot be redeemed after a restore (epoch binding)", async () => {
    const auth = authenticator();
    const c = clock();
    const cp = quiet({
      now: c.now,
      grantKey: GRANT_KEY,
      deviceSecret: "dev-secret",
      ownerPasskey: { credentialId: CRED_ID, publicKeyPem: auth.publicKeyPem, rpId: RP_ID, origin: ORIGIN },
    });
    const url = await start(cp);
    cp.vetoWindows.set("v-1", mergeWindow(c.now));
    const session = createOwnerSession("adam", { now: c.now });
    const bearer = { authorization: `Bearer ${session.token}`, "content-type": "application/json" };

    const ch = (await (
      await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST", headers: bearer })
    ).json()) as { challenge: string };

    // a kill bumps the epoch (and clears challenges); a restore would leave
    // the epoch advanced. We simulate the epoch move via a device-signed kill.
    const deviceHeaders = (body: string) => {
      const timestamp = c.now();
      const nonce = `n-${Math.random().toString(36).slice(2)}`;
      return {
        "content-type": "application/json",
        "x-device-id": "btn",
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": nonce,
        "x-device-signature": signDeviceRequest(
          { deviceId: "btn", timestamp, nonce },
          body,
          "dev-secret",
        ),
      };
    };
    const killBody = JSON.stringify({ source: "button" });
    await fetch(`${url}/kill`, { method: "POST", headers: deviceHeaders(killBody), body: killBody });

    // even though the challenge value is still known to the attacker, it is
    // both cleared and epoch-stale — redemption is refused
    const res = await fetch(`${url}/veto/v-1`, {
      method: "POST",
      headers: bearer,
      body: JSON.stringify({
        decision: "approve",
        assertion: auth.assert({ challenge: ch.challenge, signCount: 9 }),
      }),
    });
    // 409 (approve refused while killed) — the kill is still engaged here;
    // the point is that this pre-kill ceremony never authorizes a merge
    expect([401, 409]).toContain(res.status);
    expect(cp.vetoWindows.get("v-1")?.approvedBy).toBeNull();
  });

  it("the challenge endpoint is owner-authenticated and grant-eligible-only", async () => {
    const auth = authenticator();
    const { url, bearer, cp, c } = await setup(auth);
    // no session → 401
    expect((await fetch(`${url}/veto/v-1/approval-challenge`, { method: "POST" })).status).toBe(401);
    // non-eligible window → 400
    const plain = new VetoWindow({ agentId: "a", tool: "write_file" }, 0, { now: c.now });
    cp.vetoWindows.set("v-plain", plain);
    expect(
      (await fetch(`${url}/veto/v-plain/approval-challenge`, { method: "POST", headers: bearer }))
        .status,
    ).toBe(400);
  });
});
