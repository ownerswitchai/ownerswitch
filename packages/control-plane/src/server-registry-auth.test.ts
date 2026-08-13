import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import {
  enrollmentSubmission,
  FIXTURE_ORIGIN,
  FIXTURE_RP_ID,
  phone,
} from "./enroll-fixture.js";
import { createControlPlane, type ControlPlane } from "./server.js";
import { VetoWindow } from "./veto.js";

/**
 * THE REGISTRY IN THE AUTH PATH: a device enrolled through the ceremony
 * (dev_…, durable in devices.json) authenticates the SAME production
 * surfaces the keys-file devices do — device-signed GET /veto/:id/detail
 * and POST /veto/:id/seen — with its standing read LIVE off the registry:
 * a revocation persisted in the file kills its signature at the next
 * restart, and a QUARANTINED registry authenticates nothing while a
 * keys-file device keeps working. This is what turns the enrollment
 * ceremony from a parked artifact into authority.
 */
const dirs: string[] = [];
const servers: Server[] = [];
const freshDir = () => {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-registry-auth-"));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const quiet = <T>(build: () => T): T => {
  const original = console.error;
  console.error = () => {};
  try {
    return build();
  } finally {
    console.error = original;
  }
};

const enrollmentFor = (devicesFile: string) => ({
  devicesFile,
  rpId: FIXTURE_RP_ID,
  rpName: "OwnerSwitch",
  origin: FIXTURE_ORIGIN,
});

const plane = (opts: {
  devicesFile?: string;
  ownerDeviceKeys?: Record<string, string>;
  standingFile?: string;
}): ControlPlane =>
  quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      ...(opts.devicesFile !== undefined ? { enrollment: enrollmentFor(opts.devicesFile) } : {}),
      ...(opts.ownerDeviceKeys !== undefined ? { ownerDeviceKeys: opts.ownerDeviceKeys } : {}),
      ...(opts.standingFile !== undefined ? { ownerDeviceStandingFile: opts.standingFile } : {}),
    }),
  );

const start = (cp: ControlPlane): Promise<string> => {
  const server = createServer(cp.handler);
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("no address");
      resolve(`http://127.0.0.1:${addr.port}`);
    });
  });
};

/** Enroll the fixture phone over HTTP; returns its registry deviceId. */
const enrollPhone = async (cp: ControlPlane, base: string, p: ReturnType<typeof phone>) => {
  const secret = randomBytes(32).toString("base64url");
  const minted = cp.bootstrapMintInvite({
    tokenHash: createHash("sha256").update(secret, "utf8").digest("base64url"),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
  });
  if (!minted.ok) throw new Error(`mint failed: ${minted.error}`);
  const res = await fetch(`${base}/devices/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(enrollmentSubmission(p, minted.invite, secret)),
  });
  if (res.status !== 201) throw new Error(`enroll failed: ${res.status}`);
  return ((await res.json()) as { deviceId: string }).deviceId;
};

/** Device-sign a request with a node EC key, exactly as the phone signs. */
const signedFetch = (
  base: string,
  key: { privateKey: import("node:crypto").KeyObject },
  deviceId: string,
  method: string,
  pathAndQuery: string,
  body: string,
) => {
  const timestamp = Date.now();
  const nonce = randomBytes(16).toString("hex");
  const preimage = ownerDeviceSigPreimage({
    deviceId,
    method,
    pathAndQuery,
    bodyHash: new Uint8Array(createHash("sha256").update(body, "utf8").digest()),
    timestamp,
    nonce,
  });
  const signature = ecSign("sha256", preimage, {
    key: key.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  return fetch(`${base}${pathAndQuery}`, {
    method,
    headers: {
      "content-type": "application/json",
      "x-device-id": deviceId,
      "x-device-timestamp": String(timestamp),
      "x-device-nonce": nonce,
      "x-device-signature": signature,
    },
    ...(method === "POST" ? { body } : {}),
  });
};

const armWindow = (cp: ControlPlane, id: string) => {
  const window = new VetoWindow(
    { agentId: "agent-1", tool: "stripe.payout", args: { amount: 5000, to: "acct_x" } },
    cp.killSwitch.epoch,
  );
  cp.vetoWindows.set(id, window);
  return window;
};

describe("registry in the auth path — ceremony-enrolled devices carry production authority", () => {
  it("an enrolled dev_ device reads the detail AND flips delivered through the full seen ack", async () => {
    const cp = plane({ devicesFile: join(freshDir(), "devices.json") });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);
    expect(deviceId).toMatch(/^dev_/);
    const window = armWindow(cp, "v-reg");

    // the device-signed detail: authenticated by the REGISTRY, not a keys file
    const detailRes = await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-reg/detail", "");
    expect(detailRes.status).toBe(200);
    const detail = (await detailRes.json()) as {
      deliveryId: string;
      revision: number;
      renderContentHash: string;
    };
    expect(detail.deliveryId).toMatch(/^del_/);

    // the full versioned ack — deliveryId + revision + hash echo — lands, and
    // the window records the REGISTRY identity at the registry generation
    const ackBody = JSON.stringify({
      deliveryId: detail.deliveryId,
      revision: detail.revision,
      renderContentHash: detail.renderContentHash,
    });
    const seenRes = await signedFetch(base, p.cheapLane, deviceId, "POST", "/veto/v-reg/seen", ackBody);
    expect(seenRes.status).toBe(200);
    expect(((await seenRes.json()) as { delivered: boolean }).delivered).toBe(true);
    expect(window.isDelivered).toBe(true);
    expect(window.deliveredBy).toBe(deviceId);

    // an unknown dev_ id signed by the same (real) key is 401 — the registry
    // resolves nothing for it, and there is no fallback guess
    const stranger = await signedFetch(base, p.cheapLane, "dev_unknown", "GET", "/veto/v-reg/detail", "");
    expect(stranger.status).toBe(401);
  });

  it("a revocation persisted in devices.json is fatal at the next restart — the same signature is 401", async () => {
    const devicesFile = join(freshDir(), "devices.json");
    const cp = plane({ devicesFile });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);
    armWindow(cp, "v-alive");
    expect((await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-alive/detail", "")).status).toBe(200);

    // revoke IN THE FILE (as revocation tooling will), then restart over it
    const persisted = JSON.parse(readFileSync(devicesFile, "utf8")) as {
      devices: Record<string, { revokedAt: number | null }>;
    };
    expect(persisted.devices[deviceId]).toBeDefined();
    persisted.devices[deviceId].revokedAt = Date.now();
    writeFileSync(devicesFile, JSON.stringify(persisted), { mode: 0o600 });

    const restarted = plane({ devicesFile });
    expect(restarted.enrolledDevices?.usable).toBe(true);
    const base2 = await start(restarted);
    armWindow(restarted, "v-revoked");
    // the key still signs perfectly — and authenticates NOTHING
    expect(
      (await signedFetch(base2, p.cheapLane, deviceId, "GET", "/veto/v-revoked/detail", "")).status,
    ).toBe(401);
  });

  it("a QUARANTINED registry authenticates nothing, while a keys-file device on the same plane keeps working", async () => {
    const devicesFile = join(freshDir(), "devices.json");
    const cp = plane({ devicesFile });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);

    // a provisioned keys-file device, exactly as STANDING-DEPLOYMENT wires it
    const staticKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const staticSpki = (staticKey.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
      "base64url",
    );

    // corrupt the registry file, then restart over it with BOTH lanes wired
    writeFileSync(devicesFile, "{ this is not the registry", { mode: 0o600 });
    const restarted = plane({ devicesFile, ownerDeviceKeys: { "owner-phone": staticSpki } });
    expect(restarted.enrolledDevices?.usable).toBe(false);
    const base2 = await start(restarted);
    armWindow(restarted, "v-q");

    // the enrolled identity is GONE while quarantined — fail closed, no guess
    expect((await signedFetch(base2, p.cheapLane, deviceId, "GET", "/veto/v-q/detail", "")).status).toBe(401);
    // …but the keys-file lane is UNTOUCHED: the static device still reads
    expect(
      (await signedFetch(base2, staticKey, "owner-phone", "GET", "/veto/v-q/detail", "")).status,
    ).toBe(200);
    void base; // first plane held only to enroll
  });

  it("the enrollment registry ALONE wires the owner-device lane: 401 (not 501) unsigned, and no lane at all without either", async () => {
    // registry configured, zero keys-file devices: the lane exists
    const withRegistry = plane({ devicesFile: join(freshDir(), "devices.json") });
    const base = await start(withRegistry);
    armWindow(withRegistry, "v-lane");
    expect((await fetch(`${base}/veto/v-lane/detail`)).status).toBe(401);
    expect((await fetch(`${base}/veto/v-lane/seen`, { method: "POST", body: "{}" })).status).toBe(401);

    // neither registry nor keys file: honestly 501 — nothing could ever verify
    const bare = plane({});
    const base2 = await start(bare);
    armWindow(bare, "v-none");
    expect((await fetch(`${base2}/veto/v-none/detail`)).status).toBe(501);
    expect((await fetch(`${base2}/veto/v-none/seen`, { method: "POST", body: "{}" })).status).toBe(501);
  });
});

describe("v28: dev_ revocation, alias supersession, standing export", () => {
  it("REVOKE over HTTP: durable in the registry, exported to the standing file, immediate 401, idempotent, restart-proof", async () => {
    const dir = freshDir();
    const devicesFile = join(dir, "devices.json");
    const standingFile = join(dir, "standing.json");
    const cp = plane({ devicesFile, standingFile });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);
    armWindow(cp, "v-rv");
    expect((await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-rv/detail", "")).status).toBe(200);

    // enrollment already EXPORTED the device into the standing file (v2, spki)
    const afterEnroll = JSON.parse(readFileSync(standingFile, "utf8")) as {
      version: number;
      devices: Record<string, { generation: number; revokedAt: number | null; spki?: string }>;
    };
    expect(afterEnroll.version).toBe(2);
    expect(afterEnroll.devices[deviceId].revokedAt).toBeNull();
    expect(afterEnroll.devices[deviceId].spki).toBe(cp.enrolledDevices?.get(deviceId)?.cheapLaneKeySpki);

    // the revoke (loopback caller — severing must never fail on auth config)
    const revoke = await fetch(`${base}/devices/${deviceId}/revoke`, { method: "POST" });
    expect(revoke.status).toBe(200);
    expect((await revoke.json()) as object).toMatchObject({
      revoked: true,
      deviceId,
      generation: 2,
      durable: true,
    });
    // immediate: the same key + id authenticate NOTHING in this process
    expect((await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-rv/detail", "")).status).toBe(401);
    // exported: the escalation reader's view flips at its very next load
    const afterRevoke = JSON.parse(readFileSync(standingFile, "utf8")) as typeof afterEnroll;
    expect(afterRevoke.devices[deviceId].revokedAt).not.toBeNull();
    expect(afterRevoke.devices[deviceId].generation).toBe(2);
    // idempotent
    const again = await fetch(`${base}/devices/${deviceId}/revoke`, { method: "POST" });
    expect(again.status).toBe(200);
    expect(((await again.json()) as { alreadyRevoked?: boolean }).alreadyRevoked).toBe(true);
    // restart-proof: a fresh control plane over the same files still refuses
    const restarted = plane({ devicesFile, standingFile });
    const base2 = await start(restarted);
    armWindow(restarted, "v-rv2");
    expect(
      (await signedFetch(base2, p.cheapLane, deviceId, "GET", "/veto/v-rv2/detail", "")).status,
    ).toBe(401);
  });

  it("a revocation the registry cannot publish durably answers 503 and engages a DURABLE KILL", async () => {
    const cp = plane({ devicesFile: join(freshDir(), "devices.json") });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);
    armWindow(cp, "v-kill");

    // The registry's own publish-failed branch is proven with a REAL fsync
    // failure in enrolled-devices.test.ts ("quarantines the registry — and
    // the intact file would resurrect the device"). Here the SERVER's
    // documented reaction to that outcome is under test, injected at the
    // registry's public revoke() boundary.
    const registry = cp.enrolledDevices;
    if (registry === undefined) throw new Error("registry missing");
    const realRevoke = registry.revoke.bind(registry);
    registry.revoke = () => ({ outcome: "publish-failed", detail: "injected: dir entry not durable" });
    const res = await fetch(`${base}/devices/${deviceId}/revoke`, { method: "POST" });
    registry.revoke = realRevoke;
    expect(res.status).toBe(503);
    const body = (await res.json()) as { killed: boolean; quarantined: boolean; error: string };
    expect(body.killed).toBe(true);
    expect(body.quarantined).toBe(true);
    expect(body.error).toMatch(/restart boots killed/);
    // the kill is REAL and names the sequence
    expect(cp.killSwitch.killed).toBe(true);
    expect(cp.killSwitch.lastKill?.reason).toMatch(/registry publish FAILED while revoking/);
    // and while killed, the permissive lane is closed: the detail mints no
    // delivery and the ack path accepts no evidence
    const detail = await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-kill/detail", "");
    expect(detail.status).toBe(200);
    expect(((await detail.json()) as { deliveryId: string | null }).deliveryId).toBeNull();
    const seen = await signedFetch(base, p.cheapLane, deviceId, "POST", "/veto/v-kill/seen", "{}");
    expect(seen.status).toBe(503);
  });

  it("ALIAS SUPERSESSION, live: enrolling the static device's own key revokes the static name in the same breath", async () => {
    const dir = freshDir();
    const p = phone();
    const staticSpki = (p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
      "base64url",
    );
    const standingFile = join(dir, "standing.json");
    const cp = plane({
      devicesFile: join(dir, "devices.json"),
      standingFile,
      ownerDeviceKeys: { "owner-phone": staticSpki },
    });
    const base = await start(cp);
    armWindow(cp, "v-al");
    // before the enrollment, the static name works
    expect((await signedFetch(base, p.cheapLane, "owner-phone", "GET", "/veto/v-al/detail", "")).status).toBe(200);

    const deviceId = await enrollPhone(cp, base, p);
    // after: ONE key, ONE identity — the registry name answers, the static is dead
    expect((await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-al/detail", "")).status).toBe(200);
    expect((await signedFetch(base, p.cheapLane, "owner-phone", "GET", "/veto/v-al/detail", "")).status).toBe(401);
    // and the severing is DURABLE in the shared standing file
    const standing = JSON.parse(readFileSync(standingFile, "utf8")) as {
      devices: Record<string, { revokedAt: number | null; spki?: string }>;
    };
    expect(standing.devices["owner-phone"].revokedAt).not.toBeNull();
    expect(standing.devices[deviceId].revokedAt).toBeNull();
    // revoking the dev_ name later does NOT resurrect the static one
    await fetch(`${base}/devices/${deviceId}/revoke`, { method: "POST" });
    expect((await signedFetch(base, p.cheapLane, "owner-phone", "GET", "/veto/v-al/detail", "")).status).toBe(401);
    expect((await signedFetch(base, p.cheapLane, deviceId, "GET", "/veto/v-al/detail", "")).status).toBe(401);
  });

  it("ALIAS at BOOT: a restart that re-provisions the enrolled key under a static name refuses the static name", async () => {
    const dir = freshDir();
    const devicesFile = join(dir, "devices.json");
    const standingFile = join(dir, "standing.json");
    const p = phone();
    // enroll on a registry-only plane
    const first = plane({ devicesFile, standingFile });
    const base1 = await start(first);
    const deviceId = await enrollPhone(first, base1, p);
    // "operator re-adds the key to the keys file", then restarts
    const staticSpki = (p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
      "base64url",
    );
    const restarted = plane({
      devicesFile,
      standingFile,
      ownerDeviceKeys: { "owner-phone": staticSpki },
    });
    const base2 = await start(restarted);
    armWindow(restarted, "v-boot");
    expect(
      (await signedFetch(base2, p.cheapLane, "owner-phone", "GET", "/veto/v-boot/detail", "")).status,
    ).toBe(401);
    expect(
      (await signedFetch(base2, p.cheapLane, deviceId, "GET", "/veto/v-boot/detail", "")).status,
    ).toBe(200);
  });

  it("the dev_ namespace is refused in ownerDeviceKeys — the two id spaces cannot collide", () => {
    const p = phone();
    const spki = (p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString(
      "base64url",
    );
    expect(() =>
      quiet(() =>
        createControlPlane({
          dev: true,
          killStateFile: null,
          acceptSessionOnlyApprovalRisk: true,
          ownerDeviceKeys: { dev_squatter: spki },
        }),
      ),
    ).toThrow(/reserved for/);
  });

  it("DENY-ONLY: a registry device vetoes with one signature, and can never approve with it", async () => {
    const cp = plane({ devicesFile: join(freshDir(), "devices.json") });
    const base = await start(cp);
    const p = phone();
    const deviceId = await enrollPhone(cp, base, p);
    const window = armWindow(cp, "v-deny");

    // the one verb a device credential carries here: veto
    const approve = await signedFetch(
      base,
      p.cheapLane,
      deviceId,
      "POST",
      "/veto/v-deny",
      JSON.stringify({ decision: "approve" }),
    );
    expect(approve.status).toBe(403);
    expect(window.state).not.toBe("vetoed");
    const veto = await signedFetch(base, p.cheapLane, deviceId, "POST", "/veto/v-deny", "{}");
    expect(veto.status).toBe(200);
    expect(window.state).toBe("vetoed");
    expect(window.vetoedBy).toBe(`owner-device:${deviceId}`);
  });
});
