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
}): ControlPlane =>
  quiet(() =>
    createControlPlane({
      dev: true,
      killStateFile: null,
      acceptSessionOnlyApprovalRisk: true,
      ...(opts.devicesFile !== undefined ? { enrollment: enrollmentFor(opts.devicesFile) } : {}),
      ...(opts.ownerDeviceKeys !== undefined ? { ownerDeviceKeys: opts.ownerDeviceKeys } : {}),
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
