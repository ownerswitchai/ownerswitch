import { createHash, createPublicKey, randomBytes, verify as ecVerify } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, type ControlPlane } from "@ownerswitchai/control-plane";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFakeIndexedDb, resetFakeIndexedDb } from "./idb-fake.js";

/**
 * The cheap-lane key CUSTODY discipline (DESIGN §2 step 4) in
 * owner-runtime.mjs, driven against the fake IndexedDB: atomic
 * create-if-absent, single-flight, close/reopen read-back with a probe
 * signature, reload stability — and the ENROLLED IDENTITY binding: after a
 * real 201, the persisted {deviceId} + the persisted key together
 * authenticate as the registry's own record.
 */
installFakeIndexedDb();

const runtime = () => import("../public/owner-runtime.mjs");
/** a fresh module registry = a page reload: module state gone, "disk" kept */
const reloaded = async () => {
  vi.resetModules();
  return import("../public/owner-runtime.mjs");
};

const dirs: string[] = [];
const servers: Server[] = [];
beforeEach(() => {
  resetFakeIndexedDb();
  vi.resetModules();
});
afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const spki = async (publicKey: CryptoKey) =>
  Buffer.from(await crypto.subtle.exportKey("spki", publicKey)).toString("base64url");

describe("owner-runtime key custody — persistence round-trip, races, identity", () => {
  it("FIRST RUN: the returned pair is the READ-BACK pair, and it signs after close/reopen", async () => {
    const rt = await runtime();
    const pair = await rt.ensureDeviceKey();
    expect(pair.privateKey).toBeDefined();
    // the same key comes back after a "reload" — persisted, not per-context
    const rt2 = await reloaded();
    const again = await rt2.ensureDeviceKey();
    expect(await spki(again.publicKey)).toBe(await spki(pair.publicKey));
  });

  it("RACE: concurrent ensures in one page share ONE flight; racing contexts converge on ONE persisted key", async () => {
    const rt = await runtime();
    // page-level: two concurrent calls, one flight
    const [a, b] = await Promise.all([rt.ensureDeviceKey(), rt.ensureDeviceKey()]);
    expect(a).toBe(b);
    // cross-context: a second module instance racing the first — the atomic
    // add means exactly one key wins, and BOTH contexts end up holding it
    resetFakeIndexedDb();
    vi.resetModules();
    const ctx1 = await import("../public/owner-runtime.mjs");
    vi.resetModules();
    const ctx2 = await import("../public/owner-runtime.mjs");
    const [k1, k2] = await Promise.all([ctx1.ensureDeviceKey(), ctx2.ensureDeviceKey()]);
    expect(await spki(k1.publicKey)).toBe(await spki(k2.publicKey));
  });

  it("IDENTITY: adopt survives reload; malformed ids refuse", async () => {
    const rt = await runtime();
    expect(await rt.enrolledIdentity()).toBeNull();
    await rt.adoptEnrolledIdentity("dev_abc123");
    const rt2 = await reloaded();
    expect(await rt2.enrolledIdentity()).toBe("dev_abc123");
    await expect(rt2.adoptEnrolledIdentity("not-a-device-id")).rejects.toThrow(/refusing to adopt/);
    await expect(rt2.adoptEnrolledIdentity("dev_" + "x".repeat(80))).rejects.toThrow(/refusing to adopt/);
  });

  it("BINDING (the review's regression): enroll -> reload -> the stored id + stored key verify against the REGISTRY record", async () => {
    // a real control plane with enrollment wired
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-custody-"));
    dirs.push(dir);
    const quiet = <T,>(build: () => T): T => {
      const original = console.error;
      console.error = () => {};
      try {
        return build();
      } finally {
        console.error = original;
      }
    };
    const cp: ControlPlane = quiet(() =>
      createControlPlane({
        dev: true,
        killStateFile: null,
        acceptSessionOnlyApprovalRisk: true,
        enrollment: {
          devicesFile: join(dir, "devices.json"),
          rpId: "owner.example",
          rpName: "OwnerSwitch",
          origin: "https://owner.example",
        },
      }),
    );
    const server = createServer(cp.handler);
    servers.push(server);
    const base = await new Promise<string>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr === null || typeof addr === "string") throw new Error("no address");
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });

    // mint + run the WHOLE ceremony with the RUNTIME-custodied key
    const token = randomBytes(32).toString("base64url");
    const minted = cp.bootstrapMintInvite({
      tokenHash: createHash("sha256").update(token, "utf8").digest("base64url"),
      ownerId: "owner-adam",
      deviceName: "Adam's phone",
    });
    if (!minted.ok) throw new Error(minted.error);
    const rt = await runtime();
    const pair = await rt.ensureDeviceKey();
    const { completeEnrollmentCeremony } = await import("../public/enroll-ceremony.mjs");
    const { syntheticAuthenticator } = await import("./webauthn-fake.js");
    const outcome = await completeEnrollmentCeremony(
      { ...minted.invite, token },
      {
        credentials: syntheticAuthenticator("owner.example", "https://owner.example").container,
        cheapLane: pair,
        fetchImpl: fetch,
        baseUrl: base,
      },
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    await rt.adoptEnrolledIdentity(outcome.deviceId);

    // RELOAD: the identity and the key both come back from "disk"
    const rt2 = await reloaded();
    const storedId = await rt2.enrolledIdentity();
    expect(storedId).toBe(outcome.deviceId);
    const storedPair = await rt2.ensureDeviceKey();

    // the REGISTRY's record for that id holds EXACTLY the stored key…
    const record = cp.enrolledDevices?.get(outcome.deviceId);
    expect(record).toBeDefined();
    expect(record?.cheapLaneKeySpki).toBe(await spki(storedPair.publicKey));

    // …and a real signed request made with {stored id, stored key} verifies
    // against that registry key, byte for byte
    const { signRequestHeaders } = await import("../public/owner-crypto.mjs");
    const body = JSON.stringify({ probe: true });
    const at = Date.now();
    const headers = await signRequestHeaders(storedPair.privateKey, {
      deviceId: storedId as string,
      method: "POST",
      pathAndQuery: "/veto/w1/seen",
      body,
      timestamp: at,
      nonce: "n-custody-1",
    });
    expect(headers["x-device-id"]).toBe(outcome.deviceId);
    const preimage = ownerDeviceSigPreimage({
      deviceId: storedId as string,
      method: "POST",
      pathAndQuery: "/veto/w1/seen",
      bodyHash: new Uint8Array(createHash("sha256").update(body).digest()),
      timestamp: at,
      nonce: "n-custody-1",
    });
    const registryPublicKey = createPublicKey({
      key: Buffer.from(record!.cheapLaneKeySpki, "base64url"),
      format: "der",
      type: "spki",
    });
    const verified = ecVerify(
      "sha256",
      preimage,
      { key: registryPublicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(headers["x-device-signature"], "base64url"),
    );
    expect(verified).toBe(true);
  });
});
