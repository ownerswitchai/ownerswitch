import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EnrolledDeviceFileStore,
  EnrolledDeviceRegistry,
  type LiveKillState,
} from "./enrolled-devices.js";
import {
  enrollmentSubmission,
  FIXTURE_ORIGIN,
  FIXTURE_RP_ID,
  phone,
  type FixtureInvite,
} from "./enroll-fixture.js";
import * as packageApi from "./index.js";

/**
 * The persistence half of the ceremony: the registry-private spend path,
 * witnesses and owners from live state only, the crash-atomic admit
 * (device + bootstrap-generation bump in one publish, quarantine on
 * unproven durability), and the fail-closed whole-namespace boundary.
 */
const LIVE_KILL: LiveKillState = { killed: false, epoch: 0 };

const dirs: string[] = [];
function freshDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "ownerswitch-enrolled-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length > 0) {
    rmSync(dirs.pop() as string, { recursive: true, force: true });
  }
});

let deviceSeq = 0;
const storeAt = (path: string) =>
  new EnrolledDeviceFileStore(path, { unsafeAllowUntrustedAncestryForTests: true });
const registryAt = (path: string) =>
  new EnrolledDeviceRegistry(storeAt(path), {
    deviceIdFactory: () => `dev_test_${(deviceSeq += 1)}`,
  });

function mintRequest(
  inviteId: string,
  secret: string,
  issuer: { kind: "bootstrap"; ownerId: string } | { kind: "device"; deviceId: string } = {
    kind: "bootstrap",
    ownerId: "owner-adam",
  },
) {
  return {
    inviteId,
    tokenHash: createHash("sha256").update(secret, "utf8").digest("base64url"),
    deviceName: "Adam's phone",
    challenge: randomBytes(32).toString("base64url"),
    assertionChallenge: randomBytes(32).toString("base64url"),
    issuer,
  };
}

const fixtureInvite = (record: {
  inviteId: string;
  ownerId: string;
  deviceName: string;
  challenge: string;
  assertionChallenge: string;
}): FixtureInvite => record;

const OPTS = (kill: LiveKillState = LIVE_KILL) => ({
  kill,
  rpId: FIXTURE_RP_ID,
  expectedOrigin: FIXTURE_ORIGIN,
});

describe("EnrolledDeviceRegistry — durable, crash-atomic, registry-private spend path", () => {
  const SECRET = randomBytes(24).toString("base64url");

  it("first boot persists generation 1 durably; a fresh instance reloads it", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    expect(registry.initialize().ok).toBe(true);
    expect(registry.usable).toBe(true);
    expect(registry.bootstrapGeneration).toBe(1);
    expect(registry.activeDeviceCount).toBe(0);
    const again = registryAt(path);
    expect(again.initialize().ok).toBe(true);
    expect(again.bootstrapGeneration).toBe(1);
  });

  it("the full ceremony admits a device: durable record + bootstrap-generation bump in ONE publish", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    expect(minted.origin).toEqual({ kind: "bootstrap", bootstrapGeneration: 1 });
    expect(minted.killEpoch).toBe(0);
    expect(minted.ownerId).toBe("owner-adam");

    const p = phone();
    const outcome = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(minted), SECRET), OPTS());
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.device.deviceName).toBe("Adam's phone");
      expect(outcome.device.ownerId).toBe("owner-adam");
      expect(outcome.device.generation).toBe(1);
      expect(outcome.device.signCount).toBe(4); // the possession assertion's counter
      expect(outcome.durable).toBe(true);
    }
    expect(registry.activeDeviceCount).toBe(1);
    expect(registry.bootstrapGeneration).toBe(2); // the lane closed durably with the admit

    const reloaded = registryAt(path);
    expect(reloaded.initialize().ok).toBe(true);
    expect(reloaded.activeDeviceCount).toBe(1);
    expect(reloaded.bootstrapGeneration).toBe(2);
    const persisted = reloaded.list()[0];
    expect(persisted.credentialId).toBe(p.credentialId.toString("base64url"));
    expect(persisted.cheapLaneKeySpki).toBe(
      (p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),
    );
  });

  it("OWNER FROM THE ISSUER: a device-minted invite inherits the issuer's persisted ownerId — there is no field to claim another", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const inv1 = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    const first = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv1), SECRET), OPTS());
    expect(first.ok).toBe(true);
    const issuerId = first.ok ? first.device.deviceId : "";

    // the device-issuer variant carries NO ownerId — the compile-time shape
    // is the regression; at runtime the invite is bound to the issuer's own
    const secret2 = randomBytes(24).toString("base64url");
    const inv2 = registry.mintInvite(
      LIVE_KILL,
      mintRequest("inv-2", secret2, { kind: "device", deviceId: issuerId }),
    );
    expect(inv2.ownerId).toBe("owner-adam"); // the ISSUER's persisted owner
    expect(inv2.origin).toEqual({ kind: "device", deviceId: issuerId, deviceGeneration: 1 });
    const second = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv2), secret2), OPTS());
    expect(second.ok).toBe(true);
    if (second.ok) expect(second.device.ownerId).toBe("owner-adam");
    expect(registry.activeDeviceCount).toBe(2);

    // an unknown issuer mints nothing — zero invites, zero burns, zero publishes
    expect(() =>
      registry.mintInvite(LIVE_KILL, mintRequest("inv-3", SECRET, { kind: "device", deviceId: "dev_ghost" })),
    ).toThrow(/not enrolled and in standing/);
  });

  it("after the first phone, the bootstrap lane is closed: old-generation invites are dead and new bootstrap mints refuse", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const inv1 = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    const secret2 = randomBytes(24).toString("base64url");
    registry.mintInvite(LIVE_KILL, mintRequest("inv-2", secret2));

    expect(registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv1), SECRET), OPTS()).ok).toBe(true);
    // the sibling burned atomically at the spend; and a NEW bootstrap mint
    // into the occupied registry refuses AT THE MINT
    const secret3 = randomBytes(24).toString("base64url");
    expect(() => registry.mintInvite(LIVE_KILL, mintRequest("inv-3", secret3))).toThrow(/EMPTY registry/);
  });

  it("a KILLED system mints nothing; a spend attempt under kill burns; a malformed kill snapshot refuses pre-chain", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    expect(() => registry.mintInvite({ killed: true, epoch: 0 }, mintRequest("inv-1", SECRET))).toThrow(
      /nothing MINTS while killed/,
    );

    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-2", SECRET));
    const killedSpend = registry.commitEnrollment(
      enrollmentSubmission(phone(), fixtureInvite(minted), SECRET),
      OPTS({ killed: true, epoch: 0 }),
    );
    expect(killedSpend.ok).toBe(false);
    if (!killedSpend.ok) {
      expect(killedSpend.reason).toMatch(/kill switch/);
      expect(killedSpend.inviteSurvives).toBe(false); // burned, not held open
    }
    const stillMinted = registry.mintInvite(LIVE_KILL, mintRequest("inv-3", SECRET));
    const malformed = registry.commitEnrollment(
      enrollmentSubmission(phone(), fixtureInvite(stillMinted), SECRET),
      OPTS({ killed: "no" as unknown as boolean, epoch: 0 }),
    );
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.inviteSurvives).toBe(true);
  });

  it("an UNPROVEN publish QUARANTINES the registry, and recovery is IMPOSSIBLE until the durability barrier succeeds", () => {
    const path = join(freshDir(), "devices.json");
    const store = storeAt(path);
    const registry = new EnrolledDeviceRegistry(store, {
      deviceIdFactory: () => `dev_test_${(deviceSeq += 1)}`,
    });
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    // the REAL failing branch: the directory entry cannot be fsynced — the
    // publish becomes visible, but its durability is genuinely unprovable.
    // (fsyncDir is the one primitive both save() and the load-time barrier
    // stand on, so disabling it models a directory whose entries cannot be
    // made durable, not a lie about an already-durable save.)
    type FsyncPatch = { fsyncDir: () => boolean };
    const realFsyncDir = (store as unknown as FsyncPatch).fsyncDir.bind(store);
    (store as unknown as FsyncPatch).fsyncDir = () => false;

    const refused = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS());
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/UNPROVEN.*quarantined/);
      expect(refused.inviteSurvives).toBe(false);
    }
    // QUARANTINE: the visible-but-unproven device is served on NO authority path
    expect(registry.usable).toBe(false);
    expect(() => registry.activeDeviceCount).toThrow(/not usable/);
    expect(() => registry.standing("dev_test_1", 1)).toThrow(/not usable/);
    expect(() => registry.mintInvite(LIVE_KILL, mintRequest("inv-2", SECRET))).toThrow(/not usable/);
    const enrollRefused = registry.commitEnrollment({}, OPTS());
    expect(enrollRefused.ok).toBe(false);
    if (!enrollRefused.ok) expect(enrollRefused.reason).toMatch(/not usable/);

    // RECOVERY DENIED while durability stays unprovable: re-initializing the
    // SAME store — and a restart-shaped attempt through a store whose
    // directory still cannot fsync — both stay corrupt. Re-reading a
    // visible file proves nothing.
    const sameStoreRetry = registry.initialize();
    expect(sameStoreRetry.ok).toBe(false);
    if (!sameStoreRetry.ok) expect(sameStoreRetry.detail).toMatch(/could not be fsynced/);
    expect(registry.usable).toBe(false);
    const restartStore = storeAt(path);
    (restartStore as unknown as FsyncPatch).fsyncDir = () => false;
    const restarted = new EnrolledDeviceRegistry(restartStore, {
      deviceIdFactory: () => `dev_test_${(deviceSeq += 1)}`,
    });
    const restartAttempt = restarted.initialize();
    expect(restartAttempt.ok).toBe(false);
    expect(restarted.usable).toBe(false);

    // ONLY a successful barrier lifts the quarantine: the directory can
    // fsync again, and load() proves the visible state durable BEFORE
    // serving it — the admitted device resumes authority exactly here
    (store as unknown as FsyncPatch).fsyncDir = realFsyncDir;
    const recovered = registry.initialize();
    expect(recovered.ok).toBe(true);
    expect(registry.usable).toBe(true);
    expect(registry.activeDeviceCount).toBe(1);
    expect(registry.bootstrapGeneration).toBe(2);
  });

  it("a FAILED publish admits nothing: the invite burns, memory and disk stay consistent, registry stays usable", () => {
    const dir = freshDir();
    const path = join(dir, "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));

    // swap the whole directory for a file: the pinned directory identity
    // check refuses the publish — works whoever the uid is
    rmSync(dir, { recursive: true, force: true });
    writeFileSync(dir, "not a directory\n");

    const refused = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS());
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/durable registry publish FAILED/);
      expect(refused.inviteSurvives).toBe(false); // spent — the safe direction
    }
    // memory did NOT admit the device; the failed publish did not quarantine
    // (disk was never touched — memory still matches the last durable state)
    expect(registry.activeDeviceCount).toBe(0);
    expect(registry.bootstrapGeneration).toBe(1);
    // and the burned invite cannot be replayed once the disk heals
    rmSync(dir, { force: true });
    mkdirSync(dir, { recursive: true });
    const retry = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS());
    expect(retry.ok).toBe(false); // absent — mint a fresh invite
  });

  it('a hostile "__proto__" device id is CORRUPT, not an invisible record', () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const hostile = {
      version: 2,
      bootstrapGeneration: 1,
      owners: {},
      devices: {
        ["__proto__"]: {
          deviceId: "__proto__",
          ownerId: "owner-eve",
          deviceName: "ghost",
          credentialId: randomBytes(16).toString("base64url"),
          publicKeySpki: randomBytes(16).toString("base64url"),
          cheapLaneKeySpki: randomBytes(16).toString("base64url"),
          signCount: 0,
          generation: 1,
          revokedAt: null,
          enrolledAt: 1,
        },
      },
    };
    writeFileSync(path, JSON.stringify(hostile), { mode: 0o600 });
    const reloaded = registryAt(path);
    const init = reloaded.initialize();
    expect(init.ok).toBe(false);
    if (!init.ok) expect(init.detail).toMatch(/unexpected shape/);
    expect(reloaded.usable).toBe(false);
  });

  it("a CORRUPT registry refuses everything BEFORE the proof chain — a healthy registry's invite is untouched", () => {
    const path = join(freshDir(), "devices.json");
    const good = registryAt(path);
    good.initialize();
    writeFileSync(path, "{ not json", { mode: 0o600 });
    const corrupt = registryAt(path);
    expect(corrupt.initialize().ok).toBe(false);

    const healthy = registryAt(join(freshDir(), "devices.json"));
    healthy.initialize();
    const minted = healthy.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    const refused = corrupt.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS());
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/not usable/);
      expect(refused.inviteSurvives).toBe(true);
    }
    // the healthy registry still spends that same invite — proof it was untouched
    expect(healthy.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS()).ok).toBe(true);
  });

  it("DELETING the registry file after initialization is corruption; so is a symlinked or oversized marker", () => {
    const path = join(freshDir(), "devices.json");
    registryAt(path).initialize();
    rmSync(path);
    const afterDelete = registryAt(path).initialize();
    expect(afterDelete.ok).toBe(false);
    if (!afterDelete.ok) expect(afterDelete.detail).toMatch(/missing but the store is initialised/);

    // marker swapped for a symlink → corrupt, never followed
    const dir2 = freshDir();
    const path2 = join(dir2, "devices.json");
    registryAt(path2).initialize();
    rmSync(`${path2}.initialized`);
    symlinkSync(join(dir2, "elsewhere"), `${path2}.initialized`);
    const symlinked = registryAt(path2).initialize();
    expect(symlinked.ok).toBe(false);
    if (!symlinked.ok) expect(symlinked.detail).toMatch(/symlink/);
  });

  it("a marker MISSING next to existing state is re-established durably — and state loads only if that succeeds", () => {
    const path = join(freshDir(), "devices.json");
    registryAt(path).initialize();
    rmSync(`${path}.initialized`);
    // healthy path: the marker is recreated and the state loads
    const recovered = registryAt(path);
    expect(recovered.initialize().ok).toBe(true);
    // the marker is back — deleting the state NOW is corruption again
    rmSync(path);
    expect(registryAt(path).initialize().ok).toBe(false);
  });

  it("a mode that is not EXACTLY 0600 — on the state OR the marker — loads as corrupt", () => {
    const path = join(freshDir(), "devices.json");
    registryAt(path).initialize();
    chmodSync(path, 0o644);
    const badState = registryAt(path).initialize();
    expect(badState.ok).toBe(false);
    if (!badState.ok) expect(badState.detail).toMatch(/EXACTLY 0600/);

    const path2 = join(freshDir(), "devices.json");
    registryAt(path2).initialize();
    chmodSync(`${path2}.initialized`, 0o666);
    const badMarker = registryAt(path2).initialize();
    expect(badMarker.ok).toBe(false);
    if (!badMarker.ok) expect(badMarker.detail).toMatch(/EXACTLY 0600/);
  });

  it("a marker with foreign CONTENT or an oversized body is corrupt — the marker is a byte-exact constant", () => {
    const path = join(freshDir(), "devices.json");
    registryAt(path).initialize();
    writeFileSync(`${path}.initialized`, "SOMEONE ELSE'S NOTE\n", { mode: 0o600 });
    const foreign = registryAt(path).initialize();
    expect(foreign.ok).toBe(false);
    if (!foreign.ok) expect(foreign.detail).toMatch(/marker note/);

    const path2 = join(freshDir(), "devices.json");
    registryAt(path2).initialize();
    writeFileSync(`${path2}.initialized`, "x".repeat(5000), { mode: 0o600 });
    const oversized = registryAt(path2).initialize();
    expect(oversized.ok).toBe(false);
    if (!oversized.ok) expect(oversized.detail).toMatch(/bytes — not the marker/);
  });

  it("a stored key that is canonical base64url but NOT a real P-256 SPKI is corrupt", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    expect(registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS()).ok).toBe(true);
    // tamper: swap the persisted WebAuthn key for bytes that only LOOK like a key
    const raw = JSON.parse(readFileSync(path, "utf8")) as {
      devices: Record<string, { publicKeySpki: string }>;
    };
    for (const device of Object.values(raw.devices)) {
      device.publicKeySpki = randomBytes(40).toString("base64url");
    }
    writeFileSync(path, JSON.stringify(raw), { mode: 0o600 });
    const reloaded = registryAt(path).initialize();
    expect(reloaded.ok).toBe(false);
    if (!reloaded.ok) expect(reloaded.detail).toMatch(/unexpected shape/);
  });

  it("the store demands an ABSOLUTE path", () => {
    expect(() => new EnrolledDeviceFileStore("relative/devices.json", { unsafeAllowUntrustedAncestryForTests: true })).toThrow(
      /must be absolute/,
    );
  });

  it("ONE credential, ONE device — across the whole history: a replayed credential costs the invite", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const p = phone(); // the SAME phone, twice
    const inv1 = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    const first = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(inv1), SECRET), OPTS());
    expect(first.ok).toBe(true);
    const issuerId = first.ok ? first.device.deviceId : "";

    const secret2 = randomBytes(24).toString("base64url");
    const inv2 = registry.mintInvite(
      LIVE_KILL,
      mintRequest("inv-2", secret2, { kind: "device", deviceId: issuerId }),
    );
    const replay = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(inv2), secret2), OPTS());
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.reason).toMatch(/requires fresh keys/);
      expect(replay.inviteSurvives).toBe(false); // honest: the replay cost the invite
    }
    expect(registry.activeDeviceCount).toBe(1);
  });

  it("get()/list() and the success outcome hand out COPIES — mutating them changes nothing inside", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    const outcome = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS());
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    outcome.device.deviceName = "tampered";
    outcome.device.transports?.push("evil");
    const listed = registry.list()[0];
    expect(listed.deviceName).toBe("Adam's phone");
    expect(listed.transports ?? []).not.toContain("evil");
    listed.generation = 99;
    expect(registry.get(listed.deviceId)?.generation).toBe(1);
  });

  it("an UNINITIALIZED registry refuses everything", () => {
    const registry = registryAt(join(freshDir(), "devices.json"));
    expect(registry.usable).toBe(false);
    expect(() => registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET))).toThrow(/initialize/);
    const refused = registry.commitEnrollment({}, OPTS());
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.inviteSurvives).toBe(true);
  });

  it("V1 -> V2 MIGRATION: a genuine pre-owners registry loads, mints handles durably, and they stay stable across restarts", () => {
    const path = join(freshDir(), "devices.json");
    // build a GENUINE v1 file the v18-v21 code would have written: enroll a
    // device through the CURRENT code, then strip the owners table and set
    // version 1 — field-for-field the old shape
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    expect(registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS()).ok).toBe(true);
    const current = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    const legacy = {
      version: 1,
      bootstrapGeneration: current.bootstrapGeneration,
      devices: current.devices,
    };
    writeFileSync(path, JSON.stringify(legacy), { mode: 0o600 });

    // restart over the v1 file: migration mints an owner handle and publishes v2
    const migrated = registryAt(path);
    expect(migrated.initialize().ok).toBe(true);
    expect(migrated.activeDeviceCount).toBe(1);
    expect(migrated.bootstrapGeneration).toBe(2); // preserved, not reset
    const handle = migrated.ownerUserId("owner-adam");
    expect(handle).not.toBeNull();
    // the file on disk is v2 now
    const upgraded = JSON.parse(readFileSync(path, "utf8")) as { version: number; owners: Record<string, { userId: string }> };
    expect(upgraded.version).toBe(2);
    expect(upgraded.owners["owner-adam"].userId).toBe(handle);

    // and ANOTHER restart serves the SAME handle — minted once, durable
    const again = registryAt(path);
    expect(again.initialize().ok).toBe(true);
    expect(again.ownerUserId("owner-adam")).toBe(handle);

    // a v1 file that would NOT have validated under the old code is corrupt, not migrated
    writeFileSync(path, JSON.stringify({ ...legacy, extra: true }), { mode: 0o600 });
    expect(registryAt(path).initialize().ok).toBe(false);
  });

  it("MIGRATION CEILING: 129 distinct historical owners refuse BEFORE any publish; 128 migrate and reload", () => {
    const spki = () =>
      (generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
        type: "spki",
        format: "der",
      }) as Buffer).toString("base64url");
    const legacyWith = (ownerCount: number) => {
      const devices: Record<string, unknown> = {};
      for (let i = 0; i < ownerCount; i += 1) {
        devices[`dev_old_${i}`] = {
          deviceId: `dev_old_${i}`,
          ownerId: `owner-${i}`,
          deviceName: "old phone",
          credentialId: randomBytes(16).toString("base64url"),
          publicKeySpki: spki(),
          cheapLaneKeySpki: spki(),
          signCount: 0,
          generation: 1,
          revokedAt: 1, // historical: revoked, so the ACTIVE ceiling is untouched
          enrolledAt: 1,
        };
      }
      return { version: 1, bootstrapGeneration: 3, devices };
    };

    // 129 distinct owners: a VALID v1 file, but the owner-handle ceiling
    // refuses the migration before anything is generated or published
    const overPath = join(freshDir(), "devices.json");
    writeFileSync(overPath, JSON.stringify(legacyWith(129)), { mode: 0o600 });
    const over = registryAt(overPath);
    const refused = over.initialize();
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.detail).toMatch(/129 distinct owners exceed the 128/);
    expect(over.usable).toBe(false);
    // NOTHING was published: the file is still version 1
    expect((JSON.parse(readFileSync(overPath, "utf8")) as { version: number }).version).toBe(1);

    // exactly AT the ceiling: migrates, publishes v2, and a restart loads it
    const atPath = join(freshDir(), "devices.json");
    writeFileSync(atPath, JSON.stringify(legacyWith(128)), { mode: 0o600 });
    const at = registryAt(atPath);
    expect(at.initialize().ok).toBe(true);
    expect(at.ownerUserId("owner-0")).not.toBeNull();
    const reloaded = registryAt(atPath);
    expect(reloaded.initialize().ok).toBe(true);
    expect(reloaded.ownerUserId("owner-127")).toBe(at.ownerUserId("owner-127"));
  });

  it("REFERENTIAL INTEGRITY: a v2 file whose device names an owner without a handle is corrupt — no second identity can ever be minted", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const minted = registry.mintInvite(LIVE_KILL, mintRequest("inv-1", SECRET));
    expect(registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), OPTS()).ok).toBe(true);
    // tamper: drop the owner's handle while the device still names the owner
    const raw = JSON.parse(readFileSync(path, "utf8")) as { owners: Record<string, unknown> };
    raw.owners = {};
    writeFileSync(path, JSON.stringify(raw), { mode: 0o600 });
    const reloadedInit = registryAt(path).initialize();
    expect(reloadedInit.ok).toBe(false);
    if (!reloadedInit.ok) expect(reloadedInit.detail).toMatch(/unexpected shape/);
  });

  it("save() DIRECTLY refuses loader-invalid state — and the previous file's bytes are untouched", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const before = readFileSync(path, "utf8");
    const store = storeAt(path);
    // a state the loader would refuse (a device naming a handle-less owner)
    const invalid = {
      version: 2 as const,
      bootstrapGeneration: 1,
      devices: {
        dev_x: {
          deviceId: "dev_x",
          ownerId: "owner-ghost",
          deviceName: "ghost",
          credentialId: randomBytes(16).toString("base64url"),
          publicKeySpki: (generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
            type: "spki",
            format: "der",
          }) as Buffer).toString("base64url"),
          cheapLaneKeySpki: (generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({
            type: "spki",
            format: "der",
          }) as Buffer).toString("base64url"),
          signCount: 0,
          generation: 1,
          revokedAt: null,
          enrolledAt: 1,
        },
      },
      owners: {},
    };
    expect(() => store.save(invalid)).toThrow(/does not satisfy the loader's schema/);
    // nothing was written — byte for byte the previous publish
    expect(readFileSync(path, "utf8")).toBe(before);
  });

  it("PACKAGE SURFACE: no invite store, no witness, no low-level spend — the registry is the only door", () => {
    const surface = Object.keys(packageApi);
    for (const name of surface) {
      expect(name).not.toMatch(/^performEnrollment$|^InviteStore$|consume|claim|witness/i);
    }
    // the two doors that DO exist
    expect(typeof packageApi.EnrolledDeviceRegistry).toBe("function");
    expect(typeof packageApi.EnrolledDeviceFileStore).toBe("function");
  });
});
