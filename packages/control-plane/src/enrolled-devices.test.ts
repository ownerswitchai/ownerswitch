import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
import { InviteStore } from "./invite.js";

/**
 * The persistence half of the ceremony: witnesses assembled ONLY from live
 * state, the crash-atomic admit (device + bootstrap-generation bump in one
 * publish), and the fail-closed registry. Every spend here drives the full
 * ceremony — there is no other way to reach the burn.
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
const registryAt = (path: string) =>
  new EnrolledDeviceRegistry(new EnrolledDeviceFileStore(path), {
    deviceIdFactory: () => `dev_test_${(deviceSeq += 1)}`,
  });

function mintRequest(inviteId: string, secret: string, issuer: { kind: "bootstrap" } | { kind: "device"; deviceId: string } = { kind: "bootstrap" }) {
  return {
    inviteId,
    tokenHash: createHash("sha256").update(secret, "utf8").digest("base64url"),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
    challenge: randomBytes(32).toString("base64url"),
    assertionChallenge: randomBytes(32).toString("base64url"),
    issuer,
  };
}

const fixtureInvite = (record: { inviteId: string; ownerId: string; deviceName: string; challenge: string; assertionChallenge: string }): FixtureInvite => record;

describe("EnrolledDeviceRegistry — durable, crash-atomic, witness-from-live-state", () => {
  const SECRET = randomBytes(24).toString("base64url");

  it("first boot persists generation 1 durably; a fresh instance reloads it", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    expect(registry.initialize().ok).toBe(true);
    expect(registry.usable).toBe(true);
    expect(registry.bootstrapGeneration).toBe(1);
    expect(registry.activeDeviceCount).toBe(0);
    // reload from disk in a brand-new instance: same state, marker honoured
    const again = registryAt(path);
    expect(again.initialize().ok).toBe(true);
    expect(again.bootstrapGeneration).toBe(1);
  });

  it("the full ceremony admits a device: durable record + bootstrap-generation bump in ONE publish", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    const minted = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));
    expect(minted.origin).toEqual({ kind: "bootstrap", bootstrapGeneration: 1 });
    expect(minted.killEpoch).toBe(0);

    const p = phone();
    const outcome = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(minted), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.device.deviceName).toBe("Adam's phone");
      expect(outcome.device.ownerId).toBe("owner-adam");
      expect(outcome.device.generation).toBe(1);
      expect(outcome.device.signCount).toBe(4); // the possession assertion's counter
      expect(outcome.durable).toBe(true);
    }
    expect(registry.activeDeviceCount).toBe(1);
    // the bootstrap lane closed DURABLY with the admit — same publish
    expect(registry.bootstrapGeneration).toBe(2);

    // a restart sees the SAME facts: the device and the bump were one write
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

  it("after the first phone, a bootstrap invite minted under the OLD generation is dead — and the registry refuses a second root", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    // two bootstrap invites minted before any phone enrolls
    const inv1 = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));
    const secret2 = randomBytes(24).toString("base64url");
    registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-2", secret2));

    expect(
      registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv1), SECRET), {
        invites,
        kill: LIVE_KILL,
        rpId: FIXTURE_RP_ID,
        expectedOrigin: FIXTURE_ORIGIN,
      }).ok,
    ).toBe(true);
    // the sibling was burned atomically at the spend; and a NEW bootstrap
    // mint into the now-occupied registry refuses AT THE MINT — the
    // register() live-witness gate, one step earlier than the spend check
    const secret3 = randomBytes(24).toString("base64url");
    expect(() => registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-3", secret3))).toThrow(
      /EMPTY registry/,
    );
  });

  it("an enrolled device invites the SECOND phone; a revoked-in-file issuer cannot", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    const inv1 = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));
    const first = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv1), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(first.ok).toBe(true);
    const issuerId = first.ok ? first.device.deviceId : "";

    // the enrolled phone mints for the second phone — issuer generation
    // comes from the REGISTRY, not the request
    const secret2 = randomBytes(24).toString("base64url");
    const inv2 = registry.mintInvite(
      invites,
      LIVE_KILL,
      mintRequest("inv-2", secret2, { kind: "device", deviceId: issuerId }),
    );
    expect(inv2.origin).toEqual({ kind: "device", deviceId: issuerId, deviceGeneration: 1 });
    const second = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(inv2), secret2), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(second.ok).toBe(true);
    expect(registry.activeDeviceCount).toBe(2);

    // an unknown issuer mints nothing
    expect(() =>
      registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-3", SECRET, { kind: "device", deviceId: "dev_ghost" })),
    ).toThrow(/not enrolled and in standing/);
  });

  it("a KILLED system mints nothing and a spend attempt under kill burns (through the registry witness)", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    expect(() =>
      registry.mintInvite(invites, { killed: true, epoch: 0 }, mintRequest("inv-1", SECRET)),
    ).toThrow(/nothing MINTS while killed/);

    const minted = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-2", SECRET));
    const killedSpend = registry.commitEnrollment(
      enrollmentSubmission(phone(), fixtureInvite(minted), SECRET),
      { invites, kill: { killed: true, epoch: 0 }, rpId: FIXTURE_RP_ID, expectedOrigin: FIXTURE_ORIGIN },
    );
    expect(killedSpend.ok).toBe(false);
    if (!killedSpend.ok) {
      expect(killedSpend.reason).toMatch(/kill switch/);
      expect(killedSpend.inviteSurvives).toBe(false); // burned, not held open
    }
    // a MALFORMED kill snapshot refuses fail-closed, before the chain
    const malformed = registry.commitEnrollment(
      enrollmentSubmission(phone(), fixtureInvite(minted), SECRET),
      {
        invites,
        kill: { killed: "no" as unknown as boolean, epoch: 0 },
        rpId: FIXTURE_RP_ID,
        expectedOrigin: FIXTURE_ORIGIN,
      },
    );
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.inviteSurvives).toBe(true);
  });

  it("a CORRUPT registry refuses everything — and the refusal comes BEFORE the proof chain, invite untouched", () => {
    const path = join(freshDir(), "devices.json");
    const good = registryAt(path);
    good.initialize();
    // tamper: garbage where the registry should be
    writeFileSync(path, "{ not json", { mode: 0o600 });
    const registry = registryAt(path);
    const init = registry.initialize();
    expect(init.ok).toBe(false);
    expect(registry.usable).toBe(false);

    const invites = new InviteStore();
    // mint an invite via a SEPARATE healthy registry dir, then try to spend
    // against the corrupt one — the refusal must not touch the invite
    const healthy = registryAt(join(freshDir(), "devices.json"));
    healthy.initialize();
    const minted = healthy.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));
    const refused = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/not usable/);
      expect(refused.inviteSurvives).toBe(true);
    }
    // witnesses and mints refuse too
    expect(() => registry.liveWitness(LIVE_KILL)).toThrow(/not usable/);
    expect(() => registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-2", SECRET))).toThrow(
      /not usable/,
    );
  });

  it("DELETING the registry file after initialization is corruption, not a fresh start", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    rmSync(path);
    const reloaded = registryAt(path);
    const init = reloaded.initialize();
    expect(init.ok).toBe(false);
    if (!init.ok) expect(init.detail).toMatch(/missing but the store is initialised/);
  });

  it("a mode that is not EXACTLY 0600 loads as corrupt — the registry is private authorization state", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    chmodSync(path, 0o644);
    const reloaded = registryAt(path);
    const init = reloaded.initialize();
    expect(init.ok).toBe(false);
    if (!init.ok) expect(init.detail).toMatch(/EXACTLY 0600/);
  });

  it("a FAILED durable publish admits nothing: the invite burns, memory and disk stay consistent", () => {
    const dir = freshDir();
    const path = join(dir, "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    const minted = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));

    // sabotage the NEXT publish: the temp-file create needs the directory,
    // so replacing the directory with a plain file makes save() throw —
    // works whoever the uid is (chmod tricks do not bind root)
    rmSync(dir, { recursive: true, force: true });
    writeFileSync(dir, "not a directory\n");

    const refused = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/durable registry publish FAILED/);
      expect(refused.inviteSurvives).toBe(false); // spent — the safe direction
    }
    // memory did NOT admit the device
    expect(registry.activeDeviceCount).toBe(0);
    expect(registry.bootstrapGeneration).toBe(1);
    // and the burned invite cannot be replayed once the disk heals
    rmSync(dir, { force: true });
    mkdirSync(dir, { recursive: true });
    const retry = registry.commitEnrollment(enrollmentSubmission(phone(), fixtureInvite(minted), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(retry.ok).toBe(false); // absent — mint a fresh invite
  });

  it("ONE credential, ONE device: replaying an enrolled credential into a second invite costs the invite", () => {
    const path = join(freshDir(), "devices.json");
    const registry = registryAt(path);
    registry.initialize();
    const invites = new InviteStore();
    const p = phone(); // the SAME phone, twice
    const inv1 = registry.mintInvite(invites, LIVE_KILL, mintRequest("inv-1", SECRET));
    const first = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(inv1), SECRET), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(first.ok).toBe(true);
    const issuerId = first.ok ? first.device.deviceId : "";

    const secret2 = randomBytes(24).toString("base64url");
    const inv2 = registry.mintInvite(
      invites,
      LIVE_KILL,
      mintRequest("inv-2", secret2, { kind: "device", deviceId: issuerId }),
    );
    const replay = registry.commitEnrollment(enrollmentSubmission(p, fixtureInvite(inv2), secret2), {
      invites,
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.reason).toMatch(/already enrolled/);
      expect(replay.inviteSurvives).toBe(false); // honest: the replay cost the invite
    }
    expect(registry.activeDeviceCount).toBe(1);
  });

  it("an UNINITIALIZED registry refuses witnesses, mints, and enrollments", () => {
    const registry = registryAt(join(freshDir(), "devices.json"));
    // no initialize() call
    expect(registry.usable).toBe(false);
    expect(() => registry.liveWitness(LIVE_KILL)).toThrow(/initialize/);
    const refused = registry.commitEnrollment({}, {
      invites: new InviteStore(),
      kill: LIVE_KILL,
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.inviteSurvives).toBe(true);
  });
});
