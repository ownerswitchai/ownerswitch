import { createHash, generateKeyPairSync, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import * as inviteModule from "./invite.js";
import { InviteStore, performEnrollment, type InviteSpendWitness } from "./invite.js";
import {
  enrollmentSubmission,
  FIXTURE_ORIGIN,
  FIXTURE_RP_ID,
  phone,
} from "./enroll-fixture.js";
import { enrolledOwnerDeviceFromSpki, verifyEnrollProofOfPossession } from "./owner-device.js";

const clock = (start = 1_000) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

// canonical ≥128-bit tokens, as the mint contract generates them
const SECRET_1 = Buffer.from("s1".repeat(12)).toString("base64url");
const SECRET_2 = Buffer.from("s2".repeat(12)).toString("base64url");
const SECRET_3 = Buffer.from("s3".repeat(12)).toString("base64url");
const commit = (secret: string) => createHash("sha256").update(secret, "utf8").digest("base64url");

const record = (inviteId: string, secret: string, kind: "bootstrap" | "device" = "bootstrap") => ({
  inviteId,
  tokenHash: commit(secret),
  ownerId: "owner-adam",
  deviceName: "Adam's phone",
  challenge: Buffer.from("ch".repeat(16)).toString("base64url"),
  assertionChallenge: Buffer.from("ac".repeat(16)).toString("base64url"),
  killEpoch: 0,
  origin:
    kind === "bootstrap"
      ? ({ kind: "bootstrap", bootstrapGeneration: 1 } as const)
      : ({ kind: "device", deviceId: "phone-1", deviceGeneration: 1 } as const),
});

/** A witness where everything is still live — each test flips ONE fact. */
const LIVE: InviteSpendWitness = {
  killed: false,
  killEpoch: 0,
  bootstrapGeneration: 1,
  activeDeviceCount: 0,
  deviceStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 1,
};

/**
 * The store has NO public spend method — the only spend path is the full
 * ceremony through performEnrollment (same module as the burn). Every spend
 * in these tests therefore drives the complete proof chain with a synthetic
 * phone; what each test varies is the invite's authority state and the live
 * witness at the moment of the burn.
 */
const spend = (
  store: InviteStore,
  invite: ReturnType<typeof record>,
  secret: string,
  witness: InviteSpendWitness = LIVE,
) =>
  performEnrollment(enrollmentSubmission(phone(), invite, secret), {
    store,
    witness,
    rpId: FIXTURE_RP_ID,
    expectedOrigin: FIXTURE_ORIGIN,
  });

describe("InviteStore — hash commitment, single use, TTL, live-witness mint AND spend", () => {
  it("stores only the COMMITMENT and spends exactly once on the correct preimage", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    const minted = store.register(inv, LIVE);
    // the record carries the hash, never the secret
    expect(JSON.stringify(minted)).not.toContain(SECRET_1);

    expect(spend(store, inv, SECRET_1).ok).toBe(true);
    // burned: the same preimage opens nothing twice
    expect(spend(store, inv, SECRET_1).ok).toBe(false);
  });

  it("a FAILED attempt does not burn the invite; a non-canonical secret never reaches the comparison", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE);
    const wrong = spend(store, inv, SECRET_2); // wrong preimage
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.inviteSurvives).toBe(true);
    const short = spend(store, inv, "1234"); // human-typed junk: refused by FORMAT
    expect(short.ok).toBe(false);
    if (!short.ok) {
      expect(short.reason).toMatch(/canonical token/);
      expect(short.inviteSurvives).toBe(true);
    }
    // still alive for the real preimage
    expect(spend(store, inv, SECRET_1).ok).toBe(true);
  });

  it("KILL EPOCH: an invite minted before a kill is dead after it — even after a restore", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE); // minted at epoch 0
    // a kill (and restore) advanced the epoch; the invite must not survive it
    const spent = spend(store, inv, SECRET_1, { ...LIVE, killEpoch: 1 });
    expect(spent.ok).toBe(false);
    if (!spent.ok) {
      expect(spent.reason).toMatch(/kill epoch/);
      expect(spent.inviteSurvives).toBe(false); // burned, honestly
    }
    // and it is GONE, not retryable at the old epoch
    expect(spend(store, inv, SECRET_1).ok).toBe(false);
  });

  it("KILLED at spend BURNS the attempted invite — nothing is held open across a kill", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE);
    const killed = spend(store, inv, SECRET_1, { ...LIVE, killed: true });
    expect(killed.ok).toBe(false);
    if (!killed.ok) {
      expect(killed.reason).toMatch(/kill switch/);
      expect(killed.inviteSurvives).toBe(false);
    }
    // gone: a restore that does NOT advance the epoch still finds nothing
    const after = spend(store, inv, SECRET_1);
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.inviteSurvives).toBe(false); // absent
  });

  it("MINT is bound to live state: killed, stale epoch, stale generation, or an out-of-standing issuer cannot mint", () => {
    const store = new InviteStore();
    expect(() => store.register(record("inv-1", SECRET_1), { ...LIVE, killed: true })).toThrow(
      /nothing MINTS while killed/,
    );
    expect(() => store.register(record("inv-2", SECRET_2), { ...LIVE, killEpoch: 3 })).toThrow(
      /CURRENT kill epoch/,
    );
    expect(() => store.register(record("inv-3", SECRET_3), { ...LIVE, bootstrapGeneration: 2 })).toThrow(
      /CURRENT bootstrap generation/,
    );
    expect(() => store.register(record("inv-4", SECRET_1), { ...LIVE, activeDeviceCount: 1 })).toThrow(
      /EMPTY registry/,
    );
    expect(() =>
      store.register(record("inv-5", SECRET_2, "device"), { ...LIVE, deviceStanding: () => false }),
    ).toThrow(/not in standing/);
    expect(() =>
      store.register(record("inv-6", SECRET_3, "device"), {
        ...LIVE,
        deviceStanding: () => {
          throw new Error("registry down");
        },
      }),
    ).toThrow(/FAILED at mint/);
    expect(() =>
      store.register(record("inv-7", SECRET_1), { ...LIVE, killed: "no" as unknown as boolean }),
    ).toThrow(/malformed mint witness/);
    // and nothing was minted by any of it
    expect(store.size).toBe(0);
  });

  it("ISSUER STANDING: a revoked or generation-bumped minting device kills its unspent invites", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv1 = record("inv-1", SECRET_1, "device");
    store.register(inv1, LIVE); // minted by phone-1@gen1
    // phone-1 was revoked (or re-enrolled at a new generation) before the spend
    const revoked = spend(store, inv1, SECRET_1, { ...LIVE, deviceStanding: () => false });
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) {
      expect(revoked.reason).toMatch(/no longer in standing/);
      expect(revoked.inviteSurvives).toBe(false); // burned
    }

    // generation mismatch alone refuses too — the witness receives the
    // MINTING generation and must match it exactly
    const inv2 = record("inv-2", SECRET_2, "device");
    store.register(inv2, LIVE);
    const bumped = spend(store, inv2, SECRET_2, {
      ...LIVE,
      deviceStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 2,
    });
    expect(bumped.ok).toBe(false);
  });

  it("BOOTSTRAP GENERATION: a superseded bootstrap generation refuses the spend", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE); // bootstrapGeneration 1
    const stale = spend(store, inv, SECRET_1, { ...LIVE, bootstrapGeneration: 2 });
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.reason).toMatch(/bootstrap generation/);
  });

  it("FIRST PHONE WINS, atomically: a successful bootstrap spend burns every bootstrap sibling in the same step", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const boot1 = record("boot-1", SECRET_1, "bootstrap");
    const boot2 = record("boot-2", SECRET_2, "bootstrap");
    const dev1 = record("dev-1", SECRET_3, "device");
    store.register(boot1, LIVE);
    store.register(boot2, LIVE);
    store.register(dev1, LIVE);

    expect(spend(store, boot1, SECRET_1).ok).toBe(true);
    // the RACE the review named: boot-2's spend arrives right after — there is
    // no window between consume and any separate invalidation call
    expect(spend(store, boot2, SECRET_2).ok).toBe(false);
    // device-minted flow untouched
    expect(spend(store, dev1, SECRET_3).ok).toBe(true);
  });

  it("expires by TTL, sweeps, and enforces the live-invite cap", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now, ttlMs: 60_000, maxInvites: 2 });
    const inv1 = record("inv-1", SECRET_1);
    store.register(inv1, LIVE);
    store.register(record("inv-2", SECRET_2), LIVE);
    expect(() => store.register(record("inv-3", SECRET_3), LIVE)).toThrow(/too many/);
    c.advance(60_001);
    const expired = spend(store, inv1, SECRET_1); // expired
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.inviteSurvives).toBe(false); // absent
    store.register(record("inv-3", SECRET_3), LIVE); // the sweep freed the cap
    expect(store.size).toBe(1);
  });

  it("refuses malformed records at mint: bad commitment, duplicate id, missing authority fields", () => {
    const store = new InviteStore();
    expect(() =>
      store.register({ ...record("inv-1", SECRET_1), tokenHash: "not-a-hash" }, LIVE),
    ).toThrow(/43/);
    store.register(record("inv-2", SECRET_1), LIVE);
    expect(() => store.register(record("inv-2", SECRET_2), LIVE)).toThrow(/already exists/);
    expect(() => store.register({ ...record("inv-3", SECRET_3), killEpoch: -1 }, LIVE)).toThrow(
      /killEpoch/,
    );
    expect(() =>
      store.register(
        {
          ...record("inv-4", SECRET_3),
          origin: { kind: "device", deviceId: "", deviceGeneration: 1 },
        },
        LIVE,
      ),
    ).toThrow(/deviceId/);
    expect(() =>
      store.register(
        {
          ...record("inv-5", SECRET_3),
          origin: { kind: "device", deviceId: "phone-1", deviceGeneration: 0 },
        },
        LIVE,
      ),
    ).toThrow(/generation/);
  });

  it("THERE IS NO SPEND DOOR: no public method, no reachable record map, no claimable capability", () => {
    const store = new InviteStore();
    // no consume — as a method, a property, or anything else on the instance
    expect((store as unknown as Record<string, unknown>)["consume"]).toBeUndefined();
    // the record map is an ECMAScript #private field — property access from
    // outside the module finds nothing to mint into or burn from
    expect((store as unknown as Record<string, unknown>)["invites"]).toBeUndefined();
    // the prototype's whole public surface, pinned: registering, reading,
    // sweeping — no spending
    expect(Object.getOwnPropertyNames(InviteStore.prototype).sort()).toEqual([
      "constructor",
      "invalidateSupersededEpoch",
      "peek",
      "register",
      "size",
    ]);
    // and the MODULE exports no minter, brand, claim, or authorization to
    // race for — the one spend path is performEnrollment, which is the full
    // proof chain, not a capability
    for (const name of Object.keys(inviteModule)) {
      expect(name).not.toMatch(/consume|claim|mint|authorization|brand/i);
    }
    expect(typeof inviteModule.performEnrollment).toBe("function");
  });

  it("a THROWING standing callback is a failed check (burned), never an escaping exception", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1, "device");
    store.register(inv, LIVE);
    const thrown = spend(store, inv, SECRET_1, {
      ...LIVE,
      deviceStanding: () => {
        throw new Error("registry unavailable");
      },
    });
    expect(thrown.ok).toBe(false);
    if (!thrown.ok) {
      expect(thrown.reason).toMatch(/FAILED/);
      expect(thrown.inviteSurvives).toBe(false); // burned
    }
  });

  it("a MALFORMED witness proves nothing and spends nothing (fail closed, invite alive)", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE);
    const bad = spend(store, inv, SECRET_1, { ...LIVE, killed: "no" as unknown as boolean });
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.reason).toMatch(/malformed live witness/);
      expect(bad.inviteSurvives).toBe(true);
    }
    // a truthy-but-not-true standing answer is NOT standing
    const dev = record("dev-1", SECRET_2, "device");
    store.register(dev, LIVE);
    const truthy = spend(store, dev, SECRET_2, {
      ...LIVE,
      deviceStanding: (() => 1) as unknown as (d: string, g: number) => boolean,
    });
    expect(truthy.ok).toBe(false);
  });

  it("BOOTSTRAP + ACTIVE DEVICE: a bootstrap invite enrolls only into an EMPTY registry", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1);
    store.register(inv, LIVE); // bootstrap, generation current
    const occupied = spend(store, inv, SECRET_1, { ...LIVE, activeDeviceCount: 1 });
    expect(occupied.ok).toBe(false);
    if (!occupied.ok) expect(occupied.reason).toMatch(/EMPTY registry/);
  });

  it("REENTRANCY: a spend re-entered from inside deviceStanding() cannot double-spend", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const inv = record("inv-1", SECRET_1, "device");
    store.register(inv, LIVE);
    const submission = enrollmentSubmission(phone(), inv, SECRET_1);
    let inner: ReturnType<typeof performEnrollment> | null = null;
    const outer = performEnrollment(submission, {
      store,
      witness: {
        ...LIVE,
        deviceStanding: () => {
          // the hostile callback re-enters the same spend — the record was
          // RESERVED before this callback ran, so the inner chain's peek
          // finds nothing
          inner = performEnrollment(submission, {
            store,
            witness: LIVE,
            rpId: FIXTURE_RP_ID,
            expectedOrigin: FIXTURE_ORIGIN,
          });
          return true;
        },
      },
      rpId: FIXTURE_RP_ID,
      expectedOrigin: FIXTURE_ORIGIN,
    });
    expect(outer.ok).toBe(true);
    expect(inner).not.toBeNull();
    expect((inner as unknown as { ok: boolean }).ok).toBe(false); // exactly ONE success
  });

  it("INPUT ALIASING: mutating the caller's origin object after register() changes nothing in the store", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const input = record("inv-1", SECRET_1, "device");
    store.register(input, LIVE);
    // the caller rewrites its own object — a stale issuer trying to look current
    (input.origin as { deviceGeneration: number }).deviceGeneration = 99;
    // the STORE's copy still demands the minting generation (1)
    const spent = spend(store, input, SECRET_1, {
      ...LIVE,
      deviceStanding: (_id, generation) => generation === 1,
    });
    expect(spent.ok).toBe(true);
  });

  it("EPOCH SWEEP: invalidateSupersededEpoch frees dead invites from the cap immediately", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1), LIVE); // epoch 0
    store.register({ ...record("inv-2", SECRET_2), killEpoch: 1 }, { ...LIVE, killEpoch: 1 });
    expect(store.invalidateSupersededEpoch(1)).toBe(1); // inv-1 dies with epoch 0
    expect(store.size).toBe(1);
  });

  it("hands out FROZEN copies — a caller cannot mutate the store's authority state", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const minted = store.register(record("inv-1", SECRET_1), LIVE);
    expect(Object.isFrozen(minted)).toBe(true);
    expect(Object.isFrozen(minted.origin)).toBe(true);
    expect(() => {
      (minted as { killEpoch: number }).killEpoch = 99;
    }).toThrow();
    const peeked = store.peek("inv-1");
    expect(peeked && Object.isFrozen(peeked)).toBe(true);
  });
});

describe("verifyEnrollProofOfPossession — the ceremony transcript", () => {
  const kp = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const device = enrolledOwnerDeviceFromSpki(
    "phone-new",
    kp.publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const credentialId = Buffer.from("credential-id-bytes-0001").toString("base64url");
  const fields = { inviteId: "inv-1", ownerId: "owner-adam", credentialId };

  const signPop = (over: Partial<typeof fields> = {}) => {
    const f = { ...fields, ...over };
    const preimage = ownerEnrollPopPreimage({
      inviteId: f.inviteId,
      ownerId: f.ownerId,
      credentialId: new Uint8Array(Buffer.from(f.credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    return ecSign("sha256", preimage, { key: kp.privateKey, dsaEncoding: "ieee-p1363" }).toString(
      "base64url",
    );
  };

  it("accepts the key's own signature over the exact ceremony transcript", () => {
    expect(verifyEnrollProofOfPossession({ ...fields, device, proof: signPop() })).toBe(true);
  });

  it("binds every field: another invite, owner, or credential cannot reuse the proof", () => {
    const proof = signPop();
    expect(verifyEnrollProofOfPossession({ ...fields, inviteId: "inv-2", device, proof })).toBe(false);
    expect(verifyEnrollProofOfPossession({ ...fields, ownerId: "owner-eve", device, proof })).toBe(false);
    expect(
      verifyEnrollProofOfPossession({
        ...fields,
        credentialId: Buffer.from("other-credential").toString("base64url"),
        device,
        proof,
      }),
    ).toBe(false);
  });

  it("a DIFFERENT key's signature never proves possession of this one", () => {
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const preimage = ownerEnrollPopPreimage({
      inviteId: fields.inviteId,
      ownerId: fields.ownerId,
      credentialId: new Uint8Array(Buffer.from(credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    const forged = ecSign("sha256", preimage, { key: other.privateKey, dsaEncoding: "ieee-p1363" });
    expect(
      verifyEnrollProofOfPossession({ ...fields, device, proof: forged.toString("base64url") }),
    ).toBe(false);
  });

  it("refuses DER signatures, NON-CANONICAL base64url, and empty fields", () => {
    const preimage = ownerEnrollPopPreimage({
      inviteId: fields.inviteId,
      ownerId: fields.ownerId,
      credentialId: new Uint8Array(Buffer.from(credentialId, "base64url")),
      spki: new Uint8Array(device.publicKey.export({ type: "spki", format: "der" })),
    });
    const der = ecSign("sha256", preimage, kp.privateKey).toString("base64url"); // default DER
    expect(verifyEnrollProofOfPossession({ ...fields, device, proof: der })).toBe(false);
    // a proof with characters the permissive decoder would silently DROP
    expect(verifyEnrollProofOfPossession({ ...fields, device, proof: `${signPop()}!` })).toBe(false);
    // a credentialId whose repair would change the transcript bytes
    expect(
      verifyEnrollProofOfPossession({ ...fields, credentialId: "AB=CD", device, proof: signPop() }),
    ).toBe(false);
    expect(verifyEnrollProofOfPossession({ ...fields, inviteId: "", device, proof: signPop() })).toBe(
      false,
    );
  });
});
