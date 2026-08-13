import { createHash, generateKeyPairSync, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { InviteStore, type InviteSpendWitness } from "./invite.js";
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
  killEpoch: 0,
  origin:
    kind === "bootstrap"
      ? ({ kind: "bootstrap", bootstrapGeneration: 1 } as const)
      : ({ kind: "device", deviceId: "phone-1", deviceGeneration: 1 } as const),
});

/** A witness where everything is still live — each test flips ONE fact. */
const LIVE: InviteSpendWitness = {
  killEpoch: 0,
  bootstrapGeneration: 1,
  deviceStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 1,
};

describe("InviteStore — hash commitment, single use, TTL, live-witness spend", () => {
  it("stores only the COMMITMENT and spends exactly once on the correct preimage", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const minted = store.register(record("inv-1", SECRET_1));
    // the record carries the hash, never the secret
    expect(JSON.stringify(minted)).not.toContain(SECRET_1);

    expect(store.consume("inv-1", SECRET_1, LIVE).ok).toBe(true);
    // burned: the same preimage opens nothing twice
    expect(store.consume("inv-1", SECRET_1, LIVE).ok).toBe(false);
  });

  it("a FAILED attempt does not burn the invite; a non-canonical secret never reaches the comparison", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));
    expect(store.consume("inv-1", SECRET_2, LIVE).ok).toBe(false); // wrong preimage
    const short = store.consume("inv-1", "1234", LIVE); // human-typed junk: refused by FORMAT
    expect(short.ok).toBe(false);
    if (!short.ok) expect(short.reason).toMatch(/canonical token/);
    // still alive for the real preimage
    expect(store.consume("inv-1", SECRET_1, LIVE).ok).toBe(true);
  });

  it("KILL EPOCH: an invite minted before a kill is dead after it — even after a restore", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // minted at epoch 0
    // a kill (and restore) advanced the epoch; the invite must not survive it
    const spent = store.consume("inv-1", SECRET_1, { ...LIVE, killEpoch: 1 });
    expect(spent.ok).toBe(false);
    if (!spent.ok) expect(spent.reason).toMatch(/kill epoch/);
    // and it is GONE, not retryable at the old epoch
    expect(store.consume("inv-1", SECRET_1, LIVE).ok).toBe(false);
  });

  it("ISSUER STANDING: a revoked or generation-bumped minting device kills its unspent invites", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1, "device")); // minted by phone-1@gen1
    // phone-1 was revoked (or re-enrolled at a new generation) before the spend
    const revoked = store.consume("inv-1", SECRET_1, { ...LIVE, deviceStanding: () => false });
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) expect(revoked.reason).toMatch(/no longer in standing/);

    // generation mismatch alone refuses too — the witness receives the
    // MINTING generation and must match it exactly
    store.register(record("inv-2", SECRET_2, "device"));
    const bumped = store.consume("inv-2", SECRET_2, {
      ...LIVE,
      deviceStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 2,
    });
    expect(bumped.ok).toBe(false);
  });

  it("BOOTSTRAP GENERATION: a superseded bootstrap generation refuses the spend", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // bootstrapGeneration 1
    const stale = store.consume("inv-1", SECRET_1, { ...LIVE, bootstrapGeneration: 2 });
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.reason).toMatch(/bootstrap generation/);
  });

  it("FIRST PHONE WINS, atomically: a successful bootstrap spend burns every bootstrap sibling in the same step", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("boot-1", SECRET_1, "bootstrap"));
    store.register(record("boot-2", SECRET_2, "bootstrap"));
    store.register(record("dev-1", SECRET_3, "device"));

    expect(store.consume("boot-1", SECRET_1, LIVE).ok).toBe(true);
    // the RACE the review named: boot-2's spend arrives right after — there is
    // no window between consume and any separate invalidation call
    expect(store.consume("boot-2", SECRET_2, LIVE).ok).toBe(false);
    // device-minted flow untouched
    expect(store.consume("dev-1", SECRET_3, LIVE).ok).toBe(true);
  });

  it("expires by TTL, sweeps, and enforces the live-invite cap", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now, ttlMs: 60_000, maxInvites: 2 });
    store.register(record("inv-1", SECRET_1));
    store.register(record("inv-2", SECRET_2));
    expect(() => store.register(record("inv-3", SECRET_3))).toThrow(/too many/);
    c.advance(60_001);
    expect(store.consume("inv-1", SECRET_1, LIVE).ok).toBe(false); // expired
    store.register(record("inv-3", SECRET_3)); // the sweep freed the cap
    expect(store.size).toBe(1);
  });

  it("refuses malformed records at mint: bad commitment, duplicate id, missing authority fields", () => {
    const store = new InviteStore();
    expect(() => store.register({ ...record("inv-1", SECRET_1), tokenHash: "not-a-hash" })).toThrow(/43/);
    store.register(record("inv-2", SECRET_1));
    expect(() => store.register(record("inv-2", SECRET_2))).toThrow(/already exists/);
    expect(() => store.register({ ...record("inv-3", SECRET_3), killEpoch: -1 })).toThrow(/killEpoch/);
    expect(() =>
      store.register({
        ...record("inv-4", SECRET_3),
        origin: { kind: "device", deviceId: "", deviceGeneration: 1 },
      }),
    ).toThrow(/deviceId/);
    expect(() =>
      store.register({
        ...record("inv-5", SECRET_3),
        origin: { kind: "device", deviceId: "phone-1", deviceGeneration: 0 },
      }),
    ).toThrow(/generation/);
  });

  it("hands out FROZEN copies — a caller cannot mutate the store's authority state", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const minted = store.register(record("inv-1", SECRET_1));
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
