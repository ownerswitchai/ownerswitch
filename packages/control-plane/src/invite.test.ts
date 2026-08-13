import { createHash, generateKeyPairSync, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import {
  claimSpendMinter,
  InviteStore,
  SpendAuthorization,
  type InviteSpendWitness,
} from "./invite.js";
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

// This test file's module registry has not loaded enrollment.ts, so the
// ONE claim is available here; in the real package graph enrollment.ts
// claims it at import time and every later claimant throws.
const mintAuth = claimSpendMinter();
const auth = (inviteId: string) => mintAuth(inviteId);

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

describe("InviteStore — hash commitment, single use, TTL, live-witness spend", () => {
  it("stores only the COMMITMENT and spends exactly once on the correct preimage", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const minted = store.register(record("inv-1", SECRET_1));
    // the record carries the hash, never the secret
    expect(JSON.stringify(minted)).not.toContain(SECRET_1);

    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(true);
    // burned: the same preimage opens nothing twice
    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(false);
  });

  it("a FAILED attempt does not burn the invite; a non-canonical secret never reaches the comparison", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));
    expect(store.consume("inv-1", SECRET_2, LIVE, auth("inv-1")).ok).toBe(false); // wrong preimage
    const short = store.consume("inv-1", "1234", LIVE, auth("inv-1")); // human-typed junk: refused by FORMAT
    expect(short.ok).toBe(false);
    if (!short.ok) expect(short.reason).toMatch(/canonical token/);
    // still alive for the real preimage
    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(true);
  });

  it("KILL EPOCH: an invite minted before a kill is dead after it — even after a restore", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // minted at epoch 0
    // a kill (and restore) advanced the epoch; the invite must not survive it
    const spent = store.consume("inv-1", SECRET_1, { ...LIVE, killEpoch: 1 }, auth("inv-1"));
    expect(spent.ok).toBe(false);
    if (!spent.ok) expect(spent.reason).toMatch(/kill epoch/);
    // and it is GONE, not retryable at the old epoch
    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(false);
  });

  it("ISSUER STANDING: a revoked or generation-bumped minting device kills its unspent invites", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1, "device")); // minted by phone-1@gen1
    // phone-1 was revoked (or re-enrolled at a new generation) before the spend
    const revoked = store.consume("inv-1", SECRET_1, { ...LIVE, deviceStanding: () => false }, auth("inv-1"));
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) expect(revoked.reason).toMatch(/no longer in standing/);

    // generation mismatch alone refuses too — the witness receives the
    // MINTING generation and must match it exactly
    store.register(record("inv-2", SECRET_2, "device"));
    const bumped = store.consume(
      "inv-2",
      SECRET_2,
      { ...LIVE, deviceStanding: (deviceId, generation) => deviceId === "phone-1" && generation === 2 },
      auth("inv-2"),
    );
    expect(bumped.ok).toBe(false);
  });

  it("BOOTSTRAP GENERATION: a superseded bootstrap generation refuses the spend", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // bootstrapGeneration 1
    const stale = store.consume("inv-1", SECRET_1, { ...LIVE, bootstrapGeneration: 2 }, auth("inv-1"));
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.reason).toMatch(/bootstrap generation/);
  });

  it("FIRST PHONE WINS, atomically: a successful bootstrap spend burns every bootstrap sibling in the same step", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("boot-1", SECRET_1, "bootstrap"));
    store.register(record("boot-2", SECRET_2, "bootstrap"));
    store.register(record("dev-1", SECRET_3, "device"));

    expect(store.consume("boot-1", SECRET_1, LIVE, auth("boot-1")).ok).toBe(true);
    // the RACE the review named: boot-2's spend arrives right after — there is
    // no window between consume and any separate invalidation call
    expect(store.consume("boot-2", SECRET_2, LIVE, auth("boot-2")).ok).toBe(false);
    // device-minted flow untouched
    expect(store.consume("dev-1", SECRET_3, LIVE, auth("dev-1")).ok).toBe(true);
  });

  it("expires by TTL, sweeps, and enforces the live-invite cap", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now, ttlMs: 60_000, maxInvites: 2 });
    store.register(record("inv-1", SECRET_1));
    store.register(record("inv-2", SECRET_2));
    expect(() => store.register(record("inv-3", SECRET_3))).toThrow(/too many/);
    c.advance(60_001);
    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(false); // expired
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

  it("SPEND AUTHORIZATION is a JS boundary: plain-JS forgeries share the prototype but not the WeakSet", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));

    // Object.create(prototype): passes instanceof, is NOT minted — refused
    const protoForgery = Object.create(SpendAuthorization.prototype) as SpendAuthorization;
    (protoForgery as { inviteId?: string }).inviteId = "inv-1";
    expect(protoForgery instanceof SpendAuthorization).toBe(true); // the TS fiction
    expect(store.consume("inv-1", SECRET_1, LIVE, protoForgery).ok).toBe(false);

    // Reflect.construct: the "private" constructor compiles away — still refused
    const constructed = Reflect.construct(
      SpendAuthorization as unknown as new (inviteId: string) => SpendAuthorization,
      ["inv-1"],
    );
    expect(store.consume("inv-1", SECRET_1, LIVE, constructed).ok).toBe(false);

    // a plain object with the right shape — refused
    const shaped = { inviteId: "inv-1" } as unknown as SpendAuthorization;
    expect(store.consume("inv-1", SECRET_1, LIVE, shaped).ok).toBe(false);

    // an authorization minted for a DIFFERENT invite spends nothing
    const wrong = store.consume("inv-1", SECRET_1, LIVE, auth("inv-2"));
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.reason).toMatch(/authorization/);

    // the second claim of the minter throws — there is exactly one
    expect(() => claimSpendMinter()).toThrow(/already claimed/);

    // the real chain still works, and every forgery above left the invite ALIVE
    expect(store.consume("inv-1", SECRET_1, LIVE, auth("inv-1")).ok).toBe(true);
  });

  it("FATE is an explicit fact: alive / burned / absent, never reason-text inference", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));
    // wrong secret -> alive
    const wrongSecret = store.consume("inv-1", SECRET_2, LIVE, auth("inv-1"));
    expect(!wrongSecret.ok && wrongSecret.fate).toBe("alive");
    // superseded epoch -> burned
    const burned = store.consume("inv-1", SECRET_1, { ...LIVE, killEpoch: 9 }, auth("inv-1"));
    expect(!burned.ok && burned.fate).toBe("burned");
    // and now there is nothing -> absent
    const absent = store.consume("inv-1", SECRET_1, LIVE, auth("inv-1"));
    expect(!absent.ok && absent.fate).toBe("absent");
  });

  it("a THROWING standing callback is a failed check (burned), never an escaping exception", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1, "device"));
    const thrown = store.consume(
      "inv-1",
      SECRET_1,
      {
        ...LIVE,
        deviceStanding: () => {
          throw new Error("registry unavailable");
        },
      },
      auth("inv-1"),
    );
    expect(thrown.ok).toBe(false);
    if (!thrown.ok) {
      expect(thrown.reason).toMatch(/FAILED/);
      expect(thrown.fate).toBe("burned");
    }
  });

  it("a MALFORMED witness proves nothing and spends nothing (fail closed, invite alive)", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));
    const bad = store.consume(
      "inv-1",
      SECRET_1,
      { ...LIVE, killed: "no" as unknown as boolean },
      auth("inv-1"),
    );
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.reason).toMatch(/malformed live witness/);
      expect(bad.fate).toBe("alive");
    }
    // a truthy-but-not-true standing answer is NOT standing
    store.register(record("dev-1", SECRET_2, "device"));
    const truthy = store.consume(
      "dev-1",
      SECRET_2,
      { ...LIVE, deviceStanding: (() => 1) as unknown as (d: string, g: number) => boolean },
      auth("dev-1"),
    );
    expect(truthy.ok).toBe(false);
  });

  it("KILLED: an engaged kill switch refuses every spend, whatever the epoch says", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1));
    const killed = store.consume("inv-1", SECRET_1, { ...LIVE, killed: true }, auth("inv-1"));
    expect(killed.ok).toBe(false);
    if (!killed.ok) {
      expect(killed.reason).toMatch(/kill switch/);
      // refused BEFORE the reserve: the invite stays alive — harmless,
      // because a restore bumps the epoch and burns it at any later spend
      expect(killed.fate).toBe("alive");
    }
  });

  it("BOOTSTRAP + ACTIVE DEVICE: a bootstrap invite enrolls only into an EMPTY registry", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // bootstrap, generation current
    const occupied = store.consume("inv-1", SECRET_1, { ...LIVE, activeDeviceCount: 1 }, auth("inv-1"));
    expect(occupied.ok).toBe(false);
    if (!occupied.ok) expect(occupied.reason).toMatch(/EMPTY registry/);
  });

  it("REENTRANCY: a consume() re-entered from inside deviceStanding() cannot double-spend", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1, "device"));
    let inner: ReturnType<InviteStore["consume"]> | null = null;
    const outer = store.consume(
      "inv-1",
      SECRET_1,
      {
        ...LIVE,
        deviceStanding: () => {
          // the hostile callback re-enters the same spend — the record was
          // RESERVED before this callback ran, so the inner call finds nothing
          inner = store.consume("inv-1", SECRET_1, LIVE, auth("inv-1"));
          return true;
        },
      },
      auth("inv-1"),
    );
    expect(outer.ok).toBe(true);
    expect(inner).not.toBeNull();
    expect((inner as unknown as { ok: boolean }).ok).toBe(false); // exactly ONE success
  });

  it("INPUT ALIASING: mutating the caller's origin object after register() changes nothing in the store", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const input = record("inv-1", SECRET_1, "device");
    store.register(input);
    // the caller rewrites its own object — a stale issuer trying to look current
    (input.origin as { deviceGeneration: number }).deviceGeneration = 99;
    // the STORE's copy still demands the minting generation (1)
    const spent = store.consume(
      "inv-1",
      SECRET_1,
      { ...LIVE, deviceStanding: (_id, generation) => generation === 1 },
      auth("inv-1"),
    );
    expect(spent.ok).toBe(true);
  });

  it("EPOCH SWEEP: invalidateSupersededEpoch frees dead invites from the cap immediately", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    store.register(record("inv-1", SECRET_1)); // epoch 0
    store.register({ ...record("inv-2", SECRET_2), killEpoch: 1 });
    expect(store.invalidateSupersededEpoch(1)).toBe(1); // inv-1 dies with epoch 0
    expect(store.size).toBe(1);
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
