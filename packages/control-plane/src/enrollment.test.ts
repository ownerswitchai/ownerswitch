import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { cborEncode } from "./cbor-fixture.js";
import { performEnrollment } from "./enrollment.js";
import { InviteStore, type InviteSpendWitness } from "./invite.js";

/**
 * The WHOLE ceremony, driven end to end through the ONE public API: a
 * synthetic phone creates a WebAuthn credential, proves possession with a
 * fresh assertion, proves its cheap-lane key over the transcript, and only
 * that full chain spends the invite. Every test that removes one proof must
 * refuse — and leave the invite alive.
 */
const RP_ID = "owner.example";
const ORIGIN = "https://owner.example";

const clock = (start = 1_000) => {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
};

const LIVE: InviteSpendWitness = {
  killed: false,
  killEpoch: 0,
  bootstrapGeneration: 1,
  activeDeviceCount: 0,
  deviceStanding: () => false, // bootstrap flow — device standing unused
};

/** The synthetic phone: WebAuthn keypair + cheap-lane keypair. */
function phone() {
  return {
    webauthn: generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    cheapLane: generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    credentialId: randomBytes(24),
  };
}

function mintInvite(store: InviteStore, secret: string) {
  return store.register({
    inviteId: "inv-1",
    tokenHash: createHash("sha256").update(secret, "utf8").digest("base64url"),
    ownerId: "owner-adam",
    deviceName: "Adam's phone",
    challenge: randomBytes(32).toString("base64url"),
    assertionChallenge: randomBytes(32).toString("base64url"),
    killEpoch: 0,
    origin: { kind: "bootstrap", bootstrapGeneration: 1 },
  });
}

/** Build the full, honest enrolment submission for a phone + invite. */
function submissionFor(p: ReturnType<typeof phone>, invite: { inviteId: string; challenge: string; assertionChallenge: string; ownerId: string }, secret: string) {
  const jwk = p.webauthn.publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const cose = new Map<number, unknown>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
    [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
  ]);
  const authData = Buffer.concat([
    createHash("sha256").update(RP_ID, "utf8").digest(),
    Buffer.from([0x45]), // UP | UV | AT
    Buffer.from([0, 0, 0, 3]),
    Buffer.alloc(16),
    Buffer.from([(p.credentialId.length >> 8) & 0xff, p.credentialId.length & 0xff]),
    p.credentialId,
    cborEncode(cose),
  ]);
  const registration = {
    credentialId: p.credentialId.toString("base64url"),
    clientDataJSON: Buffer.from(
      JSON.stringify({ type: "webauthn.create", challenge: invite.challenge, origin: ORIGIN }),
    ).toString("base64url"),
    attestationObject: cborEncode(
      new Map<unknown, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", new Uint8Array(authData)],
      ]),
    ).toString("base64url"),
  };

  // the possession assertion: a fresh webauthn.get with the NEW credential
  const assertionClientData = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: invite.assertionChallenge, origin: ORIGIN }),
  );
  const assertionAuthData = Buffer.concat([
    createHash("sha256").update(RP_ID, "utf8").digest(),
    Buffer.from([0x05]), // UP | UV
    Buffer.from([0, 0, 0, 4]),
  ]);
  const possessionAssertion = {
    credentialId: p.credentialId.toString("base64url"),
    clientDataJSON: assertionClientData.toString("base64url"),
    authenticatorData: assertionAuthData.toString("base64url"),
    signature: ecSign(
      "sha256",
      Buffer.concat([assertionAuthData, createHash("sha256").update(assertionClientData).digest()]),
      p.webauthn.privateKey,
    ).toString("base64url"),
  };

  // the cheap-lane proof of possession over the ceremony transcript
  const cheapLaneSpki = p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const popPreimage = ownerEnrollPopPreimage({
    inviteId: invite.inviteId,
    ownerId: invite.ownerId,
    credentialId: new Uint8Array(p.credentialId),
    spki: new Uint8Array(cheapLaneSpki),
  });
  const cheapLaneKeyProof = ecSign("sha256", popPreimage, {
    key: p.cheapLane.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");

  return {
    inviteId: invite.inviteId,
    token: secret,
    registration,
    possessionAssertion,
    cheapLaneKey: cheapLaneSpki.toString("base64url"),
    cheapLaneKeyProof,
  };
}

describe("performEnrollment — the ONE unbypassable spend path", () => {
  const SECRET = randomBytes(24).toString("base64url");

  it("the full honest chain enrolls: registration + possession assertion + cheap-lane PoP + burn", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const outcome = performEnrollment(submissionFor(p, invite, SECRET), {
      store,
      witness: LIVE,
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.credential.credentialId).toBe(p.credentialId.toString("base64url"));
      expect(outcome.credential.publicKeySpki).toBe(
        (p.webauthn.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),
      );
      expect(outcome.cheapLaneKeySpki).toBe(
        (p.cheapLane.publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),
      );
    }
    // spent: the same chain cannot enroll twice
    const again = performEnrollment(submissionFor(p, invite, SECRET), {
      store,
      witness: LIVE,
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
    });
    expect(again.ok).toBe(false);
  });

  it("NO possession assertion, NO enrolment — and the invite SURVIVES for the honest retry", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const { possessionAssertion: _dropped, ...withoutAssertion } = submissionFor(p, invite, SECRET);
    const refused = performEnrollment(withoutAssertion, {
      store,
      witness: LIVE,
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/possessionAssertion is required/);
      expect(refused.inviteSurvives).toBe(true);
    }
    // the honest chain still lands afterwards
    expect(
      performEnrollment(submissionFor(p, invite, SECRET), {
        store,
        witness: LIVE,
        rpId: RP_ID,
        expectedOrigin: ORIGIN,
      }).ok,
    ).toBe(true);
  });

  it("an assertion signed by a THIEF's key (not the new credential) refuses and survives", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = submissionFor(p, invite, SECRET);
    const thief = phone();
    const forged = { ...honest, possessionAssertion: submissionFor(thief, invite, SECRET).possessionAssertion };
    // thief's assertion carries the thief's credentialId → not the enrolled one
    const refused = performEnrollment(forged, { store, witness: LIVE, rpId: RP_ID, expectedOrigin: ORIGIN });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.inviteSurvives).toBe(true);
  });

  it("a wrong cheap-lane PoP refuses and survives; a wrong SECRET refuses and survives", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = submissionFor(p, invite, SECRET);

    const badPop = performEnrollment(
      { ...honest, cheapLaneKeyProof: honest.cheapLaneKeyProof.slice(0, -4) + "AAAA" },
      { store, witness: LIVE, rpId: RP_ID, expectedOrigin: ORIGIN },
    );
    expect(badPop.ok).toBe(false);
    if (!badPop.ok) expect(badPop.inviteSurvives).toBe(true);

    const wrongSecret = performEnrollment(
      { ...honest, token: randomBytes(24).toString("base64url") },
      { store, witness: LIVE, rpId: RP_ID, expectedOrigin: ORIGIN },
    );
    expect(wrongSecret.ok).toBe(false);
    if (!wrongSecret.ok) expect(wrongSecret.inviteSurvives).toBe(true);

    // still alive for the honest chain
    expect(
      performEnrollment(submissionFor(p, invite, SECRET), {
        store,
        witness: LIVE,
        rpId: RP_ID,
        expectedOrigin: ORIGIN,
      }).ok,
    ).toBe(true);
  });

  it("an AUTHORITY failure at the burn (killed) refuses and reports the invite did NOT survive", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const refused = performEnrollment(submissionFor(p, invite, SECRET), {
      store,
      witness: { ...LIVE, killed: true },
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/kill switch/);
      expect(refused.inviteSurvives).toBe(false); // burned with its authority
    }
  });

  it("NEVER THROWS on garbage submissions", () => {
    const store = new InviteStore();
    for (const garbage of [null, 42, "enroll", [], {}, { inviteId: 1 }, { inviteId: "x", extra: true }]) {
      const outcome = performEnrollment(garbage, {
        store,
        witness: LIVE,
        rpId: RP_ID,
        expectedOrigin: ORIGIN,
      });
      expect(outcome.ok).toBe(false);
    }
  });
});
