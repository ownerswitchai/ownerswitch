import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  enrollmentSubmission,
  FIXTURE_ORIGIN,
  FIXTURE_RP_ID,
  phone,
} from "./enroll-fixture.js";
import { performEnrollment } from "./enrollment.js";
import { InviteStore, type InviteSpendWitness } from "./invite.js";

/**
 * The WHOLE ceremony, driven end to end through the ONE public API: a
 * synthetic phone creates a WebAuthn credential, proves possession with a
 * fresh assertion, proves its cheap-lane key over the transcript, and only
 * that full chain spends the invite. Every test that removes one proof must
 * refuse — and leave the invite alive.
 */
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

function mintInvite(store: InviteStore, secret: string, mintWitness: InviteSpendWitness = LIVE) {
  return store.register(
    {
      inviteId: "inv-1",
      tokenHash: createHash("sha256").update(secret, "utf8").digest("base64url"),
      ownerId: "owner-adam",
      deviceName: "Adam's phone",
      challenge: randomBytes(32).toString("base64url"),
      assertionChallenge: randomBytes(32).toString("base64url"),
      killEpoch: 0,
      origin: { kind: "bootstrap", bootstrapGeneration: 1 },
    },
    mintWitness,
  );
}

const OPTS = (store: InviteStore, witness: InviteSpendWitness = LIVE) => ({
  store,
  witness,
  rpId: FIXTURE_RP_ID,
  expectedOrigin: FIXTURE_ORIGIN,
});

describe("performEnrollment — the ONE unbypassable spend path", () => {
  const SECRET = randomBytes(24).toString("base64url");

  it("the full honest chain enrolls: registration + possession assertion + cheap-lane PoP + burn", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const outcome = performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store));
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
    const again = performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store));
    expect(again.ok).toBe(false);
  });

  it("NO possession assertion, NO enrolment — and the invite SURVIVES for the honest retry", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const { possessionAssertion: _dropped, ...withoutAssertion } = enrollmentSubmission(p, invite, SECRET);
    const refused = performEnrollment(withoutAssertion, OPTS(store));
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.reason).toMatch(/possessionAssertion is required/);
      expect(refused.inviteSurvives).toBe(true);
    }
    // the honest chain still lands afterwards
    expect(performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store)).ok).toBe(true);
  });

  it("an assertion signed by a THIEF's key (not the new credential) refuses and survives", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = enrollmentSubmission(p, invite, SECRET);
    const thief = phone();
    const forged = {
      ...honest,
      possessionAssertion: enrollmentSubmission(thief, invite, SECRET).possessionAssertion,
    };
    // thief's assertion carries the thief's credentialId → not the enrolled one
    const refused = performEnrollment(forged, OPTS(store));
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.inviteSurvives).toBe(true);
  });

  it("a wrong cheap-lane PoP refuses and survives; a wrong SECRET refuses and survives", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = enrollmentSubmission(p, invite, SECRET);

    const badPop = performEnrollment(
      { ...honest, cheapLaneKeyProof: honest.cheapLaneKeyProof.slice(0, -4) + "AAAA" },
      OPTS(store),
    );
    expect(badPop.ok).toBe(false);
    if (!badPop.ok) expect(badPop.inviteSurvives).toBe(true);

    const wrongSecret = performEnrollment(
      { ...honest, token: randomBytes(24).toString("base64url") },
      OPTS(store),
    );
    expect(wrongSecret.ok).toBe(false);
    if (!wrongSecret.ok) expect(wrongSecret.inviteSurvives).toBe(true);

    // still alive for the honest chain
    expect(performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store)).ok).toBe(true);
  });

  it("deviceName must repeat the mint-committed label EXACTLY — absent or different refuses, invite alive", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = enrollmentSubmission(p, invite, SECRET);

    const { deviceName: _dropped, ...withoutName } = honest;
    const missing = performEnrollment(withoutName, OPTS(store));
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.reason).toMatch(/deviceName is required/);
      expect(missing.inviteSurvives).toBe(true);
    }

    const renamed = performEnrollment({ ...honest, deviceName: "Eve's phone" }, OPTS(store));
    expect(renamed.ok).toBe(false);
    if (!renamed.ok) {
      expect(renamed.reason).toMatch(/does not match the label committed at mint/);
      expect(renamed.inviteSurvives).toBe(true);
    }

    expect(performEnrollment(honest, OPTS(store)).ok).toBe(true);
  });

  it("INHERITED fields are not a submission: required keys must be OWN properties", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = enrollmentSubmission(p, invite, SECRET);

    // every required field present — but on the PROTOTYPE, not the object
    const smuggled = Object.create(honest) as Record<string, unknown>;
    const refused = performEnrollment(smuggled, OPTS(store));
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.inviteSurvives).toBe(true);

    // one own field, the rest inherited — still a refusal
    const partial = Object.create(honest) as Record<string, unknown>;
    partial.inviteId = honest.inviteId;
    expect(performEnrollment(partial, OPTS(store)).ok).toBe(false);

    // and inherited fields inside the possession assertion refuse too
    const inheritedAssertion = {
      ...honest,
      possessionAssertion: Object.create(honest.possessionAssertion) as Record<string, unknown>,
    };
    expect(performEnrollment(inheritedAssertion, OPTS(store)).ok).toBe(false);

    // the invite survived all of it
    expect(performEnrollment(honest, OPTS(store)).ok).toBe(true);
  });

  it("userHandle: canonical base64url of 1–64 bytes rides through to the credential; anything else refuses", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const honest = enrollmentSubmission(p, invite, SECRET);
    const handle = randomBytes(32).toString("base64url");

    // non-canonical: repairable padding characters are a refusal, alive
    const padded = performEnrollment(
      { ...honest, possessionAssertion: { ...honest.possessionAssertion, userHandle: "AB=CD" } },
      OPTS(store),
    );
    expect(padded.ok).toBe(false);
    if (!padded.ok) expect(padded.inviteSurvives).toBe(true);

    // oversized: 65 decoded bytes exceeds the WebAuthn user.id bound
    const oversized = performEnrollment(
      {
        ...honest,
        possessionAssertion: {
          ...honest.possessionAssertion,
          userHandle: randomBytes(65).toString("base64url"),
        },
      },
      OPTS(store),
    );
    expect(oversized.ok).toBe(false);

    // canonical: verified chain succeeds and the handle is THREADED through
    const outcome = performEnrollment(
      { ...honest, possessionAssertion: { ...honest.possessionAssertion, userHandle: handle } },
      OPTS(store),
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.credential.userHandle).toBe(handle);
  });

  it("KILLED burns the attempted invite (defense in depth); a dead EPOCH burns; absent reports absent", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    const killed = performEnrollment(
      enrollmentSubmission(p, invite, SECRET),
      OPTS(store, { ...LIVE, killed: true }),
    );
    expect(killed.ok).toBe(false);
    if (!killed.ok) {
      expect(killed.reason).toMatch(/kill switch/);
      // BURNED, not held open across the kill: mint under kill is refused at
      // register(), and a spend attempt under kill destroys what it touched —
      // an invite is born and spent inside one live state
      expect(killed.inviteSurvives).toBe(false);
    }
    // and now the invite is ABSENT — also reported as non-surviving
    const absent = performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store));
    expect(absent.ok).toBe(false);
    if (!absent.ok) expect(absent.inviteSurvives).toBe(false);

    // a superseded EPOCH is an authority failure AT the burn — not survivable
    const invite2 = mintInvite(store, SECRET);
    const epoch = performEnrollment(
      enrollmentSubmission(p, invite2, SECRET),
      OPTS(store, { ...LIVE, killEpoch: 9 }),
    );
    expect(epoch.ok).toBe(false);
    if (!epoch.ok) expect(epoch.inviteSurvives).toBe(false); // burned, honestly
  });

  it("stores the POSSESSION assertion's signCount (the newest signed counter), not the unsigned registration field", () => {
    const c = clock();
    const store = new InviteStore({ now: c.now });
    const invite = mintInvite(store, SECRET);
    const p = phone();
    // enrollmentSubmission builds registration signCount=3 and assertion signCount=4
    const outcome = performEnrollment(enrollmentSubmission(p, invite, SECRET), OPTS(store));
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.credential.signCount).toBe(4);
  });

  it("NEVER THROWS on garbage submissions", () => {
    const store = new InviteStore();
    for (const garbage of [null, 42, "enroll", [], {}, { inviteId: 1 }, { inviteId: "x", extra: true }]) {
      const outcome = performEnrollment(garbage, OPTS(store));
      expect(outcome.ok).toBe(false);
    }
  });
});
