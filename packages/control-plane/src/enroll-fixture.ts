/**
 * TEST-ONLY enrolment ceremony fixture — a synthetic phone and the honest,
 * complete EnrollmentRequest for it. Lives in its own module (like
 * cbor-fixture.ts) so both invite.test.ts and enrollment.test.ts can drive
 * the ONE spend path, performEnrollment, without re-registering each
 * other's tests. Not exported from the package.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as ecSign } from "node:crypto";
import { ownerEnrollPopPreimage } from "@ownerswitchai/shared";
import { cborEncode } from "./cbor-fixture.js";

export const FIXTURE_RP_ID = "owner.example";
export const FIXTURE_ORIGIN = "https://owner.example";

/** The synthetic phone: WebAuthn keypair + cheap-lane keypair. */
export function phone() {
  return {
    webauthn: generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    cheapLane: generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    credentialId: randomBytes(24),
  };
}

export interface FixtureInvite {
  inviteId: string;
  ownerId: string;
  deviceName: string;
  challenge: string;
  assertionChallenge: string;
}

/**
 * Build the full, honest enrolment submission for a phone + invite:
 * registration (signCount 3) + fresh possession assertion (signCount 4) +
 * cheap-lane PoP + the mint-committed deviceName repeated.
 */
export function enrollmentSubmission(p: ReturnType<typeof phone>, invite: FixtureInvite, secret: string) {
  const jwk = p.webauthn.publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const cose = new Map<number, unknown>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
    [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
  ]);
  const authData = Buffer.concat([
    createHash("sha256").update(FIXTURE_RP_ID, "utf8").digest(),
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
      JSON.stringify({ type: "webauthn.create", challenge: invite.challenge, origin: FIXTURE_ORIGIN }),
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
    JSON.stringify({ type: "webauthn.get", challenge: invite.assertionChallenge, origin: FIXTURE_ORIGIN }),
  );
  const assertionAuthData = Buffer.concat([
    createHash("sha256").update(FIXTURE_RP_ID, "utf8").digest(),
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
    deviceName: invite.deviceName,
    registration,
    possessionAssertion,
    cheapLaneKey: cheapLaneSpki.toString("base64url"),
    cheapLaneKeyProof,
  };
}
