/**
 * THE enrolment core — the ONE function that can spend an invite.
 *
 * performEnrollment() runs the full proof chain the ceremony contract
 * requires (apps/owner/DESIGN.md §2, types.ts EnrollmentRequest), in order,
 * and only a fully successful chain reaches the burn:
 *
 *  1. WIRE ENVELOPE — the submission is `unknown`; exact keys, strings,
 *     size caps; every malformed shape is a refusal, never a throw.
 *  2. REGISTRATION (structural) — verifyOwnerRegistration() against the
 *     invite's CREATION challenge: canonical credential id + canonical
 *     SPKI, with attestation "none" honestly treated as parsing, not
 *     possession proof.
 *  3. POSSESSION ASSERTION — a FRESH webauthn.get with the NEWLY created
 *     credential over the invite's SECOND challenge, verified with
 *     webauthn.ts's verifyOwnerAssertion against the key step 2 returned.
 *     THIS is the proof the client holds the new private key and a human
 *     passed user verification — the evidence fmt:"none" cannot give.
 *  4. CHEAP-LANE PoP — the ack-signing key proves possession over the
 *     ceremony transcript (invite, owner, credential, canonical SPKI).
 *  5. CONSUME — InviteStore.consume() under a SpendAuthorization minted
 *     HERE, with the live witness (kill state, epoch, bootstrap
 *     generation + zero-active-devices, issuer standing). The minting
 *     brand is not exported from the package root, so no handler can
 *     reach the burn around steps 1–4: skipping a proof is a type error
 *     and a runtime error, not a code-review hope.
 *
 * A refusal reports whether the invite SURVIVES (steps 1–4 fail: yes — a
 * stranger's garbage must not burn the owner's capability) or was consumed
 * by an authority failure at the burn itself (dead epoch/issuer: no).
 */
import { verifyOwnerAssertion, type WebAuthnAssertion } from "./webauthn.js";
import {
  INTERNAL_SPEND_BRAND,
  SpendAuthorization,
  type InviteRecord,
  type InviteSpendWitness,
  type InviteStore,
} from "./invite.js";
import {
  enrolledOwnerDeviceFromSpki,
  verifyEnrollProofOfPossession,
} from "./owner-device.js";
import { storedSpkiToPem, verifyOwnerRegistration } from "./webauthn-register.js";

export interface PerformEnrollmentOptions {
  store: InviteStore;
  witness: InviteSpendWitness;
  rpId: string;
  expectedOrigin: string;
}

export type EnrollmentOutcome =
  | {
      ok: true;
      invite: InviteRecord;
      /** the verified WebAuthn credential, in the canonical stored forms */
      credential: { credentialId: string; publicKeySpki: string; signCount: number };
      /** the cheap-lane public key, canonical SPKI DER base64url */
      cheapLaneKeySpki: string;
    }
  | { ok: false; reason: string; inviteSurvives: boolean };

const MAX_FIELD_CHARS = 128 * 1024;
const SUBMISSION_KEYS: ReadonlySet<string> = new Set([
  "inviteId",
  "token",
  "registration",
  "possessionAssertion",
  "cheapLaneKey",
  "cheapLaneKeyProof",
  "deviceName",
]);

function stringField(value: unknown, cap = 4096): string | null {
  return typeof value === "string" && value !== "" && value.length <= cap ? value : null;
}

/** The assertion's own wire envelope — strings only, before webauthn.ts sees it. */
function assertionFrom(value: unknown): WebAuthnAssertion | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed = new Set(["credentialId", "clientDataJSON", "authenticatorData", "signature"]);
  if (keys.some((key) => !allowed.has(key))) return null;
  const credentialId = stringField(record.credentialId);
  const clientDataJSON = stringField(record.clientDataJSON, 64 * 1024);
  const authenticatorData = stringField(record.authenticatorData, 8 * 1024);
  const signature = stringField(record.signature, 4 * 1024);
  if (credentialId === null || clientDataJSON === null || authenticatorData === null || signature === null) {
    return null;
  }
  return { credentialId, clientDataJSON, authenticatorData, signature };
}

export function performEnrollment(submission: unknown, opts: PerformEnrollmentOptions): EnrollmentOutcome {
  try {
    return performEnrollmentInner(submission, opts);
  } catch (err) {
    // the never-throws backstop: whatever slipped past the envelope checks
    // is a refusal that leaves the invite alone
    return {
      ok: false,
      reason: `malformed enrolment: ${err instanceof Error ? err.message : "unparseable"}`,
      inviteSurvives: true,
    };
  }
}

function performEnrollmentInner(submission: unknown, opts: PerformEnrollmentOptions): EnrollmentOutcome {
  const survive = (reason: string): EnrollmentOutcome => ({ ok: false, reason, inviteSurvives: true });

  /* 1 — the wire envelope */
  if (typeof submission !== "object" || submission === null || Array.isArray(submission)) {
    return survive("enrolment must be a JSON object");
  }
  for (const key of Object.keys(submission)) {
    if (!SUBMISSION_KEYS.has(key)) return survive(`unexpected enrolment property ${JSON.stringify(key)}`);
  }
  const record = submission as Record<string, unknown>;
  const inviteId = stringField(record.inviteId, 256);
  const token = stringField(record.token, 256);
  const cheapLaneKey = stringField(record.cheapLaneKey, 8 * 1024);
  const cheapLaneKeyProof = stringField(record.cheapLaneKeyProof, 1024);
  if (inviteId === null) return survive("inviteId must be a non-empty string");
  if (token === null) return survive("token must be a non-empty string");
  if (cheapLaneKey === null) return survive("cheapLaneKey must be a non-empty string");
  if (cheapLaneKeyProof === null) return survive("cheapLaneKeyProof must be a non-empty string");
  if (record.registration === undefined) return survive("registration is required");
  if (record.possessionAssertion === undefined) {
    return survive(
      "possessionAssertion is required — with attestation \"none\" only a fresh assertion with the " +
        "new credential proves the client holds its private key",
    );
  }
  if (typeof record.registration === "string" && record.registration.length > MAX_FIELD_CHARS) {
    return survive("registration is oversized");
  }

  /* the invite this ceremony claims — read-only until the burn */
  const invite = opts.store.peek(inviteId);
  if (invite === null) return survive("unknown, expired, or already-spent invite");

  /* 2 — registration, against the invite's CREATION challenge */
  const registration = verifyOwnerRegistration(record.registration, {
    rpId: opts.rpId,
    expectedOrigin: opts.expectedOrigin,
    expectedChallenge: invite.challenge,
  });
  if (!registration.ok) return survive(`registration refused: ${registration.reason}`);

  /* 3 — possession: a FRESH assertion with the NEW credential */
  const assertion = assertionFrom(record.possessionAssertion);
  if (assertion === null) return survive("possessionAssertion is malformed");
  const pem = storedSpkiToPem(registration.publicKeySpki);
  if (!pem.ok) return survive(`registration key unusable: ${pem.reason}`);
  const possession = verifyOwnerAssertion(assertion, {
    passkey: { credentialId: registration.credentialId, publicKeyPem: pem.pem },
    rpId: opts.rpId,
    expectedOrigin: opts.expectedOrigin,
    expectedChallenge: invite.assertionChallenge,
    lastSignCount: registration.signCount,
  });
  if (!possession.ok) return survive(`possession assertion refused: ${possession.reason}`);

  /* 4 — cheap-lane proof of possession over the ceremony transcript */
  let cheapLaneDevice;
  try {
    cheapLaneDevice = enrolledOwnerDeviceFromSpki("enrolling-device", cheapLaneKey);
  } catch (err) {
    return survive(`cheapLaneKey refused: ${err instanceof Error ? err.message : "unparseable"}`);
  }
  const popOk = verifyEnrollProofOfPossession({
    inviteId,
    ownerId: invite.ownerId,
    credentialId: registration.credentialId,
    device: cheapLaneDevice,
    proof: cheapLaneKeyProof,
  });
  if (!popOk) return survive("cheap-lane proof of possession refused");

  /* 5 — the burn, under the authorization only this module can mint */
  const authorization = SpendAuthorization.mintInternal(INTERNAL_SPEND_BRAND, inviteId);
  const consumed = opts.store.consume(inviteId, token, opts.witness, authorization);
  if (!consumed.ok) {
    // the store already decided the invite's fate: a wrong secret left it
    // alive; an authority failure (kill, epoch, generation, standing)
    // burned it — report which, honestly
    const survived = consumed.reason.includes("secret") || consumed.reason.includes("canonical token");
    return { ok: false, reason: consumed.reason, inviteSurvives: survived };
  }

  return {
    ok: true,
    invite: consumed.record,
    credential: {
      credentialId: registration.credentialId,
      publicKeySpki: registration.publicKeySpki,
      signCount: registration.signCount,
    },
    cheapLaneKeySpki: Buffer.from(
      cheapLaneDevice.publicKey.export({ type: "spki", format: "der" }),
    ).toString("base64url"),
  };
}
