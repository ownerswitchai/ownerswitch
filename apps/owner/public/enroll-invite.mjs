/*
 * enroll-invite.mjs — the PHONE's side of the device-to-device invite hop
 * (apps/owner/DESIGN.md §2): validate the scanned/typed payload, convert it
 * into the exact PublicKeyCredentialCreationOptions the ceremony pinned,
 * and drive navigator.credentials.create() with the SERVER-minted
 * challenge, user entity, and RP — never with anything the app invented.
 *
 * DRIFT-PINNED to @ownerswitchai/shared's enrollment-invite.ts
 * (enrollmentInviteFromWire) by src/enroll-invite.test.ts, the same way
 * renderable-alert.mjs is pinned to its shared twin: public/ is served as
 * plain files with no bundler, so the shared TS module cannot be imported
 * here — the test drives shared vectors through BOTH implementations and
 * demands identical verdicts.
 *
 * What this module deliberately does NOT do yet: the cheap-lane keypair,
 * the persistence test, the possession assertion, and the enrolment POST
 * are the next slice (the ceremony UI); until then production enrollment
 * stays on ACTIVATION HOLD. What it guarantees already: no payload that
 * this validator rejects ever reaches create(), and create() only ever
 * sees the server's bytes.
 */

const B64URL = /^[A-Za-z0-9_-]+$/;

/** canonical base64url -> Uint8Array, or null (round-trip enforced) */
export function base64urlToBytes(value) {
  if (typeof value !== "string" || value === "" || !B64URL.test(value)) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  let binary;
  try {
    binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  let re = "";
  for (const b of bytes) re += String.fromCharCode(b);
  const canonical = btoa(re).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return canonical === value ? bytes : null;
}

const TOP_KEYS = [
  "inviteId",
  "token",
  "expiresAt",
  "ownerId",
  "rpId",
  "rpName",
  "user",
  "pubKeyCredParams",
  "authenticatorSelection",
  "challenge",
  "assertionChallenge",
  "deviceName",
];

const own = (record, key) =>
  Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;

function exactKeys(record, keys) {
  const present = Object.keys(record);
  if (present.length !== keys.length) return false;
  const expected = new Set(keys);
  return present.every((key) => expected.has(key)) && keys.every((key) => own(record, key) !== undefined);
}

const boundedString = (value, max) => typeof value === "string" && value !== "" && value.length <= max;

function canonicalB64url(value, minBytes, maxBytes) {
  if (typeof value !== "string") return false;
  const bytes = base64urlToBytes(value);
  return bytes !== null && bytes.length >= minBytes && bytes.length <= maxBytes;
}

/**
 * Parse an unknown value as the exact device-to-device invite payload —
 * byte-for-byte the shared validator's rules (see the drift pin). Returns
 * null on ANY deviation; the caller treats that as "not an invite".
 */
export function parseEnrollmentInvite(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value;
  if (!exactKeys(record, TOP_KEYS)) return null;
  const inviteId = own(record, "inviteId");
  const token = own(record, "token");
  const expiresAt = own(record, "expiresAt");
  const ownerId = own(record, "ownerId");
  const rpId = own(record, "rpId");
  const rpName = own(record, "rpName");
  const userRaw = own(record, "user");
  const paramsRaw = own(record, "pubKeyCredParams");
  const selectionRaw = own(record, "authenticatorSelection");
  const challenge = own(record, "challenge");
  const assertionChallenge = own(record, "assertionChallenge");
  const deviceName = own(record, "deviceName");

  if (!boundedString(inviteId, 256)) return null;
  if (!canonicalB64url(token, 16, 96)) return null;
  if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) return null;
  if (!boundedString(ownerId, 256)) return null;
  if (!boundedString(rpId, 256)) return null;
  if (!boundedString(rpName, 256)) return null;
  if (!boundedString(deviceName, 200)) return null;
  if (!canonicalB64url(challenge, 16, 96)) return null;
  if (!canonicalB64url(assertionChallenge, 16, 96)) return null;

  if (typeof userRaw !== "object" || userRaw === null || Array.isArray(userRaw)) return null;
  if (!exactKeys(userRaw, ["id", "name", "displayName"])) return null;
  const userId = own(userRaw, "id");
  const userName = own(userRaw, "name");
  const userDisplayName = own(userRaw, "displayName");
  if (!canonicalB64url(userId, 1, 64)) return null;
  if (!boundedString(userName, 256) || !boundedString(userDisplayName, 256)) return null;

  if (!Array.isArray(paramsRaw) || paramsRaw.length !== 1) return null;
  const param = paramsRaw[0];
  if (typeof param !== "object" || param === null || Array.isArray(param)) return null;
  if (!exactKeys(param, ["type", "alg"])) return null;
  if (own(param, "type") !== "public-key" || own(param, "alg") !== -7) return null;

  if (typeof selectionRaw !== "object" || selectionRaw === null || Array.isArray(selectionRaw)) return null;
  if (!exactKeys(selectionRaw, ["authenticatorAttachment", "residentKey", "userVerification"])) return null;
  if (
    own(selectionRaw, "authenticatorAttachment") !== "platform" ||
    own(selectionRaw, "residentKey") !== "preferred" ||
    own(selectionRaw, "userVerification") !== "required"
  ) {
    return null;
  }

  return {
    inviteId,
    token,
    expiresAt,
    ownerId,
    rpId,
    rpName,
    user: { id: userId, name: userName, displayName: userDisplayName },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
    },
    challenge,
    assertionChallenge,
    deviceName,
  };
}

/**
 * The validated invite as EXACT PublicKeyCredentialCreationOptions: the
 * base64url binary fields become real BufferSources HERE (challenge and
 * user.id), the constants ride verbatim, and attestation is pinned "none"
 * (the deliberate DESIGN §2/§4 choice — possession is proven by the fresh
 * assertion, not by attestation).
 */
export function creationOptionsFromInvite(invite) {
  const challenge = base64urlToBytes(invite.challenge);
  const userId = base64urlToBytes(invite.user.id);
  if (challenge === null || userId === null) {
    throw new Error("invite challenge/user.id are not canonical base64url — refuse before create()");
  }
  return {
    rp: { id: invite.rpId, name: invite.rpName },
    user: { id: userId, name: invite.user.name, displayName: invite.user.displayName },
    challenge,
    pubKeyCredParams: invite.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
    authenticatorSelection: { ...invite.authenticatorSelection },
    attestation: "none",
  };
}

/**
 * Run the CREATION step of the ceremony against a CredentialsContainer
 * (navigator.credentials in production; a mock in tests): validate, adapt,
 * create — and hand back the credential together with everything the
 * ENROLLMENT REQUEST still needs (the second challenge, the local token,
 * the committed deviceName, the identifiers). A payload the validator
 * rejects never reaches create().
 */
export async function beginEnrollmentCeremony(payload, credentials, now = Date.now) {
  const invite = parseEnrollmentInvite(payload);
  if (invite === null) {
    return { ok: false, reason: "not a valid enrollment invite — refusing the ceremony" };
  }
  // an EXPIRED invite must not raise the platform prompt at all: the server
  // would refuse the spend anyway, and a credential created for a dead
  // invite is pure orphaned state on the phone
  if (invite.expiresAt <= now()) {
    return { ok: false, reason: "this invite has expired — mint a fresh one" };
  }
  // the REAL navigator.credentials.create() reports a user cancel or a
  // timeout as a REJECTED promise (NotAllowedError), not as null — every
  // rejection folds into the same fixed refusal, echoing no exception text
  // and leaving no partial ceremony state behind. The container LOOKUP is
  // inside the try too: an exotic object with a throwing `create` getter
  // is a refusal, never an escaping exception.
  let credential;
  try {
    if (
      credentials === null ||
      credentials === undefined ||
      typeof credentials.create !== "function"
    ) {
      return { ok: false, reason: "credential creation was refused, unavailable, or dismissed" };
    }
    credential = await credentials.create({ publicKey: creationOptionsFromInvite(invite) });
  } catch {
    return { ok: false, reason: "credential creation was refused, unavailable, or dismissed" };
  }
  if (credential === null || credential === undefined) {
    return { ok: false, reason: "credential creation was refused, unavailable, or dismissed" };
  }
  return {
    ok: true,
    credential,
    // retained for the enrolment request (EnrollmentRequest): the SECOND
    // challenge for the fresh possession assertion, the local secret to
    // spend, and the committed label to repeat verbatim
    inviteId: invite.inviteId,
    token: invite.token,
    ownerId: invite.ownerId,
    deviceName: invite.deviceName,
    assertionChallenge: invite.assertionChallenge,
    rpId: invite.rpId,
  };
}
