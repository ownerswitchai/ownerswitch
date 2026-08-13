/*
 * enroll-ceremony.mjs — the WHOLE enrolment ceremony on the phone, from a
 * scanned/typed invite payload to the 201 (apps/owner/DESIGN.md §2):
 *
 *   parse+validate (enroll-invite.mjs) → credentials.create() →
 *   fresh possession assertion (credentials.get with the NEW credential,
 *   over the invite's second challenge) → cheap-lane proof of possession
 *   over the pinned transcript → POST /devices/enroll.
 *
 * Dependency-injected on purpose: the CredentialsContainer, the cheap-lane
 * WebCrypto keypair, and fetch all arrive as arguments — app.js passes the
 * real navigator.credentials / ensureDeviceKey() pair / fetch, and the Node
 * tests drive the SAME code against a REAL control plane with a synthetic
 * authenticator. Every WebAuthn call is wrapped: a rejection (cancel,
 * timeout, missing platform support) folds into a fixed refusal string,
 * never an escaping exception, and no partial ceremony state survives a
 * refusal.
 *
 * The PoP transcript encoder here is DRIFT-PINNED to
 * @ownerswitchai/shared's ownerEnrollPopPreimage by src/enroll-ceremony.test.ts
 * (byte-for-byte), the same discipline as owner-crypto.mjs.
 */
import { beginEnrollmentCeremony } from "./enroll-invite.mjs";

export const ENROLL_POP_LABEL = "ownerswitch/enroll-cheap-lane/v1";

function utf8(text) {
  return new TextEncoder().encode(text);
}

/** 4-byte big-endian length-prefixed concatenation (injective). */
function lengthPrefixed(fields) {
  let total = 0;
  for (const f of fields) total += 4 + f.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const f of fields) {
    view.setUint32(off, f.length, false);
    off += 4;
    out.set(f, off);
    off += f.length;
  }
  return out;
}

function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const asBytes = (value) => new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer ?? value);

/**
 * The pinned cheap-lane PoP transcript — MUST match shared's
 * ownerEnrollPopPreimage byte-for-byte (pinned by test): length-prefixed
 * label, UTF-8 inviteId, UTF-8 ownerId, RAW credential-id bytes, RAW SPKI.
 */
export function enrollPopPreimage({ inviteId, ownerId, credentialIdBytes, spkiBytes }) {
  if (inviteId === "" || ownerId === "" || credentialIdBytes.length === 0 || spkiBytes.length === 0) {
    throw new Error("enroll PoP transcript refuses empty fields");
  }
  return lengthPrefixed([
    utf8(ENROLL_POP_LABEL),
    utf8(inviteId),
    utf8(ownerId),
    credentialIdBytes,
    spkiBytes,
  ]);
}

const REFUSED = "credential creation was refused, unavailable, or dismissed";
const ASSERTION_REFUSED = "the possession assertion was refused, unavailable, or dismissed";

/**
 * Run the ceremony end to end and spend the invite. `deps`:
 *  - credentials: a CredentialsContainer (navigator.credentials in prod);
 *  - cheapLane: { privateKey, publicKey } — the app's IndexedDB-persisted
 *    non-extractable P-256 pair (ensureDeviceKey()), ALREADY past its
 *    persistence round-trip by construction: every load retrieves it from
 *    IndexedDB, and the push path exercises signing from the service
 *    worker — the DESIGN §2 step-4 discipline this module relies on;
 *  - fetchImpl / baseUrl: where POST /devices/enroll goes;
 *  - now: injectable clock for the expiry gate.
 * Returns {ok:true, deviceId} or a structured refusal; NEVER throws for
 * user-cancel/platform shapes.
 */
export async function completeEnrollmentCeremony(payload, deps) {
  const { credentials, cheapLane, fetchImpl, baseUrl, now } = deps;

  /* 1+2 — validate, adapt, create (enroll-invite.mjs owns the refusals) */
  const begun = await beginEnrollmentCeremony(payload, credentials, now ?? Date.now);
  if (!begun.ok) return begun;

  /* 3 — the registration wire fields, from the REAL credential object */
  let registration;
  let rawCredentialId;
  try {
    const credential = begun.credential;
    rawCredentialId = asBytes(credential.rawId);
    const response = credential.response;
    registration = {
      credentialId: base64url(rawCredentialId),
      clientDataJSON: base64url(asBytes(response.clientDataJSON)),
      attestationObject: base64url(asBytes(response.attestationObject)),
      ...(typeof response.getTransports === "function"
        ? { transports: response.getTransports() }
        : {}),
    };
  } catch {
    return { ok: false, reason: REFUSED };
  }

  /* 4 — the FRESH possession assertion with the NEW credential, over the
     invite's second challenge: the proof attestation "none" cannot give */
  let possessionAssertion;
  try {
    const challengeBytes = Uint8Array.from(atob(begun.assertionChallenge.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
      c.charCodeAt(0),
    );
    const assertion = await credentials.get({
      publicKey: {
        challenge: challengeBytes,
        rpId: begun.rpId,
        allowCredentials: [{ type: "public-key", id: rawCredentialId }],
        userVerification: "required",
      },
    });
    if (assertion === null || assertion === undefined) {
      return { ok: false, reason: ASSERTION_REFUSED };
    }
    const response = assertion.response;
    possessionAssertion = {
      credentialId: base64url(asBytes(assertion.rawId)),
      clientDataJSON: base64url(asBytes(response.clientDataJSON)),
      authenticatorData: base64url(asBytes(response.authenticatorData)),
      signature: base64url(asBytes(response.signature)),
      ...(response.userHandle !== null && response.userHandle !== undefined
        ? { userHandle: base64url(asBytes(response.userHandle)) }
        : {}),
    };
  } catch {
    return { ok: false, reason: ASSERTION_REFUSED };
  }

  /* 5 — the cheap-lane proof of possession over the pinned transcript */
  let cheapLaneKey;
  let cheapLaneKeyProof;
  try {
    const spkiBytes = new Uint8Array(await crypto.subtle.exportKey("spki", cheapLane.publicKey));
    cheapLaneKey = base64url(spkiBytes);
    const preimage = enrollPopPreimage({
      inviteId: begun.inviteId,
      ownerId: begun.ownerId,
      credentialIdBytes: rawCredentialId,
      spkiBytes,
    });
    const buf = new ArrayBuffer(preimage.byteLength);
    new Uint8Array(buf).set(preimage);
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cheapLane.privateKey, buf),
    );
    cheapLaneKeyProof = base64url(raw);
  } catch {
    return { ok: false, reason: "the cheap-lane key could not prove possession — enrolment refused" };
  }

  /* 6 — the pinned EnrollmentRequest, spent exactly once */
  const body = JSON.stringify({
    inviteId: begun.inviteId,
    token: begun.token,
    deviceName: begun.deviceName,
    registration,
    possessionAssertion,
    cheapLaneKey,
    cheapLaneKeyProof,
  });
  let response;
  try {
    response = await fetchImpl(`${baseUrl}/devices/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
  } catch {
    return { ok: false, reason: "the control plane is unreachable — the invite was not spent", inviteSurvives: true };
  }
  let parsed = null;
  try {
    parsed = await response.json();
  } catch {
    /* structured error below */
  }
  if (response.status === 201 && parsed !== null && typeof parsed.deviceId === "string") {
    return { ok: true, deviceId: parsed.deviceId };
  }
  return {
    ok: false,
    reason:
      parsed !== null && typeof parsed.error === "string"
        ? parsed.error
        : `enrolment refused (HTTP ${response.status})`,
    ...(parsed !== null && typeof parsed.inviteSurvives === "boolean"
      ? { inviteSurvives: parsed.inviteSurvives }
      : {}),
  };
}
