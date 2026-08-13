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
 * never an escaping exception. Honesty about partial state: a refusal
 * creates NO server-side authority, ever — but a passkey created before a
 * later refusal can remain in the platform authenticator (browsers expose
 * no deletion API); it is inert, because the server never admitted it.
 *
 * TRUST DIRECTION, pinned (the review's rule): no unauthenticated pasted
 * payload ever steers a WebAuthn prompt. Before ANY prompt, the ceremony
 * fetches the control plane's OWN copy of the invite contract (the
 * non-consuming GET /devices/enroll/contract/:id, over the DEPLOYMENT-
 * CONFIGURED origin) and refuses unless the pasted payload matches it
 * field for field. What create()/get() see is the server's record; the
 * paste contributes only the invite id and the local secret.
 *
 * The PoP transcript encoder here is DRIFT-PINNED to
 * @ownerswitchai/shared's ownerEnrollPopPreimage by src/enroll-ceremony.test.ts
 * (byte-for-byte), the same discipline as owner-crypto.mjs.
 */
import { beginEnrollmentCeremony, parseEnrollmentInvite } from "./enroll-invite.mjs";

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

function asBytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    // honor the view's window — a TypedArray/DataView over a larger buffer
    // must not leak (or truncate to) the wrong bytes
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error("not a BufferSource");
}

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

/**
 * The control-plane base URL must be an ORIGIN, from the deployment config:
 * https (or http on loopback, for dev), no path/query/fragment. Everything
 * else refuses before any request or prompt exists.
 */
function trustedOrigin(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    return null;
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]" || url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return null;
  if ((url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "") return null;
  return url.origin;
}

const FETCH_GUARDS = { cache: "no-store", redirect: "error" };

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

  /* 0 — the deployment-configured origin is the trust anchor */
  const origin = trustedOrigin(baseUrl);
  if (origin === null) {
    // no survival claim: nothing about the server was observable from here
    return {
      ok: false,
      reason: "control-plane URL is not a trusted origin (https, no path) — refusing the ceremony",
    };
  }

  /* 1 — parse the paste (exact shape), then PREFLIGHT: fetch the control
     plane's own contract for this inviteId and demand field-for-field
     agreement BEFORE any platform prompt. The paste contributes the id and
     the secret; the SERVER's record is what the prompts will see. */
  const pasted = parseEnrollmentInvite(payload);
  if (pasted === null) {
    // no survival claim: an invalid paste says nothing about any server record
    return { ok: false, reason: "not a valid enrollment invite — refusing the ceremony" };
  }
  let serverInvite = null;
  try {
    const preflight = await fetchImpl(
      new URL(`/devices/enroll/contract/${encodeURIComponent(pasted.inviteId)}`, origin).toString(),
      { method: "GET", ...FETCH_GUARDS },
    );
    if (preflight.status === 200) {
      const body = await preflight.json();
      if (body !== null && typeof body === "object" && !Array.isArray(body)) {
        serverInvite = parseEnrollmentInvite({ ...body.invite, token: pasted.token });
      }
    }
  } catch {
    serverInvite = null;
  }
  if (serverInvite === null) {
    // no survival claim here, deliberately: "not vouched" covers unknown,
    // expired, and ALREADY-SPENT alike — asserting the invite survives
    // would be a guess about a record this refusal never saw
    return {
      ok: false,
      reason: "the control plane does not vouch for this invite — refusing before any prompt",
    };
  }
  if (JSON.stringify(serverInvite) !== JSON.stringify(pasted)) {
    return {
      ok: false,
      reason: "the pasted invite does not match the control plane's contract — refusing before any prompt",
      inviteSurvives: true,
    };
  }

  /* 2 — validate, adapt, create — on the SERVER-vouched contract */
  const begun = await beginEnrollmentCeremony(serverInvite, credentials, now ?? Date.now);
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
    response = await fetchImpl(new URL("/devices/enroll", origin).toString(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      ...FETCH_GUARDS,
    });
  } catch {
    // POST-DISPATCH TRANSPORT FAILURE IS UNKNOWN, honestly: the control
    // plane may already have burned the invite, durably admitted the
    // device, and sent a 201 this connection lost — or the request may
    // never have arrived. Claiming either survival or spend here would be
    // a guess; the operator checks the device list (or re-mints).
    return {
      ok: false,
      outcome: "unknown",
      reason:
        "the connection to the control plane failed mid-enrolment — the OUTCOME IS UNKNOWN: " +
        "check the device list before re-minting; the invite may or may not have been spent",
    };
  }
  let parsed = null;
  try {
    parsed = await response.json();
  } catch {
    /* structured error below */
  }
  if (response.status === 201) {
    // the pinned EnrollmentResponse, EXACTLY: {deviceId} with the control
    // plane's id grammar — extra fields or a strange id refuse, because a
    // response this load-bearing is a contract, not a suggestion
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      Object.keys(parsed).length === 1 &&
      typeof parsed.deviceId === "string" &&
      /^dev_[A-Za-z0-9_-]{1,64}$/.test(parsed.deviceId)
    ) {
      return { ok: true, deviceId: parsed.deviceId };
    }
    return {
      ok: false,
      outcome: "unknown",
      reason:
        "the control plane's 201 did not carry the pinned {deviceId} contract — treat the outcome as " +
        "UNKNOWN and check the device list",
    };
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
