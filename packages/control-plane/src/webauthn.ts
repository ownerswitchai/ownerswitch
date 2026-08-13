import { createHash, createVerify, timingSafeEqual } from "node:crypto";

/**
 * WebAuthn ASSERTION verification for the owner's approval passkey — the
 * "fresh, device-signed assertion atomically redeemed for exactly one
 * action" the merge lane requires (server.ts postVeto).
 *
 * Why this exists: an owner SESSION is a reusable bearer token. Anything
 * that can read it — malware on a browser, a leaked log — can replay it,
 * and a replayable credential must not be able to mint merge authority.
 * A WebAuthn assertion is different in exactly the ways that matter:
 *  - it is produced by the authenticator hardware, per ceremony, over a
 *    server-minted single-use CHALLENGE — there is nothing standing to
 *    steal;
 *  - the challenge is bound server-side to {windowId, callHash}, so the
 *    signature authorizes exactly one reviewed action and nothing else;
 *  - user presence AND user verification (UP+UV) are demanded, so the
 *    ceremony required a human at the device passing its screen lock;
 *  - the signature counter must not regress, which flags cloned
 *    authenticators that report counters.
 *
 * Scope, honestly: this verifies ASSERTIONS (webauthn.get) only.
 * Enrollment — extracting the credential id and COSE→SPKI public key from
 * a registration ceremony — happens in the owner app at provisioning time
 * and is provided to the control plane as configuration, the same trust
 * step as provisioning the device secret. ES256 (P-256) only, which every
 * platform authenticator supports; the DER signature is verified with
 * node:crypto against the SPKI public key. No CBOR is needed for
 * assertions: authenticatorData is a fixed binary layout.
 */

export interface OwnerPasskey {
  /** base64url credential id, as produced at enrollment */
  credentialId: string;
  /** the credential's P-256 public key, SPKI PEM */
  publicKeyPem: string;
}

export interface WebAuthnAssertion {
  credentialId: string;
  /** base64url */
  clientDataJSON: string;
  /** base64url */
  authenticatorData: string;
  /** base64url, ASN.1/DER ECDSA signature */
  signature: string;
  /**
   * base64url echo of the credential's user.id, when the authenticator
   * returned one — opaque metadata, never proof. The enrolment envelope
   * (invite.ts) validates it as canonical base64url of 1–64 bytes;
   * verification here does not read it.
   */
  userHandle?: string;
}

export interface VerifyAssertionOptions {
  passkey: OwnerPasskey;
  /** the relying party id the authenticator scoped the credential to */
  rpId: string;
  /** the exact base64url challenge this ceremony was minted for */
  expectedChallenge: string;
  /**
   * The exact origin the owner app runs at, e.g. https://owner.example.
   * REQUIRED: WebAuthn's anti-phishing guarantee is the origin binding, so a
   * verifier that skips it accepts an assertion produced against any site.
   * The caller (server.ts) demands this in any grant-enabled configuration.
   */
  expectedOrigin: string;
  /** the last accepted signature counter; 0 = none recorded yet */
  lastSignCount: number;
}

export type AssertionVerdict =
  | { ok: true; signCount: number }
  | { ok: false; reason: string };

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

/**
 * Canonical base64url decode — the permissive decoder silently drops bad
 * characters and repairs padding, so two different wire strings could decode
 * to the same verified bytes; only the exact canonical encoding is accepted.
 */
function canonicalB64url(text: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const decoded = Buffer.from(text, "base64url");
  return decoded.toString("base64url") === text ? decoded : null;
}

export function verifyOwnerAssertion(
  assertion: WebAuthnAssertion,
  opts: VerifyAssertionOptions,
): AssertionVerdict {
  // 1. the enrolled credential, and only it
  if (!constantTimeStringEqual(assertion.credentialId, opts.passkey.credentialId)) {
    return { ok: false, reason: "assertion is not from the enrolled passkey" };
  }

  // 2. clientDataJSON: the right ceremony, over OUR challenge, from the
  //    expected origin
  let clientDataRaw: Buffer;
  let clientData: {
    type?: unknown;
    challenge?: unknown;
    origin?: unknown;
    crossOrigin?: unknown;
    topOrigin?: unknown;
  };
  {
    const decoded = canonicalB64url(assertion.clientDataJSON);
    if (decoded === null) {
      return { ok: false, reason: "clientDataJSON is not canonical base64url" };
    }
    clientDataRaw = decoded;
  }
  try {
    clientData = JSON.parse(clientDataRaw.toString("utf8")) as typeof clientData;
  } catch {
    return { ok: false, reason: "clientDataJSON does not decode" };
  }
  if (clientData.type !== "webauthn.get") {
    return { ok: false, reason: "clientData.type is not webauthn.get" };
  }
  if (
    typeof clientData.challenge !== "string" ||
    !constantTimeStringEqual(clientData.challenge, opts.expectedChallenge)
  ) {
    return { ok: false, reason: "assertion challenge does not match this ceremony" };
  }
  // ORIGIN is mandatory and exact — the anti-phishing binding.
  if (opts.expectedOrigin === "") {
    return { ok: false, reason: "no expected origin configured — refusing to skip origin binding" };
  }
  if (clientData.origin !== opts.expectedOrigin) {
    return { ok: false, reason: "assertion origin does not match the enrolled origin" };
  }
  // IFRAME context (WebAuthn L3 §5.8.1 / §13.4.9): a ceremony produced in a
  // cross-origin embedding is not the top-level owner app. Reject a truthy
  // crossOrigin, and any topOrigin that is not the enrolled origin. (Absent
  // fields mean a top-level ceremony from an authenticator that predates the
  // field — allowed; present-and-wrong is refused.)
  // absent or literally false, NOTHING else — a non-boolean crossOrigin is a
  // client lying about its framing, not a value to interpret
  if (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) {
    return { ok: false, reason: "assertion was produced in a cross-origin (embedded) context" };
  }
  if (clientData.topOrigin !== undefined && clientData.topOrigin !== opts.expectedOrigin) {
    return { ok: false, reason: "assertion topOrigin does not match the enrolled origin" };
  }

  // 3. authenticatorData: rpIdHash, UP+UV flags, signature counter
  const authDataDecoded = canonicalB64url(assertion.authenticatorData);
  if (authDataDecoded === null) {
    return { ok: false, reason: "authenticatorData is not canonical base64url" };
  }
  const authData: Buffer = authDataDecoded;
  if (authData.length < 37) {
    return { ok: false, reason: "authenticatorData is too short" };
  }
  const rpIdHash = createHash("sha256").update(opts.rpId, "utf8").digest();
  if (!timingSafeEqual(authData.subarray(0, 32), rpIdHash)) {
    return { ok: false, reason: "assertion rpIdHash does not match this control plane's rpId" };
  }
  const flags = authData[32]!;
  if ((flags & FLAG_UP) === 0) {
    return { ok: false, reason: "user presence (UP) not asserted" };
  }
  if ((flags & FLAG_UV) === 0) {
    return { ok: false, reason: "user verification (UV) not asserted — the merge lane requires it" };
  }
  const signCount = authData.readUInt32BE(33);
  // A regressing counter on a counter-reporting authenticator is the
  // cloned-credential signal. Authenticators that never report counters
  // send 0 on every assertion; 0 → 0 is therefore allowed.
  if (signCount !== 0 || opts.lastSignCount !== 0) {
    if (signCount <= opts.lastSignCount) {
      return {
        ok: false,
        reason: `signature counter did not advance (${signCount} after ${opts.lastSignCount}) — possible cloned authenticator`,
      };
    }
  }

  // 4. the ECDSA signature over authenticatorData || sha256(clientDataJSON)
  const signatureDecoded = canonicalB64url(assertion.signature);
  if (signatureDecoded === null) {
    return { ok: false, reason: "signature is not canonical base64url" };
  }
  const signature: Buffer = signatureDecoded;
  const clientDataHash = createHash("sha256").update(clientDataRaw).digest();
  let verified: boolean;
  try {
    verified = createVerify("sha256")
      .update(authData)
      .update(clientDataHash)
      .verify(opts.passkey.publicKeyPem, signature);
  } catch {
    return { ok: false, reason: "the enrolled public key or signature is unusable" };
  }
  if (!verified) {
    return { ok: false, reason: "assertion signature does not verify under the enrolled passkey" };
  }
  return { ok: true, signCount };
}

/** length-guarded timing-safe comparison for identifier strings */
function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
