/**
 * WebAuthn REGISTRATION verification — the enrolment half webauthn.ts's
 * header note deferred ("provided to the control plane as configuration").
 * The enrolment ceremony (apps/owner/DESIGN.md §2) makes that a live server
 * path: `navigator.credentials.create()`'s output arrives over the wire and
 * this module decides whether it becomes an enrolled credential.
 *
 * What is verified, and where each fact actually lives:
 *  - clientDataJSON: type === "webauthn.create"; the challenge equals the
 *    server-minted one for THIS invite (constant-time); the origin is
 *    EXACTLY the owner app's; crossOrigin:true is refused and a topOrigin
 *    differing from the origin is refused (a registration produced inside
 *    someone else's frame must not enroll — types.ts /devices/enroll);
 *  - attestationObject (strict-subset CBOR, cbor.ts): fmt MUST be "none"
 *    with an empty attStmt. This deployment model asks the platform for no
 *    attestation and treats transports/AAGUID as hints, never proof
 *    (types.ts EnrolledDevice) — so any OTHER format is refused loudly
 *    instead of half-verified: a format we would not check is a format an
 *    attacker chooses;
 *  - authenticatorData: rpIdHash === SHA-256(rpId); UP+UV flags required
 *    (enrolment must involve a human passing the screen lock); AT required
 *    (there must BE attested credential data); the ED flag is refused (no
 *    extensions are requested, so extension bytes are smuggling room);
 *    signCount recorded; the credential id (≤1023 bytes per spec) must
 *    equal the wire-level credentialId byte-for-byte;
 *  - the COSE key: EC2 / ES256 / P-256 with 32-byte coordinates — the only
 *    algorithm enrolment admits (pubKeyCredParams pins ES256) — imported
 *    via JWK and re-exported as CANONICAL SPKI PEM, so downstream stores
 *    bytes this verifier produced, never attacker-framed ones. The COSE key
 *    must consume authenticatorData EXACTLY; trailing bytes refuse.
 *
 * Everything returns a refusal REASON (never a throw across the API): the
 * caller turns it into a 4xx and the invite SURVIVES a failed attempt —
 * only a fully verified registration consumes it (DESIGN.md §2).
 */
import { createHash, createPublicKey, timingSafeEqual } from "node:crypto";
import { cborDecodeExact, cborDecodeFirst, type CborValue } from "./cbor.js";

export interface WebAuthnRegistrationWire {
  /** base64url */
  credentialId: string;
  /** base64url */
  clientDataJSON: string;
  /** base64url */
  attestationObject: string;
}

export interface VerifyRegistrationOptions {
  rpId: string;
  /** the exact origin the owner app runs at, e.g. https://owner.example */
  expectedOrigin: string;
  /** the exact base64url challenge minted for this enrolment ceremony */
  expectedChallenge: string;
}

export type RegistrationVerdict =
  | {
      ok: true;
      /** base64url, byte-verified against the attested credential data */
      credentialId: string;
      /** canonical SPKI PEM re-exported by THIS verifier */
      publicKeyPem: string;
      signCount: number;
    }
  | { ok: false; reason: string };

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;
/** WebAuthn L2 §6.4.1: credential ids are at most 1023 bytes. */
const MAX_CREDENTIAL_ID_BYTES = 1023;

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromB64url(text: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const decoded = Buffer.from(text, "base64url");
  // canonical round-trip: reject inputs the decoder silently repaired
  return decoded.toString("base64url") === text.replace(/=+$/, "") ? decoded : null;
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function verifyOwnerRegistration(
  registration: WebAuthnRegistrationWire,
  opts: VerifyRegistrationOptions,
): RegistrationVerdict {
  const refuse = (reason: string): RegistrationVerdict => ({ ok: false, reason });

  /* ---- clientDataJSON ---- */
  const clientDataRaw = fromB64url(registration.clientDataJSON);
  if (clientDataRaw === null) return refuse("clientDataJSON is not canonical base64url");
  let clientData: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(clientDataRaw.toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return refuse("clientDataJSON is not a JSON object");
    }
    clientData = parsed as Record<string, unknown>;
  } catch {
    return refuse("clientDataJSON is not valid JSON");
  }
  if (clientData.type !== "webauthn.create") {
    return refuse('clientDataJSON.type is not "webauthn.create" — an assertion cannot enroll');
  }
  if (
    typeof clientData.challenge !== "string" ||
    !constantTimeStringEqual(clientData.challenge, opts.expectedChallenge)
  ) {
    return refuse("clientDataJSON.challenge does not match this enrolment ceremony");
  }
  if (clientData.origin !== opts.expectedOrigin) {
    return refuse(`clientDataJSON.origin is not the owner app (${JSON.stringify(clientData.origin)})`);
  }
  if (clientData.crossOrigin === true) {
    return refuse("registration was produced cross-origin (an embedding frame) — refused");
  }
  if ("topOrigin" in clientData && clientData.topOrigin !== opts.expectedOrigin) {
    return refuse("registration was produced under a different top-level origin — refused");
  }

  /* ---- attestationObject ---- */
  const attestationRaw = fromB64url(registration.attestationObject);
  if (attestationRaw === null) return refuse("attestationObject is not canonical base64url");
  let attestation: CborValue;
  try {
    attestation = cborDecodeExact(new Uint8Array(attestationRaw));
  } catch (err) {
    return refuse(`attestationObject: ${err instanceof Error ? err.message : "bad CBOR"}`);
  }
  if (typeof attestation !== "object" || attestation === null || Array.isArray(attestation) || attestation instanceof Uint8Array) {
    return refuse("attestationObject is not a CBOR map");
  }
  const fmt = attestation.fmt;
  if (fmt !== "none") {
    return refuse(
      `attestation format ${JSON.stringify(fmt)} is not supported — this deployment enrolls with ` +
        'attestation "none" (transports/AAGUID are hints, never proof); a format we would not ' +
        "verify is a format an attacker chooses",
    );
  }
  const attStmt = attestation.attStmt;
  if (
    typeof attStmt !== "object" ||
    attStmt === null ||
    Array.isArray(attStmt) ||
    attStmt instanceof Uint8Array ||
    Object.keys(attStmt).length !== 0
  ) {
    return refuse('attestation "none" must carry an empty attStmt');
  }
  const authData = attestation.authData;
  if (!(authData instanceof Uint8Array)) return refuse("attestationObject.authData is not a byte string");

  /* ---- authenticatorData ---- */
  if (authData.length < 37) return refuse("authenticatorData is shorter than its fixed header");
  const rpIdHash = authData.subarray(0, 32);
  const expectedRpIdHash = createHash("sha256").update(opts.rpId, "utf8").digest();
  if (!timingSafeEqual(Buffer.from(rpIdHash), expectedRpIdHash)) {
    return refuse("rpIdHash does not match the relying party — enrolled against a different rpId");
  }
  const flags = authData[32];
  if ((flags & FLAG_UP) === 0) return refuse("user-presence flag missing — no human touched the authenticator");
  if ((flags & FLAG_UV) === 0) {
    return refuse("user-verification flag missing — enrolment requires passing the screen lock (UV)");
  }
  if ((flags & FLAG_AT) === 0) return refuse("attested-credential-data flag missing — nothing to enroll");
  if ((flags & FLAG_ED) !== 0) {
    return refuse("extension-data flag set — no extensions are requested, extension bytes are refused");
  }
  const signCount =
    ((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]) >>> 0;

  /* ---- attested credential data ---- */
  // AAGUID(16) + credIdLen(2) + credId + COSE key
  if (authData.length < 37 + 16 + 2) return refuse("attested credential data is truncated");
  const credIdLength = (authData[53] << 8) | authData[54];
  if (credIdLength === 0 || credIdLength > MAX_CREDENTIAL_ID_BYTES) {
    return refuse(`credential id length ${credIdLength} is outside the spec's bounds`);
  }
  const credIdStart = 55;
  const credIdEnd = credIdStart + credIdLength;
  if (authData.length < credIdEnd) return refuse("credential id is truncated");
  const credentialIdBytes = authData.subarray(credIdStart, credIdEnd);

  // the wire-level credentialId must be EXACTLY the attested bytes — a
  // mismatch means the caller would store an id the authenticator never made
  const wireCredentialId = fromB64url(registration.credentialId);
  if (wireCredentialId === null) return refuse("credentialId is not canonical base64url");
  if (
    wireCredentialId.length !== credentialIdBytes.length ||
    !timingSafeEqual(wireCredentialId, Buffer.from(credentialIdBytes))
  ) {
    return refuse("credentialId does not match the attested credential data");
  }

  /* ---- COSE public key (must consume the remainder EXACTLY) ---- */
  const coseBytes = authData.subarray(credIdEnd);
  let coseKey: CborValue;
  try {
    const { value, bytesRead } = cborDecodeFirst(coseBytes);
    if (bytesRead !== coseBytes.length) {
      return refuse("trailing bytes after the COSE key — refusing smuggled data in authenticatorData");
    }
    coseKey = value;
  } catch (err) {
    return refuse(`COSE key: ${err instanceof Error ? err.message : "bad CBOR"}`);
  }
  if (typeof coseKey !== "object" || coseKey === null || Array.isArray(coseKey) || coseKey instanceof Uint8Array) {
    return refuse("COSE key is not a CBOR map");
  }
  // RFC 8152 labels: 1=kty (2=EC2), 3=alg (-7=ES256), -1=crv (1=P-256), -2=x, -3=y
  if (coseKey["1"] !== 2) return refuse("COSE key is not EC2 — only ES256 on P-256 enrolls");
  if (coseKey["3"] !== -7) return refuse("COSE alg is not ES256 — the only algorithm enrolment admits");
  if (coseKey["-1"] !== 1) return refuse("COSE curve is not P-256");
  const x = coseKey["-2"];
  const y = coseKey["-3"];
  if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) {
    return refuse("COSE coordinates must be exactly 32 bytes each");
  }
  let publicKeyPem: string;
  try {
    // import via JWK — node validates the point is ON the curve — and
    // re-export canonical SPKI so downstream binds verifier-produced bytes
    const key = createPublicKey({
      key: { kty: "EC", crv: "P-256", x: b64url(x), y: b64url(y) },
      format: "jwk",
    });
    publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
  } catch {
    return refuse("COSE coordinates do not form a valid P-256 point");
  }

  return { ok: true, credentialId: b64url(credentialIdBytes), publicKeyPem, signCount };
}
