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
 *  - authenticatorData: rpIdHash === SHA-256(rpId); UP+UV flags required as
 *    SYNTACTIC preconditions (with attestation "none" nothing signs them, so
 *    they are not by themselves evidence — see RegistrationVerdict: the
 *    possession-and-UV proof is the paired fresh assertion); AT required
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

/**
 * WHAT A PASSING VERDICT MEANS — and, with attestation "none", what it does
 * not. This verifier proves the registration is STRUCTURALLY sound and
 * extracts a canonical credential; it does NOT by itself prove the client
 * possesses the new credential's private key, nor that a platform
 * authenticator truly performed user verification — with fmt "none" there
 * is no signature over authenticatorData||SHA-256(clientDataJSON) to check,
 * so a hostile client could fabricate every byte here (the UP/UV flags are
 * syntactic requirements, not evidence). The ceremony therefore REQUIRES a
 * second step before any invite is consumed: a FRESH webauthn.get assertion
 * with the newly registered credential, over a second server-minted
 * challenge, verified with webauthn.ts's verifyOwnerAssertion against the
 * key THIS verdict returned — that assertion is the possession-and-UV
 * proof. The invite spends only after registration + assertion + cheap-lane
 * PoP all pass. `signCount` is a starting point for the later counter
 * tripwire, not a verified fact of this ceremony.
 */
export type RegistrationVerdict =
  | {
      ok: true;
      /** base64url, byte-verified against the attested credential data */
      credentialId: string;
      /**
       * THE canonical stored representation (one format everywhere:
       * RegistrationVerdict → device registry → assertion verifier):
       * base64url of the canonical SPKI DER this verifier re-exported.
       * Convert to PEM at the assertion-verify edge with spkiToPem().
       */
      publicKeySpki: string;
      signCount: number;
      /** the pinned optional hint, shape-checked and passed through — stored, never trusted */
      transports?: string[];
    }
  | { ok: false; reason: string };

/**
 * The one conversion the PEM-taking assertion verifier needs — held to the
 * SAME strictness as every other stored-key parse in this repo, because
 * registry data is still bytes on a disk: canonical base64url round-trip
 * (the permissive decoder repairs what it should refuse), parse as SPKI,
 * re-export DER must equal the input byte-for-byte (Node's parser accepts
 * trailing DER, so SPKI‖0x00 or SPKI‖PKCS8 would otherwise convert), and
 * the key must be EC on P-256. Structured refusal, never a throw — corrupt
 * registry data is a reason, not a 500.
 */
export function storedSpkiToPem(publicKeySpki: string): { ok: true; pem: string } | { ok: false; reason: string } {
  const der = fromB64url(publicKeySpki);
  if (der === null || der.length === 0) return { ok: false, reason: "stored key is not canonical base64url" };
  let key;
  try {
    key = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    return { ok: false, reason: "stored key does not parse as SPKI" };
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    return { ok: false, reason: "stored key is not EC P-256" };
  }
  const canonical = key.export({ type: "spki", format: "der" }) as Buffer;
  if (!canonical.equals(der)) {
    return { ok: false, reason: "stored key has trailing bytes after the SPKI — refusing smuggled data" };
  }
  return { ok: true, pem: key.export({ type: "spki", format: "pem" }).toString() };
}

/** Nothing in a legitimate registration is near these; a bigger field is an attack. */
const MAX_CREDENTIAL_ID_CHARS = 2048;
const MAX_CLIENT_DATA_CHARS = 16 * 1024;
const MAX_ATTESTATION_CHARS = 128 * 1024;
const WIRE_KEYS: ReadonlySet<string> = new Set([
  "credentialId",
  "clientDataJSON",
  "attestationObject",
  // pinned contract (types.ts WebAuthnRegistration): an OPTIONAL hint,
  // "stored as a hint, never as proof" — accepted and shape-checked below,
  // never verified
  "transports",
]);

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
  wire: unknown,
  opts: VerifyRegistrationOptions,
): RegistrationVerdict {
  // The outer catch is the LAST belt on the never-throws contract: this
  // function faces raw request JSON on the future enroll route, and a
  // malformed body must be a refusal reason, never a 500.
  try {
    return verifyOwnerRegistrationInner(wire, opts);
  } catch (err) {
    return { ok: false, reason: `malformed registration: ${err instanceof Error ? err.message : "unparseable"}` };
  }
}

function verifyOwnerRegistrationInner(
  wire: unknown,
  opts: VerifyRegistrationOptions,
): RegistrationVerdict {
  const refuse = (reason: string): RegistrationVerdict => ({ ok: false, reason });

  /* ---- the WIRE ENVELOPE, before anything is trusted to be a string ---- */
  if (typeof wire !== "object" || wire === null || Array.isArray(wire)) {
    return refuse("registration must be a JSON object");
  }
  for (const key of Object.keys(wire)) {
    if (!WIRE_KEYS.has(key)) return refuse(`unexpected registration property ${JSON.stringify(key)}`);
  }
  const record = wire as Record<string, unknown>;
  // OWN properties only: with a crafted prototype, a plain property read
  // could return an INHERITED value the own-key allowlist above never saw
  const own = (key: string): unknown =>
    Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
  const credentialIdField = own("credentialId");
  const clientDataField = own("clientDataJSON");
  const attestationField = own("attestationObject");
  if (typeof credentialIdField !== "string" || credentialIdField === "") {
    return refuse("credentialId must be a non-empty string");
  }
  if (typeof clientDataField !== "string" || clientDataField === "") {
    return refuse("clientDataJSON must be a non-empty string");
  }
  if (typeof attestationField !== "string" || attestationField === "") {
    return refuse("attestationObject must be a non-empty string");
  }
  if (credentialIdField.length > MAX_CREDENTIAL_ID_CHARS) return refuse("credentialId is oversized");
  if (clientDataField.length > MAX_CLIENT_DATA_CHARS) return refuse("clientDataJSON is oversized");
  if (attestationField.length > MAX_ATTESTATION_CHARS) return refuse("attestationObject is oversized");
  // transports (optional): a bounded array of short strings, a HINT stored
  // but never trusted (types.ts) — shape-checked so junk cannot ride it
  let transports: string[] | undefined;
  const transportsField = own("transports");
  if (transportsField !== undefined) {
    if (
      !Array.isArray(transportsField) ||
      transportsField.length > 8 ||
      transportsField.some((entry) => typeof entry !== "string" || entry === "" || entry.length > 32)
    ) {
      return refuse("transports must be a small array of short strings (a hint, never proof)");
    }
    transports = [...(transportsField as string[])];
  }
  const registration: WebAuthnRegistrationWire = {
    credentialId: credentialIdField,
    clientDataJSON: clientDataField,
    attestationObject: attestationField,
  };

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
  // crossOrigin: absent or literally false, nothing else — a non-boolean
  // value is a client lying about its framing, not a value to interpret
  if ("crossOrigin" in clientData && clientData.crossOrigin !== false) {
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
  // EXACT required-key contract: exactly {fmt, attStmt, authData}, all own
  // properties of the decoder's null-prototype map — nothing rides along,
  // nothing may be inherited
  const attestationKeys = Object.keys(attestation).sort();
  if (attestationKeys.join(",") !== "attStmt,authData,fmt") {
    return refuse(`attestationObject must carry exactly fmt, attStmt, authData (got ${attestationKeys.join(", ")})`);
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
  // EXACT label set: an ES256 EC2 key is exactly {1,3,-1,-2,-3} — an extra
  // label is smuggling room a "strict" verifier must not carry
  const coseLabels = Object.keys(coseKey).sort();
  if (coseLabels.join(",") !== "-1,-2,-3,1,3") {
    return refuse(`COSE key must carry exactly labels 1,3,-1,-2,-3 (got ${coseLabels.join(", ")})`);
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
  let publicKeySpki: string;
  try {
    // import via JWK — node validates the point is ON the curve — and
    // re-export canonical SPKI DER so downstream binds verifier-produced
    // bytes, in THE one stored representation (base64url DER)
    const key = createPublicKey({
      key: { kty: "EC", crv: "P-256", x: b64url(x), y: b64url(y) },
      format: "jwk",
    });
    publicKeySpki = b64url(new Uint8Array(key.export({ type: "spki", format: "der" })));
  } catch {
    return refuse("COSE coordinates do not form a valid P-256 point");
  }

  return {
    ok: true,
    credentialId: b64url(credentialIdBytes),
    publicKeySpki,
    signCount,
    ...(transports !== undefined ? { transports } : {}),
  };
}
