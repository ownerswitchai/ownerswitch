import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { ownerDeviceSigPreimage, ownerEnrollPopPreimage } from "@ownerswitchai/shared";

/**
 * Verifier for the owner app's cheap-lane device signature — the real,
 * security-first credential for the PERMISSIVE veto-lane path (the delivery
 * ack that lets silence release a window). Unlike the fleet device HMAC
 * (auth.ts), this is ASYMMETRIC: the owner's phone holds a non-extractable
 * ECDSA P-256 private key, the control plane holds only the exportable SPKI
 * public key, and a signature proves possession of a key that never left the
 * device — so a leaked server-side secret cannot forge an "owner saw it".
 *
 * Signature: ECDSA on P-256 with SHA-256, RAW r||s (64 bytes), never DER —
 * the exact form WebCrypto's `sign()` emits (apps/owner/DESIGN.md §3). Node
 * accepts r||s via `dsaEncoding: "ieee-p1363"`, the same path webauthn.ts
 * already uses for owner assertions.
 *
 * The preimage — method, path+query, body hash, timestamp, nonce — comes
 * from @ownerswitchai/shared, the one encoder both signer and verifier use.
 */

export interface EnrolledOwnerDevice {
  deviceId: string;
  /** the device's ECDSA P-256 public key, SPKI PEM or DER (base64) */
  publicKey: KeyObject;
  /**
   * Revocation generation — 1 at enrolment, bumped atomically by revocation.
   * Everything minted FOR this device (foreground-detail deliveries, the ack
   * evidence a window holds) records the generation it was minted under and is
   * re-checked against the CURRENT one at use — so revoking a device kills
   * what it minted at the next decision point, not at some expiry.
   */
  generation: number;
  /** set once by revocation; a revoked device authenticates NOTHING */
  revokedAt: number | null;
}

export interface OwnerDeviceCredential {
  deviceId: string;
  /** decimal ms, exactly as signed */
  timestamp: number;
  /** single-use nonce; replays of a seen nonce are rejected */
  nonce: string;
  /** base64url raw r||s ECDSA signature (64 bytes) */
  signature: string;
}

/**
 * What the signature verifier actually needs from a device source: one
 * lookup. Both a plain Map of keys-file devices and the control plane's
 * registry-backed resolver satisfy it — the EXPLICIT interface replaces the
 * earlier ReadonlyMap cast, so a resolver is a first-class citizen, not a
 * type-system trick.
 */
export interface OwnerDeviceLookup {
  get(deviceId: string): EnrolledOwnerDevice | undefined;
}

export interface OwnerDeviceVerifyOptions {
  now?: () => number;
  /** accepted clock skew, which is also the replay window; default 60 s */
  maxSkewMs?: number;
  /** shared seen-nonce store (nonce key -> forget-after instant) */
  seenNonces?: Map<string, number>;
}

/**
 * Parse an enrolled device's PUBLIC key from an SPKI PEM (or base64 DER),
 * STRICTLY. This is an authorization root — whoever provisions it can flip
 * the release-permitting delivered bit — so a PRIVATE key is refused
 * outright: `createPublicKey(privatePem)` will happily DERIVE a public key
 * from a PKCS#8/SEC1 private PEM, and accepting that would put signing
 * material in a file meant to hold only public bytes (the same hole
 * mcp/src/passkey-key.ts closes). We reject any `PRIVATE KEY` armor, require
 * exactly one SPKI `PUBLIC KEY` block (or raw base64 DER), parse the DER with
 * an explicit `{type:"spki"}` (a private DER fails the ASN.1 shape), and
 * return a CANONICAL re-export so downstream binds bytes this parser produced.
 */
export function enrolledOwnerDeviceFromSpki(deviceId: string, spki: string): EnrolledOwnerDevice {
  const trimmed = spki.trim();
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(trimmed)) {
    throw new Error(
      `owner device "${deviceId}" was given a PRIVATE key — provide ONLY the SPKI public key. A ` +
        "private key here would put signing authority in public-key configuration",
    );
  }
  // The base64 body we will decode, whitespace-stripped, plus whether it is a
  // PEM block (standard base64, padded) or a raw browser export (base64url, no
  // padding — exportPublicKeySpki emits base64url). We keep the exact body text
  // so a NON-CANONICAL encoding can be caught: Node's base64 decoder silently
  // DROPS text after the canonical padding, so `base64(SPKI) || base64(PKCS8)`
  // (two encodings concatenated as text — distinct from `base64(SPKI||PKCS8)`,
  // which the DER length check already rejects) would decode to a clean SPKI
  // while the 0644 registry text still carries the whole private key in base64.
  // The exact-DER check below cannot see that; a canonical round-trip can.
  let bodyText: string;
  let isPem = false;
  let der: Buffer;
  if (trimmed.includes("BEGIN")) {
    isPem = true;
    if ((trimmed.match(/-----BEGIN /g) ?? []).length !== 1) {
      throw new Error(`owner device "${deviceId}" key must be exactly one PEM block`);
    }
    const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\s]+?)-----END PUBLIC KEY-----\s*$/.exec(trimmed);
    if (match === null) {
      throw new Error(`owner device "${deviceId}" key is not a single SPKI "PUBLIC KEY" PEM block`);
    }
    bodyText = match[1].replace(/\s+/g, "");
    der = Buffer.from(bodyText, "base64");
  } else {
    bodyText = trimmed.replace(/\s+/g, "");
    // a raw body may be standard base64 or base64url — decode in the alphabet
    // it actually uses (Node's "base64" mode is lenient about -/_ , which would
    // let a base64url input mis-decode); the round-trip below is the real gate.
    const isUrl = /[-_]/.test(bodyText);
    der = Buffer.from(bodyText, isUrl ? "base64url" : "base64");
  }
  let key: KeyObject;
  try {
    // explicit SPKI DER — NOT createPublicKey(pem), which derives from private
    key = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    throw new Error(`owner device "${deviceId}" key does not parse as an SPKI public key`);
  }
  if (key.asymmetricKeyType !== "ec") {
    throw new Error(`owner device "${deviceId}" key must be an ECDSA P-256 (prime256v1) public key`);
  }
  const curve = key.asymmetricKeyDetails?.namedCurve;
  if (curve !== "prime256v1") {
    throw new Error(`owner device "${deviceId}" key must be on prime256v1 (P-256), got ${curve ?? "unknown"}`);
  }
  // FULL-CONSUMPTION check: Node's DER decoder parses the leading SPKI and
  // ignores trailing bytes, so `canonical-SPKI-DER || PKCS8-private-DER` (even
  // base64'd into one PUBLIC KEY block) would parse as a public key while a
  // 0644 file smuggles the private half for the agent to read. Re-export the
  // canonical SPKI DER and require it to equal the input byte-for-byte — any
  // appended bytes (a private key, a 0x00, anything) fail here.
  const canonicalDer = key.export({ type: "spki", format: "der" });
  if (!canonicalDer.equals(der)) {
    throw new Error(
      `owner device "${deviceId}" key has trailing bytes after the SPKI public key — ` +
        "refusing (a private key or padding may be smuggled after the public half)",
    );
  }
  // CANONICAL-ENCODING check: the body text must be EXACTLY the base64/base64url
  // of the canonical SPKI — nothing after it. `canonicalDer.equals(der)` only
  // sees the DECODED bytes, and the decoder drops post-padding text, so a
  // second base64 blob (`base64(SPKI) || base64(PKCS8)`) passes the DER check
  // while smuggling the private key in the file. A canonical encoding is clean
  // and complete, so the concatenation — strictly longer — can equal neither
  // form and is refused here.
  // A PEM body is RFC 7468 standard padded base64 ONLY; the base64url form is
  // for raw browser exports (exportPublicKeySpki) — accepting it inside PEM
  // armor would widen the grammar for no producer.
  const canonicalOk = isPem
    ? bodyText === canonicalDer.toString("base64")
    : bodyText === canonicalDer.toString("base64") || bodyText === canonicalDer.toString("base64url");
  if (!canonicalOk) {
    throw new Error(
      `owner device "${deviceId}" key is not canonical base64 — trailing or non-standard ` +
        "characters after the SPKI public key (a second key may be smuggled in the encoding)",
    );
  }
  // bind bytes this parser produced, not the input
  return {
    deviceId,
    publicKey: createPublicKey({ key: canonicalDer, format: "der", type: "spki" }),
    generation: 1,
    revokedAt: null,
  };
}

/**
 * Verify the enrolment PROOF OF POSSESSION: the submitted cheap-lane key's
 * PRIVATE half signed the ceremony transcript (shared/enroll-pop.ts —
 * label, inviteId, ownerId, RAW credentialId, RAW canonical SPKI), raw
 * r||s like every cheap-lane signature. Runs BEFORE the invite is
 * consumed: a key the client cannot sign with is refused and the invite
 * survives (apps/owner/DESIGN.md §2 step 4). The SPKI bytes in the
 * transcript are the CANONICAL DER this module's own strict parser
 * produced — the signer exported the same canonical bytes from WebCrypto,
 * so both sides sign/verify one encoding.
 */
export function verifyEnrollProofOfPossession(fields: {
  inviteId: string;
  ownerId: string;
  /** base64url WebAuthn credential id (as verified by webauthn-register) */
  credentialId: string;
  /** the enrolled device, from enrolledOwnerDeviceFromSpki (canonical key) */
  device: EnrolledOwnerDevice;
  /** base64url raw r||s ECDSA signature over the transcript */
  proof: string;
}): boolean {
  // CANONICAL base64url only — Buffer.from is permissive (drops bad chars,
  // repairs padding), and a transcript built from repaired bytes is a
  // transcript the signer never signed; a round-trip mismatch refuses.
  const canonicalB64url = (text: string): Buffer | null => {
    if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
    const decoded = Buffer.from(text, "base64url");
    return decoded.toString("base64url") === text ? decoded : null;
  };
  const credentialIdBytes = canonicalB64url(fields.credentialId);
  if (credentialIdBytes === null) return false;
  let preimage: Uint8Array;
  try {
    preimage = ownerEnrollPopPreimage({
      inviteId: fields.inviteId,
      ownerId: fields.ownerId,
      credentialId: new Uint8Array(credentialIdBytes),
      spki: new Uint8Array(fields.device.publicKey.export({ type: "spki", format: "der" })),
    });
  } catch {
    return false; // empty field — never a guess
  }
  const sig = canonicalB64url(fields.proof);
  if (sig === null) return false;
  if (sig.length !== 64) return false; // raw r||s for P-256, never DER
  try {
    return cryptoVerify(
      "sha256",
      preimage,
      { key: fields.device.publicKey, dsaEncoding: "ieee-p1363" },
      sig,
    );
  } catch {
    return false;
  }
}

/**
 * Verify an owner-device signature over `method pathAndQuery rawBody`, made
 * by the enrolled device named in the credential. Returns the verified
 * deviceId, or null on ANY failure — bad signature, skew, replay, unknown
 * device, malformed field. Nonce is burned only on a fully valid signature,
 * so an attacker cannot invalidate a device's pending request by guessing.
 */
export function verifyOwnerDeviceSignature(
  credential: OwnerDeviceCredential,
  method: string,
  pathAndQuery: string,
  rawBody: string,
  devices: OwnerDeviceLookup,
  opts: OwnerDeviceVerifyOptions = {},
): string | null {
  const now = opts.now ?? Date.now;
  const maxSkewMs = opts.maxSkewMs ?? 60_000;
  const seenNonces = opts.seenNonces;

  // sweep dead nonces so a long-lived store stays bounded
  if (seenNonces !== undefined) {
    for (const [key, staleAfter] of seenNonces) {
      if (now() > staleAfter) seenNonces.delete(key);
    }
  }

  const { deviceId, timestamp, nonce, signature } = credential;
  // The nonce store key is `owner:<deviceId>:<nonce>` — reject the ":"
  // separator in either field so two credentials can never alias one key.
  if (typeof deviceId !== "string" || deviceId === "" || deviceId.includes(":")) return null;
  if (typeof nonce !== "string" || nonce === "" || nonce.includes(":")) return null;
  if (typeof signature !== "string" || signature === "") return null;
  if (!Number.isSafeInteger(timestamp)) return null;
  if (Math.abs(now() - timestamp) > maxSkewMs) return null;

  const device = devices.get(deviceId);
  if (device === undefined) return null;
  // A revoked device authenticates NOTHING — checked before any verify so its
  // key never validates another byte, whatever it signs.
  if (device.revokedAt !== null) return null;

  let preimage: Uint8Array;
  try {
    preimage = ownerDeviceSigPreimage({
      deviceId,
      method,
      pathAndQuery,
      bodyHash: new Uint8Array(createHash("sha256").update(rawBody).digest()),
      timestamp,
      nonce,
    });
  } catch {
    return null; // non-canonical path, bad field — never a guess
  }

  let sig: Buffer;
  try {
    sig = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }
  // raw r||s for P-256 is exactly 64 bytes; reject anything else before verify
  if (sig.length !== 64) return null;

  let ok: boolean;
  try {
    ok = cryptoVerify("sha256", preimage, { key: device.publicKey, dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return null;
  }
  if (!ok) return null;

  // burn the nonce last: only a VALID signature spends it
  if (seenNonces !== undefined) {
    const nonceKey = `owner:${deviceId}:${nonce}`;
    if (seenNonces.has(nonceKey)) return null;
    seenNonces.set(nonceKey, timestamp + maxSkewMs);
  }
  return deviceId;
}
