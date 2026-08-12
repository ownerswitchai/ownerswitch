import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { ownerDeviceSigPreimage } from "@ownerswitchai/shared";

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
  let der: Buffer;
  if (trimmed.includes("BEGIN")) {
    if ((trimmed.match(/-----BEGIN /g) ?? []).length !== 1) {
      throw new Error(`owner device "${deviceId}" key must be exactly one PEM block`);
    }
    const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\s]+?)-----END PUBLIC KEY-----\s*$/.exec(trimmed);
    if (match === null) {
      throw new Error(`owner device "${deviceId}" key is not a single SPKI "PUBLIC KEY" PEM block`);
    }
    der = Buffer.from(match[1].replace(/\s+/g, ""), "base64");
  } else {
    der = Buffer.from(trimmed, "base64");
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
  // canonical re-export: bind bytes this parser produced, not the input
  return { deviceId, publicKey: createPublicKey(key.export({ type: "spki", format: "pem" })) };
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
  devices: ReadonlyMap<string, EnrolledOwnerDevice>,
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
