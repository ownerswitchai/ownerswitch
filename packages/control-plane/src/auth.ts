import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { fleetHmacPreimage } from "@ownerswitchai/shared";

/**
 * Authentication for the control plane's HTTP surface.
 *
 * Two credential kinds, one per side of the stop/start asymmetry:
 *
 *  - device HMAC signatures — cheap, offline-provisioned shared secrets for
 *    the physical button and any other kill trigger. They ATTRIBUTE a kill
 *    ("this really was the button"); they are never required to stop.
 *  - owner sessions — short-lived bearer tokens for the expensive direction:
 *    restore and veto always demand one.
 */

export interface DeviceCredential {
  deviceId: string;
  /** ms since epoch, exactly as the device signed it */
  timestamp: number;
  /** unique per request; replays of a seen nonce are rejected */
  nonce: string;
  /** hex HMAC-SHA256 over the fleet-hmac v2 preimage (@ownerswitchai/shared) */
  signature: string;
}

/**
 * The REQUEST the signature binds (PR #62 audit #7): the verifier derives
 * these from the request it actually received, the signer states what it is
 * about to send — so a captured MAC cannot be redirected to another verb,
 * endpoint or window id even on its first use.
 */
export interface DeviceRequestContext {
  /** HTTP method; compared UPPER-cased inside the preimage */
  method: string;
  /** origin-form request target, byte-exact as sent (path + query) */
  pathAndQuery: string;
}

export interface DeviceVerifyOptions {
  now?: () => number;
  /** accepted clock skew, which is also the replay window; default 60 s */
  maxSkewMs?: number;
  /**
   * Seen-nonce store override (tests, or one store per server); defaults to a
   * module-level store. Maps nonce key -> the instant it can be forgotten.
   */
  seenNonces?: Map<string, number>;
}

// TODO(persistence): nonces live in process memory, so a restart forgets them.
// Inside the 60 s window that is a real (if small) replay gap — move to a
// shared store before this runs as more than one process.
const defaultSeenNonces = new Map<string, number>();

// deviceId and nonce stay dot-free and non-empty: the nonce store keys on
// `${deviceId}:${nonce}` and older tooling may still log the v1 dotted
// shape; the preimage itself is length-prefixed, so this is a grammar
// choice, not an ambiguity requirement any more.
const unambiguousField = (value: string): boolean => value !== "" && !value.includes(".");

/**
 * The v2 preimage HMAC input, or null when the fields cannot form a
 * canonical transcript (bad path, unsafe timestamp) — the verifier maps
 * null to "invalid" instead of throwing on attacker-shaped input.
 */
function preimageOf(
  fields: Pick<DeviceCredential, "deviceId" | "timestamp" | "nonce">,
  rawBody: string,
  context: DeviceRequestContext,
): Uint8Array | null {
  try {
    return fleetHmacPreimage({
      deviceId: fields.deviceId,
      method: context.method,
      pathAndQuery: context.pathAndQuery,
      bodyHash: createHash("sha256").update(rawBody, "utf8").digest(),
      timestamp: fields.timestamp,
      nonce: fields.nonce,
    });
  } catch {
    return null;
  }
}

/** Compute the signature a device must send; also documents the exact format. */
export function signDeviceRequest(
  fields: Pick<DeviceCredential, "deviceId" | "timestamp" | "nonce">,
  rawBody: string,
  secret: string,
  context: DeviceRequestContext,
): string {
  if (!unambiguousField(fields.deviceId) || !unambiguousField(fields.nonce)) {
    throw new Error('deviceId and nonce must be non-empty and contain no "."');
  }
  if (!Number.isInteger(fields.timestamp)) {
    throw new Error("timestamp must be an integer (ms since epoch)");
  }
  const preimage = preimageOf(fields, rawBody, context);
  if (preimage === null) {
    throw new Error("cannot sign: method/pathAndQuery do not form a canonical fleet-hmac transcript");
  }
  return createHmac("sha256", secret).update(preimage).digest("hex");
}

export function verifyDeviceSignature(
  credential: DeviceCredential,
  rawBody: string,
  secret: string,
  context: DeviceRequestContext,
  opts: DeviceVerifyOptions = {},
): boolean {
  const now = opts.now ?? Date.now;
  const maxSkewMs = opts.maxSkewMs ?? 60_000;
  const seenNonces = opts.seenNonces ?? defaultSeenNonces;
  const { deviceId, timestamp, nonce, signature } = credential;

  // A nonce outside the skew window can never verify again, so its entry is
  // dead weight — sweep here to keep the store bounded in a long-lived process.
  for (const [key, staleAfter] of seenNonces) {
    if (now() > staleAfter) seenNonces.delete(key);
  }

  if (!unambiguousField(deviceId) || !unambiguousField(nonce) || signature === "") return false;
  if (!Number.isInteger(timestamp)) return false;
  if (Math.abs(now() - timestamp) > maxSkewMs) return false;

  // the verifier binds the request IT received — a MAC minted for another
  // method/path/body computes a different preimage and simply fails here
  const preimage = preimageOf(credential, rawBody, context);
  if (preimage === null) return false;
  const expected = createHmac("sha256", secret).update(preimage).digest();
  // Buffer.from(hex) stops at the first invalid character, so garbage input
  // lands in the length check instead of throwing inside timingSafeEqual.
  const provided = Buffer.from(signature, "hex");
  if (provided.length !== expected.length) return false;
  if (!timingSafeEqual(provided, expected)) return false;

  // Nonce bookkeeping comes last: only a VALID signature burns a nonce, so an
  // attacker cannot invalidate a device's pending request by guessing at it.
  const nonceKey = `${deviceId}:${nonce}`;
  if (seenNonces.has(nonceKey)) return false;
  seenNonces.set(nonceKey, timestamp + maxSkewMs);
  return true;
}

export interface OwnerSession {
  /** opaque bearer token */
  token: string;
  ownerId: string;
  /** ms since epoch */
  expiresAt: number;
}

export interface SessionOptions {
  now?: () => number;
  /** default 15 min */
  ttlMs?: number;
}

const SESSION_TTL_MS = 15 * 60_000;

// Single owner for now, so a flat token map is enough.
const sessions = new Map<string, OwnerSession>();

// TODO(passkey): this is where WebAuthn assertion verification will plug in —
// a session gets minted only after a verified assertion, instead of for
// whoever can call this function in-process.
export function createOwnerSession(ownerId: string, opts: SessionOptions = {}): OwnerSession {
  const now = opts.now ?? Date.now;
  // Abandoned sessions would otherwise accumulate forever; each mint sweeps.
  for (const [token, existing] of sessions) {
    if (now() >= existing.expiresAt) sessions.delete(token);
  }
  const session: OwnerSession = {
    token: randomBytes(32).toString("base64url"),
    ownerId,
    expiresAt: now() + (opts.ttlMs ?? SESSION_TTL_MS),
  };
  sessions.set(session.token, session);
  return session;
}

export function verifyOwnerSession(
  token: string,
  opts: { now?: () => number } = {},
): OwnerSession | null {
  const now = opts.now ?? Date.now;
  const session = sessions.get(token);
  if (session === undefined) return null;
  if (now() >= session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

/**
 * True for addresses the kill fail-open trusts: IPv4 127/8, IPv6 ::1, and the
 * IPv4-mapped form. No address (a mocked or already-closed socket) is NOT
 * loopback — trust must be positively established.
 */
export function isLoopbackAddress(address: string | undefined): boolean {
  if (address === undefined || address === "") return false;
  if (address === "::1") return true;
  const v4 = address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4);
}
