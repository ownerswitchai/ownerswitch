import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

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
  /** hex HMAC-SHA256 over `${deviceId}.${timestamp}.${nonce}.${rawBody}` */
  signature: string;
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

const signedPayload = (c: Pick<DeviceCredential, "deviceId" | "timestamp" | "nonce">, rawBody: string) =>
  `${c.deviceId}.${c.timestamp}.${c.nonce}.${rawBody}`;

// The payload is dot-joined, so deviceId and nonce must not contain "." and
// the timestamp must be an integer — otherwise one signed string could parse
// as two different credentials (e.g. nonce "5.x" re-read as timestamp suffix
// ".5" plus nonce "x"), and a captured signature would burn two nonces.
const unambiguousField = (value: string): boolean => value !== "" && !value.includes(".");

/** Compute the signature a device must send; also documents the exact format. */
export function signDeviceRequest(
  fields: Pick<DeviceCredential, "deviceId" | "timestamp" | "nonce">,
  rawBody: string,
  secret: string,
): string {
  if (!unambiguousField(fields.deviceId) || !unambiguousField(fields.nonce)) {
    throw new Error('deviceId and nonce must be non-empty and contain no "."');
  }
  if (!Number.isInteger(fields.timestamp)) {
    throw new Error("timestamp must be an integer (ms since epoch)");
  }
  return createHmac("sha256", secret).update(signedPayload(fields, rawBody)).digest("hex");
}

export function verifyDeviceSignature(
  credential: DeviceCredential,
  rawBody: string,
  secret: string,
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

  const expected = createHmac("sha256", secret).update(signedPayload(credential, rawBody)).digest();
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
