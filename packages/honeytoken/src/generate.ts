import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Decoy credential generation.
 *
 * Every honeytoken embeds one canary core: the marker "CANARY" followed by a
 * ten-character id — six random characters plus four HMAC checksum
 * characters, all from the RFC 4648 base32 alphabet. The core is the whole
 * trick:
 *
 *  - it keeps the value HARMLESS: these strings are minted here, never issued
 *    by any provider, so they authenticate nothing anywhere;
 *  - it makes the value UNMISTAKABLE on inspection: anyone reading the audit
 *    log sees CANARY… inside the "credential" and knows it was a decoy, not a
 *    live secret that leaked;
 *  - it makes matching PRECISE and UNFORGEABLE: the checksum is an HMAC keyed
 *    on a per-deployment secret, so the scanner trips only on tokens minted
 *    with THIS deployment's key. Without the key, minting a checksum-valid
 *    core means guessing 20 bits per attempt (~a million tries) — a prompt
 *    injection cannot cheaply echo a forged canary into a tool call and
 *    induce a kill nobody planted, and a token minted for one deployment
 *    never trips another.
 *
 * Around the core, each kind wears its provider's costume (prefix, length,
 * alphabet), so greps, sweeps, and an agent skimming an env file treat it as
 * the real thing. That asymmetry is the deliberate trade: plausible at a
 * glance, unmistakable under inspection. See README.md for what that trade
 * does and does not catch.
 *
 * The deployment's device secret (already provisioned for signing kills)
 * works well as the key; pass a dedicated one to decouple the two.
 */

export const HONEYTOKEN_KINDS = ["aws", "stripe", "openai", "generic"] as const;
export type HoneytokenKind = (typeof HONEYTOKEN_KINDS)[number];

export const CANARY_MARKER = "CANARY";

// RFC 4648 base32 — also exactly the alphabet AWS access key ids use after
// "AKIA", which is why the core can sit inside every costume unmodified.
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const RANDOM_CHARS = 6;
const CHECKSUM_CHARS = 4;
export const CANARY_ID_LENGTH = RANDOM_CHARS + CHECKSUM_CHARS;

export interface GenerateOptions {
  kind: HoneytokenKind;
  /** Human context for the planting record ("prod .env.backup"). Never embedded in the value. */
  label?: string;
  /**
   * Per-deployment canary key. The scanner only trips on tokens minted with
   * the same key — reuse the deployment's device secret, or dedicate one.
   */
  secret: string;
}

export interface Honeytoken {
  kind: HoneytokenKind;
  label?: string;
  /** Ten base32 chars, six random + four keyed-checksum — names the token in audit. */
  canaryId: string;
  /** The exact substring every scanner looks for: CANARY + canaryId. */
  core: string;
  /** The decoy secret, provider costume included. */
  value: string;
}

function randomFrom(alphabet: string, length: number): string {
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

/** Missing key is a configuration error, loudly — never a silent never-match. */
function requireSecret(secret: string): void {
  if (typeof secret !== "string" || secret === "") {
    throw new Error(
      "a per-deployment canary secret is required — canary checksums are keyed so they " +
        "cannot be forged from source alone (the device secret works; see README.md)",
    );
  }
}

/**
 * Four checksum characters, HMAC-keyed over the random part. Two jobs:
 * precision (prose or a foreign credential that happens to read CANARY plus
 * ten base32 characters validates with odds of one in a million) and
 * unforgeability (computing a valid checksum requires the deployment key,
 * so reading this repository is not enough to mint a kill-inducing string).
 */
function checksum(randomPart: string, secret: string): string {
  const digest = createHmac("sha256", secret)
    .update(`ownerswitch-honeytoken-v2:${randomPart}`)
    .digest();
  let out = "";
  for (let i = 0; i < CHECKSUM_CHARS; i += 1) out += BASE32[digest[i] % BASE32.length];
  return out;
}

export function newCanaryId(secret: string): string {
  requireSecret(secret);
  const randomPart = randomFrom(BASE32, RANDOM_CHARS);
  return randomPart + checksum(randomPart, secret);
}

/** True only for ids minted with THIS key — length, alphabet and keyed checksum all hold. */
export function verifyCanaryId(id: string, secret: string): boolean {
  requireSecret(secret);
  if (id.length !== CANARY_ID_LENGTH) return false;
  for (const ch of id) {
    if (!BASE32.includes(ch)) return false;
  }
  // Constant-time: the checksum is a keyed secret, so don't leak it char by
  // char through comparison timing. Both halves are exactly CHECKSUM_CHARS
  // ASCII bytes here (length and alphabet already validated above).
  const expected = Buffer.from(checksum(id.slice(0, RANDOM_CHARS), secret), "ascii");
  const provided = Buffer.from(id.slice(RANDOM_CHARS), "ascii");
  return timingSafeEqual(expected, provided);
}

export function generateHoneytoken(opts: GenerateOptions): Honeytoken {
  if (!HONEYTOKEN_KINDS.includes(opts.kind)) {
    throw new Error(
      `unknown honeytoken kind "${String(opts.kind)}" — expected ${HONEYTOKEN_KINDS.join(" | ")}`,
    );
  }
  const canaryId = newCanaryId(opts.secret);
  const core = CANARY_MARKER + canaryId;
  let value: string;
  switch (opts.kind) {
    case "aws":
      // 20 chars, AKIA + 16×base32 — the documented access-key-id shape.
      value = `AKIA${core}`;
      break;
    case "stripe":
      // sk_live_ + 24 alphanumerics — the classic live secret-key shape.
      value = `sk_live_${core}${randomFrom(BASE62, 8)}`;
      break;
    case "openai":
      // sk- + 48 alphanumerics — the classic API-key shape.
      value = `sk-${core}${randomFrom(BASE62, 32)}`;
      break;
    case "generic":
      // 40 alphanumerics — passes for an AWS secret key, a PAT, a session token.
      value = `${core}${randomFrom(BASE62, 24)}`;
      break;
  }
  return {
    kind: opts.kind,
    ...(opts.label !== undefined ? { label: opts.label } : {}),
    canaryId,
    core,
    value,
  };
}
