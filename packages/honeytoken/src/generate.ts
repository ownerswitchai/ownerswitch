import { createHash, randomBytes } from "node:crypto";

/**
 * Decoy credential generation.
 *
 * Every honeytoken embeds one canary core: the marker "CANARY" followed by a
 * ten-character id — eight random characters plus two checksum characters,
 * all from the RFC 4648 base32 alphabet. The core is the whole trick:
 *
 *  - it keeps the value HARMLESS: these strings are minted here, never issued
 *    by any provider, so they authenticate nothing anywhere;
 *  - it makes the value UNMISTAKABLE on inspection: anyone reading the audit
 *    log sees CANARY… inside the "credential" and knows it was a decoy, not a
 *    live secret that leaked;
 *  - it makes matching PRECISE: the scanner trips only on a core whose
 *    checksum validates, so real credentials — and prose that happens to say
 *    CANARY — do not false-positive.
 *
 * Around the core, each kind wears its provider's costume (prefix, length,
 * alphabet), so greps, sweeps, and an agent skimming an env file treat it as
 * the real thing. That asymmetry is the deliberate trade: plausible at a
 * glance, unmistakable under inspection. See README.md for what that trade
 * does and does not catch.
 */

export const HONEYTOKEN_KINDS = ["aws", "stripe", "openai", "generic"] as const;
export type HoneytokenKind = (typeof HONEYTOKEN_KINDS)[number];

export const CANARY_MARKER = "CANARY";

// RFC 4648 base32 — also exactly the alphabet AWS access key ids use after
// "AKIA", which is why the core can sit inside every costume unmodified.
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const RANDOM_CHARS = 8;
const CHECKSUM_CHARS = 2;
export const CANARY_ID_LENGTH = RANDOM_CHARS + CHECKSUM_CHARS;

export interface GenerateOptions {
  kind: HoneytokenKind;
  /** Human context for the planting record ("prod .env.backup"). Never embedded in the value. */
  label?: string;
}

export interface Honeytoken {
  kind: HoneytokenKind;
  label?: string;
  /** Ten base32 chars, eight random + two checksum — self-validating; names the token in audit. */
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

/**
 * Two checksum characters over the random part. The point is precision, not
 * secrecy: a foreign string that happens to read CANARY plus ten base32
 * characters still has only a 1-in-1024 chance of validating, so in practice
 * the scanner trips only on values minted here.
 */
function checksum(randomPart: string): string {
  const digest = createHash("sha256").update(`ownerswitch-honeytoken-v1:${randomPart}`).digest();
  return `${BASE32[digest[0] % BASE32.length]}${BASE32[digest[1] % BASE32.length]}`;
}

export function newCanaryId(): string {
  const randomPart = randomFrom(BASE32, RANDOM_CHARS);
  return randomPart + checksum(randomPart);
}

/** True only for ids minted by newCanaryId — length, alphabet and checksum all hold. */
export function verifyCanaryId(id: string): boolean {
  if (id.length !== CANARY_ID_LENGTH) return false;
  for (const ch of id) {
    if (!BASE32.includes(ch)) return false;
  }
  return checksum(id.slice(0, RANDOM_CHARS)) === id.slice(RANDOM_CHARS);
}

export function generateHoneytoken(opts: GenerateOptions): Honeytoken {
  if (!HONEYTOKEN_KINDS.includes(opts.kind)) {
    throw new Error(
      `unknown honeytoken kind "${String(opts.kind)}" — expected ${HONEYTOKEN_KINDS.join(" | ")}`,
    );
  }
  const canaryId = newCanaryId();
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
