import { createHash, randomBytes } from "node:crypto";

/**
 * Decoy credential generation.
 *
 * A honeytoken's security rests on ONE thing: its value is a high-entropy
 * random string that an attacker cannot reproduce or guess. Recognition is by
 * exact membership in a per-deployment registry of the planted values (see
 * registry.ts), NOT by a short self-validating checksum. That choice is
 * deliberate and is what makes the tripwire safe to wire to a global kill:
 *
 *  - There is no short tag to brute-force. The earlier design embedded a
 *    20-bit keyed checksum; an attacker could enumerate all ~1M candidates
 *    for one random prefix in a single tool-call payload, land the one that
 *    validated, and fire a kill nobody planted (while forcing ~1M HMACs).
 *    Membership matching removes the tag entirely: to make the scanner fire
 *    you must present a value that was actually planted, i.e. reproduce the
 *    token's full random body.
 *  - Each costume carries as much random as its shape allows. Entropy floors:
 *    generic 170 bits, openai 210, stripe 90, aws 50. Even the aws floor
 *    (2^50 twenty-byte candidates ≈ 20 PB) cannot be enumerated in a payload.
 *    Where ≥128-bit assurance is required for an AWS *secret*, plant the
 *    `generic` costume (170 bits); the 20-char access-key-id shape simply
 *    cannot exceed 80 bits and still look like an access key id.
 *
 * Every value still carries the visible CANARY marker so the audit log can
 * never mistake a decoy for a live credential, and each costume still wears
 * its provider's shape so a sweep greps it up as the real thing. See the
 * README for what this catches and what it does not.
 */

export const HONEYTOKEN_KINDS = ["aws", "stripe", "openai", "generic"] as const;
export type HoneytokenKind = (typeof HONEYTOKEN_KINDS)[number];

export const CANARY_MARKER = "CANARY";

// RFC 4648 base32 — also the alphabet AWS access-key ids use after "AKIA".
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Random base32 chars AFTER the CANARY marker, per costume. This is the
 * entropy an attacker would have to reproduce to trip the scanner:
 *   aws 10ch/50b · stripe 18ch/90b · openai 42ch/210b · generic 34ch/170b
 */
const BODY_CHARS: Record<HoneytokenKind, number> = { aws: 10, stripe: 18, openai: 42, generic: 34 };

/** Length in base32 chars of a canary id (a public label; not security-bearing). */
export const CANARY_ID_LENGTH = 12;

export interface GenerateOptions {
  kind: HoneytokenKind;
  /** Human context for the planting record ("prod .env.backup"). Never embedded in the value. */
  label?: string;
}

export interface Honeytoken {
  kind: HoneytokenKind;
  label?: string;
  /**
   * A public, non-secret label derived from the value (SHA-256 → 12 base32).
   * Preimage-resistant, so it can name the token in the audit log and kill
   * reason without revealing the value it identifies.
   */
  canaryId: string;
  /** The visible CANARY marker plus the random body — the audit-recognisable core. */
  core: string;
  /** The full decoy secret, provider costume included. THIS is what the registry matches. */
  value: string;
}

function randomBase32(length: number): string {
  const bytes = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i += 1) out += BASE32[bytes[i] % BASE32.length];
  return out;
}

/** Map a digest to `length` base32 chars — a stable public label for the value. */
function labelFor(value: string): string {
  const digest = createHash("sha256").update(`ownerswitch-honeytoken-id:${value}`).digest();
  let out = "";
  for (let i = 0; i < CANARY_ID_LENGTH; i += 1) out += BASE32[digest[i] % BASE32.length];
  return out;
}

export function generateHoneytoken(opts: GenerateOptions): Honeytoken {
  if (!HONEYTOKEN_KINDS.includes(opts.kind)) {
    throw new Error(
      `unknown honeytoken kind "${String(opts.kind)}" — expected ${HONEYTOKEN_KINDS.join(" | ")}`,
    );
  }
  const core = CANARY_MARKER + randomBase32(BODY_CHARS[opts.kind]);
  let value: string;
  switch (opts.kind) {
    case "aws":
      // 20 chars, AKIA + 16×base32 — the documented access-key-id shape.
      value = `AKIA${core}`;
      break;
    case "stripe":
      // sk_live_ + 24 alphanumerics — the classic live secret-key shape.
      value = `sk_live_${core}`;
      break;
    case "openai":
      // sk- + 48 alphanumerics — the classic API-key shape.
      value = `sk-${core}`;
      break;
    case "generic":
      // 40 alphanumerics — passes for an AWS secret key, a PAT, a session token.
      value = core;
      break;
  }
  return {
    kind: opts.kind,
    ...(opts.label !== undefined ? { label: opts.label } : {}),
    canaryId: labelFor(value),
    core,
    value,
  };
}
