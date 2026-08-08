import { CANARY_ID_LENGTH, CANARY_MARKER, verifyCanaryId } from "./generate.js";

/**
 * The tripwire matcher: does this text contain a decoy value MINTED FOR THIS
 * DEPLOYMENT?
 *
 * Matching is pattern + keyed checksum, not a registry lookup: any token
 * minted with this deployment's canary secret trips, wherever it was planted,
 * and nothing else does. Real credentials never contain a checksum-valid
 * core; a forged core requires the key (or ~a million guesses); and a token
 * minted for a DIFFERENT deployment stays inert here — one tenant's bait
 * cannot kill another tenant's agents. The cost, stated honestly, is that
 * only the exact planted value matches — a transformed copy (base64,
 * lowercase, split across fields) walks past this scanner. That is
 * targeted-attacker territory; see README.md.
 *
 * The MCP gateway runs this on every outbound tool call's arguments BEFORE
 * the policy check: a decoy value crossing the gateway has no innocent
 * explanation, so that trip kills first and asks nothing.
 */
export interface HoneytokenMatch {
  /** The self-validating id — this is what names the token in the kill reason. */
  canaryId: string;
  /** The exact matched core, CANARY + canaryId. */
  core: string;
  /** Character offset of the core in the scanned text (first occurrence). */
  index: number;
  /** Best guess at the costume, read from the characters just before the core. */
  kindHint?: "aws" | "stripe" | "openai";
}

function kindHint(text: string, index: number): HoneytokenMatch["kindHint"] {
  const before = text.slice(Math.max(0, index - 8), index);
  if (before.endsWith("AKIA")) return "aws";
  if (before.endsWith("sk_live_")) return "stripe";
  if (before.endsWith("sk-")) return "openai";
  return undefined;
}

/**
 * Every canary core in `text` whose checksum validates under `secret` — the
 * per-deployment canary key — deduplicated by canary id (first occurrence
 * wins). Empty array = clean. Throws on a missing key rather than silently
 * never matching.
 */
export function scanForHoneytokens(text: string, secret: string): HoneytokenMatch[] {
  const pattern = new RegExp(`${CANARY_MARKER}([A-Z2-7]{${CANARY_ID_LENGTH}})`, "g");
  const matches: HoneytokenMatch[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(pattern)) {
    const canaryId = m[1];
    if (seen.has(canaryId) || !verifyCanaryId(canaryId, secret)) continue;
    seen.add(canaryId);
    const index = m.index ?? 0;
    const hint = kindHint(text, index);
    matches.push({
      canaryId,
      core: m[0],
      index,
      ...(hint !== undefined ? { kindHint: hint } : {}),
    });
  }
  return matches;
}
