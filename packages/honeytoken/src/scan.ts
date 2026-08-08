import { CANARY_ID_LENGTH, CANARY_MARKER, verifyCanaryId } from "./generate.js";

/**
 * The tripwire matcher: does this text contain a decoy value?
 *
 * Matching is pattern + checksum, not a registry lookup, so ANY OwnerSwitch
 * honeytoken trips — including one minted by another process or planted on
 * another machine. Real credentials never contain a checksum-valid canary
 * core, so precision comes for free; the cost, stated honestly, is that only
 * the exact planted value matches — a transformed copy (base64, lowercase,
 * split across fields) walks past this scanner. That is targeted-attacker
 * territory; see README.md.
 *
 * The MCP gateway runs this on every outbound tool call's arguments BEFORE
 * the policy check: a tripped honeytoken kills first and asks nothing.
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
 * Every checksum-valid canary core in `text`, deduplicated by canary id
 * (first occurrence wins). Empty array = clean.
 */
export function scanForHoneytokens(text: string): HoneytokenMatch[] {
  const pattern = new RegExp(`${CANARY_MARKER}([A-Z2-7]{${CANARY_ID_LENGTH}})`, "g");
  const matches: HoneytokenMatch[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(pattern)) {
    const canaryId = m[1];
    if (!verifyCanaryId(canaryId) || seen.has(canaryId)) continue;
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
