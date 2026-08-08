import type { HoneytokenMatch, HoneytokenRegistry } from "./registry.js";

/**
 * The tripwire matcher: which planted decoy values appear in this text?
 *
 * Matching is exact membership in a deployment-scoped registry (registry.ts),
 * not a self-validating checksum. So:
 *  - a real credential never matches (it was never planted);
 *  - a forged value never matches (you cannot reproduce a planted token's
 *    high-entropy body — there is no short tag to brute-force, and no
 *    per-candidate HMAC to grind into a DoS);
 *  - another deployment's token never matches (its values aren't in this
 *    registry, and the registry is bound to this deployment).
 *
 * The cost, stated honestly, is that only the exact planted value matches — a
 * transformed copy (base64, lowercase, split across fields) walks past this
 * scanner. That is targeted-attacker territory; see README.md.
 *
 * The MCP gateway runs this immediately before it would FORWARD a call — a
 * decoy value about to cross the boundary is exfiltration in progress, so that
 * trip kills. A denied call never forwards, so a decoy in it only alerts.
 */
export type { HoneytokenMatch } from "./registry.js";

export function scanForHoneytokens(text: string, registry: HoneytokenRegistry): HoneytokenMatch[] {
  return registry.match(text);
}
