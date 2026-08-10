import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * MergeGrant — the unforgeable authorization evidence that crosses from the
 * gateway to the executing broker (packages/executor/src/merge-broker.ts).
 *
 * Why it exists: within one uid there is NO secret the gateway can hold that
 * the agent cannot read, and in the stdio deployment the gateway and the
 * agent share a uid. So a merge cannot be authorized by anything the gateway
 * knows — an agent could reproduce it. The grant is therefore minted OUTSIDE
 * the agent's reach, by the CONTROL PLANE at owner-approval time (a veto
 * window the owner was shown releasing while its kill epoch is current), and
 * signed with a key the control plane shares ONLY with the broker
 * (`OWNERSWITCH_GRANT_KEY`) — never provisioned into the gateway/agent
 * environment. The broker verifies the signature independently, so the
 * gateway relays the grant but cannot forge one.
 *
 * What is inside it, and why: the exact tool call the owner reviewed
 * (`tool`, `agentId`, canonical `args`), the content hash of those bytes
 * (`callHash`), the kill epoch in force at approval (`killEpoch`), a
 * single-use id (`jti`), and a short expiry. The broker refuses a merge
 * whose arguments do not re-canonicalize to the signed bytes — so the pinned
 * `expectedHeadSha` inside the args is covered by the signature, and a
 * gateway (or agent) cannot swap in a different head, repo, or PR after the
 * owner approved.
 *
 * Single-use burns in two places the agent cannot reach: the control plane
 * issues each window's grant at most once (a second read is served `spent`),
 * and the broker burns the `jti` locally before dispatch. The gateway's own
 * nonce store is defense in depth, not the boundary.
 */
export interface MergeGrant {
  /** grant format version, so a future change is explicit */
  v: 1;
  /** single-use id; the broker burns it before dispatch, agent-inaccessible */
  jti: string;
  /** who the action was authorized for — echoed into the audit trail */
  agentId: string;
  /** the MCP tool name the owner's decision was about, e.g. "github.merge_pr" */
  tool: string;
  /**
   * the owner-reviewed arguments, canonicalized (canonicalJson). The broker
   * merges exactly these bytes and refuses any other args — the pinned
   * expectedHeadSha lives in here and is therefore signed.
   */
  canonicalArgs: string;
  /** sha256 of canonicalArgs, hex — a redundant, explicit match target */
  callHash: string;
  /** the control plane's kill epoch at approval; the broker re-checks it live */
  killEpoch: number;
  /** unix ms — a grant is short-lived, minutes not hours */
  expiresAt: number;
}

/** A MergeGrant plus its detached HMAC signature — the wire form. */
export interface SignedMergeGrant extends MergeGrant {
  /** hex HMAC-SHA256 over canonicalJson of the grant fields (sig excluded) */
  sig: string;
}

/**
 * Canonical JSON: object keys sorted lexicographically at every depth, no
 * insignificant whitespace, arrays in original order, undefined-valued keys
 * dropped. Same value in, same bytes out — so the control plane's signature
 * and the broker's re-canonicalization of the merge args agree exactly, and
 * so a ticket's args cannot diverge from what was signed. (Full RFC 8785 JCS
 * is deliberately deferred; deep key-sort covers every argument shape the
 * connectors use today.)
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return Object.fromEntries(entries.map(([k, v]) => [k, sortDeep(v)]));
  }
  return value;
}

/** sha256 of a string, hex — the grant's callHash over its canonicalArgs. */
export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const grantMessage = (g: MergeGrant): string =>
  canonicalJson({
    v: g.v,
    jti: g.jti,
    agentId: g.agentId,
    tool: g.tool,
    canonicalArgs: g.canonicalArgs,
    callHash: g.callHash,
    killEpoch: g.killEpoch,
    expiresAt: g.expiresAt,
  });

/** Sign a grant with the control-plane↔broker shared key. */
export function signMergeGrant(grant: MergeGrant, grantKey: string): SignedMergeGrant {
  if (grantKey === "") throw new Error("grant key must not be empty");
  const sig = createHmac("sha256", grantKey).update(grantMessage(grant)).digest("hex");
  return { ...grant, sig };
}

export interface VerifyGrantOptions {
  now?: () => number;
}

export type GrantVerifyResult =
  | { ok: true; grant: MergeGrant }
  | { ok: false; reason: string };

/**
 * Verify a signed grant against the shared key — the broker's independent
 * check. Confirms the HMAC (timing-safe), the version, that the grant has
 * not expired, and that `callHash` matches `canonicalArgs`. It does NOT
 * check single-use (the broker burns the jti) or kill state (the broker
 * re-checks live) — those need state this pure function does not have.
 */
export function verifyMergeGrant(
  signed: unknown,
  grantKey: string,
  opts: VerifyGrantOptions = {},
): GrantVerifyResult {
  const now = opts.now ?? Date.now;
  if (grantKey === "") return { ok: false, reason: "no grant key configured" };
  if (typeof signed !== "object" || signed === null) return { ok: false, reason: "grant is not an object" };
  const s = signed as Record<string, unknown>;
  if (s.v !== 1) return { ok: false, reason: "unsupported grant version" };
  if (
    typeof s.jti !== "string" ||
    typeof s.agentId !== "string" ||
    typeof s.tool !== "string" ||
    typeof s.canonicalArgs !== "string" ||
    typeof s.callHash !== "string" ||
    typeof s.killEpoch !== "number" ||
    !Number.isSafeInteger(s.killEpoch) ||
    typeof s.expiresAt !== "number" ||
    !Number.isFinite(s.expiresAt) ||
    typeof s.sig !== "string" ||
    s.sig === ""
  ) {
    return { ok: false, reason: "grant is missing or malformed fields" };
  }
  const grant: MergeGrant = {
    v: 1,
    jti: s.jti,
    agentId: s.agentId,
    tool: s.tool,
    canonicalArgs: s.canonicalArgs,
    callHash: s.callHash,
    killEpoch: s.killEpoch,
    expiresAt: s.expiresAt,
  };
  const expected = createHmac("sha256", grantKey).update(grantMessage(grant)).digest();
  const provided = Buffer.from(s.sig, "hex");
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "grant signature does not verify" };
  }
  if (sha256Hex(grant.canonicalArgs) !== grant.callHash) {
    return { ok: false, reason: "grant callHash does not match its canonicalArgs" };
  }
  if (now() >= grant.expiresAt) {
    return { ok: false, reason: "grant has expired" };
  }
  return { ok: true, grant };
}
