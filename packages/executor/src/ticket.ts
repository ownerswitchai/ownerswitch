/**
 * ActionTicket — the one data structure that crosses from "decided" to
 * "executed". Minted by the gateway when a call clears its lane
 * (allow, veto released, or approve confirmed); consumed exactly once
 * by the executor. See DESIGN.md §1.
 */
export interface ActionTicket {
  /** who the action was authorized for — same id as ToolCall.agentId */
  agentId: string;
  /** which backend performs it, e.g. "github" */
  connector: string;
  /** which action within the connector, e.g. "merge_pull_request" */
  operation: string;
  /**
   * The arguments, canonicalized (canonicalizeArgs). The executor runs
   * these bytes — not a re-supplied copy — so what runs is exactly what
   * was evaluated and approved.
   */
  canonicalArgs: string;
  /** stable id of the object acted on, e.g. "github:pr:ownerswitchai/ownerswitch#7" */
  resourceId: string;
  /** content hash of the policy the verdict came from */
  policyVersion: string;
  /** the control plane's kill epoch at mint time; must still match at execution */
  killEpoch: number;
  /** unix ms — a yes is not a standing grant */
  expiresAt: number;
  /** unique per ticket; burned on first execution attempt */
  nonce: string;
  /**
   * Always true in v0. Exists so a future batch/recurring grant is an
   * explicit design change, not an accidental default.
   */
  singleUse: true;
}

/**
 * Canonical JSON: object keys sorted lexicographically at every depth,
 * no insignificant whitespace, arrays in original order. Same arguments
 * in, same bytes out. (Full RFC 8785 JCS deliberately deferred.)
 */
export function canonicalizeArgs(args: Record<string, unknown>): string {
  return JSON.stringify(sortDeep(args));
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
