/**
 * The GitHub merge purpose — the one (connector, operation) pair a
 * MergeGrant may authorize today — and the strict, CLOSED argument schema
 * that purpose accepts.
 *
 * This lives in shared because every party enforces it INDEPENDENTLY, and
 * none of them trusts another's parse: the gateway refuses unknown fields
 * before the owner ever sees a request (validateMergePrRequestArgs), the
 * control plane refuses to register or sign a merge-purpose window whose
 * arguments do not parse as exactly one merge, and the executing broker
 * re-parses the signed bytes before acting. A key set that is closed in
 * three places cannot be re-opened by compromising one of them.
 */

export const GITHUB_CONNECTOR = "github";
export const MERGE_PULL_REQUEST = "merge_pull_request";

export interface MergePrArgs {
  owner: string;
  repo: string;
  pullNumber: number;
  /**
   * The head the owner's approval was pinned to — mandatory, and derived
   * server-side at review time. A merge is sent with exactly this sha; a
   * branch that moved after review draws a 409 instead of merging commits
   * nobody reviewed.
   */
  expectedHeadSha: string;
  mergeMethod?: "merge" | "squash" | "rebase";
}

/** The exact, closed key set of a canonical merge action. Nothing else. */
const MERGE_PR_CANONICAL_KEYS: ReadonlySet<string> = new Set([
  "owner",
  "repo",
  "pullNumber",
  "mergeMethod",
  "expectedHeadSha",
]);

/**
 * Parse canonical merge arguments STRICTLY: the closed key set above, the
 * allowed merge methods, a full-length head sha. An unknown key is a hard
 * error, never ignored — arguments that carry a field execution would not
 * honor must not become owner-reviewed, signed, or executed bytes.
 */
export function parseMergePrArgs(canonicalArgs: string): MergePrArgs {
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonicalArgs);
  } catch {
    throw new Error("canonicalArgs is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("canonicalArgs must be a JSON object");
  }
  for (const key of Object.keys(parsed)) {
    if (!MERGE_PR_CANONICAL_KEYS.has(key)) {
      throw new Error(
        `unknown argument "${key}" for merge_pull_request — the argument schema is closed: ` +
          `owner, repo, pullNumber, mergeMethod, expectedHeadSha`,
      );
    }
  }
  const { owner, repo, pullNumber, mergeMethod, expectedHeadSha } = parsed as Record<
    string,
    unknown
  >;
  if (typeof owner !== "string" || owner === "") throw new Error("merge_pull_request requires owner");
  if (typeof repo !== "string" || repo === "") throw new Error("merge_pull_request requires repo");
  if (typeof pullNumber !== "number" || !Number.isSafeInteger(pullNumber) || pullNumber <= 0) {
    throw new Error("merge_pull_request requires a safe positive integer pullNumber");
  }
  if (
    mergeMethod !== undefined &&
    mergeMethod !== "merge" &&
    mergeMethod !== "squash" &&
    mergeMethod !== "rebase"
  ) {
    throw new Error(`unknown mergeMethod "${String(mergeMethod)}"`);
  }
  // MANDATORY, and a full commit id (40-hex SHA-1 or 64-hex SHA-256), never
  // an abbreviation: an approval must bind to exactly one head, and a
  // prefix can be ambiguous. The proxy derives this server-side at review
  // time; a ticket without it was minted by nothing this system ships.
  if (
    typeof expectedHeadSha !== "string" ||
    !/^([0-9a-f]{40}|[0-9a-f]{64})$/i.test(expectedHeadSha)
  ) {
    throw new Error(
      "merge_pull_request requires expectedHeadSha: a full 40- or 64-character hex commit id, " +
        "pinned by OwnerSwitch at review time",
    );
  }
  return {
    owner,
    repo,
    pullNumber,
    expectedHeadSha,
    ...(mergeMethod !== undefined ? { mergeMethod } : {}),
  };
}
