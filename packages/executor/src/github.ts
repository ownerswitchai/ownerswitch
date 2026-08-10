import { ConnectorCallError } from "./connector-error.js";
import type { ExecutionContext, ExecutionResult, ExecutorBackend } from "./executor.js";
import type { ActionTicket } from "./ticket.js";

/**
 * GitHub PR merge — the first (and so far only) executor operation. The
 * client stays injectable so tests never hit GitHub; the LIVE client is
 * createGitHubMergeClient (github-client.ts), authenticated as a GitHub App
 * with short-lived, per-repository installation tokens
 * (github-app-auth.ts). See DESIGN.md §6.
 */

export const GITHUB_CONNECTOR = "github";
export const MERGE_PULL_REQUEST = "merge_pull_request";

/** Parsed shape of a merge_pull_request ticket's canonicalArgs. */
export interface MergePrArgs {
  owner: string;
  repo: string;
  pullNumber: number;
  mergeMethod?: "merge" | "squash" | "rebase";
  /**
   * MANDATORY. Forwarded as the merge API's `sha` parameter — "SHA that
   * pull request head must match to allow merge". The value is derived by
   * OWNERSWITCH at review time (the proxy pins the PR's live head before
   * the owner sees the request — never agent-supplied), so the owner's
   * approval binds to the exact head they saw: a branch that gains commits
   * after approval draws HTTP 409 instead of merging code nobody reviewed.
   */
  expectedHeadSha: string;
}

/** The calls this connector makes, injectable for tests. */
export interface GitHubMergeClient {
  /**
   * `grant` is the control-plane-signed MergeGrant, passed verbatim. The
   * same-process/live client ignores it (it mints its own token and merges
   * directly); the broker client REQUIRES it and relays it to the executing
   * broker, which is where authorization is actually verified.
   */
  mergePullRequest(
    args: MergePrArgs,
    grant?: unknown,
  ): Promise<{ merged: boolean; sha: string; message: string }>;
  /**
   * Read-only: the PR's current head sha, for the proxy's review-time pin.
   * Throws when the PR is already merged or the head is unusable.
   */
  getPullRequestHead(
    args: Pick<MergePrArgs, "owner" | "repo" | "pullNumber">,
  ): Promise<string>;
}

/**
 * OwnerSwitch's OWN GitHub credential — the one the live client will
 * authenticate with. It exists on this side of the boundary only; the agent
 * must never see it, so the backend that holds it also owns scrubbing it
 * from everything it emits: results AND errors. APIs quote credentials back
 * ("bad token ghp_… "), and an unscrubbed backend error would otherwise ride
 * an ExecutionFailed refusal straight to the agent.
 */
export interface GitHubCredential {
  token: string;
}

/** e.g. "github:pr:ownerswitchai/ownerswitch#7" */
export function githubPrResourceId(owner: string, repo: string, pullNumber: number): string {
  return `github:pr:${owner}/${repo}#${pullNumber}`;
}

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

export class GitHubMergePrExecutor implements ExecutorBackend {
  /**
   * The live client (createGitHubMergeClient) is written to never emit a
   * credential in the first place; the scrubbing here is the SECOND line of
   * defence, applied to everything this backend emits — results AND errors.
   * `credential` scrubs a single static token (the legacy seam, still
   * honored so a token set in the environment can never widen what the
   * agent sees); `redact` is the SecretLedger's redaction covering every
   * secret the live client has ever held — private key, App JWTs, every
   * installation token.
   */
  constructor(
    private readonly client?: GitHubMergeClient,
    private readonly credential?: GitHubCredential,
    private readonly redact?: (text: string) => string,
  ) {}

  /** No secret this backend's side holds leaves it, even quoted back. */
  private scrub(text: string): string {
    const token = this.credential?.token;
    const afterToken =
      token === undefined || token === "" ? text : text.split(token).join("[REDACTED]");
    return this.redact === undefined ? afterToken : this.redact(afterToken);
  }

  async execute(ticket: ActionTicket, ctx?: ExecutionContext): Promise<ExecutionResult> {
    if (ticket.connector !== GITHUB_CONNECTOR || ticket.operation !== MERGE_PULL_REQUEST) {
      throw new Error(
        `GitHubMergePrExecutor cannot execute ${ticket.connector}.${ticket.operation}`,
      );
    }
    const args = parseMergePrArgs(ticket.canonicalArgs);
    if (!this.client) {
      throw new ConnectorCallError(
        "the GitHub connector is not configured — the gateway holds no GitHub App credential " +
          "(see packages/executor/DESIGN.md §6); the merge was not attempted",
        "not-performed",
      );
    }
    let outcome;
    try {
      outcome = await this.client.mergePullRequest(args, ctx?.grant);
    } catch (err) {
      // GitHub quotes credentials back in auth errors; the scrubbed message
      // is what may ride an ExecutionFailed refusal to the agent. The
      // outcome classification (definitively-not-performed vs unknown)
      // survives the rewrap — the agent-facing error depends on it.
      const scrubbed = this.scrub(err instanceof Error ? err.message : String(err));
      throw err instanceof ConnectorCallError
        ? new ConnectorCallError(scrubbed, err.outcome)
        : new Error(scrubbed);
    }
    return {
      resourceId: githubPrResourceId(args.owner, args.repo, args.pullNumber),
      detail: {
        merged: outcome.merged,
        sha: this.scrub(outcome.sha),
        message: this.scrub(outcome.message),
      },
    };
  }
}
