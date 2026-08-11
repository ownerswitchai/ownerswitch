import { GITHUB_CONNECTOR, MERGE_PULL_REQUEST, parseMergePrArgs, type MergePrArgs } from "@ownerswitchai/shared";
import { ConnectorCallError } from "./connector-error.js";
import type { ExecutionContext, ExecutionResult, ExecutorBackend } from "./executor.js";
import type { ActionTicket } from "./ticket.js";

/**
 * GitHub PR merge — the first (and so far only) executor operation. The
 * client stays injectable so tests never hit GitHub; the LIVE client is
 * createGitHubMergeClient (github-client.ts), authenticated as a GitHub App
 * with short-lived, per-repository installation tokens
 * (github-app-auth.ts). See DESIGN.md §6.
 *
 * The connector/operation identifiers, the MergePrArgs shape, and the
 * STRICT closed-schema parser live in @ownerswitchai/shared (merge-args.ts)
 * so the control plane can enforce the same schema before signing a grant
 * that this package's broker later re-parses — re-exported here so this
 * package's public surface is unchanged.
 */

export { GITHUB_CONNECTOR, MERGE_PULL_REQUEST, parseMergePrArgs };
export type { MergePrArgs };

/**
 * How a successful merge result is attributed. "this-dispatch" — GitHub's
 * direct 200 confirmed THIS request performed the merge. "merged-state-only"
 * — the dispatch was ambiguous and a verification read observed the PR
 * merged: that proves the PR's STATE, not which request merged it, and
 * machine-readable consumers (the broker's burn record) must not upgrade it.
 */
export type MergeAttribution = "this-dispatch" | "merged-state-only";

export interface MergeResult {
  merged: boolean;
  sha: string;
  message: string;
  attribution?: MergeAttribution;
}

/**
 * The review-time pin: the PR's current head AND its merge destination.
 * Both are server-derived and both ride into the owner-reviewed canonical
 * args — the head because the merge API's `sha` guard enforces it
 * atomically, the base because GitHub lets a PR be RETARGETED to a
 * different branch after approval and the merge API has no base guard at
 * all, so OwnerSwitch pins it, shows it, signs it, and re-checks it before
 * dispatch.
 */
export interface PinnedMergeTarget {
  headSha: string;
  /** the destination branch name, e.g. "main" */
  baseRef: string;
}

/** The calls this connector makes, injectable for tests. */
export interface GitHubMergeClient {
  /**
   * `grant` is the control-plane-signed MergeGrant, passed verbatim. The
   * same-process/live client ignores it (it mints its own token and merges
   * directly); the broker client REQUIRES it and relays it to the executing
   * broker, which is where authorization is actually verified.
   */
  mergePullRequest(args: MergePrArgs, grant?: unknown): Promise<MergeResult>;
  /**
   * Read-only: the PR's current head sha and base ref, for the proxy's
   * review-time pin. Throws when the PR is already merged or either is
   * unusable.
   */
  getPullRequestHead(
    args: Pick<MergePrArgs, "owner" | "repo" | "pullNumber">,
  ): Promise<PinnedMergeTarget>;
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
