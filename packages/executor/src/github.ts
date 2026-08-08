import type { ExecutionResult, ExecutorBackend } from "./executor.js";
import type { ActionTicket } from "./ticket.js";

/**
 * GitHub PR merge — the first (and so far only) executor operation.
 * The live HTTP call is deliberately NOT implemented in this PR: the
 * client is injectable so tests never hit GitHub, and without one the
 * backend throws. The shape is the point; the integration comes after
 * the design is agreed. See DESIGN.md §6.
 */

export const GITHUB_CONNECTOR = "github";
export const MERGE_PULL_REQUEST = "merge_pull_request";

/** Parsed shape of a merge_pull_request ticket's canonicalArgs. */
export interface MergePrArgs {
  owner: string;
  repo: string;
  pullNumber: number;
  mergeMethod?: "merge" | "squash" | "rebase";
}

/** The one HTTP call this connector makes, injectable for tests. */
export interface GitHubMergeClient {
  mergePullRequest(args: MergePrArgs): Promise<{ merged: boolean; sha: string; message: string }>;
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
  const { owner, repo, pullNumber, mergeMethod } = parsed as Record<string, unknown>;
  if (typeof owner !== "string" || owner === "") throw new Error("merge_pull_request requires owner");
  if (typeof repo !== "string" || repo === "") throw new Error("merge_pull_request requires repo");
  if (typeof pullNumber !== "number" || !Number.isInteger(pullNumber) || pullNumber <= 0) {
    throw new Error("merge_pull_request requires a positive integer pullNumber");
  }
  if (
    mergeMethod !== undefined &&
    mergeMethod !== "merge" &&
    mergeMethod !== "squash" &&
    mergeMethod !== "rebase"
  ) {
    throw new Error(`unknown mergeMethod "${String(mergeMethod)}"`);
  }
  return { owner, repo, pullNumber, ...(mergeMethod !== undefined ? { mergeMethod } : {}) };
}

export class GitHubMergePrExecutor implements ExecutorBackend {
  constructor(private readonly client?: GitHubMergeClient) {}

  async execute(ticket: ActionTicket): Promise<ExecutionResult> {
    if (ticket.connector !== GITHUB_CONNECTOR || ticket.operation !== MERGE_PULL_REQUEST) {
      throw new Error(
        `GitHubMergePrExecutor cannot execute ${ticket.connector}.${ticket.operation}`,
      );
    }
    const args = parseMergePrArgs(ticket.canonicalArgs);
    if (!this.client) {
      throw new Error(
        "not implemented: the live GitHub call lands in a later PR — inject a GitHubMergeClient",
      );
    }
    const outcome = await this.client.mergePullRequest(args);
    return {
      resourceId: githubPrResourceId(args.owner, args.repo, args.pullNumber),
      detail: { merged: outcome.merged, sha: outcome.sha, message: outcome.message },
    };
  }
}
