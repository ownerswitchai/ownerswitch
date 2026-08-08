/**
 * @ownerswitchai/executor — runs the approved action itself, with
 * OwnerSwitch's own credential. The agent gets the result, never a token.
 */
export { canonicalizeArgs } from "./ticket.js";
export type { ActionTicket } from "./ticket.js";

export { Executor, refuseTicket } from "./executor.js";
export type {
  ExecutionOutcome,
  ExecutionResult,
  ExecutorBackend,
  ExecutorOptions,
  LiveKillState,
  Refusal,
} from "./executor.js";

export {
  GITHUB_CONNECTOR,
  GitHubMergePrExecutor,
  githubPrResourceId,
  MERGE_PULL_REQUEST,
  parseMergePrArgs,
} from "./github.js";
export type { GitHubMergeClient, MergePrArgs } from "./github.js";
