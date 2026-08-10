/**
 * @ownerswitchai/executor — runs the approved action itself, with
 * OwnerSwitch's own credential. The agent gets the result, never a token.
 */
export { canonicalizeArgs } from "./ticket.js";
export type { ActionTicket } from "./ticket.js";

export { Executor, refuseTicket } from "./executor.js";
export { liveKillStateFromControlPlane } from "./live-kill-state.js";
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
export type { GitHubCredential, GitHubMergeClient, MergePrArgs } from "./github.js";

export { ConnectorCallError } from "./connector-error.js";
export type { ConnectorOutcome } from "./connector-error.js";

export { createSecretLedger } from "./secret-ledger.js";
export type { SecretLedger } from "./secret-ledger.js";

export { loadGitHubAppPrivateKey, MAX_PRIVATE_KEY_FILE_BYTES } from "./github-app-key.js";
export type { LoadedPrivateKey, LoadPrivateKeyOptions } from "./github-app-key.js";

export {
  createInstallationTokenSource,
  EXPIRY_MARGIN_MS,
  INSTALLATION_TOKEN_PERMISSIONS,
} from "./github-app-auth.js";
export type {
  GitHubAppConfig,
  InstallationTokenSource,
  InstallationTokenSourceOptions,
} from "./github-app-auth.js";

export { createGitHubMergeClient } from "./github-client.js";
export type { GitHubMergeClientOptions } from "./github-client.js";

export { GITHUB_API_BASE_URL } from "./github-http.js";

export { createTokenBroker } from "./token-broker.js";
export type { TokenBroker, TokenBrokerOptions } from "./token-broker.js";

export { createBrokerTokenSource } from "./broker-client.js";
export type { BrokerTokenSourceOptions } from "./broker-client.js";
