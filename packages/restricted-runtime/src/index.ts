/**
 * @ownerswitchai/restricted-runtime — a documented, runnable OwnerSwitch
 * profile for Claude Code that removes the non-routed paths to acting, leaving
 * the OwnerSwitch MCP gateway as the agent's only route. See README.md and the
 * launcher at src/launch.ts.
 *
 * These are the pure building blocks the launcher composes — exported so the
 * profile is testable and reusable. The launcher itself (src/launch.ts) runs
 * on import, so it is intentionally NOT re-exported here.
 */
export {
  DENIED_BUILTIN_TOOLS,
  buildClaudeArgs,
  buildRestrictedSettings,
} from "./profile.js";
export type { ClaudeArgsPlan, RestrictedSettingsOptions } from "./profile.js";

export { DOWNSTREAM_CREDENTIAL_NAMES, buildRestrictedAgentEnv } from "./env.js";
export type { RestrictedEnvOptions } from "./env.js";

export {
  buildClaudeMcpConfig,
  buildGatewayLaunch,
  isFilesystemUpstream,
  resolveFilesystemServerEntry,
  resolveWorkspacePaths,
  withFastFilesystemUpstream,
} from "./gateway.js";
export type { GatewayLaunch, WorkspacePaths } from "./gateway.js";
