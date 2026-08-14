/**
 * Every check the gateway makes BEFORE it serves a single call — in one
 * place, so `doctor` can run exactly what `runGateway` runs.
 *
 * Why this module exists at all: these gates throw at startup, and under an
 * MCP client a gateway that throws at startup is invisible. The client
 * reports "connection closed" or a timeout; the real message — a missing
 * risk acknowledgment, an unreadable honeytoken registry, a half-set
 * connector triple — went to a stderr nobody is reading. That is precisely
 * the failure `doctor` exists to prevent, and for a while `doctor` could
 * not see it: it loaded the config and stopped there, printing "All checks
 * passed" for a configuration the gateway would refuse to start on.
 *
 * So: a new startup gate goes HERE, never inline in cli.ts. Anything added
 * inline is a gate `doctor` cannot see, and the next person meets it as a
 * dead MCP connection.
 *
 * These gates are pure validation — reads and parses, no sockets, no
 * spawns, no writes — so `doctor` can run them without side effects.
 */
import { resolve } from "node:path";
import { loadGitHubAppPrivateKey } from "@ownerswitchai/executor";
import { HoneytokenRegistry, loadRegistry, readRegistryFile } from "@ownerswitchai/honeytoken";
import {
  assertExecutorRoutesCoherent,
  assertKillLimitRiskAccepted,
  ConfigError,
  type OwnerSwitchMcpConfig,
} from "./config.js";
import { resolveGitHubConnectorEnv, type GitHubConnectorEnv } from "./github-app-env.js";
import { assertUpstreamArgsCredentialFree } from "./upstream-env.js";

export interface StartupGateDeps {
  /** injectable for tests; defaults to the real registry file read */
  readRegistry?: (path: string) => string;
  /** the gateway's own cwd — the workspace a same-process key must stay out of */
  cwd?: () => string;
}

/**
 * What the gates resolved along the way. The gateway rebuilds what it needs
 * from the same functions; this is returned so a caller that wants the
 * resolved shapes (a status line, a test) does not have to re-derive them.
 */
export interface StartupGateResult {
  connector?: GitHubConnectorEnv;
  honeytokenRegistry?: HoneytokenRegistry;
}

/**
 * Load the honeytoken registry named by the environment, or undefined when
 * none is configured. Shared by the gateway's tripwire arming and by
 * `doctor`, so the two can never disagree about what a valid registry is.
 */
export function loadHoneytokenRegistryFromEnv(
  env: Record<string, string | undefined>,
  deps: StartupGateDeps = {},
): HoneytokenRegistry | undefined {
  const registryPath = env.OWNERSWITCH_HONEYTOKEN_REGISTRY;
  if (registryPath === undefined) return undefined;

  const canaryKey = env.OWNERSWITCH_CANARY_KEY;
  const deploymentId = env.OWNERSWITCH_DEPLOYMENT_ID;
  if (!canaryKey || !deploymentId) {
    throw new ConfigError(
      "OWNERSWITCH_HONEYTOKEN_REGISTRY is set but OWNERSWITCH_CANARY_KEY and/or " +
        "OWNERSWITCH_DEPLOYMENT_ID are missing — the registry cannot be verified without them",
    );
  }
  let serialized: string;
  try {
    // readRegistryFile refuses to follow a symlink at registryPath and caps
    // the file size before the bytes are read into memory — a locally
    // replaced huge or symlinked file is rejected here, before parsing.
    serialized = (deps.readRegistry ?? readRegistryFile)(registryPath);
  } catch (err) {
    throw new ConfigError(
      `cannot read honeytoken registry "${registryPath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    return loadRegistry(serialized, { canaryKey, deploymentId });
  } catch (err) {
    throw new ConfigError(
      `honeytoken registry rejected: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Run every startup gate, in the order the gateway hits them. Throws
 * `ConfigError` with the message the gateway would print; returns what it
 * resolved when everything passes.
 */
export function runStartupGates(
  config: OwnerSwitchMcpConfig,
  env: Record<string, string | undefined>,
  deps: StartupGateDeps = {},
): StartupGateResult {
  // 1. Kill-action budgets demand the explicit process-local-risk flag —
  //    rationale and contract in config.ts assertKillLimitRiskAccepted.
  assertKillLimitRiskAccepted(config.limits, env);

  // 2. The honeytoken registry, when one is configured: present, complete,
  //    readable, and minted for THIS deployment.
  const honeytokenRegistry = loadHoneytokenRegistryFromEnv(env, deps);

  // 3. The GitHub connector's credential seam: all-or-nothing within the
  //    triple, and a same-process key must not live in the agent's
  //    workspace. The workspace is upstream.cwd when set — otherwise the
  //    child inherits this process's cwd, so that is the workspace.
  const connector = resolveGitHubConnectorEnv(env);
  let githubAppKeyPem: string | undefined;
  if (connector?.mode === "same-process") {
    const agentWorkspace = resolve(config.upstream.cwd ?? (deps.cwd ?? process.cwd)());
    try {
      githubAppKeyPem = loadGitHubAppPrivateKey(connector.privateKeyFile, {
        workspaceDir: agentWorkspace,
      }).pem;
    } catch (err) {
      throw new ConfigError(err instanceof Error ? err.message : String(err));
    }
  }

  // 4. Executor routes must agree with the policy they run under.
  const routes = config.executorRoutes;
  if (routes !== undefined && Object.keys(routes).length > 0) {
    assertExecutorRoutesCoherent(config.policy, routes);
  }

  // 5. No gateway credential may ride into the upstream child through argv
  //    — visible via /proc/<pid>/cmdline and `ps aux`, so this is a refusal
  //    to start, not a filter. Same value set the environment filter uses.
  assertUpstreamArgsCredentialFree(config.upstream.args, [
    config.device.secret,
    env.OWNERSWITCH_GITHUB_TOKEN,
    githubAppKeyPem,
    env.OWNERSWITCH_CANARY_KEY,
    env.OWNERSWITCH_DEVICE_SECRET,
  ]);

  return {
    ...(connector !== undefined ? { connector } : {}),
    ...(honeytokenRegistry !== undefined ? { honeytokenRegistry } : {}),
  };
}
