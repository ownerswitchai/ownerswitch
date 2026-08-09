#!/usr/bin/env node
/**
 * stdio entry point: the process an MCP client (Claude Code, etc.) launches.
 *
 * stdout belongs to the MCP protocol — every human-facing line goes to
 * stderr. The upstream server is spawned as a child with its stderr
 * inherited, so its logs surface in the client's logs too.
 */
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createGitHubMergeClient,
  createInstallationTokenSource,
  createSecretLedger,
  Executor,
  GitHubMergePrExecutor,
  liveKillStateFromControlPlane,
  loadGitHubAppPrivateKey,
  type ActionTicket,
  type GitHubMergeClient,
} from "@ownerswitchai/executor";
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { createTripwire, loadRegistry, readRegistryFile, type Tripwire } from "@ownerswitchai/honeytoken";
import { ConfigError, loadConfig } from "./config.js";
import { doctorMain } from "./doctor.js";
import { resolveGitHubAppEnv } from "./github-app-env.js";
import { createOwnerSwitchProxy } from "./proxy.js";
import { assertUpstreamArgsCredentialFree, upstreamEnvironment } from "./upstream-env.js";
import { createVetoClient } from "./veto-client.js";
import { verifyMain } from "./verify.js";

/**
 * Un-prefixed alias names a gateway credential might ride into the upstream
 * child under, stripped from its environment by NAME regardless of value
 * (see upstream-env.ts). OWNERSWITCH_* names are always stripped separately.
 */
const KNOWN_CREDENTIAL_ENV_NAMES = ["GITHUB_TOKEN", "GH_TOKEN", "DEVICE_SECRET", "CANARY_KEY"];

/**
 * Arm the honeytoken tripwire when a registry is configured. Opt-in, and
 * explicit: the canary key is DEDICATED (never the device secret), and the
 * deployment id must match the one the registry was minted for — loadRegistry
 * rejects a tampered or foreign registry loudly. Returns undefined when no
 * registry is configured (the gateway runs without honeytoken scanning).
 */
function armTripwire(controlPlaneUrl: string, device: { id: string; secret: string }): Tripwire | undefined {
  const registryPath = process.env.OWNERSWITCH_HONEYTOKEN_REGISTRY;
  if (registryPath === undefined) return undefined;

  const canaryKey = process.env.OWNERSWITCH_CANARY_KEY;
  const deploymentId = process.env.OWNERSWITCH_DEPLOYMENT_ID;
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
    serialized = readRegistryFile(registryPath);
  } catch (err) {
    throw new ConfigError(
      `cannot read honeytoken registry "${registryPath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  let registry;
  try {
    registry = loadRegistry(serialized, { canaryKey, deploymentId });
  } catch (err) {
    throw new ConfigError(`honeytoken registry rejected: ${err instanceof Error ? err.message : String(err)}`);
  }
  return createTripwire({ controlPlaneUrl, deviceId: device.id, secret: device.secret, registry });
}

async function runGateway(argv: string[]): Promise<void> {
  const config = loadConfig(argv, process.env);
  const { controlPlaneUrl, device, timeoutMs = 1500 } = config;

  const tripwire = armTripwire(controlPlaneUrl, device);
  const controlPlane = createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs });

  // Executor routing, when configured: routed tools are performed by the
  // executor with OwnerSwitch's own credential, never forwarded upstream.
  // The executor re-checks live kill state through the SAME fail-closed
  // control-plane client the decision path uses. One Executor instance for
  // the gateway's lifetime — its nonce store is what makes tickets
  // single-use WITHIN THIS PROCESS (see DESIGN.md §5 for the deployment
  // constraint).
  //
  // The GitHub backend authenticates as a GitHub App (DESIGN.md §6):
  // OWNERSWITCH_GITHUB_APP_ID + OWNERSWITCH_GITHUB_APP_INSTALLATION_ID +
  // OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE, all-or-nothing (a partial set
  // refused above at resolveGitHubAppEnv). The key file must live OUTSIDE
  // the agent's workspace — same rule as the kill-state file, enforced at
  // load. With no App configured the gateway still runs; a routed merge
  // that clears every check fails cleanly as not-configured.
  //
  // OWNERSWITCH_GITHUB_TOKEN is NOT an accepted credential — a PAT is a
  // standing, broadly-scoped secret, exactly what DESIGN.md §5 rules out.
  // If it is set anyway, it still arms the backend's scrubbing and the
  // upstream env-strip below, so a stray token can never widen what the
  // agent sees.
  const routes = config.executorRoutes;
  const githubToken = process.env.OWNERSWITCH_GITHUB_TOKEN;
  const githubApp = resolveGitHubAppEnv(process.env);
  const ledger = createSecretLedger();
  let githubClient: GitHubMergeClient | undefined;
  let githubAppKeyPem: string | undefined;
  if (githubApp !== undefined) {
    let key;
    try {
      key = loadGitHubAppPrivateKey(githubApp.privateKeyFile, { workspaceDir: process.cwd() });
    } catch (err) {
      throw new ConfigError(err instanceof Error ? err.message : String(err));
    }
    githubAppKeyPem = key.pem;
    ledger.add(key.pem);
    githubClient = createGitHubMergeClient({
      tokens: createInstallationTokenSource({
        app: {
          appId: githubApp.appId,
          installationId: githubApp.installationId,
          privateKey: key.key,
        },
        ledger,
      }),
      ledger,
    });
  }
  const executor =
    routes !== undefined && Object.keys(routes).length > 0
      ? (() => {
          const backend = new GitHubMergePrExecutor(
            githubClient,
            githubToken !== undefined && githubToken !== "" ? { token: githubToken } : undefined,
            (text) => ledger.redact(text),
          );
          const runner = new Executor(backend, {
            fetchLiveKillState: liveKillStateFromControlPlane(controlPlane),
          });
          return { routes, run: (ticket: ActionTicket) => runner.run(ticket) };
        })()
      : undefined;

  const proxy = createOwnerSwitchProxy({
    policy: config.policy,
    agentId: config.agentId,
    controlPlane,
    vetoClient: createVetoClient({ baseUrl: controlPlaneUrl, device, timeoutMs }),
    ...(tripwire !== undefined ? { honeytokens: tripwire } : {}),
    ...(executor !== undefined ? { executor } : {}),
  });

  let shuttingDown = false;
  const shutdown = (code: number): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void proxy.close().finally(async () => {
      // Flush first: a tripped-but-unconfirmed kill must not be lost on exit.
      // Bounded, so a down control plane can't block shutdown forever.
      if (tripwire !== undefined) {
        const { delivered, pending } = await tripwire.flush();
        tripwire.stop();
        if (!delivered) {
          console.error(`[ownerswitch-mcp] exiting with ${pending} honeytoken report(s) UNCONFIRMED`);
        }
      }
      process.exit(code);
    });
  };

  // Every gateway credential this process holds, in one place: reused for
  // both the environment filter (by value AND by known alias name) and the
  // args check below (by value — a credential in argv is a hard refusal,
  // not a filter, since argv is visible to any process that can read it).
  // The GitHub App PRIVATE KEY rides along: installation tokens minted from
  // it exist only after startup and can't be inherited, but the key itself
  // pasted into an env var or an argument absolutely can be.
  const gatewaySecretValues = [
    config.device.secret,
    githubToken,
    githubAppKeyPem,
    process.env.OWNERSWITCH_CANARY_KEY,
    process.env.OWNERSWITCH_DEVICE_SECRET,
  ];
  // Command-line arguments are a worse leak surface than an environment
  // variable (visible via /proc/<pid>/cmdline, `ps aux`, …) — refuse to
  // start rather than filter, naming the offending argument, never its value.
  assertUpstreamArgsCredentialFree(config.upstream.args, gatewaySecretValues);

  await proxy.connectUpstream(
    new StdioClientTransport({
      command: config.upstream.command,
      args: config.upstream.args ?? [],
      // The child's environment is EXACTLY upstreamEnvironment()'s output:
      // built explicitly, every gateway/executor/connector credential
      // stripped by name (OWNERSWITCH_* and known aliases) and by value.
      // The upstream child is the agent's side of the boundary — it must
      // never inherit the credential the executor exists to keep away from it.
      env: upstreamEnvironment({
        base: getDefaultEnvironment(),
        configured: config.upstream.env,
        secretValues: gatewaySecretValues,
        secretNames: KNOWN_CREDENTIAL_ENV_NAMES,
      }),
      cwd: config.upstream.cwd,
      stderr: "inherit",
    }),
  );
  await proxy.connect(new StdioServerTransport());

  // the agent hanging up (stdin closed) or a signal ends both sides
  proxy.server.onclose = () => shutdown(0);
  process.on("SIGINT", () => shutdown(0));
  process.on("SIGTERM", () => shutdown(0));

  const connectorState =
    githubClient !== undefined
      ? `github connector: live (App ${githubApp?.appId ?? "?"})`
      : "github connector: not configured (routed merges will refuse)";
  console.error(
    `[ownerswitch-mcp] guarding "${config.upstream.command}" — ` +
      `policy: ${config.policy.rules.length} rule(s), default ${config.policy.defaultDecision}; ` +
      `control plane: ${controlPlaneUrl}; honeytoken tripwires: ${tripwire !== undefined ? "armed" : "off (no registry configured)"}; ` +
      `executor routes: ${executor !== undefined ? `${Object.keys(executor.routes).join(", ")} (${connectorState})` : "none (all yes-decisions forward upstream)"}`,
  );
}

async function main(): Promise<void> {
  const [sub, ...rest] = process.argv.slice(2);
  if (sub === "doctor") {
    process.exit(await doctorMain(rest, process.env));
  } else if (sub === "verify") {
    process.exit(await verifyMain(rest, process.env));
  } else {
    await runGateway(process.argv.slice(2));
  }
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) console.error(`[ownerswitch-mcp] config error: ${err.message}`);
  else console.error(`[ownerswitch-mcp] failed to start:`, err);
  process.exit(1);
});
