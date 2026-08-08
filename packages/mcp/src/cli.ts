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
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { createTripwire, loadRegistry, readRegistryFile, type Tripwire } from "@ownerswitchai/honeytoken";
import { ConfigError, loadConfig } from "./config.js";
import { doctorMain } from "./doctor.js";
import { createOwnerSwitchProxy } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";
import { verifyMain } from "./verify.js";

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

  const proxy = createOwnerSwitchProxy({
    policy: config.policy,
    agentId: config.agentId,
    controlPlane: createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs }),
    vetoClient: createVetoClient({ baseUrl: controlPlaneUrl, device, timeoutMs }),
    ...(tripwire !== undefined ? { honeytokens: tripwire } : {}),
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

  await proxy.connectUpstream(
    new StdioClientTransport({
      command: config.upstream.command,
      args: config.upstream.args ?? [],
      env: { ...getDefaultEnvironment(), ...(config.upstream.env ?? {}) },
      cwd: config.upstream.cwd,
      stderr: "inherit",
    }),
  );
  await proxy.connect(new StdioServerTransport());

  // the agent hanging up (stdin closed) or a signal ends both sides
  proxy.server.onclose = () => shutdown(0);
  process.on("SIGINT", () => shutdown(0));
  process.on("SIGTERM", () => shutdown(0));

  console.error(
    `[ownerswitch-mcp] guarding "${config.upstream.command}" — ` +
      `policy: ${config.policy.rules.length} rule(s), default ${config.policy.defaultDecision}; ` +
      `control plane: ${controlPlaneUrl}; honeytoken tripwires: ${tripwire !== undefined ? "armed" : "off (no registry configured)"}`,
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
