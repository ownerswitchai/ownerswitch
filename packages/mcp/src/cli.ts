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
import { createTripwire } from "@ownerswitchai/honeytoken";
import { ConfigError, loadConfig } from "./config.js";
import { createOwnerSwitchProxy } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";

async function main(): Promise<void> {
  const config = loadConfig(process.argv.slice(2), process.env);
  const { controlPlaneUrl, device, timeoutMs = 1500 } = config;

  // Always on — scanning is pattern-based (no registry to configure), and the
  // gateway already holds the device credentials a signed kill needs.
  const tripwire = createTripwire({
    controlPlaneUrl,
    deviceId: device.id,
    secret: device.secret,
  });

  const proxy = createOwnerSwitchProxy({
    policy: config.policy,
    agentId: config.agentId,
    controlPlane: createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs }),
    vetoClient: createVetoClient({ baseUrl: controlPlaneUrl, device, timeoutMs }),
    honeytokens: tripwire,
  });

  let shuttingDown = false;
  const shutdown = (code: number): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void proxy.close().finally(async () => {
      // Flush first: a tripped-but-unconfirmed kill must not be lost on exit.
      // Bounded, so a down control plane can't block shutdown forever.
      const { delivered, pending } = await tripwire.flush();
      tripwire.stop();
      if (!delivered) {
        console.error(`[ownerswitch-mcp] exiting with ${pending} honeytoken kill report(s) UNCONFIRMED`);
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
      `control plane: ${controlPlaneUrl}; honeytoken tripwires: armed`,
  );
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) console.error(`[ownerswitch-mcp] config error: ${err.message}`);
  else console.error(`[ownerswitch-mcp] failed to start:`, err);
  process.exit(1);
});
