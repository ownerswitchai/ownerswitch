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
import { ConfigError, loadConfig } from "./config.js";
import { doctorMain } from "./doctor.js";
import { createOwnerSwitchProxy } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";
import { verifyMain } from "./verify.js";

async function runGateway(argv: string[]): Promise<void> {
  const config = loadConfig(argv, process.env);
  const { controlPlaneUrl, device, timeoutMs = 1500 } = config;

  const proxy = createOwnerSwitchProxy({
    policy: config.policy,
    agentId: config.agentId,
    controlPlane: createControlPlaneClient({ baseUrl: controlPlaneUrl, timeoutMs }),
    vetoClient: createVetoClient({ baseUrl: controlPlaneUrl, device, timeoutMs }),
  });

  let shuttingDown = false;
  const shutdown = (code: number): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void proxy.close().finally(() => process.exit(code));
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
      `control plane: ${controlPlaneUrl}`,
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
