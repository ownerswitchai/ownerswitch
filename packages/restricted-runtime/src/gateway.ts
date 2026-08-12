import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { OwnerSwitchMcpConfig } from "@ownerswitchai/mcp";

/**
 * How the gateway is launched, and why it must launch FAST.
 *
 * Claude Code health-checks each MCP server with a bounded handshake (30 s in
 * `claude mcp list`; the per-call MCP timeout otherwise). A server that has
 * not answered the MCP `initialize` handshake by then is dropped, and its
 * tools never appear — the agent is then left with no route to acting and the
 * profile silently fails OPEN of its own purpose. We hit exactly this: the
 * README's quickstart launch (`npx tsx` for the gateway, `npx -y …` for the
 * upstream) cold-starts four-plus processes and a registry resolution and
 * blew past 30 s. The fixes, both verified to bring the whole handshake under
 * ~1 s here:
 *   - launch the gateway with the already-resolved local `tsx` binary, not
 *     `npx tsx` (no per-launch registry/resolution round trip);
 *   - launch the demo upstream with `node <resolved server entry>`, not
 *     `npx -y <pkg>` (no download/resolution on the hot path).
 * This mirrors the README's own `pnpm exec` vs `npx tsx` warning, one layer
 * deeper: for an MCP CHILD, even `npx` is too slow.
 */

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

export interface WorkspacePaths {
  workspaceRoot: string;
  /** the local tsx binary — fast launch, no npx round trip */
  tsxBin: string;
  /** packages/mcp/src/cli.ts — the gateway entry point */
  mcpCli: string;
  /** packages/mcp — the cwd the gateway is launched from */
  mcpCwd: string;
}

/** Resolve the in-repo paths the gateway launch needs, from this file's location. */
export function resolveWorkspacePaths(): WorkspacePaths {
  const pkgRoot = resolve(here, ".."); // packages/restricted-runtime
  const packagesDir = resolve(pkgRoot, ".."); // packages
  const workspaceRoot = resolve(packagesDir, ".."); // repo root
  return {
    workspaceRoot,
    tsxBin: resolve(workspaceRoot, "node_modules/.bin/tsx"),
    mcpCli: resolve(packagesDir, "mcp/src/cli.ts"),
    mcpCwd: resolve(packagesDir, "mcp"),
  };
}

/** Absolute path to the demo filesystem MCP server's entry (a devDependency). */
export function resolveFilesystemServerEntry(): string {
  return require.resolve("@modelcontextprotocol/server-filesystem/dist/index.js");
}

/** True when a config's upstream is the demo filesystem server (any launch form). */
export function isFilesystemUpstream(config: OwnerSwitchMcpConfig): boolean {
  const hay = [config.upstream.command, ...(config.upstream.args ?? [])].join(" ");
  return hay.includes("server-filesystem");
}

/**
 * Return a copy of `config` whose upstream is the demo filesystem server
 * launched the FAST way — `node <entry> <workDir>` — rooted at `workDir`.
 * Applied only when the base upstream already IS the filesystem server: a real
 * operator's upstream is left exactly as configured (they own its launch
 * speed; the launcher runs `doctor` first so a slow one fails before an agent
 * is ever spawned). Pure — does no I/O beyond the caller-supplied entry path.
 */
export function withFastFilesystemUpstream(
  config: OwnerSwitchMcpConfig,
  workDir: string,
  serverEntry: string,
): OwnerSwitchMcpConfig {
  if (!isFilesystemUpstream(config)) return config;
  return {
    ...config,
    upstream: { command: "node", args: [serverEntry, workDir] },
  };
}

export interface GatewayLaunch {
  command: string;
  args: string[];
  cwd: string;
}

/** The fast gateway launch for a given effective-config path. */
export function buildGatewayLaunch(paths: WorkspacePaths, effectiveConfigPath: string): GatewayLaunch {
  return {
    command: paths.tsxBin,
    args: [paths.mcpCli, "--config", effectiveConfigPath],
    cwd: paths.mcpCwd,
  };
}

/** The Claude Code `--mcp-config` object registering the gateway under `serverName`. */
export function buildClaudeMcpConfig(
  serverName: string,
  launch: GatewayLaunch,
): { mcpServers: Record<string, { command: string; args: string[]; cwd: string }> } {
  return {
    mcpServers: {
      [serverName]: { command: launch.command, args: launch.args, cwd: launch.cwd },
    },
  };
}
