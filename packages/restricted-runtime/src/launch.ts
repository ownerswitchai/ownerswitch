#!/usr/bin/env -S npx tsx
/**
 * ownerswitch-restricted — launch Claude Code as a restricted agent whose ONLY
 * route to acting is the OwnerSwitch MCP gateway.
 *
 * What this does, in order:
 *   1. reads a gateway config (the demo one by default),
 *   2. rewrites the demo upstream to its FAST launch form so the gateway
 *      answers Claude Code's MCP handshake in time (see gateway.ts),
 *   3. runs `doctor` on the effective config — a broken gateway fails HERE,
 *      before an agent is ever spawned,
 *   4. writes the effective gateway config, the Claude Code MCP config, and
 *      the deny settings to a locked-down temp dir,
 *   5. builds the agent's environment with every OWNERSWITCH_* and downstream
 *      credential stripped (env.ts, reusing the gateway's own env filter),
 *   6. spawns `claude` with:
 *        --settings <deny profile>      (removes Write/Edit/Bash/WebFetch/…)
 *        --mcp-config <gateway>         (the gateway, fast launch)
 *        --strict-mcp-config            (and no other MCP server)
 *        --allowedTools mcp__<name>     (gateway calls pass; deny still wins)
 *      plus whatever you pass after `--`.
 *
 * Usage:
 *   pnpm --filter @ownerswitchai/restricted-runtime start -- -p "your prompt"
 *   # or, equivalently:
 *   node_modules/.bin/tsx packages/restricted-runtime/src/launch.ts -- -p "…"
 *
 * Launcher options (before `--`):
 *   --work <dir>            agent working dir + demo filesystem root
 *                           (default: a fresh temp dir)
 *   --gateway-config <file> base OwnerSwitch gateway config
 *                           (default: profile/gateway.config.json)
 *   --control-plane <url>   override the config's controlPlaneUrl
 *   --server-name <name>    MCP server name (default: ownerswitch)
 *   --deny <tool>           deny an extra tool by name (repeatable) — for a
 *                           host that injects acting tools beyond the stock
 *                           built-ins; fail closed against what you don't want
 *   --print-plan            print the resolved launch plan as JSON and exit
 *                           (no agent spawned) — used by the docs and tests
 *   --skip-doctor           skip the preflight (not recommended)
 *   --keep-runtime          leave the temp config dir on disk (for debugging)
 *   -h, --help
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadConfig, type OwnerSwitchMcpConfig } from "@ownerswitchai/mcp";
import { buildRestrictedAgentEnv } from "./env.js";
import {
  buildClaudeMcpConfig,
  buildGatewayLaunch,
  resolveFilesystemServerEntry,
  resolveWorkspacePaths,
  withFastFilesystemUpstream,
} from "./gateway.js";
import { buildClaudeArgs, buildRestrictedSettings } from "./profile.js";

interface CliOptions {
  work?: string;
  gatewayConfig?: string;
  controlPlane?: string;
  serverName: string;
  extraDeny: string[];
  printPlan: boolean;
  skipDoctor: boolean;
  keepRuntime: boolean;
  passthrough: string[];
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    serverName: "ownerswitch",
    extraDeny: [],
    printPlan: false,
    skipDoctor: false,
    keepRuntime: false,
    passthrough: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      opts.passthrough = argv.slice(i + 1);
      break;
    } else if (a === "--work") opts.work = argv[++i];
    else if (a === "--gateway-config") opts.gatewayConfig = argv[++i];
    else if (a === "--control-plane") opts.controlPlane = argv[++i];
    else if (a === "--server-name") opts.serverName = argv[++i] ?? opts.serverName;
    else if (a === "--deny") {
      const tool = argv[++i];
      if (tool) opts.extraDeny.push(tool);
    } else if (a === "--print-plan") opts.printPlan = true;
    else if (a === "--skip-doctor") opts.skipDoctor = true;
    else if (a === "--keep-runtime") opts.keepRuntime = true;
    else if (a === "-h" || a === "--help") {
      printHelp();
      process.exit(0);
    } else {
      fail(`unknown option "${a}" (put claude's own flags after a standalone --)`);
    }
  }
  return opts;
}

function printHelp(): void {
  // The header comment is the manual; keep this terse.
  process.stderr.write(
    "ownerswitch-restricted -- <claude args>\n" +
      "  --work <dir> --gateway-config <file> --control-plane <url>\n" +
      "  --server-name <name> --deny <tool> --print-plan --skip-doctor --keep-runtime\n",
  );
}

function fail(message: string): never {
  process.stderr.write(`[ownerswitch-restricted] ${message}\n`);
  process.exit(1);
}

const DEFAULT_GATEWAY_CONFIG = resolve(
  resolveWorkspacePaths().workspaceRoot,
  "packages/restricted-runtime/profile/gateway.config.json",
);

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const paths = resolveWorkspacePaths();

  // 1. work dir (agent cwd + demo filesystem root)
  const workDir = opts.work ? resolve(opts.work) : mkdtempSync(join(tmpdir(), "ownerswitch-work-"));
  mkdirSync(workDir, { recursive: true });

  // 2. base gateway config → effective (fast demo upstream, optional CP override)
  const baseConfigPath = opts.gatewayConfig ? resolve(opts.gatewayConfig) : DEFAULT_GATEWAY_CONFIG;
  let base: OwnerSwitchMcpConfig;
  try {
    base = loadConfig(["--config", baseConfigPath], process.env);
  } catch (err) {
    return fail(`cannot load gateway config "${baseConfigPath}": ${(err as Error).message}`);
  }
  let effective = withFastFilesystemUpstream(base, workDir, resolveFilesystemServerEntry());
  if (opts.controlPlane) effective = { ...effective, controlPlaneUrl: opts.controlPlane };

  // 3. runtime dir (holds the device secret → 0700 dir, 0600 files)
  const runtimeDir = mkdtempSync(join(tmpdir(), "ownerswitch-runtime-"));
  chmodSync(runtimeDir, 0o700);
  const effectiveConfigPath = join(runtimeDir, "gateway.config.json");
  // Mode at creation (umask-masked) AND an explicit chmod (not umask-masked):
  // this file holds device.secret, so it is 0600 inside the 0700 runtime dir —
  // the "files holding security state are 0600" convention (CONTRIBUTING.md).
  writeFileSync(effectiveConfigPath, JSON.stringify(effective, null, 2), { mode: 0o600 });
  chmodSync(effectiveConfigPath, 0o600);

  const launch = buildGatewayLaunch(paths, effectiveConfigPath);

  // 4. preflight: a broken gateway fails here, not inside the agent. Doctor's
  // human diagnostics go to STDERR (captured and forwarded), keeping the
  // launcher's stdout clean for the agent's own output (e.g. --output-format
  // json), which a caller may be parsing.
  if (!opts.skipDoctor) {
    const doctor = spawnSync(
      launch.command,
      [launch.args[0], "doctor", "--config", effectiveConfigPath],
      {
        cwd: launch.cwd,
        stdio: ["ignore", "pipe", "pipe"],
        env: process.env,
        encoding: "utf8",
        // Bounded preflight (CONTRIBUTING: bounded timeouts): a wedged doctor
        // must fail the launch, not hang it. On timeout status is null, which
        // the !== 0 check below already treats as failure — fail closed.
        timeout: 60_000,
      },
    );
    if (doctor.stdout) process.stderr.write(doctor.stdout);
    if (doctor.stderr) process.stderr.write(doctor.stderr);
    if (doctor.status !== 0) {
      cleanup(runtimeDir, opts.keepRuntime);
      return fail("gateway preflight (doctor) failed — fix the above before launching an agent");
    }
  }

  // 5. Claude Code MCP config + deny settings
  const mcpConfigPath = join(runtimeDir, "claude-mcp.json");
  writeFileSync(mcpConfigPath, JSON.stringify(buildClaudeMcpConfig(opts.serverName, launch), null, 2));

  const settings = buildRestrictedSettings({
    readDenyAbsolutePaths: [effectiveConfigPath],
    extraDenyTools: opts.extraDeny,
  });
  const settingsPath = join(runtimeDir, "claude-settings.json");
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

  const claudeArgs = buildClaudeArgs({
    settingsPath,
    mcpConfigPath,
    mcpServerName: opts.serverName,
    passthrough: opts.passthrough,
  });

  // 6. the agent's environment: OWNERSWITCH_* and downstream creds stripped
  const agentEnv = buildRestrictedAgentEnv(process.env);

  if (opts.printPlan) {
    process.stdout.write(
      JSON.stringify(
        {
          workDir,
          effectiveConfigPath,
          gatewayLaunch: launch,
          deniedTools: settings.permissions.deny,
          claudeArgv: ["claude", ...claudeArgs],
          strippedFromEnv: Object.keys(process.env)
            .filter((k) => typeof process.env[k] === "string")
            .filter((k) => !(k in agentEnv)),
        },
        null,
        2,
      ) + "\n",
    );
    cleanup(runtimeDir, opts.keepRuntime);
    return;
  }

  // 7. spawn the restricted agent
  const child = spawnSync("claude", claudeArgs, { cwd: workDir, stdio: "inherit", env: agentEnv });
  cleanup(runtimeDir, opts.keepRuntime);
  process.exit(child.status ?? 1);
}

function cleanup(runtimeDir: string, keep: boolean): void {
  if (keep) {
    process.stderr.write(`[ownerswitch-restricted] runtime kept at ${runtimeDir}\n`);
    return;
  }
  try {
    rmSync(runtimeDir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

main();
