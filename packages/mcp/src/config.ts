import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { rulesMatchingTool } from "@ownerswitchai/gateway";
import {
  isValidAgentId,
  MAX_AGENT_ID_CHARS,
  type Decision,
  type Policy,
  type PolicyRule,
} from "@ownerswitchai/shared";
import type { DeviceIdentity } from "./veto-client.js";

/**
 * Gateway configuration — one JSON file, or the OWNERSWITCH_* environment
 * variables when no file is given. Everything the proxy needs lives here:
 * where the control plane is, who this gateway is (device credentials), what
 * to run upstream, and the policy that judges every tool call.
 */
export interface UpstreamConfig {
  /** command to launch the upstream MCP server (stdio) */
  command: string;
  args?: string[];
  /** extra environment for the upstream process (merged over a safe default) */
  env?: Record<string, string>;
  cwd?: string;
}

/** Where an executor-routed MCP tool lands: which backend, which action. */
export interface ExecutorRouteConfig {
  /** e.g. "github" */
  connector: string;
  /** e.g. "merge_pull_request" */
  operation: string;
}

export interface OwnerSwitchMcpConfig {
  controlPlaneUrl: string;
  device: DeviceIdentity;
  upstream: UpstreamConfig;
  policy: Policy;
  /** names this gateway's agent in tool calls and audit; default "ownerswitch-mcp" */
  agentId?: string;
  /** timeout for each control-plane HTTP call in ms; default 1500 */
  timeoutMs?: number;
  /**
   * MCP tool name → executor (connector, operation), e.g.
   * `"github.merge_pr": { "connector": "github", "operation": "merge_pull_request" }`.
   * A yes-decision on a routed tool mints an ActionTicket and the executor
   * performs the action with OwnerSwitch's own credential — the call is
   * never forwarded upstream, and the agent receives the result, never a
   * token. Tools not listed here forward exactly as before.
   */
  executorRoutes?: Record<string, ExecutorRouteConfig>;
}

/** Configuration problems are startup errors: message only, no stack noise. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const DECISIONS: readonly Decision[] = ["allow", "veto", "approve", "deny"];

const fail = (message: string): never => {
  throw new ConfigError(message);
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const requireString = (v: unknown, path: string): string =>
  typeof v === "string" && v !== "" ? v : fail(`${path} must be a non-empty string`);

const optionalString = (v: unknown, path: string): string | undefined =>
  v === undefined ? undefined : requireString(v, path);

/**
 * The agentId must satisfy the SHARED contract at startup, not at kill
 * time: an id this gateway runs under but `POST /kill {agentId}` would
 * refuse is an agent with no scoped stop — the mismatch must be a config
 * error the operator sees, never a gap the incident discovers.
 */
const requireAgentId = (v: unknown, path: string): string => {
  const id = requireString(v, path);
  return isValidAgentId(id)
    ? id
    : fail(
        `${path} must satisfy the OwnerSwitch agentId contract: 1-${MAX_AGENT_ID_CHARS} ` +
          `printable-ASCII chars, no leading/trailing spaces, not a prototype-footgun name ` +
          `("__proto__", "constructor", "prototype") — got ${JSON.stringify(id)}`,
      );
};

function parseRule(v: unknown, path: string): PolicyRule {
  if (!isRecord(v)) return fail(`${path} must be an object`);
  const decision = v.decision;
  if (!DECISIONS.includes(decision as Decision)) {
    return fail(`${path}.decision must be one of ${DECISIONS.join(" | ")}`);
  }
  const argsPattern = optionalString(v.argsPattern, `${path}.argsPattern`);
  if (argsPattern !== undefined) {
    try {
      new RegExp(argsPattern);
    } catch {
      return fail(`${path}.argsPattern is not a valid regular expression`);
    }
  }
  return {
    id: requireString(v.id, `${path}.id`),
    tool: requireString(v.tool, `${path}.tool`),
    decision: decision as Decision,
    ...(argsPattern !== undefined ? { argsPattern } : {}),
    ...(v.description !== undefined
      ? { description: requireString(v.description, `${path}.description`) }
      : {}),
  };
}

function parsePolicy(v: unknown, path: string): Policy {
  if (!isRecord(v)) return fail(`${path} must be an object with rules and defaultDecision`);
  if (!Array.isArray(v.rules)) return fail(`${path}.rules must be an array`);
  if (!DECISIONS.includes(v.defaultDecision as Decision)) {
    return fail(`${path}.defaultDecision must be one of ${DECISIONS.join(" | ")}`);
  }
  return {
    rules: v.rules.map((rule, i) => parseRule(rule, `${path}.rules[${i}]`)),
    defaultDecision: v.defaultDecision as Decision,
  };
}

function parseUpstream(v: unknown, path: string): UpstreamConfig {
  if (!isRecord(v)) return fail(`${path} must be an object with a command`);
  if (v.args !== undefined && !Array.isArray(v.args)) return fail(`${path}.args must be an array`);
  const args = (v.args as unknown[] | undefined)?.map((a, i) =>
    requireString(a, `${path}.args[${i}]`),
  );
  let env: Record<string, string> | undefined;
  if (v.env !== undefined) {
    if (!isRecord(v.env)) return fail(`${path}.env must be an object of strings`);
    env = Object.fromEntries(
      Object.entries(v.env).map(([k, val]) => [k, requireString(val, `${path}.env.${k}`)]),
    );
  }
  return {
    command: requireString(v.command, `${path}.command`),
    ...(args !== undefined ? { args } : {}),
    ...(env !== undefined ? { env } : {}),
    ...(v.cwd !== undefined ? { cwd: requireString(v.cwd, `${path}.cwd`) } : {}),
  };
}

/**
 * Everything that can influence the verdict for a tool NAME: the ordered
 * candidate rules the engine would walk for it (id, decision, argsPattern —
 * argsPattern included because it decides per call WHICH candidate fires),
 * plus the fail-closed default. Two tool names with identical signatures
 * provably get identical verdicts for identical arguments.
 */
const verdictSignature = (policy: Policy, tool: string): string =>
  JSON.stringify([
    rulesMatchingTool(policy, tool).map((r) => [r.id, r.decision, r.argsPattern ?? null]),
    policy.defaultDecision,
  ]);

/**
 * Refuse a config where one executor (connector, operation) is reachable
 * through aliases the policy can decide DIFFERENTLY. Policy judges the
 * agent-chosen MCP tool name; routes map names to real operations
 * afterwards — so `github.automerge_pr: allow` next to
 * `github.merge_pr: veto`, both routed to merge_pull_request, would let the
 * agent reach the guarded operation through whichever alias is looser. That
 * is a policy bypass, and it is a configuration error: fail loudly at
 * startup, naming both tools. Aliases whose verdicts provably coincide
 * (e.g. both covered by the same glob rule) remain allowed — several MCP
 * surfaces may front one operation, but only in the same lane.
 */
export function assertExecutorRoutesCoherent(
  policy: Policy,
  routes: Record<string, ExecutorRouteConfig>,
): void {
  const seen = new Map<string, { tool: string; signature: string }>();
  for (const [tool, route] of Object.entries(routes)) {
    const operation = `${route.connector}.${route.operation}`;
    const signature = verdictSignature(policy, tool);
    const first = seen.get(operation);
    if (first === undefined) {
      seen.set(operation, { tool, signature });
    } else if (first.signature !== signature) {
      fail(
        `executor routes "${first.tool}" and "${tool}" both reach ${operation}, but the policy ` +
          `can decide them differently — an agent would simply call whichever alias is looser. ` +
          `Refusing to start: give every alias of one operation the same policy outcome (one ` +
          `glob rule covering all aliases is the simple fix), or route only one of them.`,
      );
    }
  }
}

function parseExecutorRoutes(v: unknown, path: string): Record<string, ExecutorRouteConfig> {
  if (!isRecord(v)) return fail(`${path} must be an object mapping tool names to routes`);
  const routes: Record<string, ExecutorRouteConfig> = {};
  for (const [tool, route] of Object.entries(v)) {
    if (tool === "") return fail(`${path} keys must be non-empty tool names`);
    const routePath = `${path}["${tool}"]`;
    if (!isRecord(route)) return fail(`${routePath} must be an object with connector and operation`);
    routes[tool] = {
      connector: requireString(route.connector, `${routePath}.connector`),
      operation: requireString(route.operation, `${routePath}.operation`),
    };
  }
  return routes;
}

/** Validate an already-parsed config object (the JSON file's contents). */
export function parseConfig(v: unknown): OwnerSwitchMcpConfig {
  if (!isRecord(v)) return fail("config must be a JSON object");
  const controlPlaneUrl = requireString(v.controlPlaneUrl, "controlPlaneUrl");
  try {
    new URL(controlPlaneUrl);
  } catch {
    fail(`controlPlaneUrl is not a valid URL: "${controlPlaneUrl}"`);
  }
  if (!isRecord(v.device)) return fail("device must be an object with id and secret");
  const timeoutMs = v.timeoutMs;
  if (timeoutMs !== undefined && (typeof timeoutMs !== "number" || !(timeoutMs > 0))) {
    return fail("timeoutMs must be a positive number");
  }
  const policy = parsePolicy(v.policy, "policy");
  const executorRoutes =
    v.executorRoutes !== undefined
      ? parseExecutorRoutes(v.executorRoutes, "executorRoutes")
      : undefined;
  // a route set that lets aliases of one operation land in different policy
  // lanes is a policy bypass — a startup error, never a warning
  if (executorRoutes !== undefined) assertExecutorRoutesCoherent(policy, executorRoutes);
  return {
    controlPlaneUrl,
    device: {
      id: requireString(v.device.id, "device.id"),
      secret: requireString(v.device.secret, "device.secret"),
    },
    upstream: parseUpstream(v.upstream, "upstream"),
    policy,
    ...(v.agentId !== undefined ? { agentId: requireAgentId(v.agentId, "agentId") } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(executorRoutes !== undefined ? { executorRoutes } : {}),
  };
}

const parseJson = (text: string, source: string): unknown => {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return fail(`${source} is not valid JSON`);
  }
};

function fromEnv(env: Record<string, string | undefined>): unknown {
  const upstreamArgs = env.OWNERSWITCH_UPSTREAM_ARGS;
  return {
    controlPlaneUrl: env.OWNERSWITCH_CONTROL_PLANE_URL,
    device: { id: env.OWNERSWITCH_DEVICE_ID, secret: env.OWNERSWITCH_DEVICE_SECRET },
    upstream: {
      command: env.OWNERSWITCH_UPSTREAM_COMMAND,
      ...(upstreamArgs !== undefined
        ? { args: parseJson(upstreamArgs, "OWNERSWITCH_UPSTREAM_ARGS") }
        : {}),
    },
    policy:
      env.OWNERSWITCH_POLICY !== undefined
        ? parseJson(env.OWNERSWITCH_POLICY, "OWNERSWITCH_POLICY")
        : fail(
            "no config given: pass --config <file>, set OWNERSWITCH_MCP_CONFIG to a file, " +
              "or set the OWNERSWITCH_* variables (OWNERSWITCH_POLICY is missing)",
          ),
    ...(env.OWNERSWITCH_AGENT_ID !== undefined ? { agentId: env.OWNERSWITCH_AGENT_ID } : {}),
    ...(env.OWNERSWITCH_TIMEOUT_MS !== undefined
      ? { timeoutMs: Number(env.OWNERSWITCH_TIMEOUT_MS) }
      : {}),
    ...(env.OWNERSWITCH_EXECUTOR_ROUTES !== undefined
      ? {
          executorRoutes: parseJson(env.OWNERSWITCH_EXECUTOR_ROUTES, "OWNERSWITCH_EXECUTOR_ROUTES"),
        }
      : {}),
  };
}

const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

// O_NOFOLLOW is POSIX; on a platform without it the flag degrades to 0 and
// the fstat regular-file check in readConfigFile is the remaining guard —
// same caveat, and the same gap, as packages/honeytoken/src/registry.ts and
// packages/control-plane/src/kill-state.ts.
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/** Hard ceiling on the config file's byte size — see readConfigFile(). */
export const MAX_CONFIG_FILE_BYTES = 1024 * 1024;

/**
 * Warn — loudly, but non-fatally — when the config file's mode grants more
 * than owner read/write. It holds device.secret in plaintext; a group- or
 * world-readable config leaks that secret to every other local account. This
 * doesn't refuse to start: an operator's umask or a mounted secrets volume
 * may legitimately produce a mode this check doesn't love, and a hard
 * refusal here would turn a permissions slip into an outage of the whole
 * gateway. Owner-only extra bits (e.g. execute) aren't flagged — they don't
 * expose the secret to anyone else.
 */
function warnIfModeTooPermissive(path: string, rawMode: number): void {
  const mode = rawMode & 0o777;
  if ((mode & ~0o600) === 0) return;
  console.error(
    `[ownerswitch] config file "${path}" has mode ${mode.toString(8).padStart(3, "0")} — it holds ` +
      `device.secret in plaintext and should be 0600 (owner read/write only). Run: chmod 600 ${path}`,
  );
}

/**
 * Read the config file the way a file holding device.secret in plaintext
 * must be read: refuse to follow a symlink at `path` (O_NOFOLLOW — the
 * race-free version of "lstat, then read" — and fstat the open descriptor
 * rather than trusting the path), enforce MAX_CONFIG_FILE_BYTES DURING the
 * read itself rather than via a check-then-read stat (which a concurrent
 * writer could race), and warn loudly when the file's mode is looser than it
 * needs to be.
 *
 * This follows packages/honeytoken/src/registry.ts's readRegistryFile, not
 * packages/control-plane/src/kill-state.ts's load(). Both refuse a symlink
 * the same way (O_NOFOLLOW + fstat), but they differ on the size cap: the
 * registry reads directly off the descriptor in a loop, into a buffer sized
 * exactly limit + 1, and rejects the instant that extra byte is observed —
 * kill-state's load(), once past the regular-file check, hands the fd to a
 * single unbounded readFileSync with no size ceiling at all. Since a real
 * requirement here is "cap the size with a bounded read before parsing", the
 * registry's version is the one that actually does that; kill-state's does
 * not, despite CONTRIBUTING.md citing kill-state.ts as the example for the
 * whole hardened-I/O pattern including the size cap.
 */
export function readConfigFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | O_NOFOLLOW);
  } catch (err) {
    if (errCode(err) === "ELOOP") throw new Error(`${path} is a symlink — refusing to follow it`);
    throw err;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`${path} is not a regular file`);
    warnIfModeTooPermissive(path, stat.mode);
    const limit = MAX_CONFIG_FILE_BYTES;
    const buffer = Buffer.alloc(limit + 1);
    let total = 0;
    for (;;) {
      const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break; // EOF, within bounds
      total += bytesRead;
      if (total > limit) {
        throw new Error(
          `${path} is at least ${total} bytes, over the ${limit}-byte config file limit — ` +
            `refusing to read it into memory`,
        );
      }
    }
    return buffer.toString("utf8", 0, total);
  } finally {
    closeSync(fd);
  }
}

/**
 * Resolve the gateway's config. Precedence:
 *   1. --config <file> / --config=<file> on the command line
 *   2. OWNERSWITCH_MCP_CONFIG=<file>
 *   3. the individual OWNERSWITCH_* environment variables
 */
export function loadConfig(
  argv: string[],
  env: Record<string, string | undefined>,
  readFile: (path: string) => string = readConfigFile,
): OwnerSwitchMcpConfig {
  let file: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config") {
      file = argv[i + 1] ?? fail("--config needs a file path");
      i++;
    } else if (arg.startsWith("--config=")) {
      file = arg.slice("--config=".length);
    } else {
      fail(`unknown argument "${arg}" (only --config <file> is supported)`);
    }
  }
  file ??= env.OWNERSWITCH_MCP_CONFIG;

  if (file !== undefined) {
    let text: string;
    try {
      text = readFile(file);
    } catch (err) {
      return fail(`cannot read config file "${file}": ${err instanceof Error ? err.message : err}`);
    }
    return parseConfig(parseJson(text, `config file "${file}"`));
  }
  return parseConfig(fromEnv(env));
}
