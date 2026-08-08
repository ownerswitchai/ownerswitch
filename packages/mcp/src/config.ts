import { readFileSync } from "node:fs";
import type { Decision, Policy, PolicyRule } from "@ownerswitchai/shared";
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

export interface OwnerSwitchMcpConfig {
  controlPlaneUrl: string;
  device: DeviceIdentity;
  upstream: UpstreamConfig;
  policy: Policy;
  /** names this gateway's agent in tool calls and audit; default "ownerswitch-mcp" */
  agentId?: string;
  /** timeout for each control-plane HTTP call in ms; default 1500 */
  timeoutMs?: number;
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
  return {
    controlPlaneUrl,
    device: {
      id: requireString(v.device.id, "device.id"),
      secret: requireString(v.device.secret, "device.secret"),
    },
    upstream: parseUpstream(v.upstream, "upstream"),
    policy: parsePolicy(v.policy, "policy"),
    ...(v.agentId !== undefined ? { agentId: requireString(v.agentId, "agentId") } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
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
  };
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
  readFile: (path: string) => string = (p) => readFileSync(p, "utf8"),
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
