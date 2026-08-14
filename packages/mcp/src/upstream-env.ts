import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ConfigError, type UpstreamConfig } from "./config.js";

/**
 * Un-prefixed alias names a gateway credential might ride into the upstream
 * child under, stripped from its environment by NAME regardless of value.
 * OWNERSWITCH_* names are always stripped separately.
 */
export const KNOWN_CREDENTIAL_ENV_NAMES = [
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "DEVICE_SECRET",
  "CANARY_KEY",
] as const;

/** Everything needed to spawn the upstream child — see upstreamLaunchSpec. */
export interface UpstreamLaunchSpec {
  command: string;
  args: string[];
  env: Record<string, string>;
  cwd?: string;
}

/**
 * THE way the upstream child is launched — one function, so there is one
 * answer to "what environment does the upstream get?".
 *
 * `doctor` used to build the child's environment itself, and the copy it
 * built was the unfiltered one: base + upstream.env, no credential strip.
 * That made the preflight tool a wider leak than the thing it checks — a
 * device secret parked in `upstream.env` under an innocent name reached the
 * untrusted child on every `doctor` run, while the gateway stripped it. A
 * preflight must never be the most dangerous way to run a config, so the
 * spec is built here and both callers take it whole.
 */
export function upstreamLaunchSpec(
  upstream: UpstreamConfig,
  secretValues: ReadonlyArray<string | undefined>,
  base: Record<string, string> = getDefaultEnvironment(),
): UpstreamLaunchSpec {
  return {
    command: upstream.command,
    args: upstream.args ?? [],
    env: upstreamEnvironment({
      base,
      configured: upstream.env,
      secretValues,
      secretNames: KNOWN_CREDENTIAL_ENV_NAMES,
    }),
    ...(upstream.cwd !== undefined ? { cwd: upstream.cwd } : {}),
  };
}

/**
 * The environment handed to the spawned upstream MCP server — built
 * EXPLICITLY, never inherited wholesale.
 *
 * The executor's entire premise is that the agent's side of the boundary
 * holds no credential, and the upstream child process IS the agent's side.
 * If the child inherited the gateway's environment it would receive
 * OWNERSWITCH_GITHUB_TOKEN, the device secret, the canary key — and the
 * premise would be false, silently, with every test still green. So the
 * child's env is assembled from a safe base (the MCP SDK's
 * getDefaultEnvironment(), which whitelists HOME/PATH/etc.) plus the
 * operator's configured upstream.env, and then filtered:
 *
 *  - every OWNERSWITCH_* variable is dropped, whatever it holds — the
 *    gateway's own namespace (config, secrets, credential seams) is never
 *    the child's business, even when upstream.env re-adds one by mistake;
 *  - every entry whose NAME matches a known gateway credential alias (e.g.
 *    "GITHUB_TOKEN", "DEVICE_SECRET") is dropped regardless of its current
 *    value — defense in depth for the case a value filter can't reach: a
 *    truncated, re-encoded, or not-yet-populated credential that doesn't
 *    byte-match anything in secretValues;
 *  - every entry whose VALUE contains one of the gateway's known credential
 *    values is dropped, so a credential cannot ride into the child under an
 *    alias name (GITHUB_TOKEN, AUTH_HEADER="Bearer <token>", …).
 *
 * This is the FIRST line of defence for the child; the backend's scrubbing
 * of results and errors (github.ts) is the second. See DESIGN.md §5.
 */
export function upstreamEnvironment(opts: {
  /** safe inherited base — pass the SDK's getDefaultEnvironment() */
  base: Record<string, string>;
  /** operator-configured upstream env (config.upstream.env) */
  configured?: Record<string, string> | undefined;
  /**
   * credential VALUES the gateway holds (device secret, connector tokens,
   * canary key); entries containing any of them are stripped regardless of
   * their name. Empty/undefined values are ignored.
   */
  secretValues?: ReadonlyArray<string | undefined>;
  /**
   * environment variable NAMES known to carry a gateway credential by
   * convention (e.g. "GITHUB_TOKEN", "DEVICE_SECRET", "GH_TOKEN"), stripped
   * regardless of their current value. Comparison is case-insensitive.
   * OWNERSWITCH_* names are always stripped independent of this list.
   */
  secretNames?: ReadonlyArray<string>;
}): Record<string, string> {
  const merged = { ...opts.base, ...(opts.configured ?? {}) };
  const secrets = (opts.secretValues ?? []).filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  const secretNames = new Set((opts.secretNames ?? []).map((name) => name.toUpperCase()));
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(merged)) {
    if (/^OWNERSWITCH_/i.test(key)) continue;
    if (secretNames.has(key.toUpperCase())) continue;
    if (secrets.some((secret) => value.includes(secret))) continue;
    env[key] = value;
  }
  return env;
}

/**
 * Refuse to start if any upstream.args entry contains a known gateway
 * credential VALUE. Command-line arguments are a worse leak surface than an
 * environment variable — they are visible to any process on the host that
 * can read this process's argv (e.g. /proc/<pid>/cmdline, `ps aux`), not
 * just ones that can read its environ or attach a debugger. So a credential
 * here is not filtered like an env entry, it is a hard startup refusal. The
 * error names WHICH argument is at fault (by position), never its value.
 */
export function assertUpstreamArgsCredentialFree(
  args: ReadonlyArray<string> | undefined,
  secretValues: ReadonlyArray<string | undefined>,
): void {
  if (args === undefined) return;
  const secrets = secretValues.filter((s): s is string => typeof s === "string" && s !== "");
  if (secrets.length === 0) return;
  args.forEach((arg, index) => {
    if (secrets.some((secret) => arg.includes(secret))) {
      throw new ConfigError(
        `upstream.args[${index}] contains a gateway credential value — refusing to start. ` +
          `Command-line arguments are visible to any process on the host that can read this ` +
          `process's argv (e.g. /proc/<pid>/cmdline, "ps aux"), which is far more exposed than ` +
          `an environment variable. Remove the credential from upstream.args; the upstream ` +
          `tool has no legitimate reason to receive OwnerSwitch's own credential at all.`,
      );
    }
  });
}
