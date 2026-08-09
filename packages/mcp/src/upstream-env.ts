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
}): Record<string, string> {
  const merged = { ...opts.base, ...(opts.configured ?? {}) };
  const secrets = (opts.secretValues ?? []).filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(merged)) {
    if (/^OWNERSWITCH_/i.test(key)) continue;
    if (secrets.some((secret) => value.includes(secret))) continue;
    env[key] = value;
  }
  return env;
}
