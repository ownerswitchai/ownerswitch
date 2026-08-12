/**
 * The deny profile: which of Claude Code's built-in tools the restricted
 * runtime removes, and the settings object that removes them.
 *
 * Mechanism (verified against Claude Code 2.1.226; documented at
 * https://code.claude.com/docs/en/permissions and
 * https://code.claude.com/docs/en/settings): a `permissions.deny` entry that
 * is a BARE tool name removes that tool from the session entirely. The agent
 * is not merely refused at call time — the tool is absent, and an attempt to
 * call it returns "No such tool available: <T>. <T> is disabled for this
 * session, in subagents as well as here." Deny takes precedence over allow
 * and over every permission mode, and it propagates to subagents, so it
 * cannot be re-enabled by an --allowedTools flag, a looser user-settings
 * allow, or an Agent/Task subagent.
 */

/**
 * The built-in tools that provide a NON-ROUTED path to the same effects the
 * gateway exists to govern — the paths THREAT-MODEL.md §2 names ("Write/Edit,
 * Bash, and its own egress") and §0's agent actually used. Denying these
 * leaves the OwnerSwitch MCP gateway as the agent's only route to acting.
 *
 * Grouped by the capability each removes; the names are Claude Code's
 * canonical permission-rule tool names. A few appear under more than one name
 * across Claude Code versions (Agent vs Task, KillShell vs KillBash); we deny
 * every spelling because an unknown deny name is a harmless no-op, whereas a
 * missed one is a hole.
 */
export const DENIED_BUILTIN_TOOLS: readonly string[] = [
  // local file mutation — the exact §0 path
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  // shell — writes files, spawns curl, does anything
  "Bash",
  "BashOutput",
  "KillShell",
  "KillBash",
  // the agent's own egress
  "WebFetch",
  "WebSearch",
  // subagent spawn — a child could carry tools this list denies here; the
  // deny propagates to subagents, and denying the spawn tool closes the
  // vector outright
  "Agent",
  "Task",
];

export interface RestrictedSettingsOptions {
  /**
   * Absolute paths the agent must never Read — chiefly the gateway's
   * --config file, which holds the device secret in plaintext. Read stays
   * available for ordinary introspection; only these paths are denied, via a
   * path-scoped Read() rule (documented path-rule syntax:
   * https://code.claude.com/docs/en/permissions).
   */
  readDenyAbsolutePaths?: readonly string[];
  /** Extra bare tool names to deny beyond DENIED_BUILTIN_TOOLS. */
  extraDenyTools?: readonly string[];
}

/** The Claude Code settings object the profile hands to `--settings`. */
export function buildRestrictedSettings(opts: RestrictedSettingsOptions = {}): {
  permissions: {
    deny: string[];
    disableBypassPermissionsMode: "disable";
  };
} {
  const deny = [...DENIED_BUILTIN_TOOLS, ...(opts.extraDenyTools ?? [])];
  for (const abs of opts.readDenyAbsolutePaths ?? []) {
    // `//` prefix = filesystem-absolute path in a Read() rule.
    deny.push(`Read(//${abs.replace(/^\/+/, "")})`);
  }
  return {
    permissions: {
      deny,
      // Belt to the deny suspenders: forbid the bypassPermissions mode
      // entirely, so nothing downstream can turn permission checks off.
      disableBypassPermissionsMode: "disable",
    },
  };
}

export interface ClaudeArgsPlan {
  /** absolute path to the settings JSON written for `--settings` */
  settingsPath: string;
  /** absolute path to the Claude Code MCP config for `--mcp-config` */
  mcpConfigPath: string;
  /**
   * MCP server key the gateway is registered under; its tools are
   * `mcp__<name>__*` and are the ONLY tools allowed through without a
   * prompt in headless mode.
   */
  mcpServerName: string;
  /** everything after the profile's own flags — the prompt and passthrough */
  passthrough: readonly string[];
}

/**
 * The argument vector for `claude`. The four load-bearing flags, each
 * verified to matter in the reproduction:
 *   --settings           the deny profile (removes the non-routed tools)
 *   --mcp-config         the OwnerSwitch gateway, and only it
 *   --strict-mcp-config  ignore every other MCP source — no second server
 *   --allowedTools       let the gateway's own tools through without a prompt
 *                        (deny still governs the built-ins; allow cannot undo
 *                        a deny)
 */
export function buildClaudeArgs(plan: ClaudeArgsPlan): string[] {
  return [
    "--settings",
    plan.settingsPath,
    "--mcp-config",
    plan.mcpConfigPath,
    "--strict-mcp-config",
    "--allowedTools",
    `mcp__${plan.mcpServerName}`,
    ...plan.passthrough,
  ];
}
