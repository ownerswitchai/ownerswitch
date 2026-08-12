import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DENIED_BUILTIN_TOOLS,
  buildClaudeArgs,
  buildRestrictedSettings,
} from "./profile.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("buildRestrictedSettings", () => {
  it("denies every non-routed acting/egress tool", () => {
    const { permissions } = buildRestrictedSettings();
    // the §0 path and its siblings must all be present
    for (const tool of ["Write", "Edit", "Bash", "WebFetch", "WebSearch"]) {
      expect(permissions.deny).toContain(tool);
    }
    // the whole canonical list
    for (const tool of DENIED_BUILTIN_TOOLS) expect(permissions.deny).toContain(tool);
  });

  it("forbids the bypassPermissions mode", () => {
    expect(buildRestrictedSettings().permissions.disableBypassPermissionsMode).toBe("disable");
  });

  it("adds a filesystem-absolute Read() deny for protected paths", () => {
    const { permissions } = buildRestrictedSettings({
      readDenyAbsolutePaths: ["/tmp/run/gateway.config.json"],
    });
    // `//` prefix marks a filesystem-absolute path; the leading slash of the
    // input path is folded into that prefix → two slashes total, not three.
    expect(permissions.deny).toContain("Read(//tmp/run/gateway.config.json)");
  });

  it("appends extra deny tools", () => {
    const { permissions } = buildRestrictedSettings({ extraDenyTools: ["SomeFutureTool"] });
    expect(permissions.deny).toContain("SomeFutureTool");
  });

  it("the committed profile/claude-settings.json matches the code (no drift)", () => {
    const committed = JSON.parse(
      readFileSync(resolve(here, "../profile/claude-settings.json"), "utf8"),
    );
    expect(committed).toEqual(buildRestrictedSettings());
  });
});

describe("buildClaudeArgs", () => {
  const args = buildClaudeArgs({
    settingsPath: "/run/settings.json",
    mcpConfigPath: "/run/mcp.json",
    mcpServerName: "ownerswitch",
    passthrough: ["-p", "do the thing"],
  });

  it("passes the four load-bearing flags in order", () => {
    expect(args.slice(0, 7)).toEqual([
      "--settings",
      "/run/settings.json",
      "--mcp-config",
      "/run/mcp.json",
      "--strict-mcp-config",
      "--allowedTools",
      "mcp__ownerswitch",
    ]);
  });

  it("allows only the gateway's own MCP tools through", () => {
    const i = args.indexOf("--allowedTools");
    expect(args[i + 1]).toBe("mcp__ownerswitch");
  });

  it("appends passthrough args last", () => {
    expect(args.slice(-2)).toEqual(["-p", "do the thing"]);
  });
});
