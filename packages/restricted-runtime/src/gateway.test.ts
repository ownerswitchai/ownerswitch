import { describe, expect, it } from "vitest";
import type { OwnerSwitchMcpConfig } from "@ownerswitchai/mcp";
import {
  buildClaudeMcpConfig,
  buildGatewayLaunch,
  isFilesystemUpstream,
  resolveFilesystemServerEntry,
  resolveWorkspacePaths,
  withFastFilesystemUpstream,
} from "./gateway.js";

const baseConfig: OwnerSwitchMcpConfig = {
  controlPlaneUrl: "http://127.0.0.1:4600",
  device: { id: "d", secret: "s" },
  upstream: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/x"] },
  policy: { rules: [], defaultDecision: "approve" },
};

describe("isFilesystemUpstream", () => {
  it("detects the demo filesystem server in any launch form", () => {
    expect(isFilesystemUpstream(baseConfig)).toBe(true);
    expect(
      isFilesystemUpstream({
        ...baseConfig,
        upstream: { command: "node", args: ["/some/server-filesystem/dist/index.js", "/tmp/x"] },
      }),
    ).toBe(true);
  });

  it("leaves a real (non-filesystem) upstream unrecognised", () => {
    expect(
      isFilesystemUpstream({
        ...baseConfig,
        upstream: { command: "my-mcp-server", args: ["--port", "0"] },
      }),
    ).toBe(false);
  });
});

describe("withFastFilesystemUpstream", () => {
  it("rewrites the demo upstream to node <entry> <workDir>", () => {
    const out = withFastFilesystemUpstream(baseConfig, "/work/dir", "/abs/fs/index.js");
    expect(out.upstream).toEqual({ command: "node", args: ["/abs/fs/index.js", "/work/dir"] });
  });

  it("leaves a real operator upstream exactly as configured", () => {
    const real: OwnerSwitchMcpConfig = {
      ...baseConfig,
      upstream: { command: "my-mcp-server", args: ["--port", "0"] },
    };
    expect(withFastFilesystemUpstream(real, "/work", "/abs/fs/index.js")).toEqual(real);
  });

  it("does not mutate the input config", () => {
    const before = JSON.stringify(baseConfig);
    withFastFilesystemUpstream(baseConfig, "/work", "/abs/fs/index.js");
    expect(JSON.stringify(baseConfig)).toBe(before);
  });
});

describe("buildGatewayLaunch / buildClaudeMcpConfig", () => {
  it("launches the gateway via the local tsx binary, cwd = packages/mcp", () => {
    const paths = resolveWorkspacePaths();
    const launch = buildGatewayLaunch(paths, "/run/gw.json");
    expect(launch.command).toBe(paths.tsxBin);
    expect(launch.command).toMatch(/node_modules\/\.bin\/tsx$/);
    expect(launch.args).toEqual([paths.mcpCli, "--config", "/run/gw.json"]);
    expect(launch.cwd).toBe(paths.mcpCwd);
    expect(launch.cwd).toMatch(/packages\/mcp$/);
  });

  it("registers the gateway under the given server name", () => {
    const launch = buildGatewayLaunch(resolveWorkspacePaths(), "/run/gw.json");
    const mcp = buildClaudeMcpConfig("ownerswitch", launch);
    expect(Object.keys(mcp.mcpServers)).toEqual(["ownerswitch"]);
    expect(mcp.mcpServers.ownerswitch.command).toBe(launch.command);
  });
});

describe("resolveFilesystemServerEntry", () => {
  it("resolves the installed demo filesystem server entry", () => {
    const entry = resolveFilesystemServerEntry();
    expect(entry).toMatch(/server-filesystem.*index\.js$/);
  });
});
