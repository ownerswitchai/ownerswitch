import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "./config.js";

const VALID = {
  controlPlaneUrl: "http://127.0.0.1:4600",
  device: { id: "gw-1", secret: "dev-device-secret" },
  upstream: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/d"] },
  policy: {
    rules: [{ id: "reads", tool: "read_*", decision: "allow" }],
    defaultDecision: "approve",
  },
};

const fileWith = (contents: unknown) => (path: string) => {
  expect(path).toBe("/etc/ownerswitch.json");
  return JSON.stringify(contents);
};

describe("loadConfig", () => {
  it("loads and validates a JSON config file from --config", () => {
    const config = loadConfig(["--config", "/etc/ownerswitch.json"], {}, fileWith(VALID));
    expect(config.controlPlaneUrl).toBe("http://127.0.0.1:4600");
    expect(config.device).toEqual({ id: "gw-1", secret: "dev-device-secret" });
    expect(config.upstream.command).toBe("npx");
    expect(config.policy.rules).toHaveLength(1);
    expect(config.policy.defaultDecision).toBe("approve");
  });

  it("accepts the --config=<file> form and the OWNERSWITCH_MCP_CONFIG variable", () => {
    expect(loadConfig(["--config=/etc/ownerswitch.json"], {}, fileWith(VALID)).device.id).toBe("gw-1");
    expect(
      loadConfig([], { OWNERSWITCH_MCP_CONFIG: "/etc/ownerswitch.json" }, fileWith(VALID)).device.id,
    ).toBe("gw-1");
  });

  it("assembles a config from OWNERSWITCH_* environment variables", () => {
    const config = loadConfig(
      [],
      {
        OWNERSWITCH_CONTROL_PLANE_URL: "http://127.0.0.1:4600",
        OWNERSWITCH_DEVICE_ID: "gw-env",
        OWNERSWITCH_DEVICE_SECRET: "s3cret",
        OWNERSWITCH_UPSTREAM_COMMAND: "npx",
        OWNERSWITCH_UPSTREAM_ARGS: JSON.stringify(["-y", "some-server"]),
        OWNERSWITCH_POLICY: JSON.stringify(VALID.policy),
        OWNERSWITCH_AGENT_ID: "claude-code",
      },
      () => {
        throw new Error("no file should be read");
      },
    );
    expect(config.device.id).toBe("gw-env");
    expect(config.upstream.args).toEqual(["-y", "some-server"]);
    expect(config.agentId).toBe("claude-code");
  });

  const load = (contents: unknown) =>
    loadConfig(["--config", "/etc/ownerswitch.json"], {}, fileWith(contents));

  it("rejects a config without device credentials, naming the field", () => {
    expect(() => load({ ...VALID, device: undefined })).toThrowError(ConfigError);
    expect(() => load({ ...VALID, device: undefined })).toThrowError(/device/);
    expect(() => load({ ...VALID, device: { id: "gw-1" } })).toThrowError(/device\.secret/);
  });

  it("rejects an invalid control plane URL", () => {
    expect(() => load({ ...VALID, controlPlaneUrl: "not a url" })).toThrowError(/valid URL/);
  });

  it("rejects a rule with an unknown decision, naming the rule", () => {
    const policy = {
      rules: [{ id: "bad", tool: "*", decision: "maybe" }],
      defaultDecision: "approve",
    };
    expect(() => load({ ...VALID, policy })).toThrowError(/rules\[0\]\.decision/);
  });

  it("rejects a rule with an invalid argsPattern regex", () => {
    const policy = {
      rules: [{ id: "bad", tool: "*", argsPattern: "([", decision: "deny" }],
      defaultDecision: "approve",
    };
    expect(() => load({ ...VALID, policy })).toThrowError(/argsPattern/);
  });

  it("rejects a missing defaultDecision — the fail-closed default must be explicit", () => {
    expect(() => load({ ...VALID, policy: { rules: [] } })).toThrowError(/defaultDecision/);
  });

  it("rejects unknown command-line arguments", () => {
    expect(() => loadConfig(["--verbose"], {})).toThrowError(/unknown argument/);
  });

  it("explains what to do when no config is given at all", () => {
    expect(() => loadConfig([], {})).toThrowError(/--config|OWNERSWITCH/);
  });
});
