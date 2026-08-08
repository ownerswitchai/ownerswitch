import { chmodSync, mkdtempSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConfigError, loadConfig, MAX_CONFIG_FILE_BYTES, readConfigFile } from "./config.js";

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

  it("loads through the real hardened reader end to end, not just the injected mock", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-config-"));
    const path = join(dir, "config.json");
    writeFileSync(path, JSON.stringify(VALID), "utf8");
    chmodSync(path, 0o600);
    const config = loadConfig(["--config", path], {}); // no readFile arg: exercises readConfigFile
    expect(config.device.id).toBe("gw-1");
  });
});

describe("readConfigFile — hardened I/O for a file holding device.secret in plaintext", () => {
  const tempPath = (name = "config.json") => join(mkdtempSync(join(tmpdir(), "ownerswitch-config-")), name);

  let errorSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    errorSpy.mockRestore();
  });

  it("reads a well-formed, correctly-permissioned file cleanly and without warning", () => {
    const path = tempPath();
    writeFileSync(path, '{"ok":true}', "utf8");
    chmodSync(path, 0o600);
    expect(readConfigFile(path)).toBe('{"ok":true}');
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("refuses to follow a symlink at the config path, whatever it points at", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-config-"));
    const target = join(dir, "target.json");
    writeFileSync(target, '{"ok":true}', "utf8");
    const path = join(dir, "config.json");
    symlinkSync(target, path); // an attacker aims the config path somewhere else
    expect(() => readConfigFile(path)).toThrowError(/symlink/);
  });

  it("rejects a directory sitting where the config file should be", () => {
    const dir = mkdtempSync(join(tmpdir(), "ownerswitch-config-"));
    expect(() => readConfigFile(dir)).toThrowError(/not a regular file/);
  });

  it("enforces MAX_CONFIG_FILE_BYTES during the read, not via a check-then-read stat", () => {
    const path = tempPath();
    writeFileSync(path, Buffer.alloc(MAX_CONFIG_FILE_BYTES + 1, "a"));
    chmodSync(path, 0o600);
    expect(() => readConfigFile(path)).toThrowError(
      new RegExp(`over the ${MAX_CONFIG_FILE_BYTES}-byte config file limit`),
    );
  });

  it("reads a file exactly at the size ceiling without complaint", () => {
    const path = tempPath();
    const contents = `"${"a".repeat(MAX_CONFIG_FILE_BYTES - 2)}"`; // valid JSON string literal, exactly at the cap
    expect(contents.length).toBe(MAX_CONFIG_FILE_BYTES);
    writeFileSync(path, contents, "utf8");
    chmodSync(path, 0o600);
    expect(readConfigFile(path)).toBe(contents);
  });

  it("warns loudly, but still returns the contents, when the mode is looser than 0600", () => {
    const path = tempPath();
    writeFileSync(path, '{"ok":true}', "utf8");
    chmodSync(path, 0o644);
    expect(readConfigFile(path)).toBe('{"ok":true}');
    expect(errorSpy).toHaveBeenCalledWith(expect.stringMatching(/mode 644.*0600|chmod 600/s));
  });

  it("does not warn at exactly 0600, and does not warn for a stricter mode", () => {
    const path600 = tempPath("a.json");
    writeFileSync(path600, "{}", "utf8");
    chmodSync(path600, 0o600);
    readConfigFile(path600);
    expect(errorSpy).not.toHaveBeenCalled();

    const path400 = tempPath("b.json");
    writeFileSync(path400, "{}", "utf8");
    chmodSync(path400, 0o400);
    readConfigFile(path400);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("does not disturb the file's mode on disk", () => {
    const path = tempPath();
    writeFileSync(path, "{}", "utf8");
    chmodSync(path, 0o640);
    readConfigFile(path);
    expect(statSync(path).mode & 0o777).toBe(0o640);
  });
});
