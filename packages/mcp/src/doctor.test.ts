import { describe, expect, it, vi } from "vitest";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  checkConfig,
  checkControlPlane,
  checkDeviceCredentials,
  checkNodeVersion,
  checkStartupGates,
  checkUpstreamHandshake,
  doctorMain,
  formatDoctorReport,
  runDoctor,
  undeclaredUpstreamEnv,
  upstreamTimeoutFrom,
  type DoctorCheck,
} from "./doctor.js";
import { loadConfig } from "./config.js";

const VALID_CONFIG = {
  controlPlaneUrl: "http://127.0.0.1:4600",
  device: { id: "gw-1", secret: "dev-device-secret" },
  upstream: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/d"] },
  policy: { rules: [{ id: "reads", tool: "read_*", decision: "allow" }], defaultDecision: "approve" },
};

const fileWith = (contents: unknown) => (path: string) => {
  expect(path).toBe("/etc/ownerswitch.json");
  return JSON.stringify(contents);
};

const jsonResponse =
  (body: unknown, status = 200): typeof fetch =>
  async () =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const rejectingFetch: typeof fetch = async () => {
  throw new Error("ECONNREFUSED");
};

/** A working in-memory MCP server on the far side — the handshake completes. */
const workingUpstreamFactory = (): Transport => {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const server = new Server({ name: "fake-upstream", version: "1.0.0" }, { capabilities: {} });
  void server.connect(serverSide);
  return clientSide;
};

/** Starts, but never answers anything — like a binary that isn't an MCP server. */
const silentUpstreamFactory = (): Transport =>
  ({
    start: async () => {},
    send: async () => {},
    close: async () => {},
  }) as Transport;

/** Fails to launch at all. */
const enoentUpstreamFactory = (): Transport =>
  ({
    start: async () => {
      throw Object.assign(new Error("spawn not-a-real-cmd ENOENT"), { code: "ENOENT" });
    },
    send: async () => {},
    close: async () => {},
  }) as Transport;

describe("checkNodeVersion", () => {
  it("passes on 22+", () => {
    const c = checkNodeVersion("22.5.0");
    expect(c.status).toBe("pass");
    expect(c.detail).toContain("22.5.0");
  });

  it("fails below 22 with an actionable fix", () => {
    const c = checkNodeVersion("18.19.0");
    expect(c.status).toBe("fail");
    expect(c.fix).toMatch(/install|nvm/i);
  });
});

describe("checkConfig", () => {
  it("reports pass and returns the parsed config", () => {
    const { check, config } = checkConfig(["--config", "/etc/ownerswitch.json"], {}, fileWith(VALID_CONFIG));
    expect(check.status).toBe("pass");
    expect(config?.device.id).toBe("gw-1");
  });

  it("reports the config error and no config on failure", () => {
    const { check, config } = checkConfig(
      ["--config", "/etc/ownerswitch.json"],
      {},
      fileWith({ ...VALID_CONFIG, device: undefined }),
    );
    expect(check.status).toBe("fail");
    expect(check.detail).toMatch(/device/);
    expect(check.fix).toBeDefined();
    expect(config).toBeUndefined();
  });
});

describe("checkControlPlane", () => {
  it("passes when reachable and not killed", async () => {
    const { check, reachable } = await checkControlPlane("http://cp.test", 500, jsonResponse({ killed: false }));
    expect(check.status).toBe("pass");
    expect(reachable).toBe(true);
    expect(check.detail).toContain("not killed");
  });

  it("reports ACTION REQUIRED — not a pass — when the plane is reachable but killed", async () => {
    const { check, reachable } = await checkControlPlane(
      "http://cp.test",
      500,
      jsonResponse({ killed: true, reason: "owner pressed stop" }),
    );
    expect(check.status).toBe("action");
    expect(reachable).toBe(true);
    expect(check.detail).toContain("ENGAGED");
    expect(check.detail).toContain("owner pressed stop");
    expect(check.fix).toContain("/restore/ceremony");
    expect(check.fix).toMatch(/Restarting .* does NOT restore/);
  });

  it("fails with a fix on a network error", async () => {
    const { check, reachable } = await checkControlPlane("http://cp.test", 500, rejectingFetch);
    expect(check.status).toBe("fail");
    expect(reachable).toBe(false);
    expect(check.fix).toMatch(/dev:control-plane|controlPlaneUrl/);
  });

  it("fails on a non-2xx response", async () => {
    const { check } = await checkControlPlane("http://cp.test", 500, jsonResponse({}, 500));
    expect(check.status).toBe("fail");
  });
});

describe("checkDeviceCredentials", () => {
  const device = { id: "gw-1", secret: "s3cret" };

  it("passes on 400 — signature accepted, probe body deliberately malformed, no window created", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, jsonResponse({ error: "bad" }, 400));
    expect(check.status).toBe("pass");
  });

  it("fails on 401 naming device.id/device.secret", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, jsonResponse({}, 401));
    expect(check.status).toBe("fail");
    expect(check.fix).toMatch(/device\.id.*device\.secret|device\.secret.*device\.id/);
  });

  it("fails on network error", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, rejectingFetch);
    expect(check.status).toBe("fail");
  });
});

describe("checkUpstreamHandshake", () => {
  it("passes only after a completed MCP initialize handshake, then shuts down cleanly", async () => {
    const check = await checkUpstreamHandshake(
      { command: "fake-upstream", args: [] },
      { transportFactory: workingUpstreamFactory },
    );
    expect(check.status).toBe("pass");
    expect(check.detail).toContain("initialize handshake");
  });

  it("fails on timeout for a process that starts but never speaks MCP", async () => {
    const check = await checkUpstreamHandshake(
      { command: "not-an-mcp-server", args: [] },
      { transportFactory: silentUpstreamFactory, timeoutMs: 50 },
    );
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("did not answer the MCP initialize handshake");
    expect(check.fix).toContain("stdio MCP server");
  });

  it("names the ambient env the child will NOT inherit — the works-by-hand trap", async () => {
    // The failure that sends people in circles: the identical command runs
    // fine in their shell, so the config "must" be right. The difference is
    // the environment, and only doctor is in a position to say so.
    const check = await checkUpstreamHandshake(
      { command: "npx", args: ["-y", "some-server"] },
      {
        transportFactory: silentUpstreamFactory,
        timeoutMs: 20,
        env: { HTTPS_PROXY: "http://proxy:8080", NODE_EXTRA_CA_CERTS: "/etc/ca.pem", HOME: "/root" },
      },
    );
    expect(check.status).toBe("fail");
    expect(check.fix).toContain("STRIPPED environment");
    expect(check.fix).toContain("HTTPS_PROXY");
    expect(check.fix).toContain("NODE_EXTRA_CA_CERTS");
    expect(check.fix).not.toContain("HOME"); // the child DOES inherit that one
    expect(check.fix).toContain("upstream.env");
    // and the cold-download case, which looks identical from here
    expect(check.fix).toContain("--upstream-timeout");
  });

  it("does not blame the environment for vars the config already declares", async () => {
    const check = await checkUpstreamHandshake(
      { command: "npx", args: [], env: { HTTPS_PROXY: "http://proxy:8080" } },
      {
        transportFactory: silentUpstreamFactory,
        timeoutMs: 20,
        env: { HTTPS_PROXY: "http://proxy:8080" },
      },
    );
    expect(check.fix).toContain("STRIPPED environment");
    expect(check.fix).not.toContain("HTTPS_PROXY"); // declared — not the problem
  });

  it("fails with ENOENT guidance when the command isn't found", async () => {
    const check = await checkUpstreamHandshake(
      { command: "not-a-real-cmd", args: [] },
      { transportFactory: enoentUpstreamFactory },
    );
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("not found");
  });
});

describe("checkStartupGates — the gate doctor could not see", () => {
  const configWith = (extra: Record<string, unknown>, env: Record<string, string | undefined> = {}) =>
    checkStartupGates(
      loadConfig(["--config", "/etc/ownerswitch.json"], {}, fileWith({ ...VALID_CONFIG, ...extra })),
      env,
    );

  it("catches a kill-action budget with no risk acknowledgment — the gateway would refuse to start", () => {
    // Before this check existed, doctor printed "All checks passed" for this
    // config and the MCP client showed only a closed connection.
    const check = configWith({
      limits: [{ id: "rate", tool: "*", metric: "calls", max: 5, action: "kill" }],
    });
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("OWNERSWITCH_LIMITS_ACCEPT_PROCESS_LOCAL_BUDGET_RISK");
    expect(check.fix).toContain("REFUSES TO START");

    // ...and passes once the deployment says it accepted the bound
    const accepted = configWith(
      { limits: [{ id: "rate", tool: "*", metric: "calls", max: 5, action: "kill" }] },
      { OWNERSWITCH_LIMITS_ACCEPT_PROCESS_LOCAL_BUDGET_RISK: "1" },
    );
    expect(accepted.status).toBe("pass");
    expect(accepted.detail).toContain("1 limit rule(s)");
  });

  it("catches a half-configured honeytoken registry", () => {
    const check = configWith({}, { OWNERSWITCH_HONEYTOKEN_REGISTRY: "/tmp/registry.json" });
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("OWNERSWITCH_CANARY_KEY");
  });

  it("catches a gateway credential passed to the upstream through argv", () => {
    const check = configWith({
      upstream: { command: "npx", args: ["--token", VALID_CONFIG.device.secret] },
    });
    expect(check.status).toBe("fail");
    expect(check.detail).not.toContain(VALID_CONFIG.device.secret); // names the arg, never the value
  });

  it("passes a plain policy-only config and says nothing else is armed", () => {
    const check = configWith({});
    expect(check.status).toBe("pass");
    expect(check.detail).toContain("nothing beyond policy is armed");
  });
});

describe("--upstream-timeout", () => {
  it("takes the flag, then the env var, and ignores garbage rather than refusing to run", () => {
    expect(upstreamTimeoutFrom(["--upstream-timeout", "60000"], {})).toEqual({ timeoutMs: 60_000 });
    expect(upstreamTimeoutFrom([], { OWNERSWITCH_UPSTREAM_TIMEOUT_MS: "45000" })).toEqual({
      timeoutMs: 45_000,
    });
    for (const bad of ["", "soon", "-1", "1.5", undefined]) {
      expect(upstreamTimeoutFrom(["--upstream-timeout", bad as string], {}), String(bad)).toEqual({});
    }
  });

  it("undeclaredUpstreamEnv reports only what is set AND not declared", () => {
    expect(
      undeclaredUpstreamEnv({ command: "x" }, { HTTP_PROXY: "p", PATH: "/bin", NO_PROXY: "" }),
    ).toEqual(["HTTP_PROXY"]);
    expect(undeclaredUpstreamEnv({ command: "x", env: { HTTP_PROXY: "p" } }, { HTTP_PROXY: "p" })).toEqual([]);
  });
});

describe("runDoctor", () => {
  it("skips downstream checks once config fails to load", async () => {
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith({ ...VALID_CONFIG, device: undefined }),
    });
    expect(checks.map((c) => c.name)).toEqual([
      "node version",
      "config",
      "startup gates",
      "control plane",
      "device credentials",
      "upstream command",
    ]);
    expect(checks.find((c) => c.name === "startup gates")?.detail).toContain("skipped");
    expect(checks.find((c) => c.name === "control plane")?.detail).toContain("skipped");
    expect(checks.find((c) => c.name === "device credentials")?.detail).toContain("skipped");
    expect(checks.find((c) => c.name === "upstream command")?.detail).toContain("skipped");
  });

  it("skips the device-credentials check when the control plane is unreachable", async () => {
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith(VALID_CONFIG),
      fetchImpl: rejectingFetch,
      upstreamProbe: { transportFactory: workingUpstreamFactory },
    });
    expect(checks.find((c) => c.name === "control plane")?.status).toBe("fail");
    expect(checks.find((c) => c.name === "device credentials")?.detail).toContain("skipped");
  });

  it("still probes device credentials against a reachable-but-killed plane, and surfaces the ⚠", async () => {
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/status") return new Response(JSON.stringify({ killed: true }), { status: 200 });
      if (url.pathname === "/veto" && (init?.method ?? "GET") === "POST") {
        return new Response(JSON.stringify({ error: "call must be an object" }), { status: 400 });
      }
      throw new Error(`unexpected request to ${url.pathname}`);
    };
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith(VALID_CONFIG),
      fetchImpl,
      upstreamProbe: { transportFactory: workingUpstreamFactory },
    });
    expect(checks.find((c) => c.name === "control plane")?.status).toBe("action");
    expect(checks.find((c) => c.name === "device credentials")?.status).toBe("pass");
  });

  it("all green end to end with a stubbed control plane and upstream", async () => {
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/status") return new Response(JSON.stringify({ killed: false }), { status: 200 });
      if (url.pathname === "/veto" && (init?.method ?? "GET") === "POST") {
        return new Response(JSON.stringify({ error: "call must be an object" }), { status: 400 });
      }
      throw new Error(`unexpected request to ${url.pathname}`);
    };
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith(VALID_CONFIG),
      fetchImpl,
      upstreamProbe: { transportFactory: workingUpstreamFactory },
    });
    expect(checks.every((c) => c.status === "pass")).toBe(true);
  });
});

describe("formatDoctorReport", () => {
  it("prints a fix line under each failing check and a summary", () => {
    const checks: DoctorCheck[] = [
      { name: "node version", status: "pass", detail: "v22.0.0 (>= 22 required)" },
      { name: "config", status: "fail", detail: "boom", fix: "do the thing" },
    ];
    const report = formatDoctorReport(checks);
    expect(report).toContain("✔ node version — v22.0.0 (>= 22 required)");
    expect(report).toContain("✘ config — boom");
    expect(report).toContain("  → do the thing");
    expect(report).toContain("Some checks failed");
  });

  it("renders action-required checks as ⚠ with their fix, and a distinct summary", () => {
    const checks: DoctorCheck[] = [
      { name: "node version", status: "pass", detail: "v22.0.0" },
      { name: "control plane", status: "action", detail: "reachable but ENGAGED", fix: "run the ceremony" },
    ];
    const report = formatDoctorReport(checks);
    expect(report).toContain("⚠ control plane — reachable but ENGAGED");
    expect(report).toContain("  → run the ceremony");
    expect(report).toContain("Action required");
    expect(report).not.toContain("All checks passed");
  });

  it("summarizes all green", () => {
    const report = formatDoctorReport([{ name: "node version", status: "pass", detail: "v22.0.0" }]);
    expect(report).toContain("All checks passed.");
  });
});

describe("doctorMain", () => {
  it("returns exit code 1 and prints the report on a bad config, without touching the network", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const code = await doctorMain(["--config", "/tmp/ownerswitch-doctor-test-does-not-exist.json"], {
        // no OWNERSWITCH_* vars, and no such file — loadConfig's real readFileSync will throw ENOENT
      });
      expect(code).toBe(1);
      expect(logSpy).toHaveBeenCalledTimes(1);
      expect(logSpy.mock.calls[0][0]).toContain("✘ config");
    } finally {
      logSpy.mockRestore();
    }
  });
});
