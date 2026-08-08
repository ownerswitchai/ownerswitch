import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import {
  checkConfig,
  checkControlPlane,
  checkDeviceCredentials,
  checkNodeVersion,
  checkUpstreamSpawnable,
  doctorMain,
  formatDoctorReport,
  runDoctor,
  type DoctorCheck,
} from "./doctor.js";

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

type SpawnImpl = typeof import("node:child_process").spawn;

function fakeChildProcess() {
  const emitter = new EventEmitter();
  const killed: string[] = [];
  (emitter as unknown as { kill: (sig?: string) => boolean }).kill = (sig = "SIGTERM") => {
    killed.push(sig);
    return true;
  };
  return {
    child: emitter as unknown as ChildProcess,
    emitSpawn: () => emitter.emit("spawn"),
    emitError: (err: NodeJS.ErrnoException) => emitter.emit("error", err),
    killed,
  };
}

describe("checkNodeVersion", () => {
  it("passes on 22+", () => {
    const c = checkNodeVersion("22.5.0");
    expect(c.ok).toBe(true);
    expect(c.detail).toContain("22.5.0");
  });

  it("fails below 22 with an actionable fix", () => {
    const c = checkNodeVersion("18.19.0");
    expect(c.ok).toBe(false);
    expect(c.fix).toMatch(/install|nvm/i);
  });
});

describe("checkConfig", () => {
  it("reports ok and returns the parsed config", () => {
    const { check, config } = checkConfig(["--config", "/etc/ownerswitch.json"], {}, fileWith(VALID_CONFIG));
    expect(check.ok).toBe(true);
    expect(config?.device.id).toBe("gw-1");
  });

  it("reports the config error and no config on failure", () => {
    const { check, config } = checkConfig(
      ["--config", "/etc/ownerswitch.json"],
      {},
      fileWith({ ...VALID_CONFIG, device: undefined }),
    );
    expect(check.ok).toBe(false);
    expect(check.detail).toMatch(/device/);
    expect(check.fix).toBeDefined();
    expect(config).toBeUndefined();
  });
});

describe("checkControlPlane", () => {
  it("passes when reachable and not killed", async () => {
    const { check, reachable } = await checkControlPlane("http://cp.test", 500, jsonResponse({ killed: false }));
    expect(check.ok).toBe(true);
    expect(reachable).toBe(true);
    expect(check.detail).toContain("not killed");
  });

  it("is reachable but warns when the kill switch is already engaged", async () => {
    const { check, reachable } = await checkControlPlane("http://cp.test", 500, jsonResponse({ killed: true }));
    expect(check.ok).toBe(true);
    expect(reachable).toBe(true);
    expect(check.detail).toContain("kill switch is currently engaged");
  });

  it("fails with a fix on a network error", async () => {
    const { check, reachable } = await checkControlPlane("http://cp.test", 500, rejectingFetch);
    expect(check.ok).toBe(false);
    expect(reachable).toBe(false);
    expect(check.fix).toMatch(/dev:control-plane|controlPlaneUrl/);
  });

  it("fails on a non-2xx response", async () => {
    const { check } = await checkControlPlane("http://cp.test", 500, jsonResponse({}, 500));
    expect(check.ok).toBe(false);
  });
});

describe("checkDeviceCredentials", () => {
  const device = { id: "gw-1", secret: "s3cret" };

  it("passes on 400 — signature accepted, probe body deliberately malformed, no window created", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, jsonResponse({ error: "bad" }, 400));
    expect(check.ok).toBe(true);
  });

  it("fails on 401 naming device.id/device.secret", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, jsonResponse({}, 401));
    expect(check.ok).toBe(false);
    expect(check.fix).toMatch(/device\.id.*device\.secret|device\.secret.*device\.id/);
  });

  it("fails on network error", async () => {
    const check = await checkDeviceCredentials("http://cp.test", device, 500, rejectingFetch);
    expect(check.ok).toBe(false);
  });
});

describe("checkUpstreamSpawnable", () => {
  it("passes and kills the process the instant spawn is confirmed", async () => {
    const fake = fakeChildProcess();
    const spawnImpl = ((..._args: unknown[]) => {
      queueMicrotask(fake.emitSpawn);
      return fake.child;
    }) as unknown as SpawnImpl;
    const check = await checkUpstreamSpawnable({ command: "npx", args: [] }, spawnImpl);
    expect(check.ok).toBe(true);
    expect(fake.killed).toEqual(["SIGTERM"]);
  });

  it("fails with ENOENT guidance when the command isn't found", async () => {
    const fake = fakeChildProcess();
    const spawnImpl = ((..._args: unknown[]) => {
      queueMicrotask(() => fake.emitError(Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" })));
      return fake.child;
    }) as unknown as SpawnImpl;
    const check = await checkUpstreamSpawnable({ command: "not-a-real-cmd", args: [] }, spawnImpl);
    expect(check.ok).toBe(false);
    expect(check.detail).toContain("not found");
  });

  it("fails on timeout and kills the hung process", async () => {
    const fake = fakeChildProcess();
    const spawnImpl = (() => fake.child) as unknown as SpawnImpl;
    const check = await checkUpstreamSpawnable({ command: "slow-cmd", args: [] }, spawnImpl, 20);
    expect(check.ok).toBe(false);
    expect(check.detail).toContain("did not report starting");
    expect(fake.killed).toEqual(["SIGKILL"]);
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
      "control plane",
      "device credentials",
      "upstream command",
    ]);
    expect(checks.find((c) => c.name === "control plane")?.detail).toContain("skipped");
    expect(checks.find((c) => c.name === "device credentials")?.detail).toContain("skipped");
    expect(checks.find((c) => c.name === "upstream command")?.detail).toContain("skipped");
  });

  it("skips the device-credentials check when the control plane is unreachable", async () => {
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith(VALID_CONFIG),
      fetchImpl: rejectingFetch,
    });
    expect(checks.find((c) => c.name === "control plane")?.ok).toBe(false);
    expect(checks.find((c) => c.name === "device credentials")?.detail).toContain("skipped");
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
    const fake = fakeChildProcess();
    const spawnImpl = ((..._args: unknown[]) => {
      queueMicrotask(fake.emitSpawn);
      return fake.child;
    }) as unknown as SpawnImpl;
    const checks = await runDoctor(["--config", "/etc/ownerswitch.json"], {}, {
      readFile: fileWith(VALID_CONFIG),
      fetchImpl,
      spawnImpl,
    });
    expect(checks.every((c) => c.ok)).toBe(true);
  });
});

describe("formatDoctorReport", () => {
  it("prints a fix line under each failing check and a summary", () => {
    const checks: DoctorCheck[] = [
      { name: "node version", ok: true, detail: "v22.0.0 (>= 22 required)" },
      { name: "config", ok: false, detail: "boom", fix: "do the thing" },
    ];
    const report = formatDoctorReport(checks);
    expect(report).toContain("✔ node version — v22.0.0 (>= 22 required)");
    expect(report).toContain("✘ config — boom");
    expect(report).toContain("  → do the thing");
    expect(report).toContain("Some checks failed");
  });

  it("summarizes all green", () => {
    const report = formatDoctorReport([{ name: "node version", ok: true, detail: "v22.0.0" }]);
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
