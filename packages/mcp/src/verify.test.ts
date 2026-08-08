import { describe, expect, it, vi } from "vitest";
import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import type { Policy } from "@ownerswitchai/shared";
import type { OwnerSwitchMcpConfig } from "./config.js";
import { formatVerifyReport, resolveOwnerToken, runVerify, verifyMain } from "./verify.js";

const DEVICE = { id: "gw-1", secret: "s3cret" };
const OWNER_TOKEN = "owner-token-abc";
const CP_URL = "http://control-plane.test";

const POLICY: Policy = {
  rules: [
    { id: "reads", tool: "read_*", decision: "allow", description: "reads are safe" },
    { id: "writes", tool: "write_file", decision: "veto" },
  ],
  defaultDecision: "approve",
};

function baseConfig(policy: Policy = POLICY, device = DEVICE): OwnerSwitchMcpConfig {
  return {
    controlPlaneUrl: CP_URL,
    device,
    upstream: { command: "npx", args: [] },
    policy,
  };
}

/**
 * In-memory control plane faithful to the merged ceremony-based API
 * (control-plane/src/server.ts): /kill needs a valid device signature,
 * /restore/ceremony and /restore need the bearer token, /restore rejects
 * everything but a minted, current ceremony id with the uniform 409, and the
 * veto lane needs a device signature to register and the bearer to tap.
 */
function createFakeControlPlane(opts: { ceremonyCooldownMs?: number; restoreBroken?: boolean } = {}) {
  let killed = false;
  let mintedCeremony: string | undefined;
  const killCalls: unknown[] = [];
  const restoreCalls: unknown[] = [];
  const windows = new Map<string, { status: string }>();

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const validDevice = (init: RequestInit | undefined, rawBody: string): boolean => {
    const h = new Headers(init?.headers);
    return verifyDeviceSignature(
      {
        deviceId: h.get("x-device-id") ?? "",
        timestamp: Number(h.get("x-device-timestamp")),
        nonce: h.get("x-device-nonce") ?? "",
        signature: h.get("x-device-signature") ?? "",
      },
      rawBody,
      DEVICE.secret,
    );
  };

  const validOwner = (init: RequestInit | undefined): boolean =>
    new Headers(init?.headers).get("authorization") === `Bearer ${OWNER_TOKEN}`;

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";
    const rawBody = String(init?.body ?? "");

    if (method === "GET" && url.pathname === "/status") return json({ killed });

    if (method === "POST" && url.pathname === "/kill") {
      if (!validDevice(init, rawBody)) return json({ error: "unauthorized" }, 401);
      killed = true;
      killCalls.push(JSON.parse(rawBody));
      return json({ killed: true });
    }

    if (method === "POST" && url.pathname === "/restore/ceremony") {
      if (!validOwner(init)) return json({ error: "unauthorized" }, 401);
      if (!killed) return json({ error: "not killed — nothing to restore" }, 409);
      mintedCeremony = "cer_test_1";
      const cooldown = opts.ceremonyCooldownMs ?? 0;
      return json(
        {
          id: mintedCeremony,
          state: cooldown > 0 ? "go1" : "ready",
          cooldownRemainingMs: cooldown,
          expiresAt: Date.now() + 300_000,
        },
        201,
      );
    }

    const ceremonyMatch = /^\/restore\/ceremony\/([^/]+)$/.exec(url.pathname);
    if (method === "GET" && ceremonyMatch) {
      if (!validOwner(init)) return json({ error: "unauthorized" }, 401);
      if (ceremonyMatch[1] !== mintedCeremony) return json({ error: "no ceremony" }, 404);
      // after the cooldown wait, the ceremony reads ready
      return json({ state: "ready", cooldownRemainingMs: 0, expiresAt: Date.now() + 300_000 });
    }

    if (method === "POST" && url.pathname === "/restore") {
      if (!validOwner(init)) return json({ error: "unauthorized" }, 401);
      const ceremonyId = (JSON.parse(rawBody) as { ceremonyId?: unknown }).ceremonyId;
      if (opts.restoreBroken === true) return json({ error: "restore rejected" }, 409);
      if (typeof ceremonyId !== "string" || ceremonyId !== mintedCeremony || !killed) {
        return json({ error: "restore rejected" }, 409);
      }
      mintedCeremony = undefined; // single-use
      restoreCalls.push(ceremonyId);
      killed = false;
      return json({ killed: false });
    }

    if (method === "POST" && url.pathname === "/veto") {
      if (!validDevice(init, rawBody)) return json({ error: "unauthorized" }, 401);
      const id = `veto_fake_${windows.size + 1}`;
      windows.set(id, { status: "pending" });
      return json({ id, status: "pending" }, 201);
    }

    const vetoMatch = /^\/veto\/([^/]+)$/.exec(url.pathname);
    if (vetoMatch) {
      const window = windows.get(vetoMatch[1]);
      if (method === "POST") {
        if (!validOwner(init)) return json({ error: "unauthorized" }, 401);
        if (!window) return json({ error: "no veto window" }, 404);
        window.status = "vetoed";
        return json({ status: "vetoed" });
      }
      if (method === "GET") {
        if (!window) return json({ error: "no veto window" }, 404);
        return json({ status: window.status });
      }
    }

    return json({ error: "not found" }, 404);
  };

  return {
    fetchImpl,
    killCalls,
    restoreCalls,
    windows,
    get killed() {
      return killed;
    },
  };
}

const silentDeps = { log: () => {} };

describe("runVerify — default mode (no kill switch)", () => {
  it("requires an owner token before making any control-plane call, and points at env/prompt (not a flag)", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("must not be called");
    };
    const outcome = await runVerify(baseConfig(), undefined, {}, { fetchImpl, ...silentDeps });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps).toHaveLength(1);
    expect(outcome.steps[0]).toMatchObject({ name: "owner token", ok: false });
    expect(outcome.steps[0].detail).toMatch(/OWNERSWITCH_OWNER_TOKEN/);
    expect(outcome.steps[0].detail).toMatch(/prompt/);
  });

  it("fails fast when the control plane is unreachable", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, {}, { fetchImpl, ...silentDeps });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0].name).toBe("control plane");
  });

  it("refuses to run from a killed plane, and its message includes the ceremony recovery steps", async () => {
    const cp = createFakeControlPlane();
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/status") return new Response(JSON.stringify({ killed: true }), { status: 200 });
      return cp.fetchImpl(input, init);
    };
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, {}, { fetchImpl, ...silentDeps });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0].detail).toContain("lockdown");
    expect(outcome.steps[0].detail).toContain("/restore/ceremony");
  });

  it("rejects an invalid owner token via the harmless /restore probe — no kill, no window, nothing mutated", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), "wrong-token", {}, { fetchImpl: cp.fetchImpl, ...silentDeps });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0]).toMatchObject({ name: "owner token", ok: false });
    expect(cp.killCalls).toHaveLength(0);
    expect(cp.windows.size).toBe(0);
    expect(cp.killed).toBe(false);
  });

  it("passes end to end WITHOUT ever calling POST /kill, ending with a terminally-vetoed demo window", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, {}, { fetchImpl: cp.fetchImpl, ...silentDeps });

    expect(outcome.steps.map((s) => s.name)).toEqual([
      "owner token",
      "allow call",
      "default decision",
      "veto lane",
    ]);
    expect(outcome.steps.every((s) => s.ok)).toBe(true);
    expect(outcome.ok).toBe(true);

    expect(cp.killCalls).toHaveLength(0); // the whole point of default mode
    expect(cp.killed).toBe(false);
    expect([...cp.windows.values()].map((w) => w.status)).toEqual(["vetoed"]);
  });

  it("honestly skips the allow-call phase when the policy has no allow rule", async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = { rules: [{ id: "w", tool: "write_file", decision: "veto" }], defaultDecision: "deny" };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, {}, { fetchImpl: cp.fetchImpl, ...silentDeps });
    const allowStep = outcome.steps.find((s) => s.name === "allow call");
    expect(allowStep?.skipped).toBe(true);
    expect(allowStep?.ok).toBe(true); // skipped, not failed
    expect(outcome.ok).toBe(true);
  });

  it('flags a defaultDecision of "allow" as not fail-closed instead of passing silently', async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = {
      rules: [{ id: "reads", tool: "read_*", decision: "allow" }],
      defaultDecision: "allow",
    };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, {}, { fetchImpl: cp.fetchImpl, ...silentDeps });
    const defaultStep = outcome.steps.find((s) => s.name === "default decision");
    expect(defaultStep?.ok).toBe(false);
    expect(defaultStep?.detail).toMatch(/NOT fail-closed/);
    expect(outcome.ok).toBe(false);
  });

  it("still proves the veto lane mechanics when the policy has no veto rule, and says so", async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = {
      rules: [{ id: "reads", tool: "read_*", decision: "allow" }],
      defaultDecision: "approve",
    };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, {}, { fetchImpl: cp.fetchImpl, ...silentDeps });
    const lane = outcome.steps.find((s) => s.name === "veto lane");
    expect(lane?.ok).toBe(true);
    expect(lane?.detail).toMatch(/lane mechanics/);
    expect(outcome.ok).toBe(true);
  });

  it("fails the veto lane with a device-credentials message when registration is rejected", async () => {
    const cp = createFakeControlPlane();
    const badDeviceConfig = baseConfig(POLICY, { id: "gw-1", secret: "the-wrong-secret" });
    const outcome = await runVerify(badDeviceConfig, OWNER_TOKEN, {}, { fetchImpl: cp.fetchImpl, ...silentDeps });
    const lane = outcome.steps.find((s) => s.name === "veto lane");
    expect(lane?.ok).toBe(false);
    expect(lane?.detail).toMatch(/device credentials|device\.id/);
    expect(outcome.ok).toBe(false);
    expect(cp.killed).toBe(false);
  });
});

describe("runVerify — --include-kill-test (real ceremony)", () => {
  it("engages the kill, restores through the full ceremony, and confirms the final state — leaving SIGINT listeners as it found them", async () => {
    const cp = createFakeControlPlane();
    const sigintBefore = process.listenerCount("SIGINT");
    const outcome = await runVerify(
      baseConfig(),
      OWNER_TOKEN,
      { includeKillTest: true },
      { fetchImpl: cp.fetchImpl, ...silentDeps },
    );

    expect(outcome.steps.map((s) => s.name)).toEqual([
      "owner token",
      "allow call",
      "default decision",
      "veto lane",
      "kill switch",
      "restore ceremony",
      "final state",
    ]);
    expect(outcome.steps.every((s) => s.ok)).toBe(true);
    expect(outcome.ok).toBe(true);

    expect(cp.killCalls).toHaveLength(1);
    expect(cp.restoreCalls).toEqual(["cer_test_1"]);
    expect(cp.killed).toBe(false); // restored to the starting state
    expect(process.listenerCount("SIGINT")).toBe(sigintBefore);
  });

  it("waits out a non-zero ceremony cooldown before GO 2/2", async () => {
    const cp = createFakeControlPlane({ ceremonyCooldownMs: 120 });
    const sleeps: number[] = [];
    const sleep = async (ms: number): Promise<void> => {
      sleeps.push(ms);
    };
    const outcome = await runVerify(
      baseConfig(),
      OWNER_TOKEN,
      { includeKillTest: true },
      { fetchImpl: cp.fetchImpl, sleep, ...silentDeps },
    );
    expect(outcome.ok).toBe(true);
    expect(sleeps.some((ms) => ms >= 120)).toBe(true);
    expect(cp.killed).toBe(false);
  });

  it("reports the exact recovery commands, and does not lie about the state, when restore is rejected after a real kill", async () => {
    const cp = createFakeControlPlane({ restoreBroken: true });
    const outcome = await runVerify(
      baseConfig(),
      OWNER_TOKEN,
      { includeKillTest: true },
      { fetchImpl: cp.fetchImpl, ...silentDeps },
    );
    expect(outcome.ok).toBe(false);
    expect(outcome.steps.find((s) => s.name === "restore ceremony")?.ok).toBe(false);
    const finalStep = outcome.steps.find((s) => s.name === "final state");
    expect(finalStep?.ok).toBe(false);
    expect(finalStep?.detail).toContain("STILL KILLED");
    expect(finalStep?.detail).toContain("/restore/ceremony");
    expect(cp.killed).toBe(true);
  });

  it("does not attempt any restore, and reports state unchanged, if engaging the kill switch fails", async () => {
    const cp = createFakeControlPlane();
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/kill") throw new Error("ECONNRESET");
      return cp.fetchImpl(input, init);
    };
    const outcome = await runVerify(
      baseConfig(),
      OWNER_TOKEN,
      { includeKillTest: true },
      { fetchImpl, ...silentDeps },
    );
    expect(outcome.ok).toBe(false);
    expect(outcome.steps.at(-1)).toMatchObject({ name: "kill switch", ok: false });
    expect(outcome.steps.at(-1)?.detail).toContain("system state unchanged");
    expect(outcome.steps.find((s) => s.name === "restore ceremony")).toBeUndefined();
    expect(cp.killed).toBe(false);
  });
});

describe("formatVerifyReport", () => {
  it("renders a PASS summary when every step is ok", () => {
    const report = formatVerifyReport({
      ok: true,
      steps: [{ name: "owner token", ok: true, detail: "accepted" }],
    });
    expect(report).toContain("✔ owner token — accepted");
    expect(report).toContain("PASS");
  });

  it("renders skipped steps distinctly and a FAIL summary on failure", () => {
    const report = formatVerifyReport({
      ok: false,
      steps: [
        { name: "allow call", ok: true, skipped: true, detail: "skipped — no allow rule" },
        { name: "final state", ok: false, detail: "still engaged" },
      ],
    });
    expect(report).toContain("… allow call — skipped — no allow rule");
    expect(report).toContain("✘ final state — still engaged");
    expect(report).toContain("FAIL");
  });
});

describe("resolveOwnerToken", () => {
  it("prefers OWNERSWITCH_OWNER_TOKEN, trimmed, and never prompts when it is set", async () => {
    const prompt = vi.fn();
    await expect(
      resolveOwnerToken({ OWNERSWITCH_OWNER_TOKEN: "  env-tok  " }, prompt as never),
    ).resolves.toBe("env-tok");
    expect(prompt).not.toHaveBeenCalled();
  });

  it("falls back to the prompt when the env var is unset or blank", async () => {
    await expect(resolveOwnerToken({}, async () => "typed-tok")).resolves.toBe("typed-tok");
    await expect(resolveOwnerToken({ OWNERSWITCH_OWNER_TOKEN: "  " }, async () => "typed-tok")).resolves.toBe(
      "typed-tok",
    );
    await expect(resolveOwnerToken({}, async () => undefined)).resolves.toBeUndefined();
  });
});

describe("verifyMain", () => {
  it("refuses --owner-token outright, naming the leak, without touching config or network", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("must not be called");
    });
    try {
      const code = await verifyMain(["--owner-token", "tok", "--config", "/nope.json"], {});
      expect(code).toBe(1);
      expect(errorSpy.mock.calls[0][0]).toMatch(/shell history/);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
      fetchSpy.mockRestore();
    }
  });

  it("loads config from env vars, finds no owner token (no TTY), and never touches the network", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("must not be called");
    });
    try {
      const code = await verifyMain([], {
        OWNERSWITCH_CONTROL_PLANE_URL: CP_URL,
        OWNERSWITCH_DEVICE_ID: DEVICE.id,
        OWNERSWITCH_DEVICE_SECRET: DEVICE.secret,
        OWNERSWITCH_UPSTREAM_COMMAND: "npx",
        OWNERSWITCH_POLICY: JSON.stringify(POLICY),
      });
      expect(code).toBe(1);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(logSpy).toHaveBeenCalledTimes(1);
      expect(logSpy.mock.calls[0][0]).toContain("owner token");
    } finally {
      logSpy.mockRestore();
      fetchSpy.mockRestore();
    }
  });

  it("reports a config error via console.error and exits 1 without ever calling runVerify", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("must not be called");
    });
    try {
      const code = await verifyMain(["--config", "/tmp/ownerswitch-verify-test-does-not-exist.json"], {});
      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledTimes(1);
      expect(logSpy).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
      logSpy.mockRestore();
      fetchSpy.mockRestore();
    }
  });
});
