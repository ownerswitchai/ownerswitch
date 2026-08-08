import { describe, expect, it, vi } from "vitest";
import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import type { Policy } from "@ownerswitchai/shared";
import type { OwnerSwitchMcpConfig } from "./config.js";
import { extractOwnerToken, formatVerifyReport, runVerify, verifyMain } from "./verify.js";

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

function baseConfig(policy: Policy = POLICY): OwnerSwitchMcpConfig {
  return {
    controlPlaneUrl: CP_URL,
    device: DEVICE,
    upstream: { command: "npx", args: [] },
    policy,
  };
}

/**
 * In-memory control plane faithful to the real auth rules that matter here
 * (control-plane/src/server.ts + kill.ts): /kill needs a valid device
 * signature, /restore needs a bearer token matching OWNER_TOKEN and throws
 * "not killed" (409) if called while not killed — exactly the probe verify
 * uses to validate the token without a side effect.
 */
function createFakeControlPlane() {
  let killed = false;
  const killCalls: unknown[] = [];
  const restoreCalls: unknown[] = [];

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";
    const rawBody = String(init?.body ?? "");

    if (method === "GET" && url.pathname === "/status") return json({ killed });

    if (method === "POST" && url.pathname === "/kill") {
      const h = new Headers(init?.headers);
      const valid = verifyDeviceSignature(
        {
          deviceId: h.get("x-device-id") ?? "",
          timestamp: Number(h.get("x-device-timestamp")),
          nonce: h.get("x-device-nonce") ?? "",
          signature: h.get("x-device-signature") ?? "",
        },
        rawBody,
        DEVICE.secret,
      );
      if (!valid) return json({ error: "unauthorized" }, 401);
      killed = true;
      killCalls.push(JSON.parse(rawBody));
      return json({ killed: true });
    }

    if (method === "POST" && url.pathname === "/restore") {
      const auth = new Headers(init?.headers).get("authorization");
      if (auth !== `Bearer ${OWNER_TOKEN}`) return json({ error: "unauthorized" }, 401);
      if (!killed) return json({ error: "not killed — nothing to restore" }, 409);
      restoreCalls.push(JSON.parse(rawBody));
      killed = false;
      return json({ killed: false });
    }

    return json({ error: "not found" }, 404);
  };

  return {
    fetchImpl,
    killCalls,
    restoreCalls,
    get killed() {
      return killed;
    },
  };
}

describe("runVerify", () => {
  it("requires an owner token before making any control-plane call", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("must not be called");
    };
    const outcome = await runVerify(baseConfig(), undefined, { fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps).toHaveLength(1);
    expect(outcome.steps[0]).toMatchObject({ name: "owner token", ok: false });
    expect(outcome.steps[0].detail).toMatch(/OWNERSWITCH_OWNER_TOKEN/);
  });

  it("fails fast when the control plane is unreachable", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0].name).toBe("control plane");
  });

  it("refuses to run if the control plane is already in lockdown", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, {
      // force /status to report killed:true; everything else behaves normally
      fetchImpl: async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname === "/status") {
          return new Response(JSON.stringify({ killed: true }), { status: 200 });
        }
        return cp.fetchImpl(input, init);
      },
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0].detail).toContain("already in lockdown");
  });

  it("rejects an invalid owner token via the harmless restore probe, and never engages the kill switch", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), "wrong-token", { fetchImpl: cp.fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0]).toMatchObject({ name: "owner token", ok: false });
    expect(cp.killCalls).toHaveLength(0);
    expect(cp.killed).toBe(false);
  });

  it("passes end to end and leaves the system exactly as it started", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });

    expect(outcome.steps.map((s) => s.name)).toEqual([
      "owner token",
      "allow call",
      "default decision",
      "kill switch",
      "restore",
    ]);
    expect(outcome.steps.every((s) => s.ok)).toBe(true);
    expect(outcome.ok).toBe(true);

    expect(cp.killCalls).toHaveLength(1);
    expect(cp.restoreCalls).toHaveLength(1);
    expect(cp.killed).toBe(false); // restored to the starting state
  });

  it("honestly skips the allow-call phase when the policy has no allow rule", async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = { rules: [{ id: "w", tool: "write_file", decision: "veto" }], defaultDecision: "deny" };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const allowStep = outcome.steps.find((s) => s.name === "allow call");
    expect(allowStep?.skipped).toBe(true);
    expect(allowStep?.ok).toBe(true); // skipped, not failed
    expect(outcome.ok).toBe(true);
  });

  it("flags a defaultDecision of \"allow\" as not fail-closed instead of passing silently", async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = {
      rules: [{ id: "reads", tool: "read_*", decision: "allow" }],
      defaultDecision: "allow",
    };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const defaultStep = outcome.steps.find((s) => s.name === "default decision");
    expect(defaultStep?.ok).toBe(false);
    expect(defaultStep?.detail).toMatch(/NOT fail-closed/);
    expect(outcome.ok).toBe(false);
  });

  it("does not attempt restore, and reports state unchanged, if engaging the kill switch fails", async () => {
    const cp = createFakeControlPlane();
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/kill") throw new Error("ECONNRESET");
      return cp.fetchImpl(input, init);
    };
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps.find((s) => s.name === "restore")).toBeUndefined();
    expect(outcome.steps.at(-1)?.detail).toContain("system state unchanged");
    expect(cp.killed).toBe(false);
  });

  it("reports FAIL with recovery instructions if restore fails after a real kill — and does not lie about the state", async () => {
    const cp = createFakeControlPlane();
    let restoreAttempts = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/restore" && (init?.method ?? "GET") === "POST") {
        restoreAttempts++;
        if (restoreAttempts === 2) return new Response(JSON.stringify({ error: "boom" }), { status: 500 });
      }
      return cp.fetchImpl(input, init);
    };
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl });
    expect(outcome.ok).toBe(false);
    const restoreStep = outcome.steps.find((s) => s.name === "restore");
    expect(restoreStep?.ok).toBe(false);
    expect(restoreStep?.detail).toContain("ENGAGED");
    expect(restoreStep?.detail).toContain("curl");
    expect(cp.killed).toBe(true);
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
        { name: "restore", ok: false, detail: "still engaged" },
      ],
    });
    expect(report).toContain("… allow call — skipped — no allow rule");
    expect(report).toContain("✘ restore — still engaged");
    expect(report).toContain("FAIL");
  });
});

describe("extractOwnerToken", () => {
  it("reads --owner-token <value>", () => {
    const { ownerToken, rest } = extractOwnerToken(["--owner-token", "tok1", "--config", "f.json"], {});
    expect(ownerToken).toBe("tok1");
    expect(rest).toEqual(["--config", "f.json"]);
  });

  it("reads --owner-token=<value>", () => {
    const { ownerToken, rest } = extractOwnerToken(["--config", "f.json", "--owner-token=tok2"], {});
    expect(ownerToken).toBe("tok2");
    expect(rest).toEqual(["--config", "f.json"]);
  });

  it("falls back to OWNERSWITCH_OWNER_TOKEN, and the flag wins when both are given", () => {
    expect(extractOwnerToken(["--config", "f.json"], { OWNERSWITCH_OWNER_TOKEN: "env-tok" }).ownerToken).toBe(
      "env-tok",
    );
    expect(
      extractOwnerToken(["--owner-token", "flag-tok"], { OWNERSWITCH_OWNER_TOKEN: "env-tok" }).ownerToken,
    ).toBe("flag-tok");
  });
});

describe("verifyMain", () => {
  it("loads config from env vars, finds no owner token, and never touches the network", async () => {
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
