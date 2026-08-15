import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { verifyDeviceSignature } from "@ownerswitchai/control-plane";
import type { Policy } from "@ownerswitchai/shared";
import type { OwnerSwitchMcpConfig } from "./config.js";
import { formatVerifyReport, readHiddenLine, resolveOwnerToken, runVerify, verifyMain } from "./verify.js";

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
 * /restore needs the bearer token and rejects everything but a minted,
 * current ceremony id with the uniform 409, and the veto lane needs a
 * device signature to register and the bearer to tap.
 */
function createFakeControlPlane() {
  let killed = false;
  const killCalls: unknown[] = [];
  const windows = new Map<string, { status: string }>();

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  // fleet-hmac v2: the stub verifies the exact method+path it received, the
  // way the real control plane does
  const validDevice = (
    init: RequestInit | undefined,
    rawBody: string,
    context: { method: string; pathAndQuery: string },
  ): boolean => {
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
      context,
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
      if (!validDevice(init, rawBody, { method, pathAndQuery: "/kill" })) {
        return json({ error: "unauthorized" }, 401);
      }
      killed = true;
      killCalls.push(JSON.parse(rawBody));
      return json({ killed: true });
    }

    if (method === "POST" && url.pathname === "/restore") {
      if (!validOwner(init)) return json({ error: "unauthorized" }, 401);
      // No ceremony is ever actually minted in these tests — every restore
      // attempt is the harmless probe, which always gets the uniform 409.
      return json({ error: "restore rejected" }, 409);
    }

    if (method === "POST" && url.pathname === "/veto") {
      if (!validDevice(init, rawBody, { method, pathAndQuery: "/veto" })) {
        return json({ error: "unauthorized" }, 401);
      }
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
    windows,
    get killed() {
      return killed;
    },
  };
}

describe("runVerify", () => {
  it("requires an owner token before making any control-plane call, and points at env/prompt (not a flag)", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("must not be called");
    };
    const outcome = await runVerify(baseConfig(), undefined, { fetchImpl });
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
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl });
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
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0].detail).toContain("lockdown");
    expect(outcome.steps[0].detail).toContain("/restore/ceremony");
  });

  it("rejects an invalid owner token via the harmless /restore probe — no kill, no window, nothing mutated", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), "wrong-token", { fetchImpl: cp.fetchImpl });
    expect(outcome.ok).toBe(false);
    expect(outcome.steps[0]).toMatchObject({ name: "owner token", ok: false });
    expect(cp.killCalls).toHaveLength(0);
    expect(cp.windows.size).toBe(0);
    expect(cp.killed).toBe(false);
  });

  it("passes end to end WITHOUT ever calling POST /kill, ending with a terminally-vetoed demo window", async () => {
    const cp = createFakeControlPlane();
    const outcome = await runVerify(baseConfig(), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });

    expect(outcome.steps.map((s) => s.name)).toEqual(["owner token", "allow call", "default decision", "veto lane"]);
    expect(outcome.steps.every((s) => s.ok)).toBe(true);
    expect(outcome.ok).toBe(true);

    expect(cp.killCalls).toHaveLength(0); // verify never touches the kill switch, period
    expect(cp.killed).toBe(false);
    expect([...cp.windows.values()].map((w) => w.status)).toEqual(["vetoed"]);
  });

  it('fails the allow-call check — not a silent pass — when the policy has no allow rule, naming why', async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = { rules: [{ id: "w", tool: "write_file", decision: "veto" }], defaultDecision: "deny" };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const allowStep = outcome.steps.find((s) => s.name === "allow call");
    expect(allowStep?.ok).toBe(false);
    expect(allowStep?.detail).toMatch(/cannot prove "allow"/);
    expect(allowStep?.detail).toMatch(/no rule with decision "allow"/);
    expect(outcome.ok).toBe(false); // the whole run fails — nothing is folded into a PASS
  });

  it('fails the default-decision check — not a silent pass — when every tool matches an explicit rule, naming why', async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = {
      rules: [{ id: "catch-all", tool: "*", decision: "allow" }],
      defaultDecision: "deny",
    };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const defaultStep = outcome.steps.find((s) => s.name === "default decision");
    expect(defaultStep?.ok).toBe(false);
    expect(defaultStep?.detail).toMatch(/cannot prove the fail-closed default/);
    expect(defaultStep?.detail).toMatch(/catch-all/);
    expect(outcome.ok).toBe(false);
  });

  it('flags a defaultDecision of "allow" as not fail-closed instead of passing silently', async () => {
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

  it("still proves the veto lane mechanics when the policy has no veto rule, and says so (this lane always does real work)", async () => {
    const cp = createFakeControlPlane();
    const policy: Policy = {
      rules: [{ id: "reads", tool: "read_*", decision: "allow" }],
      defaultDecision: "approve",
    };
    const outcome = await runVerify(baseConfig(policy), OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const lane = outcome.steps.find((s) => s.name === "veto lane");
    expect(lane?.ok).toBe(true);
    expect(lane?.detail).toMatch(/lane mechanics/);
    expect(outcome.ok).toBe(true);
  });

  it("fails the veto lane with a device-credentials message when registration is rejected", async () => {
    const cp = createFakeControlPlane();
    const badDeviceConfig = baseConfig(POLICY, { id: "gw-1", secret: "the-wrong-secret" });
    const outcome = await runVerify(badDeviceConfig, OWNER_TOKEN, { fetchImpl: cp.fetchImpl });
    const lane = outcome.steps.find((s) => s.name === "veto lane");
    expect(lane?.ok).toBe(false);
    expect(lane?.detail).toMatch(/device credentials|device\.id/);
    expect(outcome.ok).toBe(false);
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

  it("renders a failed 'cannot prove' step as an ordinary ✘ failure — not a soft/skip icon — and a FAIL summary", () => {
    const report = formatVerifyReport({
      ok: false,
      steps: [
        { name: "allow call", ok: false, detail: 'cannot prove "allow" — no allow rule' },
        { name: "veto lane", ok: true, detail: "window vetoed" },
      ],
    });
    expect(report).toContain('✘ allow call — cannot prove "allow" — no allow rule');
    expect(report).not.toContain("…");
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

/** A fake TTY-like stdin: emits raw "keystrokes" as 'data' events, tracks raw-mode toggles. */
function fakeTtyInput() {
  const emitter = new EventEmitter();
  const rawModeCalls: boolean[] = [];
  let resumed = 0;
  let paused = 0;
  const input = Object.assign(emitter, {
    isTTY: true as const,
    isRaw: false,
    setRawMode: (mode: boolean) => {
      rawModeCalls.push(mode);
      input.isRaw = mode;
    },
    setEncoding: () => {},
    resume: () => {
      resumed++;
    },
    pause: () => {
      paused++;
    },
  });
  return {
    input,
    type: (text: string) => emitter.emit("data", text),
    rawModeCalls,
    get resumed() {
      return resumed;
    },
    get paused() {
      return paused;
    },
  };
}

function fakeOutput() {
  const written: string[] = [];
  return { output: { write: (chunk: string) => void written.push(chunk) }, written };
}

describe("readHiddenLine", () => {
  it("writes the prompt but NEVER echoes typed characters, and returns the typed line on Enter", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("Owner token: ", tty.input, out.output);
    tty.type("s3cr3t-token");
    tty.type("\n");
    await expect(resultPromise).resolves.toBe("s3cr3t-token");

    // Only the prompt itself and the final newline ever reached output —
    // the secret characters do not appear anywhere in what was written.
    expect(out.written).toEqual(["Owner token: ", "\n"]);
    expect(out.written.join("")).not.toContain("s3cr3t-token");
    expect(tty.rawModeCalls).toEqual([true, false]); // enabled, then restored
  });

  it("supports backspace without ever echoing a character", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("token: ", tty.input, out.output);
    tty.type("abcX");
    tty.type("\x7f"); // DEL — erase the stray "X"
    tty.type("d");
    tty.type("\r");
    await expect(resultPromise).resolves.toBe("abcd");
    expect(out.written.join("")).toBe("token: \n");
  });

  it("returns undefined for an empty line", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const resultPromise = readHiddenLine("token: ", tty.input, out.output);
    tty.type("\n");
    await expect(resultPromise).resolves.toBeUndefined();
  });

  it("restores raw mode and exits on Ctrl-C, without ever echoing what was typed so far", async () => {
    const tty = fakeTtyInput();
    const out = fakeOutput();
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
      throw new Error("__exit__");
    }) as never);
    try {
      // The mock throws instead of terminating the process, so the promise
      // readHiddenLine returned is never resolved (real process.exit never
      // returns either) — only the synchronous throw from the Ctrl-C
      // handler itself is under test here, not the promise's settlement.
      void readHiddenLine("token: ", tty.input, out.output).catch(() => undefined);
      tty.type("partial-sec");
      expect(() => tty.type("\x03")).toThrow("__exit__");
      expect(exitSpy).toHaveBeenCalledWith(130);
      expect(out.written.join("")).not.toContain("partial-sec");
      expect(tty.rawModeCalls).toEqual([true, false]);
    } finally {
      exitSpy.mockRestore();
    }
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
