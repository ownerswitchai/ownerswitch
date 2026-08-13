import { describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ToolListChangedNotificationSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { verifyDeviceSignature, type VetoStatus } from "@ownerswitchai/control-plane";
import { createControlPlaneClient, LimitTracker, type LimitTrip } from "@ownerswitchai/gateway";
import {
  createTripwire,
  generateHoneytoken,
  HoneytokenRegistry,
  scanForHoneytokens,
} from "@ownerswitchai/honeytoken";
import type { LimitRule, Policy } from "@ownerswitchai/shared";
import { OwnerSwitchErrorCode } from "./errors.js";
import { createOwnerSwitchProxy, type ProxyOptions } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";

const DEVICE_SECRET = "gateway-test-secret";
const CP_URL = "http://control-plane.test";

const POLICY: Policy = {
  rules: [
    { id: "reads", tool: "read_*", decision: "allow", description: "reads are safe" },
    { id: "writes", tool: "write_file", decision: "veto", description: "owner can veto writes" },
    { id: "deletes", tool: "delete_*", decision: "deny", description: "deletes never run" },
  ],
  defaultDecision: "approve",
};

/** The tool list the fake upstream serves — asserted to pass through verbatim. */
const UPSTREAM_TOOLS = [
  {
    name: "read_file",
    description: "Read a file",
    inputSchema: {
      type: "object" as const,
      properties: { path: { type: "string" as const } },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description: "Write a file",
    inputSchema: {
      type: "object" as const,
      properties: { path: { type: "string" as const }, content: { type: "string" as const } },
      required: ["path"],
    },
  },
  {
    name: "delete_file",
    description: "Delete a file",
    inputSchema: { type: "object" as const, properties: { path: { type: "string" as const } } },
  },
  {
    name: "mystery_tool",
    description: "Not covered by any rule",
    inputSchema: { type: "object" as const, properties: {} },
  },
];

function createFakeUpstream() {
  const calls: Array<{ name: string; args: unknown }> = [];
  const server = new Server(
    { name: "fake-upstream", version: "1.0.0" },
    { capabilities: { tools: { listChanged: true } } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: UPSTREAM_TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    calls.push({ name: req.params.name, args: req.params.arguments });
    if ((req.params.arguments as { path?: string } | undefined)?.path === "/fails") {
      // the tool RAN and reports its own failure — the error-budget case
      return {
        isError: true,
        content: [{ type: "text" as const, text: `upstream ${req.params.name} failed` }],
      };
    }
    return {
      content: [{ type: "text" as const, text: `upstream ran ${req.params.name}` }],
    };
  });
  return { server, calls };
}

/**
 * In-memory control plane: serves /status, POST /veto and GET /veto/:id from
 * mutable state. No sockets — this is the fetch implementation injected into
 * both control-plane clients.
 */
function createFakeControlPlane() {
  const state = {
    killed: false as boolean,
    reason: undefined as string | undefined,
    /** mirrors the real control plane's monotone kill epoch */
    epoch: 0,
    /** mirrors the real control plane's scoped-kill list */
    killedAgents: [] as string[],
    /** every fetch rejects, as if the process were gone */
    down: false,
    /** only veto registration fails */
    registrationDown: false,
    /** what GET /veto/:id reports */
    vetoStatus: "pending" as VetoStatus | "missing",
  };
  const registrations: Array<{ headers: Headers; rawBody: string; body: unknown }> = [];
  const statusPolls: string[] = [];

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  const fetchImpl: typeof fetch = async (input, init) => {
    if (state.down) throw new Error("ECONNREFUSED");
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";

    if (method === "GET" && url.pathname === "/status") {
      return json(
        state.killed
          ? { killed: true, reason: state.reason, epoch: state.epoch, killedAgents: state.killedAgents }
          : { killed: false, epoch: state.epoch, killedAgents: state.killedAgents },
      );
    }
    if (method === "POST" && url.pathname === "/veto") {
      if (state.registrationDown) throw new Error("ECONNREFUSED");
      const rawBody = String(init?.body);
      registrations.push({ headers: new Headers(init?.headers), rawBody, body: JSON.parse(rawBody) });
      return json({ id: `veto_${registrations.length}`, status: "pending" }, 201);
    }
    const match = /^\/veto\/([^/]+)$/.exec(url.pathname);
    if (method === "GET" && match) {
      statusPolls.push(match[1]);
      if (state.vetoStatus === "missing") return json({ error: "no such window" }, 404);
      return json({ status: state.vetoStatus });
    }
    return json({ error: "not found" }, 404);
  };

  return { state, registrations, statusPolls, fetchImpl };
}

async function startProxy(
  controlPlane = createFakeControlPlane(),
  honeytokens?: ProxyOptions["honeytokens"],
  limits?: ProxyOptions["limits"],
) {
  const upstream = createFakeUpstream();
  const [upstreamClientSide, upstreamServerSide] = InMemoryTransport.createLinkedPair();
  await upstream.server.connect(upstreamServerSide);

  const proxy = createOwnerSwitchProxy({
    policy: POLICY,
    agentId: "test-agent",
    controlPlane: createControlPlaneClient({
      baseUrl: CP_URL,
      timeoutMs: 250,
      fetchImpl: controlPlane.fetchImpl,
    }),
    vetoClient: createVetoClient({
      baseUrl: CP_URL,
      device: { id: "gw-test", secret: DEVICE_SECRET },
      timeoutMs: 250,
      fetchImpl: controlPlane.fetchImpl,
    }),
    ...(honeytokens !== undefined ? { honeytokens } : {}),
    ...(limits !== undefined ? { limits } : {}),
  });
  await proxy.connectUpstream(upstreamClientSide);

  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(serverSide);
  const client = new Client({ name: "test-downstream", version: "0.0.0" });
  await client.connect(clientSide);

  const close = async () => {
    await client.close();
    await proxy.close();
    await upstream.server.close();
  };
  return { client, upstream, controlPlane, close };
}

/** The refusal the downstream agent sees, as the SDK client surfaces it. */
async function refusalOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(McpError);
    return err as McpError;
  }
  throw new Error("expected the call to be refused, but it succeeded");
}

const text = (result: unknown): string => {
  const content = (result as CallToolResult).content;
  const first = content[0];
  return first?.type === "text" ? first.text : JSON.stringify(content);
};

describe("tool list", () => {
  it("forwards the upstream tool list unchanged", async () => {
    const t = await startProxy();
    const { tools } = await t.client.listTools();
    expect(tools).toEqual(UPSTREAM_TOOLS);
    await t.close();
  });

  it("forwards upstream tool-list-changed notifications", async () => {
    const t = await startProxy();
    let notified = 0;
    t.client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      notified += 1;
    });
    await t.upstream.server.sendToolListChanged();
    await new Promise((r) => setTimeout(r, 20));
    expect(notified).toBe(1);
    await t.close();
  });
});

describe("allow", () => {
  it("forwards the call and returns the upstream result intact", async () => {
    const t = await startProxy();
    const result = await t.client.callTool({
      name: "read_file",
      arguments: { path: "/tmp/a.txt" },
    });
    expect(text(result)).toBe("upstream ran read_file");
    expect(t.upstream.calls).toEqual([{ name: "read_file", args: { path: "/tmp/a.txt" } }]);
    await t.close();
  });
});

describe("deny", () => {
  it("refuses with the PolicyDenied code and never touches upstream", async () => {
    const t = await startProxy();
    const err = await refusalOf(t.client.callTool({ name: "delete_file", arguments: { path: "/x" } }));
    expect(err.code).toBe(OwnerSwitchErrorCode.PolicyDenied);
    expect(err.message).toContain('"delete_file"');
    expect(err.message).toContain("deletes never run");
    expect(err.message.match(/MCP error/g)).toHaveLength(1); // single clean prefix
    expect(err.data).toMatchObject({ decision: "deny", tool: "delete_file", ruleId: "deletes" });
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });
});

describe("approve", () => {
  it("refuses unknown tools with the fail-closed default and the ApprovalRequired code", async () => {
    const t = await startProxy();
    const err = await refusalOf(t.client.callTool({ name: "mystery_tool", arguments: {} }));
    expect(err.code).toBe(OwnerSwitchErrorCode.ApprovalRequired);
    expect(err.message).toContain('"mystery_tool"');
    expect(err.message).toContain("has NOT run");
    expect(err.data).toMatchObject({ decision: "approve", tool: "mystery_tool", ruleId: null });
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });
});

describe("veto", () => {
  const WRITE = { name: "write_file", arguments: { path: "/tmp/a.txt", content: "hi" } };

  it("holds the call, registers a device-signed VetoWindow, and refuses with VetoPending", async () => {
    const t = await startProxy();
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(err.message).toContain('"write_file"');
    expect(err.message).toContain("pending owner review");
    expect(err.message).toContain("veto_1");
    expect(err.data).toMatchObject({ decision: "veto", vetoWindowId: "veto_1" });
    expect(t.upstream.calls).toEqual([]); // held, not forwarded

    // exactly one registration, carrying the held call…
    expect(t.controlPlane.registrations).toHaveLength(1);
    const reg = t.controlPlane.registrations[0];
    expect(reg.body).toEqual({
      call: { agentId: "test-agent", tool: "write_file", args: WRITE.arguments },
    });
    // …signed with the gateway's device credentials (verifiable by the control plane)
    const credential = {
      deviceId: reg.headers.get("x-device-id") ?? "",
      timestamp: Number(reg.headers.get("x-device-timestamp")),
      nonce: reg.headers.get("x-device-nonce") ?? "",
      signature: reg.headers.get("x-device-signature") ?? "",
    };
    expect(credential.deviceId).toBe("gw-test");
    expect(
      verifyDeviceSignature(credential, reg.rawBody, DEVICE_SECRET, { seenNonces: new Map() }),
    ).toBe(true);
    await t.close();
  });

  it("a retry while the window is open stays refused and does not open a second window", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(err.message).toContain("still open");
    expect(t.controlPlane.registrations).toHaveLength(1);
    expect(t.controlPlane.statusPolls).toEqual(["veto_1"]);
    await t.close();
  });

  it("a vetoed window turns retries into OwnerVetoed refusals", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    t.controlPlane.state.vetoStatus = "vetoed";
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.OwnerVetoed);
    expect(err.message).toContain("the owner vetoed this action");
    expect(t.upstream.calls).toEqual([]);
    // and it stays vetoed — no new window is opened behind the owner's back
    await refusalOf(t.client.callTool(WRITE));
    expect(t.controlPlane.registrations).toHaveLength(1);
    await t.close();
  });

  it("a released window lets exactly one retry run, then the next call opens a fresh window", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    t.controlPlane.state.vetoStatus = "released";
    const result = await t.client.callTool(WRITE);
    expect(text(result)).toBe("upstream ran write_file");
    expect(t.upstream.calls).toEqual([{ name: "write_file", args: WRITE.arguments }]);

    // the released window was consumed: a new identical call is held again
    t.controlPlane.state.vetoStatus = "pending";
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.controlPlane.registrations).toHaveLength(2);
    await t.close();
  });

  it("a held window (owner unreachable) escalates to ApprovalRequired", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    t.controlPlane.state.vetoStatus = "held";
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.ApprovalRequired);
    expect(err.message).toContain("escalated to explicit approval");
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("re-registers when the control plane forgot the window (restart)", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    t.controlPlane.state.vetoStatus = "missing";
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(err.message).toContain("veto_2");
    expect(t.controlPlane.registrations).toHaveLength(2);
    await t.close();
  });

  it("different arguments get their own window", async () => {
    const t = await startProxy();
    await refusalOf(t.client.callTool(WRITE));
    await refusalOf(
      t.client.callTool({ name: "write_file", arguments: { path: "/tmp/b.txt", content: "hi" } }),
    );
    expect(t.controlPlane.registrations).toHaveLength(2);
    await t.close();
  });

  it("fails closed when registration fails, and re-attempts on the next call", async () => {
    const t = await startProxy();
    t.controlPlane.state.registrationDown = true;
    const err = await refusalOf(t.client.callTool(WRITE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(err.message).toContain("control plane unreachable — fail closed");
    expect(t.upstream.calls).toEqual([]);

    // a failed registration is not cached as a window
    t.controlPlane.state.registrationDown = false;
    const retry = await refusalOf(t.client.callTool(WRITE));
    expect(retry.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.controlPlane.registrations).toHaveLength(1);
    await t.close();
  });
});

describe("kill switch", () => {
  it("denies everything with the Lockdown code, including allowed reads", async () => {
    const t = await startProxy();
    t.controlPlane.state.killed = true;
    t.controlPlane.state.reason = "kill switch engaged: red button pressed";
    const err = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/x" } }));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(err.message).toContain("red button pressed");
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("a SCOPED kill of this gateway's agent reads as Lockdown too — never a policy deny", async () => {
    const t = await startProxy();
    t.controlPlane.state.killedAgents = ["test-agent"];
    const err = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/x" } }));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(err.message).toContain('"test-agent"');
    expect(err.message).toContain("scope-killed");
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("another agent's scoped kill leaves this gateway forwarding normally", async () => {
    const t = await startProxy();
    t.controlPlane.state.killedAgents = ["some-other-agent"];
    const result = (await t.client.callTool({
      name: "read_file",
      arguments: { path: "/x" },
    })) as { content: unknown };
    expect(result.content).toBeDefined();
    expect(t.upstream.calls).toHaveLength(1);
    await t.close();
  });
});

describe("control plane down", () => {
  it("denies every call — fail closed — and says so", async () => {
    const t = await startProxy();
    t.controlPlane.state.down = true;

    for (const call of [
      { name: "read_file", arguments: { path: "/x" } }, // would be allowed
      { name: "write_file", arguments: { path: "/x" } }, // would be vetoable
      { name: "mystery_tool", arguments: {} }, // would need approval
    ]) {
      const err = await refusalOf(t.client.callTool(call));
      expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
      expect(err.message).toContain("control plane unreachable — fail closed");
    }
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });
});

describe("honeytoken tripwire", () => {
  const CANARY_KEY = "canary-key-proxy-test-0011223344556677";
  const DEPLOY = "deploy-proxy";

  const registryWith = (...tokens: ReturnType<typeof generateHoneytoken>[]) => {
    const r = new HoneytokenRegistry(CANARY_KEY, DEPLOY);
    for (const t of tokens) r.add(t);
    return r;
  };

  /** Guard around the REAL scanner, with kill/alert reports captured. */
  function createGuardSpy(registry: HoneytokenRegistry) {
    const kills: Array<{ canaryIds: string[]; tool: string; agentId: string }> = [];
    const alerts: Array<{ canaryIds: string[]; tool: string; agentId: string; note?: string }> = [];
    const guard: ProxyOptions["honeytokens"] = {
      scan: (text) => scanForHoneytokens(text, registry),
      reportKill: (trip) => kills.push(trip),
      reportAlert: (trip) => alerts.push(trip),
    };
    return { kills, alerts, guard };
  }

  it("a decoy in an ALLOWED call trips a kill: refused, reported, upstream never touched", async () => {
    const token = generateHoneytoken({ kind: "stripe" });
    const spy = createGuardSpy(registryWith(token));
    const t = await startProxy(createFakeControlPlane(), spy.guard);

    const err = await refusalOf(
      t.client.callTool({
        name: "read_file", // policy ALLOWS this tool — it will forward, so the decoy kills
        arguments: { path: "/tmp/x", note: `use ${token.value} for the payout` },
      }),
    );

    expect(err.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);
    expect(err.message).toContain(token.canaryId);
    expect(t.upstream.calls).toEqual([]);
    expect(spy.kills).toEqual([{ canaryIds: [token.canaryId], tool: "read_file", agentId: "test-agent" }]);
    expect(spy.alerts).toEqual([]);
    await t.close();
  });

  it("a decoy in a DENIED call only ALERTS — no remote kill primitive (fix #3)", async () => {
    const token = generateHoneytoken({ kind: "aws" });
    const spy = createGuardSpy(registryWith(token));
    const t = await startProxy(createFakeControlPlane(), spy.guard);

    // delete_* is a policy DENY. The call never forwards, so a decoy in it must
    // NOT kill — otherwise an attacker fires a global kill by dropping the value
    // into any attempted call. It stays denied and raises an alert.
    const err = await refusalOf(
      t.client.callTool({ name: "delete_file", arguments: { path: token.value } }),
    );

    expect(err.code).toBe(OwnerSwitchErrorCode.PolicyDenied);
    expect(spy.kills).toEqual([]);
    expect(spy.alerts).toEqual([
      { canaryIds: [token.canaryId], tool: "delete_file", agentId: "test-agent", note: "policy denied" },
    ]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("a decoy in an approval-gated call alerts, never kills", async () => {
    const token = generateHoneytoken({ kind: "generic" });
    const spy = createGuardSpy(registryWith(token));
    const t = await startProxy(createFakeControlPlane(), spy.guard);

    const err = await refusalOf(
      t.client.callTool({ name: "mystery_tool", arguments: { x: token.value } }),
    );

    expect(err.code).toBe(OwnerSwitchErrorCode.ApprovalRequired);
    expect(spy.kills).toEqual([]);
    expect(spy.alerts[0]).toMatchObject({ note: "held for owner approval" });
    await t.close();
  });

  it("a decoy in a vetoed call alerts on open, and kills only once released, right before forward", async () => {
    const token = generateHoneytoken({ kind: "openai" });
    const spy = createGuardSpy(registryWith(token));
    const controlPlane = createFakeControlPlane();
    const t = await startProxy(controlPlane, spy.guard);
    const call = { name: "write_file", arguments: { path: "/x", content: token.value } };

    // first attempt: the window opens, the call is HELD (not forwarded) → alert only
    const pending = await refusalOf(t.client.callTool(call));
    expect(pending.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(spy.kills).toEqual([]);
    expect(spy.alerts).toHaveLength(1);
    expect(spy.alerts[0]).toMatchObject({ note: "held for owner review" });

    // the owner stays silent, the window releases; the retry would forward — so
    // the scan runs right before forwarding and the decoy kills instead.
    controlPlane.state.vetoStatus = "released";
    const killed = await refusalOf(t.client.callTool(call));
    expect(killed.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);
    expect(spy.kills).toHaveLength(1);
    expect(t.upstream.calls).toEqual([]); // killed instead of forwarded
    await t.close();
  });

  it("clean calls pass through untouched with the tripwire armed", async () => {
    const spy = createGuardSpy(registryWith(generateHoneytoken({ kind: "aws" })));
    const t = await startProxy(createFakeControlPlane(), spy.guard);

    const result = await t.client.callTool({
      name: "read_file",
      // real-shaped foreign credential: NOT ours, never planted, must not trip
      arguments: { path: "/tmp/a.txt", key: "AKIAIOSFODNN7EXAMPLE" },
    });

    expect(text(result)).toBe("upstream ran read_file");
    expect(spy.kills).toEqual([]);
    expect(spy.alerts).toEqual([]);
    expect(t.upstream.calls).toHaveLength(1);
    await t.close();
  });

  it("the real createTripwire wiring POSTs a signed kill when an allowed call trips", async () => {
    const token = generateHoneytoken({ kind: "openai" });
    const killPosts: Array<{ headers: Record<string, string>; body: string }> = [];
    const tripwire = createTripwire({
      controlPlaneUrl: CP_URL,
      deviceId: "gw-test",
      secret: DEVICE_SECRET,
      registry: registryWith(token),
      log: () => undefined,
      fetchImpl: (async (url: URL | RequestInfo, init?: RequestInit) => {
        expect(String(url)).toBe(`${CP_URL}/kill`);
        killPosts.push({
          headers: { ...(init?.headers as Record<string, string>) },
          body: String(init?.body),
        });
        return new Response(JSON.stringify({ killed: true }), { status: 200 });
      }) as typeof fetch,
    });
    const t = await startProxy(createFakeControlPlane(), tripwire);

    const err = await refusalOf(
      t.client.callTool({ name: "read_file", arguments: { path: token.value } }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);

    await vi.waitFor(() => expect(killPosts).toHaveLength(1));
    const post = killPosts[0];
    expect(JSON.parse(post.body)).toEqual({
      source: "honeytoken",
      reason:
        `honeytoken ${token.canaryId} tripped: decoy value about to be forwarded in tool-call ` +
        `arguments (tool "read_file", agent "test-agent")`,
    });
    expect(
      verifyDeviceSignature(
        {
          deviceId: post.headers["x-device-id"],
          timestamp: Number(post.headers["x-device-timestamp"]),
          nonce: post.headers["x-device-nonce"],
          signature: post.headers["x-device-signature"],
        },
        post.body,
        DEVICE_SECRET,
        { now: () => Number(post.headers["x-device-timestamp"]), seenNonces: new Map() },
      ),
    ).toBe(true);

    tripwire.stop();
    await t.close();
  });

  it("without the option, the gateway does not scan (tripwires are wired in by the CLI)", async () => {
    const t = await startProxy();
    const token = generateHoneytoken({ kind: "generic" });
    const result = await t.client.callTool({ name: "read_file", arguments: { path: token.value } });
    expect(text(result)).toBe("upstream ran read_file");
    await t.close();
  });
});

describe("cumulative limits", () => {
  const recordingLimits = (rules: LimitRule[]) => {
    const kills: LimitTrip[] = [];
    const alerts: LimitTrip[] = [];
    return {
      kills,
      alerts,
      limits: {
        tracker: new LimitTracker(rules),
        reportKill: (trip: LimitTrip) => kills.push(trip),
        reportAlert: (trip: LimitTrip) => alerts.push(trip),
      },
    };
  };

  it("a kill-action call budget refuses the crossing call, reports the scoped kill, and latches", async () => {
    const r = recordingLimits([
      { id: "read-budget", tool: "read_*", metric: "calls", max: 2, action: "kill" },
    ]);
    const t = await startProxy(createFakeControlPlane(), undefined, r.limits);

    await t.client.callTool({ name: "read_file", arguments: { path: "/a" } });
    await t.client.callTool({ name: "read_file", arguments: { path: "/b" } });
    const err = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/c" } }));
    expect(err.code).toBe(OwnerSwitchErrorCode.LimitTripped);
    expect(err.message).toContain("read-budget");
    expect(t.upstream.calls).toHaveLength(2); // the crossing call never forwarded
    expect(r.kills).toHaveLength(1);
    expect(r.kills[0].rule.id).toBe("read-budget");

    // latched: EVERY later call is refused while the scoped kill propagates —
    // even one the budget does not count
    const later = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/d" } }));
    expect(later.code).toBe(OwnerSwitchErrorCode.LimitTripped);
    expect(later.message).toContain("in flight");
    expect(t.upstream.calls).toHaveLength(2);
    await t.close();
  });

  it("an alert-action limit flags and the calls keep running", async () => {
    const r = recordingLimits([
      { id: "read-watch", tool: "read_*", metric: "calls", max: 0, action: "alert" },
    ]);
    const t = await startProxy(createFakeControlPlane(), undefined, r.limits);

    const result = await t.client.callTool({ name: "read_file", arguments: { path: "/a" } });
    expect(text(result)).toContain("upstream ran read_file");
    await t.client.callTool({ name: "read_file", arguments: { path: "/b" } });
    expect(r.alerts).toHaveLength(1); // one crossing, one alert — no flood
    expect(r.kills).toHaveLength(0);
    expect(t.upstream.calls).toHaveLength(2);
    await t.close();
  });

  it("an error budget counts failed executions; the failing result still reaches the agent", async () => {
    const r = recordingLimits([
      { id: "error-budget", tool: "read_*", metric: "errors", max: 1, action: "kill" },
    ]);
    const t = await startProxy(createFakeControlPlane(), undefined, r.limits);

    const first = (await t.client.callTool({
      name: "read_file",
      arguments: { path: "/fails" },
    })) as CallToolResult;
    expect(first.isError).toBe(true); // the agent sees its failure
    expect(r.kills).toHaveLength(0); // 1 error == max: not over yet

    const second = (await t.client.callTool({
      name: "read_file",
      arguments: { path: "/fails" },
    })) as CallToolResult;
    expect(second.isError).toBe(true); // the crossing failure STILL returns
    expect(r.kills).toHaveLength(1); // ...and the scoped kill fired

    // the latch refuses the next call before it reaches upstream
    const err = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/ok" } }));
    expect(err.code).toBe(OwnerSwitchErrorCode.LimitTripped);
    expect(t.upstream.calls).toHaveLength(2);
    await t.close();
  });

  it("the full trip lifecycle: refused in flight → scope-killed → owner restore re-arms the budget", async () => {
    const r = recordingLimits([
      { id: "hard", tool: "read_*", metric: "calls", max: 1, action: "kill" },
    ]);
    const cp = createFakeControlPlane();
    const t = await startProxy(cp, undefined, r.limits);

    await t.client.callTool({ name: "read_file", arguments: { path: "/a" } });
    const crossing = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/b" } }));
    expect(crossing.code).toBe(OwnerSwitchErrorCode.LimitTripped);
    expect(r.kills).toHaveLength(1);

    // the kill has NOT landed yet: refusals say so, and an empty killedAgents
    // list must not release anything (fail closed)
    const inFlight = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/c" } }));
    expect(inFlight.message).toContain("in flight");

    // the control plane applies the scoped kill (epoch bumps, agent listed):
    // the refusal becomes the authoritative scoped lockdown
    cp.state.epoch += 1;
    cp.state.killedAgents = ["test-agent"];
    const killed = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/d" } }));
    expect(killed.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(killed.message).toContain("scope-killed");

    // the owner's 2GO restore: the agent leaves the list — the latch
    // releases WITHOUT a gateway restart and the budgets re-arm fresh
    cp.state.killedAgents = [];
    const revived = await t.client.callTool({ name: "read_file", arguments: { path: "/e" } });
    expect(text(revived)).toContain("upstream ran read_file");

    // re-armed: the budget counts from zero again and can trip again
    const retrip = await refusalOf(t.client.callTool({ name: "read_file", arguments: { path: "/f" } }));
    expect(retrip.code).toBe(OwnerSwitchErrorCode.LimitTripped);
    expect(r.kills).toHaveLength(2);
    await t.close();
  });

  it("calls that never act never spend a budget: denied and approval-gated calls do not count", async () => {
    const r = recordingLimits([
      { id: "any-call", tool: "*", metric: "calls", max: 0, action: "kill" },
    ]);
    const t = await startProxy(createFakeControlPlane(), undefined, r.limits);

    const denied = await refusalOf(t.client.callTool({ name: "delete_file", arguments: { path: "/x" } }));
    expect(denied.code).toBe(OwnerSwitchErrorCode.PolicyDenied); // not LimitTripped
    const gated = await refusalOf(t.client.callTool({ name: "mystery_tool", arguments: {} }));
    expect(gated.code).toBe(OwnerSwitchErrorCode.ApprovalRequired);
    expect(r.kills).toHaveLength(0);
    expect(r.alerts).toHaveLength(0);
    await t.close();
  });
});
