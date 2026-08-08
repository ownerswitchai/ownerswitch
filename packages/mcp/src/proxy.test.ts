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
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import { createTripwire, generateHoneytoken, scanForHoneytokens } from "@ownerswitchai/honeytoken";
import type { Policy } from "@ownerswitchai/shared";
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
      return json(state.killed ? { killed: true, reason: state.reason } : { killed: false });
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
  /** Guard around the REAL scanner, with report captured for assertions. */
  function createGuardSpy() {
    const reports: Array<{ canaryIds: string[]; tool: string; agentId: string }> = [];
    const guard: ProxyOptions["honeytokens"] = {
      scan: (text) => scanForHoneytokens(text, DEVICE_SECRET),
      report: (trip) => reports.push(trip),
    };
    return { reports, guard };
  }

  it("a decoy value in tool arguments trips: refused, reported, upstream never touched", async () => {
    const spy = createGuardSpy();
    const t = await startProxy(createFakeControlPlane(), spy.guard);
    const token = generateHoneytoken({ kind: "stripe", secret: DEVICE_SECRET });

    const err = await refusalOf(
      t.client.callTool({
        name: "read_file", // policy would ALLOW this tool — the value is what trips
        arguments: { path: "/tmp/x", note: `use ${token.value} for the payout` },
      }),
    );

    expect(err.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);
    expect(err.message).toContain("decoy credential");
    expect(err.message).toContain(token.canaryId);
    expect(err.data).toMatchObject({
      decision: "lockdown",
      tool: "read_file",
      reason: `honeytoken ${token.canaryId} in tool-call arguments`,
    });
    expect(t.upstream.calls).toEqual([]);
    expect(spy.reports).toEqual([
      { canaryIds: [token.canaryId], tool: "read_file", agentId: "test-agent" },
    ]);
    await t.close();
  });

  it("kills first and asks nothing: trips before policy, even with the control plane down", async () => {
    const spy = createGuardSpy();
    const controlPlane = createFakeControlPlane();
    controlPlane.state.down = true; // a policy/kill-state path would say "lockdown, unreachable"
    const t = await startProxy(controlPlane, spy.guard);
    const token = generateHoneytoken({ kind: "aws", secret: DEVICE_SECRET });

    // delete_* is a policy DENY — but the honeytoken verdict must come first
    const err = await refusalOf(
      t.client.callTool({ name: "delete_file", arguments: { path: token.value } }),
    );

    expect(err.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);
    expect(spy.reports).toHaveLength(1);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("clean calls pass through untouched with the tripwire armed", async () => {
    const spy = createGuardSpy();
    const t = await startProxy(createFakeControlPlane(), spy.guard);

    const result = await t.client.callTool({
      name: "read_file",
      // real-shaped foreign credential: NOT ours, must not trip
      arguments: { path: "/tmp/a.txt", key: "AKIAIOSFODNN7EXAMPLE" },
    });

    expect(text(result)).toBe("upstream ran read_file");
    expect(spy.reports).toEqual([]);
    expect(t.upstream.calls).toHaveLength(1);
    await t.close();
  });

  it("the real createTripwire wiring POSTs a signed kill when a call trips", async () => {
    const killPosts: Array<{ headers: Record<string, string>; body: string }> = [];
    const tripwire = createTripwire({
      controlPlaneUrl: CP_URL,
      deviceId: "gw-test",
      secret: DEVICE_SECRET,
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
    const token = generateHoneytoken({ kind: "openai", secret: DEVICE_SECRET });

    const err = await refusalOf(
      t.client.callTool({ name: "write_file", arguments: { path: "/x", content: token.value } }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.HoneytokenTripped);

    await vi.waitFor(() => expect(killPosts).toHaveLength(1));
    const post = killPosts[0];
    expect(JSON.parse(post.body)).toEqual({
      source: "honeytoken",
      reason:
        `honeytoken ${token.canaryId} tripped: decoy value appeared in tool-call arguments ` +
        `(tool "write_file", agent "test-agent")`,
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
    const token = generateHoneytoken({ kind: "generic", secret: DEVICE_SECRET });
    const result = await t.client.callTool({
      name: "read_file",
      arguments: { path: token.value },
    });
    expect(text(result)).toBe("upstream ran read_file");
    await t.close();
  });
});
