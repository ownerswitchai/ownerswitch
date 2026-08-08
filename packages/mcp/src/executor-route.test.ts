import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import {
  Executor,
  GitHubMergePrExecutor,
  liveKillStateFromControlPlane,
  type ActionTicket,
  type ExecutorBackend,
  type GitHubMergeClient,
  type MergePrArgs,
} from "@ownerswitchai/executor";
import { createControlPlaneClient } from "@ownerswitchai/gateway";
import type { Policy, ToolCall } from "@ownerswitchai/shared";
import { describe, expect, it } from "vitest";
import { OwnerSwitchErrorCode } from "./errors.js";
import {
  deriveResourceId,
  mintActionTicket,
  policyVersionOf,
} from "./executor-route.js";
import { createOwnerSwitchProxy } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";

/**
 * End-to-end proof of DESIGN.md's central claim, with only the outermost
 * I/O faked: real proxy, real veto client, real gateway control-plane
 * client, real Executor, real GitHubMergePrExecutor — and a fake /status
 * wire, a fake upstream MCP server, and a fake GitHub HTTP client. The
 * agent asks, OwnerSwitch performs, the agent never sees a credential.
 */

const CP_URL = "http://control-plane.test";
const DEVICE_SECRET = "gateway-test-secret";

/** github.merge_pr sits in the veto lane, exactly as the design describes. */
const POLICY: Policy = {
  rules: [
    { id: "reads", tool: "read_*", decision: "allow", description: "reads are safe" },
    { id: "merge", tool: "github.merge_pr", decision: "veto", description: "owner can veto merges" },
    { id: "automerge", tool: "github.automerge_pr", decision: "allow", description: "allow-lane merge" },
  ],
  defaultDecision: "approve",
};

/**
 * Two MCP surfaces fronting the same executor operation — the ticket stores
 * (connector, operation), not the MCP name (DESIGN.md §1, "Naming").
 */
const ROUTES = {
  "github.merge_pr": { connector: "github", operation: "merge_pull_request" },
  "github.automerge_pr": { connector: "github", operation: "merge_pull_request" },
};

const MERGE_ARGS = { owner: "ownerswitchai", repo: "ownerswitch", pullNumber: 7 };
const MERGE = { name: "github.merge_pr", arguments: MERGE_ARGS };
const RESOURCE_ID = "github:pr:ownerswitchai/ownerswitch#7";

/**
 * This credential lives on OwnerSwitch's side of the boundary and must never
 * appear in anything the agent receives.
 */
const OWNERSWITCH_CREDENTIAL = "ghp_ownerswitch_own_credential_0123456789";

/** The connector's HTTP seam: records merges, returns data — never a token. */
function createFakeGitHub() {
  const merges: MergePrArgs[] = [];
  const client: GitHubMergeClient = {
    mergePullRequest: async (args) => {
      merges.push(args);
      return { merged: true, sha: "abc123def456", message: "Pull Request successfully merged" };
    },
  };
  return { merges, client };
}

function createFakeUpstream() {
  const calls: Array<{ name: string; args: unknown }> = [];
  const server = new Server(
    { name: "fake-upstream", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    calls.push({ name: req.params.name, args: req.params.arguments });
    return { content: [{ type: "text" as const, text: `upstream ran ${req.params.name}` }] };
  });
  return { server, calls };
}

/**
 * In-memory control plane serving /status and the veto endpoints. `onStatus`
 * fires with the 1-based /status fetch count BEFORE the response is built —
 * a test can engage the kill (or throw, as a network failure) between the
 * decision's kill-state fetch and the executor's re-check, which is exactly
 * the race the ticket exists to lose safely.
 */
function createFakeControlPlane() {
  const state = {
    killed: false as boolean,
    reason: undefined as string | undefined,
    epoch: 0,
    vetoStatus: "pending" as string,
  };
  let statusFetches = 0;
  const hooks = { onStatus: undefined as ((n: number) => void) | undefined };
  const registrations: Array<{ body: unknown }> = [];

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";

    if (method === "GET" && url.pathname === "/status") {
      statusFetches += 1;
      hooks.onStatus?.(statusFetches);
      return json(
        state.killed
          ? { killed: true, reason: state.reason, epoch: state.epoch }
          : { killed: false, epoch: state.epoch },
      );
    }
    if (method === "POST" && url.pathname === "/veto") {
      registrations.push({ body: JSON.parse(String(init?.body)) });
      return json({ id: `veto_${registrations.length}`, status: "pending" }, 201);
    }
    if (method === "GET" && /^\/veto\/[^/]+$/.test(url.pathname)) {
      return json({ status: state.vetoStatus });
    }
    return json({ error: "not found" }, 404);
  };

  return {
    state,
    hooks,
    registrations,
    fetchImpl,
    statusFetchCount: () => statusFetches,
  };
}

/** The full wired stack; only /status, the upstream, and GitHub HTTP are fake. */
async function startRoutedProxy(opts?: {
  backend?: ExecutorBackend;
  ticketTtlMs?: number;
  /** the executor's clock — skew it past expiresAt to age a ticket */
  executorNow?: () => number;
}) {
  const controlPlane = createFakeControlPlane();
  const github = createFakeGitHub();
  const upstream = createFakeUpstream();

  const executorRunner = new Executor(opts?.backend ?? new GitHubMergePrExecutor(github.client), {
    fetchLiveKillState: liveKillStateFromControlPlane(
      createControlPlaneClient({
        baseUrl: CP_URL,
        timeoutMs: 250,
        fetchImpl: controlPlane.fetchImpl,
      }),
    ),
    ...(opts?.executorNow !== undefined ? { now: opts.executorNow } : {}),
  });

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
    executor: {
      routes: ROUTES,
      run: (ticket) => executorRunner.run(ticket),
      ...(opts?.ticketTtlMs !== undefined ? { ticketTtlMs: opts.ticketTtlMs } : {}),
    },
  });

  const [upstreamClientSide, upstreamServerSide] = InMemoryTransport.createLinkedPair();
  await upstream.server.connect(upstreamServerSide);
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
  return { client, upstream, controlPlane, github, close };
}

async function refusalOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(McpError);
    return err as McpError;
  }
  throw new Error("expected the call to be refused, but it succeeded");
}

const resultJson = (result: unknown): unknown => {
  const content = (result as CallToolResult).content;
  const first = content[0];
  if (first?.type !== "text") throw new Error("expected a text result");
  return JSON.parse(first.text);
};

describe("the central claim: mint → kill → refuse, backend never called", () => {
  it("an approval is minted, a kill lands before execution, the ticket is refused", async () => {
    const t = await startRoutedProxy();

    // the owner-review flow: held, then released by silence — an approval
    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoStatus = "released";

    // The retry re-evaluates against live kill state (fetch #2, alive) and
    // mints the ticket — then the kill lands BEFORE the executor's re-check
    // (fetch #3). This is the exact race a verdict alone cannot survive.
    t.controlPlane.hooks.onStatus = (n) => {
      if (n === 3) {
        t.controlPlane.state.killed = true;
        t.controlPlane.state.reason = "red button pressed";
        t.controlPlane.state.epoch += 1;
      }
    };

    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.controlPlane.statusFetchCount()).toBe(3); // the re-check is what saw the kill
    expect(t.github.merges).toEqual([]); // the backend was NEVER called
    expect(t.upstream.calls).toEqual([]); // and nothing was forwarded either
    await t.close();
  });

  it("kill-then-restore: killed is false again, but the epoch moved — the ticket is dead forever", async () => {
    const t = await startRoutedProxy();

    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoStatus = "released";

    // between mint (epoch 0) and re-check: a kill AND a completed restore —
    // the world looks healthy, but it is not the world that approved
    t.controlPlane.hooks.onStatus = (n) => {
      if (n === 3) t.controlPlane.state.epoch += 1;
    };

    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.TicketRefused);
    expect(err.data).toMatchObject({ decision: "refused", refusalCode: "epoch-mismatch" });
    expect(err.message).toContain("did NOT run");
    expect(t.github.merges).toEqual([]);
    await t.close();
  });

  it("same race on the allow lane: evaluated alive, killed before the re-check", async () => {
    const t = await startRoutedProxy();
    // fetch #1 is the decision (alive), fetch #2 is the executor's re-check
    t.controlPlane.hooks.onStatus = (n) => {
      if (n === 2) {
        t.controlPlane.state.killed = true;
        t.controlPlane.state.epoch += 1;
      }
    };
    const err = await refusalOf(
      t.client.callTool({ name: "github.automerge_pr", arguments: MERGE_ARGS }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    await t.close();
  });
});

describe("the other refusals at execution time", () => {
  it("an expired ticket is refused — a yes is not a standing grant", async () => {
    // the executor's clock sits past the ticket's one-minute TTL, as if the
    // ticket had been parked between mint and run
    const t = await startRoutedProxy({
      ticketTtlMs: 60_000,
      executorNow: () => Date.now() + 120_000,
    });
    const err = await refusalOf(
      t.client.callTool({ name: "github.automerge_pr", arguments: MERGE_ARGS }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.TicketRefused);
    expect(err.data).toMatchObject({ refusalCode: "ticket-expired" });
    expect(t.github.merges).toEqual([]);
    await t.close();
  });

  it("a replayed nonce is refused: the same ticket cannot execute twice", async () => {
    // the executor seam itself: the proxy mints a fresh nonce per yes, so a
    // replay can only be attempted with the ticket in hand — and burns
    const backendCalls: ActionTicket[] = [];
    const backend: ExecutorBackend = {
      execute: async (ticket) => {
        backendCalls.push(ticket);
        return { resourceId: ticket.resourceId, detail: { merged: true } };
      },
    };
    const executor = new Executor(backend, {
      fetchLiveKillState: async () => ({ killed: false, epoch: 0 }),
    });
    const call: ToolCall = { agentId: "test-agent", tool: "github.merge_pr", args: MERGE_ARGS };
    const ticket = mintActionTicket(call, ROUTES["github.merge_pr"], {
      policyVersion: policyVersionOf(POLICY),
      killEpoch: 0,
      now: Date.now(),
      ttlMs: 60_000,
      nonce: "nonce-1",
    });

    const first = await executor.run(ticket);
    expect(first.status).toBe("executed");
    const replay = await executor.run(ticket);
    expect(replay.status).toBe("refused");
    if (replay.status === "refused") expect(replay.refusal.code).toBe("nonce-consumed");
    expect(backendCalls).toHaveLength(1); // exactly once, ever
  });

  it("an unreachable control plane at execution time refuses — fail closed", async () => {
    const t = await startRoutedProxy();
    // the decision's fetch (#1) succeeds; the control plane dies before the
    // executor's re-check (#2) — no live answer must never read as "go"
    t.controlPlane.hooks.onStatus = (n) => {
      if (n >= 2) throw new Error("ECONNREFUSED");
    };
    const err = await refusalOf(
      t.client.callTool({ name: "github.automerge_pr", arguments: MERGE_ARGS }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });
});

describe("the happy path", () => {
  it("veto lane: held, released, executed exactly once — the agent gets the result, never a token", async () => {
    const t = await startRoutedProxy();

    // held for owner review; nothing has run
    const pending = await refusalOf(t.client.callTool(MERGE));
    expect(pending.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.github.merges).toEqual([]);

    // the owner stays silent; the window releases; the retry executes
    t.controlPlane.state.vetoStatus = "released";
    const result = await t.client.callTool(MERGE);

    // the RESULT of the action — data, never a token
    expect(resultJson(result)).toEqual({
      resourceId: RESOURCE_ID,
      detail: { merged: true, sha: "abc123def456", message: "Pull Request successfully merged" },
    });
    // the backend ran exactly once, with the arguments the owner saw
    expect(t.github.merges).toEqual([MERGE_ARGS]);
    // the upstream MCP server was never involved — there is no credential on
    // the agent's side of the boundary to leak
    expect(t.upstream.calls).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(OWNERSWITCH_CREDENTIAL);
    expect(JSON.stringify(result)).not.toMatch(/ghp_|token|secret/i);

    // a released window authorized exactly one run: the same call again is
    // held again, in a fresh window — not executed
    t.controlPlane.state.vetoStatus = "pending";
    const again = await refusalOf(t.client.callTool(MERGE));
    expect(again.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.controlPlane.registrations).toHaveLength(2);
    expect(t.github.merges).toHaveLength(1);
    await t.close();
  });

  it("allow lane: an executor-routed allow runs immediately, never touching upstream", async () => {
    const t = await startRoutedProxy();
    const result = await t.client.callTool({ name: "github.automerge_pr", arguments: MERGE_ARGS });
    expect(resultJson(result)).toMatchObject({ resourceId: RESOURCE_ID });
    expect(t.github.merges).toHaveLength(1);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("tools NOT routed keep forwarding exactly as today", async () => {
    const t = await startRoutedProxy();
    const result = await t.client.callTool({ name: "read_file", arguments: { path: "/tmp/a" } });
    expect(result).toMatchObject({
      content: [{ type: "text", text: "upstream ran read_file" }],
    });
    expect(t.upstream.calls).toEqual([{ name: "read_file", args: { path: "/tmp/a" } }]);
    expect(t.github.merges).toEqual([]);
    await t.close();
  });
});

describe("edges of the executor lane", () => {
  it("malformed arguments refuse at mint time — no ticket, no window burned, nothing runs", async () => {
    const t = await startRoutedProxy();
    const err = await refusalOf(
      t.client.callTool({
        name: "github.automerge_pr",
        arguments: { owner: "ownerswitchai", repo: "ownerswitch" }, // no pullNumber
      }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.TicketRefused);
    expect(err.data).toMatchObject({ refusalCode: "mint-failed" });
    expect(err.message).toContain("pullNumber");
    expect(t.github.merges).toEqual([]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("the stubbed GitHub backend (no HTTP client, as the CLI wires it today) fails honestly", async () => {
    const t = await startRoutedProxy({ backend: new GitHubMergePrExecutor() });
    const err = await refusalOf(
      t.client.callTool({ name: "github.automerge_pr", arguments: MERGE_ARGS }),
    );
    expect(err.code).toBe(OwnerSwitchErrorCode.ExecutionFailed);
    expect(err.message).toContain("not implemented");
    expect(err.message).toContain("MAY OR MAY NOT");
    expect(err.data).toMatchObject({ decision: "failed" });
    await t.close();
  });
});

describe("minting", () => {
  it("policyVersionOf is a content hash: key order does not matter, content does", () => {
    const reordered: Policy = JSON.parse(JSON.stringify(POLICY));
    expect(policyVersionOf(reordered)).toBe(policyVersionOf(POLICY));
    const edited: Policy = { ...POLICY, defaultDecision: "deny" };
    expect(policyVersionOf(edited)).not.toBe(policyVersionOf(POLICY));
    expect(policyVersionOf(POLICY)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("derives the github PR resource id, and a stable args-keyed id for unknown operations", () => {
    const canonical = '{"owner":"ownerswitchai","pullNumber":7,"repo":"ownerswitch"}';
    expect(deriveResourceId(ROUTES["github.merge_pr"], canonical)).toBe(RESOURCE_ID);
    const generic = deriveResourceId({ connector: "stripe", operation: "payout" }, '{"a":1}');
    expect(generic).toMatch(/^stripe:payout:args:[0-9a-f]{16}$/);
    expect(deriveResourceId({ connector: "stripe", operation: "payout" }, '{"a":1}')).toBe(generic);
  });

  it("canonicalizes args at mint: same arguments in any order, same ticket bytes", () => {
    const ctx = {
      policyVersion: "sha256:test",
      killEpoch: 0,
      now: 1_000,
      ttlMs: 60_000,
      nonce: "n",
    };
    const a = mintActionTicket(
      { agentId: "a", tool: "github.merge_pr", args: { repo: "r", owner: "o", pullNumber: 1 } },
      ROUTES["github.merge_pr"],
      ctx,
    );
    const b = mintActionTicket(
      { agentId: "a", tool: "github.merge_pr", args: { pullNumber: 1, owner: "o", repo: "r" } },
      ROUTES["github.merge_pr"],
      ctx,
    );
    expect(a.canonicalArgs).toBe(b.canonicalArgs);
    expect(a).toMatchObject({
      connector: "github",
      operation: "merge_pull_request",
      killEpoch: 0,
      expiresAt: 61_000,
      singleUse: true,
    });
  });
});
