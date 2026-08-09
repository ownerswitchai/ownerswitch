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
import type { Decision, Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { assertExecutorRoutesCoherent, ConfigError } from "./config.js";
import { OwnerSwitchErrorCode } from "./errors.js";
import {
  authorizationVersionOf,
  deriveResourceId,
  mintActionTicket,
} from "./executor-route.js";
import { createOwnerSwitchProxy, type ProxyOptions } from "./proxy.js";
import { createVetoClient } from "./veto-client.js";

/**
 * End-to-end proof of DESIGN.md's central claim, with only the outermost
 * I/O faked: real proxy, real veto client, real gateway control-plane
 * client, real Executor, real GitHubMergePrExecutor — and a fake /status
 * wire, a fake upstream MCP server, and a fake GitHub HTTP client. The
 * agent asks, OwnerSwitch performs, the agent never sees a credential.
 *
 * Stated precisely (DESIGN.md §3): a ticket is refused if the final
 * pre-dispatch live-state check observes a kill or an epoch change. A kill
 * landing after that check may race with dispatch; once dispatched it
 * cannot be recalled. Every "kill wins" test here exercises a kill the
 * pre-dispatch check does observe.
 */

const CP_URL = "http://control-plane.test";
const DEVICE_SECRET = "gateway-test-secret";

/** github.merge_pr in the requested lane — veto by default, as the design describes. */
const policyWithMergeLane = (lane: Decision): Policy => ({
  rules: [
    { id: "reads", tool: "read_*", decision: "allow", description: "reads are safe" },
    { id: "merge", tool: "github.merge_pr", decision: lane, description: "merges are guarded" },
  ],
  defaultDecision: "approve",
});

/** The one route this gateway declares. Alias sets are tested separately — and refused. */
const ROUTES = {
  "github.merge_pr": { connector: "github", operation: "merge_pull_request" },
};

const MERGE_ARGS = { owner: "ownerswitchai", repo: "ownerswitch", pullNumber: 7 };
const MERGE = { name: "github.merge_pr", arguments: MERGE_ARGS };
const RESOURCE_ID = "github:pr:ownerswitchai/ownerswitch#7";

/**
 * OwnerSwitch's OWN credential. It is injected through the same config path
 * a real connector uses — the GitHubMergePrExecutor's credential — so the
 * fake backend genuinely HOLDS it, and the no-leak assertions below are
 * about a secret that actually exists on the executor's side.
 */
const OWNERSWITCH_TOKEN = "ghp_ownerswitch_own_credential_0123456789";

/** The connector's HTTP seam: records merges; can be told to fail like GitHub would. */
function createFakeGitHub() {
  const merges: MergePrArgs[] = [];
  let failure: Error | undefined;
  const client: GitHubMergeClient = {
    mergePullRequest: async (args) => {
      if (failure !== undefined) throw failure;
      merges.push(args);
      return { merged: true, sha: "abc123def456", message: "Pull Request successfully merged" };
    },
  };
  return { merges, client, failWith: (err: Error) => (failure = err) };
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
 * In-memory control plane serving /status and the veto endpoints, with the
 * real server's epoch rules mimicked:
 *  - a registered window records the kill epoch in force at registration;
 *  - a would-be "released" answer whose recorded epoch is no longer current
 *    is served as "spent" (control-plane/src/server.ts getVeto).
 * `onStatus` fires with the 1-based /status fetch count BEFORE the response
 * is built — a test can engage the kill (or throw, as a network failure)
 * between the decision's kill-state fetch and the executor's re-checks,
 * which is exactly the race the ticket exists to lose safely.
 */
function createFakeControlPlane() {
  const state = {
    killed: false as boolean,
    reason: undefined as string | undefined,
    epoch: 0,
    vetoStatus: "pending" as string,
    /** when set, GET /veto/:id returns this raw body instead of JSON */
    vetoRawBody: undefined as string | undefined,
  };
  let statusFetches = 0;
  const hooks = { onStatus: undefined as ((n: number) => void) | undefined };
  const registrations: Array<{ body: unknown; killEpoch: number; lost?: boolean }> = [];

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
      registrations.push({ body: JSON.parse(String(init?.body)), killEpoch: state.epoch });
      return json({ id: `veto_${registrations.length}`, status: "pending" }, 201);
    }
    const match = /^\/veto\/veto_(\d+)$/.exec(url.pathname);
    if (method === "GET" && match) {
      const registration = registrations[Number(match[1]) - 1];
      // a restart loses window records: the id is simply unknown afterwards
      if (registration === undefined || registration.lost === true) {
        return json({ error: "no such window" }, 404);
      }
      if (state.vetoRawBody !== undefined) return new Response(state.vetoRawBody, { status: 200 });
      let status = state.vetoStatus;
      if (status === "released" && registration.killEpoch !== state.epoch) status = "spent";
      return json({ status });
    }
    return json({ error: "not found" }, 404);
  };

  return {
    state,
    hooks,
    registrations,
    fetchImpl,
    statusFetchCount: () => statusFetches,
    /** simulate a control-plane restart: every live window record is forgotten */
    restart: () => {
      for (const registration of registrations) registration.lost = true;
    },
  };
}

/** The full wired stack; only /status, the upstream, and GitHub HTTP are fake. */
async function startRoutedProxy(opts?: {
  lane?: Decision;
  backend?: ExecutorBackend;
  ticketTtlMs?: number;
  /** the executor's clock — skew it past expiresAt to age a ticket */
  executorNow?: () => number;
}) {
  const controlPlane = createFakeControlPlane();
  const github = createFakeGitHub();
  const upstream = createFakeUpstream();

  const executorRunner = new Executor(
    opts?.backend ?? new GitHubMergePrExecutor(github.client, { token: OWNERSWITCH_TOKEN }),
    {
      fetchLiveKillState: liveKillStateFromControlPlane(
        createControlPlaneClient({
          baseUrl: CP_URL,
          timeoutMs: 250,
          fetchImpl: controlPlane.fetchImpl,
        }),
      ),
      ...(opts?.executorNow !== undefined ? { now: opts.executorNow } : {}),
    },
  );

  const proxy = createOwnerSwitchProxy({
    policy: policyWithMergeLane(opts?.lane ?? "veto"),
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

describe("the central claim: a kill the pre-dispatch check observes refuses the ticket, backend never called", () => {
  it("an approval is minted, a kill lands before the pre-dispatch check, the ticket is refused", async () => {
    const t = await startRoutedProxy();

    // the owner-review flow: held, then released by silence — an approval
    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoStatus = "released";

    // The retry re-evaluates against live kill state (fetch #2, alive) and
    // mints the ticket — then the kill lands BEFORE the executor's live
    // re-check (fetch #3), so that check observes it and refuses.
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

    // Between mint (epoch 0) and the re-check: a kill AND a completed
    // restore — the world looks healthy, but it is not the world that
    // approved. The fake CP would also report the window itself spent from
    // here on; this test flips the epoch only for the EXECUTOR's fetch
    // (n === 3, after the veto poll), so it is the ticket's own epoch check
    // that must catch it.
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

  it("a veto RELEASE does not survive a kill: released, killed, restored, retried → spent, refused", async () => {
    const t = await startRoutedProxy();

    // window opens under epoch 0
    await refusalOf(t.client.callTool(MERGE));
    expect(t.controlPlane.registrations[0]?.killEpoch).toBe(0);

    // the owner stays silent and the window releases… then a kill lands and
    // is fully restored BEFORE the retry. killed is false again — but the
    // window's server-side record binds it to epoch 0, and the epoch is 1.
    t.controlPlane.state.vetoStatus = "released";
    t.controlPlane.state.epoch += 1;

    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.TicketRefused);
    expect(err.data).toMatchObject({
      decision: "refused",
      refusalCode: "release-spent",
      vetoStatus: "spent",
    });
    expect(err.message).toContain("did NOT run");
    expect(t.github.merges).toEqual([]); // the backend was never called
    expect(t.upstream.calls).toEqual([]);

    // "require a fresh window": the spent window is dropped, the next call
    // opens a NEW window under the current epoch instead of reusing the release
    t.controlPlane.state.vetoStatus = "pending";
    const again = await refusalOf(t.client.callTool(MERGE));
    expect(again.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.controlPlane.registrations).toHaveLength(2);
    expect(t.controlPlane.registrations[1]?.killEpoch).toBe(1);
    expect(t.github.merges).toEqual([]);
    await t.close();
  });

  it("a control-plane restart that loses the window refuses — it can never become a fresh release", async () => {
    const t = await startRoutedProxy();

    // window opens, releases… and then the control plane restarts and
    // forgets it. Whatever the window's state WAS, the record is gone — the
    // only safe meaning of a missing window is "start owner review over".
    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoStatus = "released";
    t.controlPlane.restart();

    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.VetoPending); // a fresh PENDING window — never a release
    expect(t.controlPlane.registrations).toHaveLength(2);
    expect(t.github.merges).toEqual([]); // nothing executed
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("an unknown veto status refuses, fail closed — it does not read as a release", async () => {
    const t = await startRoutedProxy();
    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoStatus = "sideways"; // not in the protocol
    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("an unparseable veto-status body refuses, fail closed — garbage is not a release", async () => {
    const t = await startRoutedProxy();
    await refusalOf(t.client.callTool(MERGE));
    t.controlPlane.state.vetoRawBody = "<html>proxy error</html>";
    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });

  it("same race on the allow lane: evaluated alive, killed before the re-check", async () => {
    const t = await startRoutedProxy({ lane: "allow" });
    // fetch #1 is the decision (alive), fetch #2 is the executor's re-check
    t.controlPlane.hooks.onStatus = (n) => {
      if (n === 2) {
        t.controlPlane.state.killed = true;
        t.controlPlane.state.epoch += 1;
      }
    };
    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    await t.close();
  });

  it("a kill the first re-check misses is still caught by the second, pre-dispatch check", async () => {
    const t = await startRoutedProxy({ lane: "allow" });
    // fetch #1 decision, #2 first re-check (alive), #3 the pre-dispatch
    // check — the kill lands there and that check observes it. A kill
    // landing after THIS check resolves, or while the connector call is on
    // the wire, races with dispatch instead of being caught (DESIGN.md §3).
    t.controlPlane.hooks.onStatus = (n) => {
      if (n === 3) {
        t.controlPlane.state.killed = true;
        t.controlPlane.state.epoch += 1;
      }
    };
    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.controlPlane.statusFetchCount()).toBe(3);
    expect(t.github.merges).toEqual([]); // never dispatched
    await t.close();
  });
});

describe("the other refusals at execution time", () => {
  it("an expired ticket is refused — a yes is not a standing grant", async () => {
    // the executor's clock sits past the ticket's one-minute TTL, as if the
    // ticket had been parked between mint and run
    const t = await startRoutedProxy({
      lane: "allow",
      ticketTtlMs: 60_000,
      executorNow: () => Date.now() + 120_000,
    });
    const err = await refusalOf(t.client.callTool(MERGE));
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
    const verdict: Verdict = { decision: "veto", ruleId: "merge", reason: "merges are guarded" };
    const ticket = mintActionTicket(call, ROUTES["github.merge_pr"], verdict, {
      policyVersion: authorizationVersionOf(policyWithMergeLane("veto"), ROUTES),
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
    const t = await startRoutedProxy({ lane: "allow" });
    // the decision's fetch (#1) succeeds; the control plane dies before the
    // executor's re-check (#2) — no live answer must never read as "go"
    t.controlPlane.hooks.onStatus = (n) => {
      if (n >= 2) throw new Error("ECONNREFUSED");
    };
    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.Lockdown);
    expect(t.github.merges).toEqual([]);
    expect(t.upstream.calls).toEqual([]);
    await t.close();
  });
});

describe("the happy path — and the credential that must never leak", () => {
  /** Every console channel, watched: "no log" is asserted, not assumed. */
  let logSpies: MockInstance[];
  beforeEach(() => {
    logSpies = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "error").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {}),
      vi.spyOn(console, "info").mockImplementation(() => {}),
      vi.spyOn(console, "debug").mockImplementation(() => {}),
    ];
  });
  afterEach(() => {
    for (const spy of logSpies) spy.mockRestore();
  });

  const allLoggedText = () =>
    logSpies
      .flatMap((spy) => spy.mock.calls.flat())
      .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
      .join("\n");

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
    // the backend HOLDS the credential (injected through the connector's
    // config path); it must appear in no result and no log
    expect(JSON.stringify(result)).not.toContain(OWNERSWITCH_TOKEN);
    expect(allLoggedText()).not.toContain(OWNERSWITCH_TOKEN);

    // a released window authorized exactly one run: the same call again is
    // held again, in a fresh window — not executed
    t.controlPlane.state.vetoStatus = "pending";
    const again = await refusalOf(t.client.callTool(MERGE));
    expect(again.code).toBe(OwnerSwitchErrorCode.VetoPending);
    expect(t.controlPlane.registrations).toHaveLength(2);
    expect(t.github.merges).toHaveLength(1);
    await t.close();
  });

  it("an upstream error that echoes the token back reaches the agent scrubbed", async () => {
    const t = await startRoutedProxy({ lane: "allow" });
    // GitHub-style auth failure quoting the credential — the realistic leak
    // path: the backend's error rides an ExecutionFailed refusal to the agent
    t.github.failWith(
      new Error(
        `401 Unauthorized: the token ${OWNERSWITCH_TOKEN} is not authorized for ownerswitchai/ownerswitch`,
      ),
    );

    const err = await refusalOf(t.client.callTool(MERGE));
    expect(err.code).toBe(OwnerSwitchErrorCode.ExecutionFailed);
    // the echo happened and was scrubbed — [REDACTED] proves the error text
    // came through the backend, minus its secret
    expect(err.message).toContain("[REDACTED]");
    expect(err.message).not.toContain(OWNERSWITCH_TOKEN);
    expect(JSON.stringify(err.data)).not.toContain(OWNERSWITCH_TOKEN);
    expect(allLoggedText()).not.toContain(OWNERSWITCH_TOKEN);
    await t.close();
  });

  it("allow lane: an executor-routed allow runs immediately, never touching upstream", async () => {
    const t = await startRoutedProxy({ lane: "allow" });
    const result = await t.client.callTool(MERGE);
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

describe("tool-alias coherence — a forbidden configuration is refused, not run", () => {
  /** Aliases of one operation sitting in DIFFERENT policy lanes: the bypass. */
  const CONFLICTING_ROUTES = {
    "github.merge_pr": { connector: "github", operation: "merge_pull_request" },
    "github.automerge_pr": { connector: "github", operation: "merge_pull_request" },
  };
  const CONFLICTING_POLICY: Policy = {
    rules: [
      { id: "merge", tool: "github.merge_pr", decision: "veto" },
      { id: "automerge", tool: "github.automerge_pr", decision: "allow" },
    ],
    defaultDecision: "approve",
  };

  const proxyOptionsWith = (
    policy: Policy,
    routes: Record<string, { connector: string; operation: string }>,
  ): ProxyOptions => ({
    policy,
    controlPlane: createControlPlaneClient({ baseUrl: CP_URL, fetchImpl: async () => new Response("{}") }),
    vetoClient: createVetoClient({
      baseUrl: CP_URL,
      device: { id: "gw", secret: "s" },
      fetchImpl: async () => new Response("{}"),
    }),
    executor: { routes, run: async () => ({ status: "refused", refusal: { code: "kill-engaged", reason: "unused" } }) },
  });

  it("two aliases of one operation in different lanes: the proxy refuses to exist, naming both tools", () => {
    expect(() => createOwnerSwitchProxy(proxyOptionsWith(CONFLICTING_POLICY, CONFLICTING_ROUTES))).toThrowError(
      ConfigError,
    );
    try {
      createOwnerSwitchProxy(proxyOptionsWith(CONFLICTING_POLICY, CONFLICTING_ROUTES));
      throw new Error("expected the conflicting route set to be refused");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      expect(message).toContain("github.merge_pr");
      expect(message).toContain("github.automerge_pr");
      expect(message).toContain("github.merge_pull_request");
    }
  });

  it("the check is about verdicts, not aliasing: aliases in the SAME lane stay allowed", () => {
    // one glob rule covers both aliases → provably identical verdicts
    const coherentPolicy: Policy = {
      rules: [{ id: "merges", tool: "github.*merge_pr", decision: "veto" }],
      defaultDecision: "approve",
    };
    expect(() => assertExecutorRoutesCoherent(coherentPolicy, CONFLICTING_ROUTES)).not.toThrow();
    const proxy = createOwnerSwitchProxy(proxyOptionsWith(coherentPolicy, CONFLICTING_ROUTES));
    expect(proxy).toBeDefined();
  });

  it("aliases decided by different rules are refused even when today's decisions coincide", () => {
    // both allow TODAY — but separate rules can drift apart in one edit, and
    // an argsPattern on one of them already splits verdicts per call. The
    // conservative rule is: same operation ⇒ same candidate rule list.
    const subtly: Policy = {
      rules: [
        { id: "m1", tool: "github.merge_pr", decision: "allow" },
        { id: "m2", tool: "github.automerge_pr", decision: "allow", argsPattern: "ownerswitch" },
      ],
      defaultDecision: "approve",
    };
    expect(() => assertExecutorRoutesCoherent(subtly, CONFLICTING_ROUTES)).toThrowError(ConfigError);
  });
});

describe("minting", () => {
  const POLICY = policyWithMergeLane("veto");
  const VERDICT: Verdict = { decision: "veto", ruleId: "merge", reason: "merges are guarded" };

  it("authorizationVersionOf hashes the WHOLE authorization semantics: policy AND routes", () => {
    const reordered: Policy = JSON.parse(JSON.stringify(POLICY));
    expect(authorizationVersionOf(reordered, ROUTES)).toBe(authorizationVersionOf(POLICY, ROUTES));
    expect(authorizationVersionOf(POLICY, ROUTES)).toMatch(/^sha256:[0-9a-f]{64}$/);

    // a policy edit changes it…
    const editedPolicy: Policy = { ...POLICY, defaultDecision: "deny" };
    expect(authorizationVersionOf(editedPolicy, ROUTES)).not.toBe(
      authorizationVersionOf(POLICY, ROUTES),
    );
    // …and so does a re-pointed route, with the policy untouched: the same
    // yes means something different when the route underneath it moved
    const repointed = {
      "github.merge_pr": { connector: "github", operation: "close_pull_request" },
    };
    expect(authorizationVersionOf(POLICY, repointed)).not.toBe(
      authorizationVersionOf(POLICY, ROUTES),
    );
  });

  it("derives the github PR resource id, and a stable args-keyed id for unknown operations", () => {
    const canonical = '{"owner":"ownerswitchai","pullNumber":7,"repo":"ownerswitch"}';
    expect(deriveResourceId(ROUTES["github.merge_pr"], canonical)).toBe(RESOURCE_ID);
    const generic = deriveResourceId({ connector: "stripe", operation: "payout" }, '{"a":1}');
    expect(generic).toMatch(/^stripe:payout:args:[0-9a-f]{16}$/);
    expect(deriveResourceId({ connector: "stripe", operation: "payout" }, '{"a":1}')).toBe(generic);
  });

  it("the ticket carries the audit trail: source tool, verdict decision, matched rule id", () => {
    const ctx = {
      policyVersion: "sha256:test",
      killEpoch: 0,
      now: 1_000,
      ttlMs: 60_000,
      nonce: "n",
    };
    const ticket = mintActionTicket(
      { agentId: "a", tool: "github.merge_pr", args: MERGE_ARGS },
      ROUTES["github.merge_pr"],
      VERDICT,
      ctx,
    );
    expect(ticket).toMatchObject({
      sourceTool: "github.merge_pr",
      decision: "veto",
      ruleId: "merge",
      connector: "github",
      operation: "merge_pull_request",
      killEpoch: 0,
      expiresAt: 61_000,
      singleUse: true,
    });
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
      VERDICT,
      ctx,
    );
    const b = mintActionTicket(
      { agentId: "a", tool: "github.merge_pr", args: { pullNumber: 1, owner: "o", repo: "r" } },
      ROUTES["github.merge_pr"],
      VERDICT,
      ctx,
    );
    expect(a.canonicalArgs).toBe(b.canonicalArgs);
  });
});
