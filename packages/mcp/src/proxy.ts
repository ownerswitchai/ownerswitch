import { createHash, randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  ToolListChangedNotificationSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { ConnectorCallError, type ActionTicket, type ExecutionOutcome } from "@ownerswitchai/executor";
import { evaluateRemote, type ControlPlaneClient, type KillState } from "@ownerswitchai/gateway";
import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
import { assertExecutorRoutesCoherent } from "./config.js";
import {
  approvalRequired,
  controlPlaneUnavailable,
  executionFailed,
  honeytokenTripped,
  lockdown,
  ownerVetoed,
  policyDenied,
  ticketRefused,
  vetoHeld,
  vetoPending,
  vetoReleaseSpent,
} from "./errors.js";
import {
  authorizationVersionOf,
  DEFAULT_TICKET_TTL_MS,
  mintActionTicket,
  type ExecutorWiring,
} from "./executor-route.js";
import { VetoClientError, type VetoClient } from "./veto-client.js";

export const PROXY_NAME = "ownerswitch-mcp";
export const PROXY_VERSION = "0.0.1";

/**
 * The OwnerSwitch MCP gateway: an MCP server that fronts another MCP server
 * and enforces OwnerSwitch policy on every tool call.
 *
 *  - tools/list is forwarded unchanged — agents SEE everything; what they may
 *    RUN is decided per call. Hiding tools would only push failures from a
 *    clear refusal at call time to a confusing absence at plan time.
 *  - tools/call goes through evaluateRemote() first: live kill-state lookup
 *    from the control plane, then the policy. Only a yes acts; for a
 *    forwarded call the upstream result passes through untouched, and for an
 *    executor-routed one (ProxyOptions.executor) the yes mints an
 *    ActionTicket and the executor performs the action itself — the agent
 *    receives the result, never a token.
 *  - every refusal is a protocol error with a distinct code and a message
 *    written for the agent to relay — an agent behind this proxy must never
 *    be left guessing whether its action ran.
 *  - fail closed end to end: an unreachable control plane reads as killed
 *    (the gateway client's contract), and any veto-lane failure refuses the
 *    call rather than letting it through.
 */
/**
 * Honeytoken tripwire, structurally the shape @ownerswitchai/honeytoken's
 * createTripwire returns. scan() must be synchronous and cheap (it runs on
 * every forwardable call); the report methods must retry internally and never
 * throw — a refusal must not depend on the POST landing first.
 *
 * Two report methods because the tier depends on whether the call FORWARDS:
 *  - reportKill: a decoy is about to cross the boundary (allow, or veto after
 *    release). Exfiltration in progress → engage the switch.
 *  - reportAlert: a decoy appeared in a call that will NOT forward (denied,
 *    approval-gated, or held). Nothing crosses the boundary → flag only.
 */
export interface HoneytokenGuard {
  /** matches of decoy values in the given text; [] when clean */
  scan(text: string): ReadonlyArray<{ canaryId: string }>;
  /** fire-and-forget kill report for a decoy about to be forwarded */
  reportKill(trip: { canaryIds: string[]; tool: string; agentId: string }): void;
  /** fire-and-forget alert for a decoy in a call that will not be forwarded */
  reportAlert(trip: { canaryIds: string[]; tool: string; agentId: string; note?: string }): void;
}

export interface ProxyOptions {
  policy: Policy;
  /** /status lookup used by evaluateRemote — fail-closed by construction */
  controlPlane: ControlPlaneClient;
  /** /veto registration + status — the owner-review lane */
  vetoClient: VetoClient;
  /** names this gateway's agent in tool calls and audit */
  agentId?: string;
  /**
   * Decoy-credential tripwire. Policy and kill state are evaluated FIRST; the
   * kill-scan runs only immediately before a call would be forwarded, so a
   * decoy dropped into a call policy would deny cannot be used as a remote
   * kill primitive — it only raises an alert.
   */
  honeytokens?: HoneytokenGuard;
  /**
   * Executor routing (DESIGN.md §2, §4). For tools listed in its routes, a
   * yes-decision — allow, or veto after release — mints an ActionTicket and
   * hands it to the executor instead of forwarding the call upstream:
   * OwnerSwitch performs the action with its own credential and the agent
   * receives the result, never a token. The decision vocabulary does not
   * change and evaluate() stays the sole authority — this only replaces
   * forward() as the "then what" for yes on routed tools.
   */
  executor?: ExecutorWiring;
}

export interface OwnerSwitchProxy {
  server: Server;
  /** connect the upstream side first, then connect() the agent-facing side */
  connectUpstream(transport: Transport): Promise<void>;
  connect(transport: Transport): Promise<void>;
  close(): Promise<void>;
}

/**
 * Stable identity of a call, so a retry of the same tool with the same args
 * finds the veto window the first attempt opened instead of opening another.
 */
function callKey(call: ToolCall): string {
  const stable = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(stable)
      : v !== null && typeof v === "object"
        ? Object.fromEntries(
            Object.entries(v as Record<string, unknown>)
              .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
              .map(([k, val]) => [k, stable(val)]),
          )
        : v;
  return createHash("sha256")
    .update(JSON.stringify(stable({ tool: call.tool, args: call.args ?? {} })))
    .digest("hex");
}

const detail = (err: unknown): string =>
  err instanceof VetoClientError ? err.message : "control plane unreachable — fail closed";

export function createOwnerSwitchProxy(options: ProxyOptions): OwnerSwitchProxy {
  const agentId = options.agentId ?? PROXY_NAME;
  const executor = options.executor;
  // Defense in depth alongside the config loader's identical check: routes
  // that let aliases of one operation land in different policy lanes are a
  // policy bypass, and a proxy handed such routes must refuse to exist.
  if (executor !== undefined) assertExecutorRoutesCoherent(options.policy, executor.routes);
  const ticketTtlMs = executor?.ticketTtlMs ?? DEFAULT_TICKET_TTL_MS;
  const mintNow = executor?.now ?? Date.now;
  const mintNonce = executor?.mintNonce ?? randomUUID;
  // pinned once: every ticket names the authorization semantics — policy AND
  // route mapping — in force when this gateway started judging calls with it
  const policyVersion = authorizationVersionOf(options.policy, executor?.routes ?? {});
  const upstream = new Client({ name: `${PROXY_NAME} (upstream side)`, version: PROXY_VERSION });
  const server = new Server(
    { name: PROXY_NAME, version: PROXY_VERSION },
    { capabilities: { tools: { listChanged: true } } },
  );

  /**
   * Veto windows this gateway has registered, by call identity. The value is
   * the registration's id promise so two concurrent identical calls share one
   * window instead of racing to open two.
   */
  const windows = new Map<string, Promise<string>>();

  server.setRequestHandler(ListToolsRequestSchema, async (req) => upstream.listTools(req.params));

  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    const call: ToolCall = { agentId, tool: req.params.name, args: req.params.arguments };

    // Policy and kill state are evaluated FIRST — deliberately BEFORE any
    // honeytoken scan. Scanning before policy would make a decoy value a
    // remote kill primitive: an attacker who gets the value into ANY attempted
    // call, even one policy denies, could fire a global kill. Here the
    // kill-scan runs only where the call would actually be forwarded (see
    // forwardOrKill); a decoy in a non-forwarded call raises an alert instead.
    //
    // evaluateRemote fetches live kill state per call and never throws; the
    // wrapper records the state it saw so a lockdown (kill engaged, or the
    // client's fail-closed "unreachable reads as killed") is reported as
    // lockdown instead of masquerading as a policy deny.
    let observedKill: KillState | undefined;
    const observing: ControlPlaneClient = {
      fetchKillState: async () => (observedKill = await options.controlPlane.fetchKillState()),
    };
    const verdict = await evaluateRemote(call, options.policy, observing);
    if (observedKill?.killed) throw lockdown(call.tool, observedKill.reason);

    switch (verdict.decision) {
      case "allow":
        return forwardOrKill(call, verdict, observedKill?.epoch);
      case "deny":
        alertIfDecoy(call, "policy denied");
        throw policyDenied(call.tool, verdict);
      case "approve":
        alertIfDecoy(call, "held for owner approval");
        throw approvalRequired(call.tool, verdict);
      case "veto":
        return vetoLane(call, verdict, observedKill?.epoch);
    }
  });

  /** Decoy values in call arguments, by canary id — [] when clean or no guard. */
  function decoyIds(call: ToolCall): string[] {
    if (options.honeytokens === undefined) return [];
    return options.honeytokens.scan(JSON.stringify(call.args ?? {})).map((m) => m.canaryId);
  }

  /**
   * The ONLY path where a yes-decision becomes an action. Scans immediately
   * before the call crosses the boundary — forwarded upstream or executed by
   * the executor alike: a decoy about to cross is exfiltration in progress —
   * report the kill and refuse. Never acts before scanning.
   *
   * `mintEpoch` is the kill epoch the control plane reported to THIS call's
   * evaluation; an executor-routed yes binds its ticket to it (DESIGN.md §3).
   */
  async function forwardOrKill(
    call: ToolCall,
    verdict: Verdict,
    mintEpoch: number | undefined,
  ): Promise<CallToolResult> {
    const canaryIds = decoyIds(call);
    if (canaryIds.length > 0) {
      options.honeytokens?.reportKill({ canaryIds, tool: call.tool, agentId });
      throw honeytokenTripped(call.tool, canaryIds);
    }
    const route = executor?.routes[call.tool];
    if (executor !== undefined && route !== undefined) {
      return runRouted(call, executor, route, verdict, mintEpoch);
    }
    // the client validated the result against CallToolResultSchema; the SDK's
    // return type is a union over every possible schema, so narrow it here
    const result = await upstream.callTool(
      { name: call.tool, arguments: call.args },
      CallToolResultSchema,
    );
    return result as CallToolResult;
  }

  /**
   * The executor lane: mint the ActionTicket and let the executor perform
   * the action with OwnerSwitch's own credential. The upstream server is
   * never involved; the agent receives the result — data, never a token.
   */
  async function runRouted(
    call: ToolCall,
    wiring: ExecutorWiring,
    route: { connector: string; operation: string },
    verdict: Verdict,
    mintEpoch: number | undefined,
  ): Promise<CallToolResult> {
    // The real control-plane client always carries an epoch on a live "not
    // killed" answer (or fails the lookup closed). No epoch means no way to
    // bind the ticket to the world that approved it — fail closed.
    if (mintEpoch === undefined) {
      throw controlPlaneUnavailable(
        call.tool,
        "live kill state carried no epoch — cannot mint an action ticket, fail closed",
      );
    }
    let ticket: ActionTicket;
    try {
      ticket = mintActionTicket(call, route, verdict, {
        policyVersion,
        killEpoch: mintEpoch,
        now: mintNow(),
        ttlMs: ticketTtlMs,
        nonce: mintNonce(),
      });
    } catch (err) {
      throw ticketRefused(
        call.tool,
        "mint-failed",
        `cannot mint an action ticket for ${route.connector}.${route.operation}: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
    let outcome: ExecutionOutcome;
    try {
      outcome = await wiring.run(ticket);
    } catch (err) {
      // The nonce burned before the backend call, so the ticket is spent —
      // but the connector may still know whether the action definitively
      // did not run (ConnectorCallError). Anything else reads as honestly
      // ambiguous: "unknown" is the fail-safe answer, never the optimistic one.
      throw executionFailed(
        call.tool,
        err instanceof Error ? err.message : String(err),
        err instanceof ConnectorCallError ? err.outcome : "unknown",
      );
    }
    if (outcome.status === "refused") {
      const { refusal } = outcome;
      // a kill seen at execution time is the same lockdown the agent would
      // have hit at decision time — same code, same account of the world
      if (refusal.code === "kill-engaged") throw lockdown(call.tool, refusal.reason);
      throw ticketRefused(call.tool, refusal.code, refusal.reason);
    }
    return {
      content: [{ type: "text", text: JSON.stringify(outcome.result) }],
    };
  }

  /** A decoy in a call that will NOT forward: flag it, never kill. */
  function alertIfDecoy(call: ToolCall, note: string): void {
    const canaryIds = decoyIds(call);
    if (canaryIds.length > 0) {
      options.honeytokens?.reportAlert({ canaryIds, tool: call.tool, agentId, note });
    }
  }

  /**
   * The owner-review lane. The call is HELD — never forwarded on the attempt
   * that opens the window — and the agent gets a distinct error for each
   * window state. Silence-plus-confirmed-delivery releases the window on the
   * control plane; a retry then (and only then) forwards the call.
   */
  async function vetoLane(
    call: ToolCall,
    verdict: Verdict,
    mintEpoch: number | undefined,
  ): Promise<CallToolResult> {
    const key = callKey(call);
    for (;;) {
      const tracked = windows.get(key);
      if (tracked === undefined) {
        const registration = options.vetoClient.register(call).then((r) => r.id);
        windows.set(key, registration);
        const id = await settle(key, registration, call);
        // The call is HELD, not forwarded — a decoy in it flags, never kills.
        // Only on first open, so a held call alerts once, not on every poll.
        alertIfDecoy(call, "held for owner review");
        throw vetoPending(call.tool, verdict, id, true);
      }
      const id = await settle(key, tracked, call);

      let status;
      try {
        status = await options.vetoClient.status(id);
      } catch (err) {
        throw controlPlaneUnavailable(call.tool, detail(err));
      }
      switch (status) {
        case "missing":
          // control plane restarted and forgot the window — re-register
          windows.delete(key);
          continue;
        case "pending":
        case "extended":
          throw vetoPending(call.tool, verdict, id, false, status);
        case "vetoed":
          // stays refused for this gateway's lifetime: the owner said no
          throw ownerVetoed(call.tool, id);
        case "held":
          // fail closed on unconfirmed delivery: now an approval, still held
          throw vetoHeld(call.tool, id);
        case "spent":
          // The window released, but the control plane's server-side record
          // says a kill happened AFTER the window was opened — approvals do
          // not survive a kill, even one since restored. The release
          // authorizes nothing; drop the window so the next attempt opens a
          // fresh owner review.
          windows.delete(key);
          throw vetoReleaseSpent(call.tool, id);
        case "released":
          // Silence let it run; a released window authorizes exactly one run.
          // Scan here, right before acting — a decoy released to cross the
          // boundary kills, exactly as an allowed call would. "released" (as
          // opposed to "spent" above) means the control plane checked the
          // window's registration-time kill epoch against the current one:
          // no kill has happened since the owner was shown this call, so the
          // epoch this attempt's evaluation observed is the same world the
          // window was approved in, and the ticket may bind to it.
          windows.delete(key);
          return forwardOrKill(call, verdict, mintEpoch);
      }
    }
  }

  /** Resolve a registration, dropping it on failure so a retry re-registers. */
  async function settle(key: string, id: Promise<string>, call: ToolCall): Promise<string> {
    try {
      return await id;
    } catch (err) {
      windows.delete(key);
      throw controlPlaneUnavailable(call.tool, detail(err));
    }
  }

  // Tool-list changes flow through; everything else about the list is
  // upstream's business.
  upstream.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
    try {
      await server.sendToolListChanged();
    } catch {
      // agent side not connected yet — it will list fresh when it does
    }
  });

  return {
    server,
    connectUpstream: (transport) => upstream.connect(transport),
    connect: (transport) => server.connect(transport),
    close: async () => {
      await Promise.allSettled([server.close(), upstream.close()]);
    },
  };
}
