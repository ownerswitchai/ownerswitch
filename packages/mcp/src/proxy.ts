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
import {
  ConnectorCallError,
  GITHUB_CONNECTOR,
  MERGE_PULL_REQUEST,
  type ActionTicket,
  type ExecutionOutcome,
} from "@ownerswitchai/executor";
import {
  evaluateRemote,
  limitTripReason,
  type ControlPlaneClient,
  type KillState,
  type LimitTracker,
  type LimitTrip,
} from "@ownerswitchai/gateway";
import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
import { assertExecutorRoutesCoherent } from "./config.js";
import {
  approvalRequired,
  controlPlaneUnavailable,
  executionFailed,
  honeytokenTripped,
  limitTripped,
  lockdown,
  OwnerSwitchErrorCode,
  OwnerSwitchRefusal,
  ownerVetoed,
  policyDenied,
  routedCallRefused,
  scopedLockdown,
  ticketRefused,
  vetoHeld,
  vetoPending,
  vetoReleaseSpent,
} from "./errors.js";
import {
  authorizationVersionOf,
  DEFAULT_TICKET_TTL_MS,
  MERGE_PR_AGENT_INPUT_SCHEMA,
  mintActionTicket,
  validateMergePrRequestArgs,
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
  /**
   * Cumulative limit rules — spend, error and call budgets counted across
   * calls (@ownerswitchai/gateway LimitTracker; shared limit-rule.ts is the
   * model). Counting happens only where a call is ATTEMPTED for dispatch:
   * calls/amount meter pre-dispatch (the crossing call is refused before it
   * runs), errors meter post-dispatch (the crossing execution already ran —
   * only the NEXT call is stopped). A kill-action trip reports a SCOPED
   * signed kill and latches, so every later call is refused while the kill
   * propagates; an alert-action trip only flags and the call proceeds.
   */
  limits?: LimitEnforcement;
}

export interface LimitEnforcement {
  tracker: LimitTracker;
  /**
   * Deliver the scoped-kill report for a tripped kill-action rule. AWAITED
   * by the proxy: the crossing refusal returns only after this settles, so
   * an implementation that delivers synchronously makes the kill durable on
   * the control plane — the separate-uid latch authority — before the agent
   * even hears "no". On failure the tracker stays latched (unconfirmed) and
   * the implementation keeps retrying in the background.
   *
   * Called at most ONCE per latch generation, always with the trip the
   * tracker latched (`trip.latchGeneration` is set). Co-crossing kill rules
   * are audited, not re-killed — a second kill would open a control-plane
   * epoch the latch cannot anchor to. The implementation should bind the
   * delivery confirmation it feeds back to `confirmKillDelivered` to that
   * same generation, so a late answer cannot confirm a later latch.
   */
  reportKill(trip: LimitTrip): void | Promise<void>;
  /** fire-and-forget alert report for a tripped alert-action rule — best effort */
  reportAlert(trip: LimitTrip): void;
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

  // The tool list flows through from upstream — with one deliberate
  // override: a tool routed to github/merge_pull_request advertises
  // OwnerSwitch's OWN input schema (no expectedHeadSha — the head sha is
  // pinned server-side at review time) in place of whatever the upstream
  // declares under that name, so agents cannot be steered by an upstream
  // schema into supplying arguments the proxy will refuse. A routed tool
  // the upstream does not advertise stays unadvertised (it remains
  // callable; discovery is upstream's business), and the call-time
  // refusal of agent-supplied expectedHeadSha is the enforcement either way.
  server.setRequestHandler(ListToolsRequestSchema, async (req) => {
    const result = await upstream.listTools(req.params);
    if (executor !== undefined) {
      for (const tool of result.tools) {
        const route = executor.routes[tool.name];
        if (route?.connector === GITHUB_CONNECTOR && route.operation === MERGE_PULL_REQUEST) {
          tool.inputSchema = MERGE_PR_AGENT_INPUT_SCHEMA as unknown as typeof tool.inputSchema;
          tool.description =
            `${tool.description === undefined || tool.description === "" ? "" : `${tool.description} `}` +
            `[OwnerSwitch: performed by the OwnerSwitch executor with its own credential after ` +
            `the owner's decision. The pull request head SHA is pinned by OwnerSwitch at review ` +
            `time — do not supply expectedHeadSha.]`;
        }
      }
    }
    return result;
  });

  /**
   * The review-time head pin for routed merges (DESIGN.md §6). Runs after
   * the verdict, BEFORE the owner-review lane — so the sha the owner sees
   * in the veto window, the sha in the canonical ticket args, and the sha
   * the merge sends are one and the same, and it came from GitHub, not
   * from the agent. Pinning transmits owner/repo/pullNumber to GitHub —
   * a boundary crossing — so the honeytoken kill-scan runs first, exactly
   * as it does before forward/execute.
   *
   * Fail closed: no pin function (connector unconfigured), or a pin read
   * that fails, refuses the call before any window opens or ticket burns.
   */
  async function pinIfRoutedMerge(call: ToolCall): Promise<ToolCall> {
    const route = executor?.routes[call.tool];
    if (
      executor === undefined ||
      route === undefined ||
      route.connector !== GITHUB_CONNECTOR ||
      route.operation !== MERGE_PULL_REQUEST
    ) {
      return call;
    }
    const canaryIds = decoyIds(call);
    if (canaryIds.length > 0) {
      options.honeytokens?.reportKill({ canaryIds, tool: call.tool, agentId });
      throw honeytokenTripped(call.tool, canaryIds);
    }
    let base;
    try {
      base = validateMergePrRequestArgs(call.args ?? {});
    } catch (err) {
      throw routedCallRefused(
        call.tool,
        "invalid-args",
        err instanceof Error ? err.message : String(err),
      );
    }
    if (executor.pinHeadSha === undefined) {
      throw routedCallRefused(
        call.tool,
        "connector-unconfigured",
        "OwnerSwitch cannot pin the pull request head — the GitHub connector is not configured " +
          "on this gateway (see packages/executor/DESIGN.md §6)",
      );
    }
    let target: { headSha: string; baseRef: string };
    try {
      target = await executor.pinHeadSha(base);
    } catch (err) {
      throw routedCallRefused(
        call.tool,
        "head-pin-failed",
        `cannot pin the pull request head at review time: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
    // Build the pinned call from the NORMALIZED base (owner, repo,
    // pullNumber, mergeMethod) plus the server-derived head sha AND base
    // ref — NEVER by spreading the raw request args. This is what keeps
    // approved-bytes == executed-semantics: an unknown field the agent
    // slipped in was already rejected by validateMergePrRequestArgs, and it
    // cannot reach the canonical action here because we do not copy it. The
    // base ref is pinned for the same reason as the head: GitHub allows
    // retargeting a PR after approval, so the destination the owner sees is
    // the destination that gets signed and re-checked at dispatch.
    return {
      ...call,
      args: { ...base, expectedHeadSha: target.headSha, expectedBaseRef: target.baseRef },
    };
  }

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
    // Drive the limit-trip lifecycle off the SAME live answer this decision
    // used, BEFORE any refusal below can cut the turn short: an unconfirmed
    // trip becomes confirmed when the agent shows up scope-killed, and a
    // confirmed trip releases (budgets re-armed) when the agent later
    // leaves the list — that absence is the owner's 2GO restore.
    if (observedKill !== undefined && !observedKill.killed) {
      options.limits?.tracker.observeKillState(observedKill.killedAgents, {
        // ordering + durability, both load-bearing: a pre-kill answer that
        // lands late must not read as the owner's restore, and a control
        // plane with degraded persistence proves nothing durable at all
        ...(observedKill.epoch !== undefined ? { epoch: observedKill.epoch } : {}),
        // fail-closed reading: only an explicit `true` counts as durable, so
        // a client that never populates the field cannot make a degraded
        // control plane look trustworthy
        durable: observedKill.durable === true,
      });
    }
    // A SCOPED kill of this gateway's agent is a lockdown too, not a policy
    // deny: the engine already denied the call (killedAgents outranks every
    // rule), but the agent must hear "you are stopped, stop retrying" rather
    // than "this tool is blocked" — the same honesty split as the global kill.
    if (observedKill?.killedAgents?.includes(agentId) === true) {
      throw scopedLockdown(call.tool, agentId);
    }
    // A latched kill-action limit trip is the same lockdown, locally held:
    // the signed scoped kill is propagating (or retrying) toward the control
    // plane, or the kill has landed and awaits the owner's restore. Released
    // only by the lifecycle above — never by a restart alone.
    const latched = options.limits?.tracker.killTripped;
    if (latched !== undefined) {
      throw limitTripped(
        call.tool,
        latched.ruleId,
        latched.confirmed
          ? `limit "${latched.ruleId}" tripped for agent "${agentId}" — scope-killed; ` +
              `an owner's 2GO restore re-arms it`
          : `limit "${latched.ruleId}" tripped for agent "${agentId}" — the scoped kill is in flight`,
      );
    }

    switch (verdict.decision) {
      case "allow":
        // pinned before execution: the canonical args carry the head sha
        return forwardOrKill(await pinIfRoutedMerge(call), verdict, observedKill?.epoch);
      case "deny":
        alertIfDecoy(call, "policy denied");
        throw policyDenied(call.tool, verdict);
      case "approve":
        alertIfDecoy(call, "held for owner approval");
        throw approvalRequired(call.tool, verdict);
      case "veto":
        // pinned before the owner sees it: the veto window registers the
        // pinned args, so what the owner reviews is what would merge. The
        // window's call identity includes the pinned sha — if the branch
        // moves between polls, the old window is simply left behind and a
        // FRESH owner review opens for the new head, which is the point.
        return vetoLane(await pinIfRoutedMerge(call), verdict, observedKill?.epoch);
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
    grant?: unknown,
  ): Promise<CallToolResult> {
    const canaryIds = decoyIds(call);
    if (canaryIds.length > 0) {
      options.honeytokens?.reportKill({ canaryIds, tool: call.tool, agentId });
      throw honeytokenTripped(call.tool, canaryIds);
    }
    // Limits count HERE — where a yes is DISPATCHED — so a call policy
    // refused, or a honeytoken killed, never spends a budget. Stated
    // precisely: calls/amount meter ATTEMPTED dispatches — a routed call the
    // executor still refuses downstream (no grant, ticket refused) has
    // already spent its unit, deliberately: budgets bound what the agent
    // tries to make happen, and an attempt-then-refusal loop must drain a
    // budget rather than probe it for free. A kill-action trip refuses THIS
    // call too: the crossing call is the one the budget says must not run.
    await observeCallLimits(call, mintEpoch);
    const route = executor?.routes[call.tool];
    if (executor !== undefined && route !== undefined) {
      try {
        return await runRouted(call, executor, route, verdict, mintEpoch, grant);
      } catch (err) {
        // The error budget measures the AGENT'S FAILING EXECUTIONS, not
        // OwnerSwitch's refusals: a routed call refused before dispatch
        // (no grant, ticket refused, lockdown) never ran, so it spends
        // nothing. ExecutionFailed — the connector genuinely ran and
        // failed — counts, as does any non-refusal throw.
        if (
          !(err instanceof OwnerSwitchRefusal) ||
          err.code === OwnerSwitchErrorCode.ExecutionFailed
        ) {
          await observeErrorLimits(call, mintEpoch);
        }
        throw err;
      }
    }
    // the client validated the result against CallToolResultSchema; the SDK's
    // return type is a union over every possible schema, so narrow it here
    let result: CallToolResult;
    try {
      result = (await upstream.callTool(
        { name: call.tool, arguments: call.args },
        CallToolResultSchema,
      )) as CallToolResult;
    } catch (err) {
      await observeErrorLimits(call, mintEpoch);
      throw err;
    }
    // an upstream tool reporting its own failure counts against the error
    // budget exactly like a transport failure — the agent's action failed
    if (result.isError === true) await observeErrorLimits(call, mintEpoch);
    return result;
  }

  /**
   * Feed a forwarded call to the limit tracker. Kill trips refuse the
   * crossing call — AFTER the scoped-kill report settles, so in the healthy
   * case the kill is already durable on the control plane when the refusal
   * returns. Alert trips only flag, and alert DELIVERY is best effort: a
   * broken reporter must not block a call an alert rule never blocks.
   */
  async function observeCallLimits(call: ToolCall, epoch: number | undefined): Promise<void> {
    const limits = options.limits;
    if (limits === undefined) return;
    // ADMISSION, synchronously: re-read the latch HERE, in the same block
    // as the counting, with no await in between. The handler's own check
    // happens before several awaits (the live lookup, the head pin, the
    // veto lane), so a concurrent call can pass it while an earlier call
    // is still awaiting its kill delivery — and by then the counter is
    // already over max, so no NEW trip would fire to stop it. This is the
    // one place that sees both the latch and the dispatch.
    const latched = limits.tracker.killTripped;
    if (latched !== undefined) {
      throw limitTripped(
        call.tool,
        latched.ruleId,
        `limit "${latched.ruleId}" tripped for agent "${agentId}" — this agent is stopped`,
      );
    }
    // THIS call's own pre-dispatch epoch anchors any trip it fires — never
    // a shared field a concurrent call could have moved underneath it.
    const trips = limits.tracker.observeCall(call, { ...(epoch !== undefined ? { epoch } : {}) });
    for (const trip of trips) {
      if (trip.rule.action === "kill") continue;
      try {
        limits.reportAlert(trip);
      } catch (err) {
        console.error(
          `[ownerswitch-mcp] limit alert report failed (rule "${trip.rule.id}"): ` +
            `${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    const killTrips = trips.filter((t) => t.rule.action === "kill");
    // AT MOST ONE scoped kill per observation — see LimitTrip.latchGeneration.
    // One call can cross several kill rules together (a `calls` budget and an
    // `amount` budget on the same payout); the tracker latches the first and
    // stamps only that one. Reporting the others would open control-plane
    // epochs the latch is not anchored to, and the owner's restore of the
    // anchored kill would then re-arm every budget while another kill of this
    // agent was still in flight. They are audited here and covered by the same
    // scoped kill: the agent stops either way, and one 2GO restore re-arms all
    // of them together.
    const latchedTrip = killTrips.find((t) => t.latchGeneration !== undefined);
    for (const trip of killTrips) {
      if (trip === latchedTrip) continue;
      console.error(
        `[ownerswitch-mcp] limit "${trip.rule.id}" also crossed on this call ` +
          `(${limitTripReason(trip, agentId)}) — covered by the scoped kill ` +
          `already in flight; not re-killed`,
      );
    }
    if (latchedTrip !== undefined) {
      try {
        await limits.reportKill(latchedTrip);
      } catch (err) {
        // the tracker latched at observe time; delivery keeps retrying in
        // the implementation — the refusal below stands either way
        console.error(
          `[ownerswitch-mcp] limit kill report failed (rule "${latchedTrip.rule.id}"): ` +
            `${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    // A kill-action crossing refuses this call whether or not IT was the
    // trip that latched: an unstamped crossing means a kill is already
    // latched (a concurrent call's), and the budget still says stop.
    const cited = latchedTrip ?? killTrips[0];
    if (cited !== undefined) {
      throw limitTripped(call.tool, cited.rule.id, limitTripReason(cited, agentId));
    }
  }

  /**
   * Feed a FAILED execution to the error budget. Never throws — enforced,
   * not assumed: the call already ran (and failed) and the agent must
   * receive that outcome, so a tracker or report-callback failure is logged
   * and swallowed rather than replacing the real result. A kill trip here
   * reports the scoped kill and latches, so the NEXT call is refused at the
   * top of the handler.
   */
  async function observeErrorLimits(call: ToolCall, epoch: number | undefined): Promise<void> {
    const limits = options.limits;
    if (limits === undefined) return;
    try {
      const observed = limits.tracker.observeError(call, {
        ...(epoch !== undefined ? { epoch } : {}),
      });
      for (const trip of observed) {
        if (trip.rule.action !== "kill") {
          limits.reportAlert(trip);
          continue;
        }
        // Same single-kill rule as the call path: only the trip the tracker
        // LATCHED is reported, so one observation never opens two epochs.
        if (trip.latchGeneration === undefined) {
          console.error(
            `[ownerswitch-mcp] limit "${trip.rule.id}" also crossed on this failure ` +
              `(${limitTripReason(trip, agentId)}) — covered by the scoped kill ` +
              `already in flight; not re-killed`,
          );
          continue;
        }
        await limits.reportKill(trip);
      }
    } catch (err) {
      console.error(
        `[ownerswitch-mcp] error-budget observation failed (tool "${call.tool}"): ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
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
    grant?: unknown,
  ): Promise<CallToolResult> {
    // Executing-broker deployment: a routed action MUST carry an owner-
    // approval grant. No grant means no owner-gated approval reached this
    // execution — the allow lane, or any path that did not clear a released
    // veto window — and the broker would refuse it anyway. Refuse HERE,
    // before minting or burning anything, with a message the agent can act on.
    if (wiring.requiresGrant === true && grant === undefined) {
      throw routedCallRefused(
        call.tool,
        "owner-grant-required",
        "this action is performed by the OwnerSwitch executor with its own credential and " +
          "requires an owner-gated decision (a veto or approval lane) — an 'allow' lane cannot " +
          "authorize it. Nothing ran; ask the owner to put this tool in the veto lane",
      );
    }
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
      outcome = await wiring.run(ticket, grant);
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
    // Executor-routed calls register under their canonical PURPOSE — the
    // route's (connector, operation) plus this gateway's authorization-world
    // hash. The control plane signs that purpose into any grant it mints and
    // refuses to mint for anything else, and the broker enforces it again —
    // so an owner approval can only ever be spent as the thing the window
    // said it was. Non-routed tools register without one.
    const route = executor?.routes[call.tool];
    const purpose =
      route === undefined
        ? undefined
        : { connector: route.connector, operation: route.operation, policyVersion };
    for (;;) {
      const tracked = windows.get(key);
      if (tracked === undefined) {
        const registration = options.vetoClient.register(call, purpose).then((r) => r.id);
        windows.set(key, registration);
        const id = await settle(key, registration, call);
        // The call is HELD, not forwarded — a decoy in it flags, never kills.
        // Only on first open, so a held call alerts once, not on every poll.
        alertIfDecoy(call, "held for owner review");
        throw vetoPending(call.tool, verdict, id, true);
      }
      const id = await settle(key, tracked, call);

      let status;
      let grant: unknown;
      try {
        ({ status, grant } = await options.vetoClient.status(id));
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
          // window was approved in, and the ticket may bind to it. The
          // control plane's single-use signed grant (when it runs the
          // executing-broker deployment) rides through here to the broker.
          windows.delete(key);
          return forwardOrKill(call, verdict, mintEpoch, grant);
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
