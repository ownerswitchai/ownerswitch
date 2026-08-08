import { createHash } from "node:crypto";
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
import { evaluateRemote, type ControlPlaneClient, type KillState } from "@ownerswitchai/gateway";
import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
import {
  approvalRequired,
  controlPlaneUnavailable,
  honeytokenTripped,
  lockdown,
  ownerVetoed,
  policyDenied,
  vetoHeld,
  vetoPending,
} from "./errors.js";
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
 *    from the control plane, then the policy. Only "allow" forwards; the
 *    upstream result passes through untouched.
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
        return forwardOrKill(call);
      case "deny":
        alertIfDecoy(call, "policy denied");
        throw policyDenied(call.tool, verdict);
      case "approve":
        alertIfDecoy(call, "held for owner approval");
        throw approvalRequired(call.tool, verdict);
      case "veto":
        return vetoLane(call, verdict);
    }
  });

  /** Decoy values in call arguments, by canary id — [] when clean or no guard. */
  function decoyIds(call: ToolCall): string[] {
    if (options.honeytokens === undefined) return [];
    return options.honeytokens.scan(JSON.stringify(call.args ?? {})).map((m) => m.canaryId);
  }

  /**
   * The ONLY path that forwards. Scans immediately before forwarding: a decoy
   * about to cross the boundary is exfiltration in progress — report the kill
   * and refuse. Never forwards before scanning.
   */
  async function forwardOrKill(call: ToolCall): Promise<CallToolResult> {
    const canaryIds = decoyIds(call);
    if (canaryIds.length > 0) {
      options.honeytokens?.reportKill({ canaryIds, tool: call.tool, agentId });
      throw honeytokenTripped(call.tool, canaryIds);
    }
    // the client validated the result against CallToolResultSchema; the SDK's
    // return type is a union over every possible schema, so narrow it here
    const result = await upstream.callTool(
      { name: call.tool, arguments: call.args },
      CallToolResultSchema,
    );
    return result as CallToolResult;
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
  async function vetoLane(call: ToolCall, verdict: Verdict): Promise<CallToolResult> {
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
        case "released":
          // silence let it run; a released window authorizes exactly one run.
          // Scan here, right before forwarding — a decoy released to cross the
          // boundary kills, exactly as an allowed call would.
          windows.delete(key);
          return forwardOrKill(call);
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
