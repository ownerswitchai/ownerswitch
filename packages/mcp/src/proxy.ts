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
 * every call); report() must retry internally and never throw — the refusal
 * must not depend on the kill POST landing first.
 */
export interface HoneytokenGuard {
  /** matches of decoy values in the given text; [] when clean */
  scan(text: string): ReadonlyArray<{ canaryId: string }>;
  /** fire-and-forget kill report for a decoy seen in a tool call */
  report(trip: { canaryIds: string[]; tool: string; agentId: string }): void;
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
   * Decoy-credential tripwire, checked on every call BEFORE kill state and
   * policy: a tripped honeytoken kills first and asks nothing.
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

    // Honeytokens outrank everything. A decoy value in the arguments is
    // evidence of credential theft in progress, so this runs BEFORE the
    // kill-state lookup and the policy — no veto window, no approval lane,
    // no appeal, and no dependency on the control plane being reachable.
    // The kill report retries in the background; the call fails right now.
    if (options.honeytokens !== undefined) {
      const matches = options.honeytokens.scan(JSON.stringify(call.args ?? {}));
      if (matches.length > 0) {
        const canaryIds = matches.map((m) => m.canaryId);
        options.honeytokens.report({ canaryIds, tool: call.tool, agentId });
        throw honeytokenTripped(call.tool, canaryIds);
      }
    }

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
        return forward(call);
      case "deny":
        throw policyDenied(call.tool, verdict);
      case "approve":
        throw approvalRequired(call.tool, verdict);
      case "veto":
        return vetoLane(call, verdict);
    }
  });

  async function forward(call: ToolCall): Promise<CallToolResult> {
    // the client validated the result against CallToolResultSchema; the SDK's
    // return type is a union over every possible schema, so narrow it here
    const result = await upstream.callTool(
      { name: call.tool, arguments: call.args },
      CallToolResultSchema,
    );
    return result as CallToolResult;
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
          // silence let it run; a released window authorizes exactly one run
          windows.delete(key);
          return forward(call);
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
