import { createHash } from "node:crypto";
import {
  canonicalizeArgs,
  GITHUB_CONNECTOR,
  githubPrResourceId,
  MERGE_PULL_REQUEST,
  parseMergePrArgs,
  type ActionTicket,
  type ExecutionOutcome,
} from "@ownerswitchai/executor";
import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
import type { ExecutorRouteConfig } from "./config.js";

/**
 * Ticket minting — the proxy side of the executor seam (DESIGN.md §1, §2).
 * A yes-decision on an executor-routed tool produces an ActionTicket here;
 * the executor consumes it exactly once. Everything the executor needs to
 * refuse a stale, replayed, or tampered request goes INTO the ticket at
 * mint time — the executor never reaches back into the gateway's memory.
 */

/** A yes is not a standing grant: tickets live minutes, not hours. */
export const DEFAULT_TICKET_TTL_MS = 2 * 60 * 1000;

/** How the proxy reaches the executor — see ProxyOptions.executor. */
export interface ExecutorWiring {
  /**
   * MCP tool name → (connector, operation). Only these tools divert from
   * forward(); everything else keeps forwarding exactly as today.
   */
  routes: Record<string, ExecutorRouteConfig>;
  /** run an already-minted ticket — an Executor instance's run() */
  run: (ticket: ActionTicket) => Promise<ExecutionOutcome>;
  /** ticket lifetime in ms; default DEFAULT_TICKET_TTL_MS */
  ticketTtlMs?: number;
  /** injectable for tests */
  now?: () => number;
  mintNonce?: () => string;
}

/**
 * The ticket's `policyVersion`: a content hash of the WHOLE authorization
 * semantics — the policy AND the executor-route mapping, canonical JSON
 * (same canonicalization as ticket args — key-sorted, no whitespace).
 * Routes decide which real operation an MCP tool name reaches, so hashing
 * the policy alone would identify only half of what was authorized: the
 * same policy with a re-pointed route is a different authorization world,
 * and the audit trail must say so.
 */
export function authorizationVersionOf(
  policy: Policy,
  routes: Record<string, ExecutorRouteConfig>,
): string {
  const canonical = canonicalizeArgs({ executorRoutes: routes, policy });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

/**
 * Stable id of the object acted on — audit and future per-resource rules
 * key on this, independent of args shape. Connector-specific where the
 * connector is known (and parsing doubles as mint-time args validation:
 * malformed arguments refuse HERE, before a ticket exists); an args-keyed
 * generic id otherwise, so an operation this gateway can't interpret still
 * gets a stable audit key.
 */
export function deriveResourceId(route: ExecutorRouteConfig, canonicalArgs: string): string {
  if (route.connector === GITHUB_CONNECTOR && route.operation === MERGE_PULL_REQUEST) {
    const args = parseMergePrArgs(canonicalArgs);
    return githubPrResourceId(args.owner, args.repo, args.pullNumber);
  }
  const digest = createHash("sha256").update(canonicalArgs).digest("hex").slice(0, 16);
  return `${route.connector}:${route.operation}:args:${digest}`;
}

export interface MintContext {
  policyVersion: string;
  /** the control plane's kill epoch observed by THIS call's evaluation */
  killEpoch: number;
  now: number;
  ttlMs: number;
  nonce: string;
}

/**
 * Throws when the arguments cannot form a valid action for the route.
 * `verdict` is the yes that authorized this mint — its decision and rule id
 * ride in the ticket so the audit trail says WHAT was approved (the source
 * tool the agent called) and UNDER WHICH rule.
 */
export function mintActionTicket(
  call: ToolCall,
  route: ExecutorRouteConfig,
  verdict: Verdict,
  ctx: MintContext,
): ActionTicket {
  const canonicalArgs = canonicalizeArgs(call.args ?? {});
  return {
    agentId: call.agentId,
    sourceTool: call.tool,
    decision: verdict.decision,
    ruleId: verdict.ruleId,
    connector: route.connector,
    operation: route.operation,
    canonicalArgs,
    resourceId: deriveResourceId(route, canonicalArgs),
    policyVersion: ctx.policyVersion,
    killEpoch: ctx.killEpoch,
    expiresAt: ctx.now + ctx.ttlMs,
    nonce: ctx.nonce,
    singleUse: true,
  };
}
