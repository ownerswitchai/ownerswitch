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
import type { Policy, ToolCall } from "@ownerswitchai/shared";
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
 * `Policy` has no version field, so the version IS the content hash of its
 * canonical JSON (same canonicalization as ticket args — key-sorted, no
 * whitespace). If the policy changed between decision and execution, the
 * audit trail shows which policy said yes.
 */
export function policyVersionOf(policy: Policy): string {
  const canonical = canonicalizeArgs(policy as unknown as Record<string, unknown>);
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

/** Throws when the arguments cannot form a valid action for the route. */
export function mintActionTicket(
  call: ToolCall,
  route: ExecutorRouteConfig,
  ctx: MintContext,
): ActionTicket {
  const canonicalArgs = canonicalizeArgs(call.args ?? {});
  return {
    agentId: call.agentId,
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
