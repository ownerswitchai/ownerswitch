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
  /**
   * Run an already-minted ticket — an Executor instance's run(). `grant` is
   * the control-plane-signed MergeGrant from a released veto window, relayed
   * to an executing broker; undefined for the in-process/same-process
   * backends (and for the allow lane, which is refused when requiresGrant).
   */
  run: (ticket: ActionTicket, grant?: unknown) => Promise<ExecutionOutcome>;
  /**
   * True for the executing-broker deployment: a routed action MUST carry an
   * owner-approval grant, so the proxy refuses a routed execution with no
   * grant (the allow lane, or any path that did not go through a released
   * veto window). The in-process/same-process wirings leave this false.
   */
  requiresGrant?: boolean;
  /**
   * The review-time head pin for github/merge_pull_request routes: the
   * PR's CURRENT head sha, read with OwnerSwitch's own credential. The
   * proxy calls this BEFORE the owner sees the request (before a veto
   * window opens, before a ticket mints) and writes the result into the
   * call's canonical arguments as `expectedHeadSha` — server-derived,
   * never agent-supplied. Absent wiring fails routed merges closed.
   */
  pinHeadSha?: (args: { owner: string; repo: string; pullNumber: number }) => Promise<string>;
  /** ticket lifetime in ms; default DEFAULT_TICKET_TTL_MS */
  ticketTtlMs?: number;
  /** injectable for tests */
  now?: () => number;
  mintNonce?: () => string;
}

/**
 * The agent-facing input schema for a routed merge tool, advertised by the
 * proxy in tools/list IN PLACE OF whatever the upstream declares under the
 * same name. Deliberately closed (`additionalProperties: false`) and
 * deliberately WITHOUT `expectedHeadSha`: the head sha is pinned by
 * OwnerSwitch at review time, and an agent-supplied value — stale or
 * false — is refused at call time (validateMergePrRequestArgs), not merely
 * undeclared.
 */
export const MERGE_PR_AGENT_INPUT_SCHEMA = {
  type: "object",
  properties: {
    owner: { type: "string", description: "repository owner (user or organization)" },
    repo: { type: "string", description: "repository name" },
    pullNumber: { type: "integer", minimum: 1, description: "pull request number" },
    mergeMethod: { type: "string", enum: ["merge", "squash", "rebase"] },
  },
  required: ["owner", "repo", "pullNumber"],
  additionalProperties: false,
} as const;

/** The exact, closed key set an agent may send for a routed merge. */
const MERGE_PR_ALLOWED_KEYS = new Set(["owner", "repo", "pullNumber", "mergeMethod"]);
const MERGE_METHODS = new Set(["merge", "squash", "rebase"]);

/** The normalized agent-supplied merge request, before OwnerSwitch pins the head. */
export interface NormalizedMergeRequest {
  owner: string;
  repo: string;
  pullNumber: number;
  mergeMethod?: "merge" | "squash" | "rebase";
}

/**
 * Validates AND NORMALIZES the agent's arguments for a routed merge — the
 * shape before OwnerSwitch pins the head. It ENFORCES the closed schema
 * rather than merely advertising it: the exact key set {owner, repo,
 * pullNumber, mergeMethod}, mergeMethod against the allowed set, and no
 * others. This matters because the caller builds the canonical action — the
 * owner-reviewed, hashed, signed bytes — from THIS normalized object, never
 * from the raw input. A raw MCP client that slips in an unknown field (a
 * `dryRun: true`, say) would otherwise ride into the owner-reviewed bytes
 * while execution silently ignored it, breaking approved-bytes ==
 * executed-semantics. Here an unknown field is a hard refusal, before any
 * head read, veto window, or ticket.
 *
 * `expectedHeadSha` is refused with a specific message (it is a common,
 * well-meaning mistake) — but it is also just an unknown key, so the closed
 * set would reject it regardless.
 */
export function validateMergePrRequestArgs(args: Record<string, unknown>): NormalizedMergeRequest {
  if ("expectedHeadSha" in args) {
    throw new Error(
      "expectedHeadSha is derived by OwnerSwitch at review time and cannot be supplied by " +
        "the agent — remove it and call again",
    );
  }
  for (const key of Object.keys(args)) {
    if (!MERGE_PR_ALLOWED_KEYS.has(key)) {
      throw new Error(
        `unknown argument "${key}" for merge_pull_request — allowed: owner, repo, pullNumber, mergeMethod`,
      );
    }
  }
  const { owner, repo, pullNumber, mergeMethod } = args;
  if (typeof owner !== "string" || owner === "") throw new Error("merge_pull_request requires owner");
  if (typeof repo !== "string" || repo === "") throw new Error("merge_pull_request requires repo");
  if (typeof pullNumber !== "number" || !Number.isSafeInteger(pullNumber) || pullNumber <= 0) {
    throw new Error("merge_pull_request requires a safe positive integer pullNumber");
  }
  if (mergeMethod !== undefined && (typeof mergeMethod !== "string" || !MERGE_METHODS.has(mergeMethod))) {
    throw new Error('mergeMethod must be one of "merge", "squash", "rebase"');
  }
  // rebuild explicitly — the returned object contains ONLY normalized fields
  return {
    owner,
    repo,
    pullNumber,
    ...(mergeMethod !== undefined ? { mergeMethod: mergeMethod as "merge" | "squash" | "rebase" } : {}),
  };
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
