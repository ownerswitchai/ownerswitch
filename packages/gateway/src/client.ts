import {
  isValidAgentId,
  MAX_KILLED_AGENTS,
  type Policy,
  type ToolCall,
  type Verdict,
} from "@ownerswitchai/shared";
import { evaluate, type KillState } from "./engine.js";

/**
 * HTTP client for the control plane's GET /status endpoint.
 *
 * Fail-closed by construction: any doubt about the control plane's answer —
 * network error, non-2xx response, timeout, unparseable body — reads as
 * "killed". fetchKillState never throws and never reports killed:false
 * on uncertainty.
 *
 * `epoch` gets the same treatment. `/status` always carries a monotone
 * `epoch` alongside `killed` — see packages/executor/DESIGN.md §3 and
 * packages/mcp/THREAT-MODEL.md for why a client needs it: `killed` alone
 * flips back to false on restore, so it cannot tell a stale approval from a
 * current one, but `epoch` never resets. A response whose `epoch` is
 * missing or not a valid non-negative integer fails the ENTIRE lookup
 * closed, exactly like a missing/invalid `killed`. The alternative —
 * defaulting an absent epoch to 0 — would make every ticket minted before
 * this deployment's first-ever kill look permanently current, silently
 * defeating the one check epoch exists to support. So there is no
 * "killed:false, epoch: unknown" state on the wire: either both fields
 * parse, or the caller gets `killed:true`.
 *
 * `killedAgents` — the SCOPED kill list — is required with the same
 * strictness. `/status` always serves it (possibly empty); a body where it
 * is missing or malformed fails the entire lookup closed rather than being
 * read as "no agent is scope-killed", which would silently disarm every
 * scoped kill at exactly the gateway that must enforce it. The accepted
 * shape IS the wire contract from @ownerswitchai/shared: at most
 * MAX_KILLED_AGENTS entries, every one a valid agent id — anything a real
 * control plane could never have emitted reads as an untrustworthy answer.
 */
export interface ControlPlaneClientOptions {
  baseUrl: string;
  /** abort the /status call after this many ms */
  timeoutMs?: number;
  /** injectable for tests */
  fetchImpl?: typeof fetch;
}

export interface ControlPlaneClient {
  fetchKillState(): Promise<KillState>;
}

const failClosed = (): KillState => ({
  killed: true,
  reason: "control plane unreachable — fail closed",
  killedAgents: [],
  // an answer we never got proves nothing about durable state either
  durable: false,
});

/**
 * Ceiling on the /status body accepted for parsing, in UTF-16 code units (a
 * lower bound on wire bytes — the safe direction for a ceiling). Honest
 * scope: the body is still read fully into memory by res.text() before this
 * check runs, so this bounds JSON.parse cost and rejects absurd responses —
 * it is NOT a streaming network-memory cap. The read itself is bounded in
 * practice by the request timeout and the loopback deployment; a streaming
 * byte-counter would buy little here at real complexity cost. A legitimate
 * body is a few hundred bytes; 256 KiB is orders of magnitude of headroom.
 */
const MAX_STATUS_BODY_UNITS = 256 * 1024;

/**
 * Strict parse of the scoped-kill list against the shared agentId contract;
 * null means fail the lookup closed.
 */
function parseKilledAgents(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_KILLED_AGENTS) return null;
  for (const entry of value) {
    if (typeof entry !== "string" || !isValidAgentId(entry)) return null;
  }
  return value as string[];
}

export function createControlPlaneClient(
  options: ControlPlaneClientOptions,
): ControlPlaneClient {
  const { baseUrl, timeoutMs = 500, fetchImpl = fetch } = options;

  async function fetchKillState(): Promise<KillState> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // cache: "no-store" plus explicit request headers: a cached
      // {killed:false, epoch:N} replayed after a kill would defeat every
      // check this lookup exists for. The control plane also serves /status
      // with Cache-Control: no-store — both ends refuse caching, and the
      // deployment requirement (no cache in front of the control plane) is
      // stated in packages/mcp/THREAT-MODEL.md.
      const res = await fetchImpl(new URL("/status", baseUrl), {
        signal: controller.signal,
        cache: "no-store",
        headers: { "cache-control": "no-store, no-cache", pragma: "no-cache" },
      });
      if (!res.ok) return failClosed();
      // Bound the body BEFORE parsing: a response no real control plane
      // could have produced must become a fail-closed answer, not an
      // unbounded parse (see MAX_STATUS_BODY_UNITS for the honest scope of
      // this cap).
      const text = await res.text();
      if (text.length > MAX_STATUS_BODY_UNITS) return failClosed();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return failClosed();
      }
      if (typeof body !== "object" || body === null) return failClosed();
      const { killed, reason, epoch, killedAgents, persistenceDegraded, unhealthy } = body as {
        killed?: unknown;
        reason?: unknown;
        epoch?: unknown;
        killedAgents?: unknown;
        persistenceDegraded?: unknown;
        unhealthy?: unknown;
      };
      if (typeof killed !== "boolean") return failClosed();
      // A missing or unparseable epoch must never be treated as epoch 0 —
      // see the class doc above. Fail the whole response closed instead of
      // guessing.
      if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
        return failClosed();
      }
      // A missing or malformed scoped-kill list must never be treated as
      // "nobody is scope-killed" — same doctrine, same direction.
      const scoped = parseKilledAgents(killedAgents);
      if (scoped === null) return failClosed();
      // Durability, carried through rather than dropped: a control plane
      // whose persistence is degraded or unhealthy is telling the truth
      // about NOW and nothing about after a restart. Anything treating this
      // answer as proof of a durable record must know (see KillState.durable).
      const durable = persistenceDegraded === undefined && unhealthy === undefined;
      if (!killed) return { killed: false, epoch, killedAgents: scoped, durable };
      return typeof reason === "string"
        ? { killed: true, reason, epoch, killedAgents: scoped, durable }
        : { killed: true, epoch, killedAgents: scoped, durable };
    } catch {
      return failClosed();
    } finally {
      clearTimeout(timer);
    }
  }

  return { fetchKillState };
}

/**
 * evaluate() with the kill state looked up live from the control plane.
 * The sync evaluate() stays the pure, testable core; this wrapper only
 * fetches the one input that must come from outside the process.
 */
export async function evaluateRemote(
  call: ToolCall,
  policy: Policy,
  client: ControlPlaneClient,
): Promise<Verdict> {
  return evaluate(call, policy, await client.fetchKillState());
}
