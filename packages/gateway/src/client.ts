import type { Policy, ToolCall, Verdict } from "@ownerswitchai/shared";
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
 * scoped kill at exactly the gateway that must enforce it. Bounds below are
 * deliberately looser than what the control plane will ever emit (it caps
 * both count and id length far lower) — they bound memory against a hostile
 * or corrupted body, not define the wire contract.
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
});

/** Memory bounds for a hostile/corrupted body — see the class doc above. */
const MAX_KILLED_AGENTS_ACCEPTED = 4096;
const MAX_AGENT_ID_CHARS_ACCEPTED = 1024;

/** Strict parse of the scoped-kill list; null means fail the lookup closed. */
function parseKilledAgents(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_KILLED_AGENTS_ACCEPTED) return null;
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_AGENT_ID_CHARS_ACCEPTED) {
      return null;
    }
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
      const body: unknown = await res.json();
      if (typeof body !== "object" || body === null) return failClosed();
      const { killed, reason, epoch, killedAgents } = body as {
        killed?: unknown;
        reason?: unknown;
        epoch?: unknown;
        killedAgents?: unknown;
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
      if (!killed) return { killed: false, epoch, killedAgents: scoped };
      return typeof reason === "string"
        ? { killed: true, reason, epoch, killedAgents: scoped }
        : { killed: true, epoch, killedAgents: scoped };
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
