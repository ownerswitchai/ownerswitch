import { chmodSync, lstatSync, statSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { dirname } from "node:path";
import {
  canonicalJson,
  verifyMergeGrant,
  type MergeGrant,
} from "@ownerswitchai/shared";
import { createJtiBurnStore, type JtiBurnStore } from "./burn-store.js";
import { ConnectorCallError } from "./connector-error.js";
import type { LiveKillState } from "./executor.js";
import { createGitHubMergeClient } from "./github-client.js";
import {
  GITHUB_CONNECTOR,
  MERGE_PULL_REQUEST,
  parseMergePrArgs,
  type GitHubMergeClient,
} from "./github.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { assertSafeRepoName } from "./github-http.js";
import type { SecretLedger } from "./secret-ledger.js";

/**
 * The credential broker — and, critically, the EXECUTING side (DESIGN.md §6).
 *
 * An earlier design had the broker return raw installation tokens. That was
 * wrong: a contents:write token authenticates git-over-HTTPS, so anything
 * that could reach the socket held raw push authority — and within one uid
 * nothing distinguishes the gateway from the agent, so a same-uid agent
 * could push directly, bypassing owner review, the ticket, the nonce, the
 * head pin and policy entirely. The separate uid protected the standing KEY;
 * it did not preserve the AUTHORIZATION BOUNDARY. The boundary is the
 * product, so the broker never returns a token or the key. It PERFORMS the
 * merge itself, with a token that never leaves this process, and returns
 * only the outcome.
 *
 * What crosses the socket:
 *   → {op:"pin-head", args}          read-only PR head (for the review-time
 *                                    pin); kill-gated, allow-listed
 *   → {op:"merge", grant, args}      a control-plane-signed, single-use
 *                                    MergeGrant plus the args it authorizes
 *   → {op:"outcome", jti}            read-only: what happened to a burned
 *                                    grant — the in-doubt resolution surface
 *                                    for a caller whose socket died
 *                                    mid-dispatch. Deliberately NOT
 *                                    kill-gated: it grants nothing and an
 *                                    operator needs it exactly when things
 *                                    went wrong.
 *   ← {ok:true, headSha}             |  {ok:true, merged, sha, message}
 *   ← {ok:true, record:{...}}        |  {ok:false, kind, outcome?, error}
 * Never a token. Never the key.
 *
 * How a merge is authorized — the broker validates INDEPENDENTLY, trusting
 * nothing the gateway says:
 *   1. verifyMergeGrant against the shared control-plane key (signature,
 *      version, expiry, callHash↔canonicalArgs) — the gateway relays the
 *      grant but cannot forge one, because the key is not in its environment.
 *   2. PURPOSE: the grant's signed connector/operation must be exactly
 *      github/merge_pull_request — the one purpose this broker serves. An
 *      owner approval registered for ANY other purpose, however
 *      merge-shaped its arguments, is refused before it is even burned.
 *   3. single-use: the grant's jti is burned HERE, before dispatch, in a
 *      DURABLE store the agent cannot reach (burn-store.ts — an atomic
 *      filesystem create that survives restarts and arbitrates between
 *      broker processes; the control plane also issues each grant at most
 *      once — two independent burns, neither in volatile memory alone).
 *   4. the supplied args must re-canonicalize to the grant's signed bytes,
 *      so the pinned expectedHeadSha and the exact PR are covered by the
 *      signature; the broker merges the SIGNED args, not the wire args —
 *      parsed by the CLOSED-schema parser, unknown fields refused.
 *   5. live kill state is checked before the mint AND across it (the
 *      github client's beforeDispatch hook), fail closed; the grant's
 *      killEpoch must equal the live epoch — a kill (even one since
 *      restored) between approval and execution refuses — and the grant's
 *      expiry is re-checked on the far side of the mint, so a grant
 *      presented moments before expiresAt cannot dispatch after it.
 *
 * What a same-uid agent that finds the socket can obtain NOW: a read-only
 * head sha (public-ish, low value), and a merge ONLY if it also presents a
 * currently-valid, unburned, owner-approved grant it cannot mint. It can
 * never obtain a token or the key. That residual is documented in
 * THREAT-MODEL.md §5.
 *
 * No-leak: no token or key is ever in a response; error strings pass the
 * ledger's redaction; the log callback never receives a secret.
 */

const MAX_REQUEST_BYTES = 8 * 1024;
const SOCKET_MODE = 0o660;

export interface MergeBrokerOptions {
  /** mints installation tokens; the ONLY holder of the private key */
  tokens: InstallationTokenSource;
  ledger: SecretLedger;
  /** the shared control-plane↔broker key that signs MergeGrants */
  grantKey: string;
  /** live kill state, fail-closed (liveKillStateFromControlPlane) */
  fetchLiveKillState: () => Promise<LiveKillState>;
  /**
   * Directory for the DURABLE single-use burn store (burn-store.ts) —
   * broker-owned, mode 0700, outside the agent workspace. Required: a burn
   * that lives only in process memory is not single-use across a restart.
   */
  burnDir: string;
  /**
   * Repositories the broker will act on. undefined = any the installation
   * covers; set it in production so a compromised same-uid requester cannot
   * even ask about repos outside the deployment's intent.
   */
  allowedRepos?: readonly string[];
  /**
   * Per-connection budget for the full request/response exchange. The
   * default clears the worst-case LEGITIMATE chain — token mint (10s
   * budget) + merge PUT (30s) + one post-ambiguity verification read (30s)
   * plus kill-state reads and slack — so it fires on pathology, not on a
   * slow but honest merge. When it does fire mid-dispatch the response is
   * kind:"connector", outcome:"unknown" (the merge may still land), NEVER
   * "refused": a caller must not hear "safe to retry" while GitHub is
   * executing. Before dispatch it is a plain refusal — nothing was sent.
   */
  requestTimeoutMs?: number;
  /** GitHub API base (tests) */
  baseUrl?: string;
  /** injectable for tests; nothing in the suite reaches GitHub */
  fetchImpl?: typeof fetch;
  /** the effective GID the socket must end up owned by (see listen()) */
  socketGid?: number;
  /** audit sink (stderr in the CLI); never given a secret */
  log?: (line: string) => void;
  now?: () => number;
}

export interface MergeBroker {
  listen(socketPath: string): Promise<void>;
  close(): Promise<void>;
}

type WireResponse =
  | { ok: true; headSha: string }
  | { ok: true; merged: boolean; sha: string; message: string }
  | {
      ok: true;
      record: {
        jti: string;
        state: string;
        outcome?: string;
        merged?: boolean;
        sha?: string;
        message?: string;
        error?: string;
      };
    }
  | { ok: false; kind: "refused"; error: string }
  | { ok: false; kind: "connector"; outcome: "not-performed" | "unknown"; error: string };

/** Where a connection's merge stands, for the phase-aware timeout. */
interface RequestPhase {
  /** true once the PUT is (about to be) in flight — outcome no longer "refused" */
  dispatched: boolean;
  /** the burned grant's jti, for the in-doubt pointer in timeout messages */
  jti?: string;
}

export function createMergeBroker(options: MergeBrokerOptions): MergeBroker {
  const {
    tokens,
    ledger,
    grantKey,
    fetchLiveKillState,
    allowedRepos,
    requestTimeoutMs = 120_000,
    baseUrl,
    fetchImpl,
    now = Date.now,
  } = options;
  const log = options.log ?? (() => undefined);
  const allowed = allowedRepos === undefined ? undefined : new Set(allowedRepos);
  let server: Server | undefined;
  let boundPath: string | undefined;

  if (grantKey === "") {
    throw new Error("merge broker requires a grant key (OWNERSWITCH_GRANT_KEY) — it trusts nothing without one");
  }

  // the durable single-use ledger — created (and its ownership/mode
  // verified) at construction so a misconfigured store refuses at startup,
  // not on the first merge
  const burns: JtiBurnStore = createJtiBurnStore(options.burnDir, { now });

  /** Fail-closed live kill state — an unreadable control plane reads as killed. */
  async function live(): Promise<LiveKillState> {
    try {
      return await fetchLiveKillState();
    } catch {
      return { killed: true, epoch: -1 };
    }
  }

  function assertRepoAllowed(repo: string): void {
    assertSafeRepoName(repo);
    if (allowed !== undefined && !allowed.has(repo)) {
      throw new BrokerRefusal(`repository "${repo}" is not in the broker's allow-list`);
    }
  }

  /** The read-only head pin. Kill-gated; returns data, never authority. */
  async function pinHead(rawArgs: unknown): Promise<WireResponse> {
    const args = asPinArgs(rawArgs);
    assertRepoAllowed(args.repo);
    const state = await live();
    if (state.killed) throw new BrokerRefusal("kill switch engaged (or control plane unreachable) — refused");
    const client = mergeClient();
    try {
      const headSha = await client.getPullRequestHead(args);
      return { ok: true, headSha };
    } catch (err) {
      throw new BrokerRefusal(
        `cannot read the pull request head: ${err instanceof Error ? err.message : "failed"}`,
      );
    }
  }

  /** Best-effort outcome bookkeeping — the response already carries the
   * truth; a bookkeeping write failure must not change it. */
  function recordOutcome(jti: string, patch: Parameters<JtiBurnStore["record"]>[1]): void {
    try {
      burns.record(jti, patch);
    } catch (err) {
      log(`[merge-broker] outcome record for ${jti} failed: ${errText(err)}`);
    }
  }

  /** Validate the grant independently, then PERFORM the merge. */
  async function merge(rawGrant: unknown, rawArgs: unknown, phase: RequestPhase): Promise<WireResponse> {
    const verified = verifyMergeGrant(rawGrant, grantKey, { now });
    if (!verified.ok) throw new BrokerRefusal(`grant rejected: ${verified.reason}`);
    const grant = verified.grant;

    // PURPOSE, before anything else: this broker performs GitHub merges and
    // nothing else. An approval the owner made for any other purpose —
    // whatever its arguments look like — authorizes nothing here, and is
    // refused before it is burned (it is not this broker's grant to spend).
    if (grant.connector !== GITHUB_CONNECTOR || grant.operation !== MERGE_PULL_REQUEST) {
      throw new BrokerRefusal(
        `grant purpose is "${grant.connector}.${grant.operation}", not ` +
          `"${GITHUB_CONNECTOR}.${MERGE_PULL_REQUEST}" — this broker performs GitHub merges only`,
      );
    }

    // single-use burns HERE, durably, before anything else can act on it —
    // a store failure is a refusal, never a memory-only pass
    if (burns.burn(grant.jti, grant.expiresAt) === "already-burned") {
      throw new BrokerRefusal("grant already used (single-use)");
    }
    phase.jti = grant.jti;

    try {
      // the broker merges the SIGNED args; the wire args must match them exactly
      if (rawArgs !== undefined && canonicalJson(rawArgs) !== grant.canonicalArgs) {
        throw new BrokerRefusal("supplied args do not match the grant's authorized args");
      }
      const mergeArgs = parseMergeArgsFromGrant(grant);
      assertRepoAllowed(mergeArgs.repo);

      // kill recheck BEFORE the mint: killed false AND the live epoch equals
      // the epoch the owner approved under
      const before = await live();
      if (before.killed) {
        throw new BrokerRefusal("kill switch engaged (or control plane unreachable) — refused");
      }
      if (before.epoch !== grant.killEpoch) {
        throw new BrokerRefusal(
          `kill epoch moved since approval (grant ${grant.killEpoch}, live ${before.epoch}) — a kill happened in between`,
        );
      }

      // recheck ACROSS the mint (beforeDispatch): the token mint can take
      // seconds; a kill, epoch change, or the grant's own EXPIRY landing
      // during it aborts before anything is sent. The last statement flips
      // the phase to dispatched — from that point a timeout is "unknown",
      // never "refused", because the very next thing the client does is
      // send the PUT.
      const client = mergeClient(async () => {
        const after = await live();
        if (after.killed || after.epoch !== before.epoch) {
          throw new Error("kill state changed during token minting");
        }
        if (now() >= grant.expiresAt) {
          throw new Error("the grant expired during token minting — refused before dispatch");
        }
        phase.dispatched = true;
      });

      try {
        const result = await client.mergePullRequest(mergeArgs);
        recordOutcome(grant.jti, {
          state: "performed",
          merged: result.merged,
          sha: result.sha,
          message: result.message,
        });
        return { ok: true, merged: result.merged, sha: result.sha, message: result.message };
      } catch (err) {
        if (err instanceof ConnectorCallError) {
          recordOutcome(grant.jti, { state: "connector-error", outcome: err.outcome, error: err.message });
          return { ok: false, kind: "connector", outcome: err.outcome, error: err.message };
        }
        recordOutcome(grant.jti, { state: "connector-error", outcome: "unknown", error: errText(err) });
        return { ok: false, kind: "connector", outcome: "unknown", error: errText(err) };
      }
    } catch (err) {
      // a refusal after the burn: the grant is spent and nothing was sent —
      // write that down so an outcome query answers honestly
      if (err instanceof BrokerRefusal) {
        recordOutcome(grant.jti, { state: "not-performed", error: err.message });
      }
      throw err;
    }
  }

  /** Read-only: what happened to a burned grant. Grants nothing. */
  function outcomeOf(rawArgs: unknown): WireResponse {
    const jti = (rawArgs as { jti?: unknown } | null | undefined)?.jti;
    if (typeof jti !== "string" || jti === "") {
      throw new BrokerRefusal("outcome requires a jti");
    }
    const record = burns.lookup(jti);
    if (record === undefined) {
      throw new BrokerRefusal("no burn record for that jti — the grant was never presented here");
    }
    return {
      ok: true,
      record: {
        jti,
        state: record.state,
        ...(record.outcome !== undefined ? { outcome: record.outcome } : {}),
        ...(record.merged !== undefined ? { merged: record.merged } : {}),
        ...(record.sha !== undefined ? { sha: record.sha } : {}),
        ...(record.message !== undefined ? { message: record.message } : {}),
        ...(record.error !== undefined ? { error: ledger.redact(record.error).slice(0, 400) } : {}),
      },
    };
  }

  function mergeClient(beforeDispatch?: () => Promise<void>): GitHubMergeClient {
    return createGitHubMergeClient({
      tokens,
      ledger,
      ...(baseUrl !== undefined ? { baseUrl } : {}),
      ...(fetchImpl !== undefined ? { fetchImpl } : {}),
      ...(beforeDispatch !== undefined ? { beforeDispatch } : {}),
    });
  }

  function errText(err: unknown): string {
    return ledger.redact(err instanceof Error ? err.message : String(err));
  }

  function handleConnection(socket: Socket): void {
    let buffer = "";
    let done = false;
    const phase: RequestPhase = { dispatched: false };
    // Phase-aware: before dispatch a timeout refuses (nothing was sent);
    // once the PUT is in flight the honest answer is UNKNOWN — the merge
    // may still land after this response, and the caller must never hear
    // "safe to retry" while GitHub is executing. The dispatch itself is NOT
    // cancelled: it runs to completion and records its outcome, so an
    // {op:"outcome"} query with the jti below resolves the doubt.
    const timer = setTimeout(() => {
      if (phase.dispatched) {
        finish({
          ok: false,
          kind: "connector",
          outcome: "unknown",
          error:
            `the merge dispatch exceeded the ${requestTimeoutMs}ms budget and is still in ` +
            `flight — its outcome is UNKNOWN, not refused. It will finish and be recorded; ` +
            `query {op:"outcome"} with jti "${phase.jti ?? ""}" to resolve it before re-approving`,
        });
      } else {
        finish({
          ok: false,
          kind: "refused",
          error: "request timed out before dispatch — nothing was sent to GitHub",
        });
      }
    }, requestTimeoutMs);

    const finish = (response: WireResponse): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const safe: WireResponse =
        response.ok === true
          ? response
          : { ...response, error: ledger.redact(response.error).slice(0, 400) };
      socket.end(`${JSON.stringify(safe)}\n`);
    };

    socket.on("error", () => {
      done = true;
      clearTimeout(timer);
    });
    socket.on("data", (chunk) => {
      if (done) return;
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_REQUEST_BYTES) {
        finish({ ok: false, kind: "refused", error: "request too large" });
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      void (async () => {
        try {
          const parsed: unknown = JSON.parse(line);
          const req = (parsed ?? {}) as { op?: unknown; grant?: unknown; args?: unknown };
          if (req.op === "pin-head") {
            finish(await pinHead(req.args));
          } else if (req.op === "merge") {
            finish(await merge(req.grant, req.args, phase));
          } else if (req.op === "outcome") {
            finish(outcomeOf(req.args));
          } else {
            finish({ ok: false, kind: "refused", error: "unknown operation" });
          }
        } catch (err) {
          if (err instanceof BrokerRefusal) {
            finish({ ok: false, kind: "refused", error: err.message });
          } else {
            finish({ ok: false, kind: "refused", error: errText(err) });
          }
        }
      })();
    });
  }

  return {
    async listen(socketPath: string): Promise<void> {
      const pruned = burns.pruneExpired();
      if (pruned > 0) log(`[merge-broker] pruned ${pruned} expired burn record(s)`);
      assertSocketDirHardened(socketPath);
      removeStaleSocket(socketPath);
      server = createServer(handleConnection);
      await new Promise<void>((resolve, reject) => {
        server!.once("error", reject);
        server!.listen(socketPath, () => {
          server!.removeListener("error", reject);
          resolve();
        });
      });
      chmodSync(socketPath, SOCKET_MODE);
      // A unix socket inherits the CREATING PROCESS'S effective gid, not the
      // directory's group — so a directory whose group is the allow-list does
      // NOT by itself make the socket connectable by that group. Verify the
      // socket's gid is the one the deployment intends (the broker must run
      // with that gid, e.g. via a setgid socket directory or `sg`); refuse to
      // serve if it is wrong, rather than listen on a socket the gateway
      // cannot reach or that a wider group can.
      const socketGid = statSync(socketPath).gid;
      if (options.socketGid !== undefined && socketGid !== options.socketGid) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        server = undefined;
        try {
          unlinkSync(socketPath);
        } catch {
          /* already gone */
        }
        throw new Error(
          `token broker socket ${socketPath} has gid ${socketGid}, not the required ${options.socketGid} — ` +
            `a unix socket inherits the broker process's effective gid, not the directory's group; run the ` +
            `broker with that gid (e.g. a setgid 02750 socket directory, or \`sg <group>\`) so the gateway's ` +
            `user can connect and no wider group can`,
        );
      }
      boundPath = socketPath;
      log(
        `[merge-broker] listening on ${socketPath} (socket mode 0660, gid ${socketGid}); ` +
          `allowed repos: ${allowed === undefined ? "(installation-bounded)" : [...allowed].join(", ")}`,
      );
    },
    async close(): Promise<void> {
      const s = server;
      server = undefined;
      if (s !== undefined) await new Promise<void>((resolve) => s.close(() => resolve()));
      if (boundPath !== undefined) {
        try {
          unlinkSync(boundPath);
        } catch {
          /* already gone */
        }
        boundPath = undefined;
      }
    },
  };
}

/** Refusal that must never carry a secret — errText/redaction still applies. */
class BrokerRefusal extends Error {}

function asPinArgs(raw: unknown): { owner: string; repo: string; pullNumber: number } {
  if (typeof raw !== "object" || raw === null) throw new BrokerRefusal("pin-head requires args");
  const { owner, repo, pullNumber } = raw as Record<string, unknown>;
  if (typeof owner !== "string" || owner === "") throw new BrokerRefusal("pin-head requires owner");
  if (typeof repo !== "string" || repo === "") throw new BrokerRefusal("pin-head requires repo");
  if (typeof pullNumber !== "number" || !Number.isSafeInteger(pullNumber) || pullNumber <= 0) {
    throw new BrokerRefusal("pin-head requires a safe positive integer pullNumber");
  }
  return { owner, repo, pullNumber };
}

function parseMergeArgsFromGrant(grant: MergeGrant): ReturnType<typeof parseMergePrArgs> {
  try {
    return parseMergePrArgs(grant.canonicalArgs);
  } catch (err) {
    throw new BrokerRefusal(
      `the grant's authorized args are not a valid merge: ${err instanceof Error ? err.message : "invalid"}`,
    );
  }
}

/**
 * The socket's parent directory is part of the peer allow-list (connect(2)
 * needs traversal), so its permissions are checked: broker-owned, no world
 * access. Group access is the deployment's allow-list knob (pair it with the
 * setgid + socket-gid mechanics above).
 */
function assertSocketDirHardened(socketPath: string): void {
  const dir = dirname(socketPath);
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    throw new Error(
      `merge broker socket directory "${dir}" does not exist — create it owned by the broker's ` +
        `user, mode 02750 (setgid), with the gateway's user in its group`,
    );
  }
  if (!stat.isDirectory()) throw new Error(`merge broker socket directory "${dir}" is not a directory`);
  const getuid = process.getuid;
  if (getuid !== undefined && stat.uid !== getuid.call(process)) {
    throw new Error(
      `merge broker socket directory "${dir}" is owned by uid ${stat.uid}, not the broker's uid ` +
        `${getuid.call(process)} — the broker must own its own front door`,
    );
  }
  if ((stat.mode & 0o007) !== 0) {
    throw new Error(
      `merge broker socket directory "${dir}" grants world access (mode ` +
        `${(stat.mode & 0o777).toString(8)}) — chmod 02750 it; world access would let any uid request merges`,
    );
  }
}

function removeStaleSocket(socketPath: string): void {
  let stat;
  try {
    stat = lstatSync(socketPath);
  } catch {
    return;
  }
  if (!stat.isSocket()) {
    throw new Error(
      `"${socketPath}" exists and is not a socket — refusing to remove it; pick a socket path the broker owns`,
    );
  }
  unlinkSync(socketPath);
}
