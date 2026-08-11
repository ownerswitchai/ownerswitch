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
  /**
   * Live kill state, fail-closed (signedLiveKillStateFromControlPlane).
   * For merges the broker uses two signed checks: a read-only grant-liveness
   * PROBE ({jti}) before the token mint (fail fast on an already-vetoed
   * grant), and an ATOMIC COMMIT ({jti, commit:true}) as the FINAL step
   * before the PUT. The commit is not a snapshot: the control plane
   * transitions the grant live→committed only if a veto/kill has not won the
   * race, and answers `committed`. A fetcher that ignores the probe/commit
   * refuses every merge, by design.
   */
  fetchLiveKillState: (probe?: { jti: string; commit?: boolean }) => Promise<LiveKillState>;
  /**
   * Directory for the DURABLE single-use burn store (burn-store.ts) —
   * broker-owned, mode 0700, outside the agent workspace. Required: a burn
   * that lives only in process memory is not single-use across a restart.
   */
  burnDir: string;
  /**
   * The agent-reachable workspace the burn directory must NOT live under —
   * same rule as the App private key (github-app-key.ts). Passed EXPLICITLY
   * so the boundary is checked against the real workspace, not this
   * process's cwd. When set, a burnDir RESOLVING inside it is refused at
   * startup; a retargetable symlink is refused regardless.
   */
  agentWorkspace?: string;
  /**
   * TESTS ONLY — forwarded to the burn store so suites can run under
   * tmpdir(), whose world-writable /tmp ancestor the trusted-ancestry check
   * rightly refuses. The broker CLI never sets this.
   */
  unsafeBurnAncestryForTests?: boolean;
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
  | { ok: true; headSha: string; baseRef: string }
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
  /**
   * Set when the connection is abandoned (the per-connection timer fired)
   * BEFORE dispatch. The merge() coroutine is not cancellable by the timer
   * directly, so it checks this latch immediately before sending the PUT and
   * aborts — otherwise a slow token mint could complete AFTER a "refused"
   * timeout answer and still dispatch, exactly the false "not performed"
   * this whole phase machinery exists to prevent.
   */
  abandoned: boolean;
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
  if (Buffer.byteLength(grantKey, "utf8") < 32) {
    throw new Error(
      "the merge broker's grant key is under 32 bytes — a merge-authorizing HMAC key must carry " +
        "at least 256 bits of secret; generate one with `openssl rand -hex 32`",
    );
  }

  // the durable single-use ledger — created (and its path/ownership/mode
  // verified) at construction so a misconfigured store refuses at startup,
  // not on the first merge
  const burns: JtiBurnStore = createJtiBurnStore(options.burnDir, {
    now,
    ...(options.agentWorkspace !== undefined ? { workspaceDir: options.agentWorkspace } : {}),
    ...(options.unsafeBurnAncestryForTests === true
      ? { unsafeAllowUntrustedAncestryForTests: true }
      : {}),
  });

  /** Fail-closed live kill state — an unreadable control plane reads as killed. */
  async function live(probe?: { jti: string; commit?: boolean }): Promise<LiveKillState> {
    try {
      return await fetchLiveKillState(probe);
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
      const target = await client.getPullRequestHead(args);
      return { ok: true, headSha: target.headSha, baseRef: target.baseRef };
    } catch (err) {
      throw new BrokerRefusal(
        `cannot read the pull request head: ${err instanceof Error ? err.message : "failed"}`,
      );
    }
  }

  /** Best-effort outcome bookkeeping — the response already carries the
   * truth; a bookkeeping write failure must not change it, and must not
   * escape (the audit logger itself could throw). Both the record and the
   * log are fully swallowed. */
  function recordOutcome(jti: string, patch: Parameters<JtiBurnStore["record"]>[1]): void {
    try {
      burns.record(jti, patch);
    } catch (err) {
      try {
        log(`[merge-broker] outcome record for ${jti} failed: ${errText(err)}`);
      } catch {
        /* a throwing audit sink must never change the merge outcome */
      }
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
      // the epoch the owner approved under AND the control plane still
      // VOUCHES for this specific grant (grant-liveness probe) — an owner
      // veto after issuance revokes the grant right here
      const before = await live({ jti: grant.jti });
      if (before.killed) {
        throw new BrokerRefusal("kill switch engaged (or control plane unreachable) — refused");
      }
      if (before.epoch !== grant.killEpoch) {
        throw new BrokerRefusal(
          `kill epoch moved since approval (grant ${grant.killEpoch}, live ${before.epoch}) — a kill happened in between`,
        );
      }
      if (before.grantLive !== true) {
        throw new BrokerRefusal(
          "the control plane no longer vouches for this grant — vetoed since approval, unknown " +
            "to it, or it restarted; nothing was dispatched",
        );
      }

      // recheck ACROSS the mint (beforeDispatch): the token mint can take
      // seconds; a kill, epoch change, the grant's own EXPIRY, or the
      // CONNECTION BEING ABANDONED (the per-connection timer fired) landing
      // during it aborts before anything is sent. The abandoned check is the
      // cancellation latch: without it a timeout could answer "refused" and
      // the mint could then complete and dispatch anyway. The last statement
      // flips the phase to dispatched — from that point a timeout is
      // "unknown", never "refused", because the very next thing the client
      // does is send the PUT.
      const client = mergeClient(async () => {
        if (phase.abandoned) {
          throw new Error(
            "the connection was abandoned before dispatch (client timed out) — not dispatched",
          );
        }
        // The FINAL check is an ATOMIC COMMIT, not a snapshot: the control
        // plane transitions this grant live→committed-for-dispatch and
        // answers `committed`, losing the race to any veto that arrives
        // first. If it commits, a later veto is reported "in flight"; if a
        // veto already landed, committed is false and nothing is sent. This
        // is what closes the "signed live:true, then veto 200, then PUT"
        // window that a read-only probe left open.
        const after = await live({ jti: grant.jti, commit: true });
        if (after.killed || after.epoch !== before.epoch) {
          throw new Error("kill state changed during token minting");
        }
        if (now() >= grant.expiresAt) {
          throw new Error("the grant expired during token minting — refused before dispatch");
        }
        if (after.committed !== true) {
          throw new Error(
            "the control plane did not commit this grant for dispatch (vetoed, killed, or " +
              "unknown at commit time) — refused before dispatch",
          );
        }
        // Re-check the latch SYNCHRONOUSLY, immediately before flipping to
        // dispatched: the live() read above awaited, and the abandon timer
        // can fire during exactly that await — a "refused; nothing sent"
        // would then already be on the wire, so dispatching now would make
        // it a lie. Between this check and the assignment there is no await,
        // so the single-threaded timer cannot interleave.
        if (phase.abandoned) {
          throw new Error(
            "the connection was abandoned during the pre-dispatch checks — not dispatched",
          );
        }
        phase.dispatched = true;
      });

      try {
        const result = await client.mergePullRequest(mergeArgs);
        // "performed" is reserved for a direct confirmation that THIS
        // dispatch merged; an ambiguity-path success only proved the PR's
        // merged STATE, and the record must not claim more than that.
        recordOutcome(grant.jti, {
          state: result.attribution === "merged-state-only" ? "merged-state-observed" : "performed",
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
    // ONE request per connection, latched SYNCHRONOUSLY the instant the
    // first full line is seen — before any await. Without this, a second
    // `data` chunk arriving while the first merge coroutine is still
    // awaiting (liveness, token mint) would re-find the same newline,
    // re-parse the same line, and launch a DUPLICATE coroutine; the
    // duplicate would see the already-burned jti and answer "refused" while
    // the original could still PUT — a false refusal alongside a real
    // merge. The latch closes that: once a request is launched every
    // further byte on the connection is ignored.
    let started = false;
    const phase: RequestPhase = { dispatched: false, abandoned: false };
    // Phase-aware: before dispatch a timeout refuses (nothing was sent) AND
    // latches `abandoned` so the merge() coroutine aborts at its
    // pre-dispatch check rather than sending a PUT after we already
    // answered. Once the PUT is in flight the honest answer is UNKNOWN — the
    // merge may still land after this response, and the caller must never
    // hear "safe to retry" while GitHub is executing; that dispatch is NOT
    // cancelled (it is already gone), it runs to completion and records its
    // outcome, so an {op:"outcome"} query with the jti below resolves the
    // doubt.
    const timer = setTimeout(() => {
      phase.abandoned = true;
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
      // once a request is launched (or the connection is finished), every
      // further byte on this connection is ignored — a connection carries
      // exactly one request
      if (done || started) return;
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_REQUEST_BYTES) {
        finish({ ok: false, kind: "refused", error: "request too large" });
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      // LATCH before the first await — nothing after this (a later chunk,
      // trailing bytes) can spawn a second request on this connection
      started = true;
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
          // Classification depends on WHEN the error escaped. A BrokerRefusal
          // is always pre-dispatch by construction (every throw site is
          // before the PUT). But an UNEXPECTED error can escape AFTER the PUT
          // succeeded — e.g. a post-merge bookkeeping write, or a logger,
          // throwing. Once phase.dispatched, the merge may have landed, so
          // the honest answer is connector/UNKNOWN, never "refused" (which
          // the client would map to not-performed — a false negative on a
          // completed merge).
          if (err instanceof BrokerRefusal) {
            finish({ ok: false, kind: "refused", error: err.message });
          } else if (phase.dispatched) {
            finish({
              ok: false,
              kind: "connector",
              outcome: "unknown",
              error:
                `the merge was dispatched, then an unexpected broker error occurred ` +
                `(${errText(err)}); its outcome is UNKNOWN, not refused — query {op:"outcome"} ` +
                `with jti "${phase.jti ?? ""}" to resolve it`,
            });
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
      burns.close();
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
  // Group access is the deployment's allow-list knob, but GROUP WRITE is
  // not: a group member that can write the directory can unlink the socket
  // and bind its own in its place (the connect-time boundary is the
  // directory's write permission, not the socket inode's). The intended
  // mode is 02750 — group r-x, no group write.
  if ((stat.mode & 0o020) !== 0) {
    throw new Error(
      `merge broker socket directory "${dir}" is group-writable (mode ` +
        `${(stat.mode & 0o777).toString(8)}) — chmod 02750 it; a group member that can write the ` +
        `directory could replace the socket with its own and impersonate the broker`,
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
