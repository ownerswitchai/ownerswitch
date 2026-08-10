import { chmodSync, lstatSync, statSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { dirname } from "node:path";
import {
  canonicalJson,
  verifyMergeGrant,
  type MergeGrant,
} from "@ownerswitchai/shared";
import { ConnectorCallError } from "./connector-error.js";
import type { LiveKillState } from "./executor.js";
import { createGitHubMergeClient } from "./github-client.js";
import { parseMergePrArgs, type GitHubMergeClient } from "./github.js";
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
 *   ← {ok:true, headSha}             |  {ok:true, merged, sha, message}
 *   ← {ok:false, kind, outcome?, error}
 * Never a token. Never the key.
 *
 * How a merge is authorized — the broker validates INDEPENDENTLY, trusting
 * nothing the gateway says:
 *   1. verifyMergeGrant against the shared control-plane key (signature,
 *      version, expiry, callHash↔canonicalArgs) — the gateway relays the
 *      grant but cannot forge one, because the key is not in its environment.
 *   2. single-use: the grant's jti is burned HERE, before dispatch, in a
 *      process the agent cannot reach (the control plane also issues each
 *      grant at most once — two independent burns).
 *   3. the supplied args must re-canonicalize to the grant's signed bytes,
 *      so the pinned expectedHeadSha and the exact PR are covered by the
 *      signature; the broker merges the SIGNED args, not the wire args.
 *   4. live kill state is checked before the mint AND across it (the
 *      github client's beforeDispatch hook), fail closed, and the grant's
 *      killEpoch must equal the live epoch — a kill (even one since
 *      restored) between approval and execution refuses.
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
   * Repositories the broker will act on. undefined = any the installation
   * covers; set it in production so a compromised same-uid requester cannot
   * even ask about repos outside the deployment's intent.
   */
  allowedRepos?: readonly string[];
  /** per-connection budget for the full request/response exchange */
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
  | { ok: false; kind: "refused"; error: string }
  | { ok: false; kind: "connector"; outcome: "not-performed" | "unknown"; error: string };

export function createMergeBroker(options: MergeBrokerOptions): MergeBroker {
  const {
    tokens,
    ledger,
    grantKey,
    fetchLiveKillState,
    allowedRepos,
    requestTimeoutMs = 40_000,
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

  /** Validate the grant independently, then PERFORM the merge. */
  async function merge(rawGrant: unknown, rawArgs: unknown): Promise<WireResponse> {
    const verified = verifyMergeGrant(rawGrant, grantKey, { now });
    if (!verified.ok) throw new BrokerRefusal(`grant rejected: ${verified.reason}`);
    const grant = verified.grant;

    // single-use burns HERE, before anything else can act on it
    if (burnedJti.has(grant.jti)) throw new BrokerRefusal("grant already used (single-use)");
    burnedJti.add(grant.jti);

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

    // kill recheck ACROSS the mint (beforeDispatch): the token mint can take
    // seconds; a kill or epoch change during it aborts before anything is sent
    const client = mergeClient(async () => {
      const after = await live();
      if (after.killed || after.epoch !== before.epoch) {
        throw new Error("kill state changed during token minting");
      }
    });

    try {
      const result = await client.mergePullRequest(mergeArgs);
      return { ok: true, merged: result.merged, sha: result.sha, message: result.message };
    } catch (err) {
      if (err instanceof ConnectorCallError) {
        return { ok: false, kind: "connector", outcome: err.outcome, error: err.message };
      }
      return { ok: false, kind: "connector", outcome: "unknown", error: errText(err) };
    }
  }

  const burnedJti = new Set<string>();

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
    const timer = setTimeout(() => finish({ ok: false, kind: "refused", error: "request timed out" }), requestTimeoutMs);

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
            finish(await merge(req.grant, req.args));
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
