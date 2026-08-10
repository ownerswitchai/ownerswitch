import { chmodSync, lstatSync, statSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { dirname } from "node:path";
import type { LiveKillState } from "./executor.js";
import type { InstallationTokenSource } from "./github-app-auth.js";
import { assertSafeRepoName } from "./github-http.js";
import type { SecretLedger } from "./secret-ledger.js";

/**
 * The credential broker — the process that alone holds the GitHub App
 * private key (DESIGN.md §6). In the stdio MCP deployment the client
 * spawns the gateway, so gateway and agent share a uid; a key file the
 * gateway can read is a key file the AGENT can read, and 0600/ownership
 * checks defend against other users, not against a same-uid child. The
 * broker restores the boundary the kernel can actually enforce: it runs
 * under its OWN uid, loads the PEM under that uid, and serves only
 * short-lived, single-repository installation TOKENS over a UNIX domain
 * socket. The gateway process never holds the key in memory.
 *
 * Peer verification, stated honestly: pure Node exposes no SO_PEERCRED, so
 * the allow-listed-uid check is expressed in the one place the kernel
 * enforces it for UNIX sockets — filesystem permission to connect. The
 * socket lives in a directory owned by the broker's uid with NO world
 * access (checked at startup, refused otherwise), and the socket file is
 * chmod 0660 after listen: only the broker's user and its group may
 * connect. Deployments allow-list the gateway by putting its uid in that
 * group. What this CANNOT do — and neither could SO_PEERCRED — is tell the
 * gateway apart from the agent, because they share a uid: a same-uid agent
 * that finds the socket can request TOKENS. The boundary this buys,
 * precisely: the agent can never read the KEY, every token it could
 * obtain is ≤ 1 h, single-repository, contents:write + pull_requests:read,
 * minted only while the kill switch is disengaged, and every mint is a
 * loggable event on the broker's side. The standing credential is out of
 * reach; the residual risk is scoped, expiring, auditable — and stated in
 * THREAT-MODEL.md.
 *
 * Kill state: the broker checks LIVE kill state before answering every
 * request — cached tokens included — through the same fail-closed contract
 * as every other check in the system (unreachable control plane reads as
 * killed). A kill therefore also stops NEW token minting at the broker,
 * one more gate in front of the executor's own two pre-dispatch checks.
 * What a kill does NOT do is revoke tokens already handed out; their ≤ 1 h
 * expiry is the bound (THREAT-MODEL.md §5).
 *
 * Protocol: one JSON line per connection — `{"op":"token","repo":"name"}`
 * → `{"ok":true,"token":"…"}` or `{"ok":false,"error":"…"}` — then the
 * connection closes. Requests are size-capped and time-bounded; error
 * strings pass the ledger's redaction; the log callback never receives a
 * secret.
 */

const MAX_REQUEST_BYTES = 4 * 1024;
const SOCKET_MODE = 0o660;

export interface TokenBrokerOptions {
  /** the real minting source — the only holder of the private key */
  tokens: InstallationTokenSource;
  ledger: SecretLedger;
  /** live kill state, fail-closed (liveKillStateFromControlPlane) */
  fetchLiveKillState: () => Promise<LiveKillState>;
  /**
   * Repositories the broker will mint for. undefined = any repository the
   * installation covers (the installation list still bounds it); set this
   * in production so a compromised same-uid requester cannot even ask for
   * tokens outside the deployment's intent.
   */
  allowedRepos?: readonly string[];
  /** per-connection budget for the full request/response exchange */
  requestTimeoutMs?: number;
  /** audit sink (stderr in the CLI); never given a secret */
  log?: (line: string) => void;
}

export interface TokenBroker {
  listen(socketPath: string): Promise<void>;
  close(): Promise<void>;
}

export function createTokenBroker(options: TokenBrokerOptions): TokenBroker {
  const { tokens, ledger, fetchLiveKillState, allowedRepos, requestTimeoutMs = 15_000 } = options;
  const log = options.log ?? (() => undefined);
  const allowed = allowedRepos === undefined ? undefined : new Set(allowedRepos);
  let server: Server | undefined;
  let boundPath: string | undefined;

  async function answer(repo: unknown): Promise<string> {
    if (typeof repo !== "string") throw new Error("request carries no repository name");
    assertSafeRepoName(repo);
    if (allowed !== undefined && !allowed.has(repo)) {
      throw new Error(`repository "${repo}" is not in the broker's allow-list`);
    }
    // live, per request, cached tokens included — fail closed
    let live: LiveKillState;
    try {
      live = await fetchLiveKillState();
    } catch {
      live = { killed: true, epoch: -1 };
    }
    if (live.killed) {
      throw new Error("kill switch engaged (or control plane unreachable) — no tokens are minted");
    }
    return tokens.tokenFor(repo);
  }

  function handleConnection(socket: Socket): void {
    let buffer = "";
    let done = false;
    const timer = setTimeout(() => {
      finish({ ok: false, error: "request timed out" }, "timeout");
    }, requestTimeoutMs);

    const finish = (response: { ok: boolean; token?: string; error?: string }, note: string): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const body =
        response.ok === true
          ? response
          : { ok: false, error: ledger.redact(response.error ?? "refused").slice(0, 300) };
      socket.end(`${JSON.stringify(body)}\n`);
      log(`[token-broker] ${note}`);
    };

    socket.on("error", () => {
      done = true;
      clearTimeout(timer);
    });
    socket.on("data", (chunk) => {
      if (done) return;
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_REQUEST_BYTES) {
        finish({ ok: false, error: "request too large" }, "oversized request refused");
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      void (async () => {
        let repo: unknown;
        try {
          const parsed: unknown = JSON.parse(line);
          const req = (parsed ?? {}) as { op?: unknown; repo?: unknown };
          if (req.op !== "token") throw new Error("unknown operation");
          repo = req.repo;
          const token = await answer(repo);
          finish({ ok: true, token }, `token served for repo "${String(repo)}"`);
        } catch (err) {
          finish(
            { ok: false, error: err instanceof Error ? err.message : "refused" },
            `refused${typeof repo === "string" ? ` for repo "${repo}"` : ""}: ` +
              ledger.redact(err instanceof Error ? err.message : "refused").slice(0, 200),
          );
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
      // connect(2) on a UNIX socket requires write permission on the socket
      // inode: 0660 = broker's user and group only. The gap between listen()
      // and chmod is closed by the directory check above — a no-world-access
      // directory already denies outsiders the traversal needed to connect.
      chmodSync(socketPath, SOCKET_MODE);
      boundPath = socketPath;
      log(`[token-broker] listening on ${socketPath} (socket mode 0660)`);
    },
    async close(): Promise<void> {
      const s = server;
      server = undefined;
      if (s !== undefined) {
        await new Promise<void>((resolve) => s.close(() => resolve()));
      }
      if (boundPath !== undefined) {
        try {
          unlinkSync(boundPath);
        } catch {
          // already gone
        }
        boundPath = undefined;
      }
    },
  };
}

/**
 * The socket's parent directory IS the peer allow-list (see the module
 * doc), so its permissions are checked, not assumed: broker-owned, and no
 * world access whatsoever. Group access is the deployment's allow-list
 * knob — put the gateway's uid in the directory's group.
 */
function assertSocketDirHardened(socketPath: string): void {
  const dir = dirname(socketPath);
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    throw new Error(
      `token broker socket directory "${dir}" does not exist — create it owned by the ` +
        `broker's user, mode 0750, with the gateway's user in its group`,
    );
  }
  if (!stat.isDirectory()) {
    throw new Error(`token broker socket directory "${dir}" is not a directory`);
  }
  const getuid = process.getuid;
  if (getuid !== undefined && stat.uid !== getuid.call(process)) {
    throw new Error(
      `token broker socket directory "${dir}" is owned by uid ${stat.uid}, not the broker's ` +
        `uid ${getuid.call(process)} — the broker must own its own front door`,
    );
  }
  if ((stat.mode & 0o007) !== 0) {
    throw new Error(
      `token broker socket directory "${dir}" grants world access (mode ` +
        `${(stat.mode & 0o777).toString(8)}) — chmod 0750 it; world access would let any uid ` +
        `on the host request tokens`,
    );
  }
}

function removeStaleSocket(socketPath: string): void {
  let stat;
  try {
    stat = lstatSync(socketPath);
  } catch {
    return; // nothing there — fine
  }
  if (!stat.isSocket()) {
    throw new Error(
      `"${socketPath}" exists and is not a socket — refusing to remove it; pick a socket path ` +
        `the broker owns outright`,
    );
  }
  unlinkSync(socketPath);
}
