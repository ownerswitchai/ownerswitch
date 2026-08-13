/**
 * The BOOTSTRAP invite channel — a permission-protected Unix socket, and
 * deliberately NOT an HTTP route (apps/owner/DESIGN.md §2): minting the
 * first invite is the root-of-trust ceremony, so its transport is filesystem
 * permissions on the host, the boundary the operator already holds. An HTTP
 * loopback "bypass" would make every same-host process a potential
 * bootstrapper; a 0600 socket in a 0700 directory makes it exactly the
 * socket owner.
 *
 * Protocol, one round per connection: the client (the host CLI) writes ONE
 * newline-terminated JSON request — {tokenHash, ownerId, deviceName}, the
 * hash COMMITMENT and labels, never a secret — and reads ONE
 * newline-terminated JSON response (BootstrapMintResult). The secret is
 * generated in the CLI's process and never crosses this socket; the server
 * returns the ceremony contract (inviteId + both challenges + rp/origin)
 * and nothing worth capturing.
 */
import { chmodSync, statSync, unlinkSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { dirname, isAbsolute } from "node:path";
import type { BootstrapMintRequest, BootstrapMintResult } from "./server.js";

/** one request line; anything longer was not written by the CLI */
const MAX_REQUEST_BYTES = 8 * 1024;
const CONNECTION_TIMEOUT_MS = 5_000;

export interface BootstrapSocketOptions {
  /** absolute path for the Unix socket; parent must be a private directory */
  socketPath: string;
  /** the control plane's bootstrapMintInvite — the ONLY thing this socket can do */
  mint: (request: BootstrapMintRequest) => BootstrapMintResult;
}

/**
 * Bind the bootstrap socket. Refuses an unsafe namespace up front: the
 * parent directory must exist, be owned by root or this process, and grant
 * no group/world write — whoever can replace the socket path IS a
 * bootstrapper. A stale socket file is removed only if it actually is a
 * socket; any other file at that path is somebody else's and refuses.
 * After listen, the socket itself is pinned to 0600.
 */
export function createBootstrapInviteSocket(opts: BootstrapSocketOptions): Server {
  const { socketPath, mint } = opts;
  if (!isAbsolute(socketPath)) {
    throw new Error(`bootstrap socket path must be absolute, got "${socketPath}"`);
  }
  const dir = dirname(socketPath);
  const dirStat = statSync(dir);
  if (!dirStat.isDirectory()) {
    throw new Error(`bootstrap socket parent "${dir}" is not a directory`);
  }
  const ourUid = typeof process.getuid === "function" ? process.getuid() : 0;
  if (dirStat.uid !== 0 && dirStat.uid !== ourUid) {
    throw new Error(
      `bootstrap socket parent "${dir}" is owned by uid ${dirStat.uid} — not root or this process; ` +
        "whoever owns the socket's directory can replace the socket and become a bootstrapper",
    );
  }
  if ((dirStat.mode & 0o022) !== 0) {
    throw new Error(
      `bootstrap socket parent "${dir}" is group- or world-writable (mode ` +
        `${(dirStat.mode & 0o777).toString(8)}) — a writable parent lets the socket be swapped`,
    );
  }
  let existing: ReturnType<typeof statSync> | null = null;
  try {
    existing = statSync(socketPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (existing !== null) {
    if (!existing.isSocket()) {
      throw new Error(
        `"${socketPath}" exists and is not a socket — refusing to unlink somebody else's file`,
      );
    }
    unlinkSync(socketPath); // a stale socket from a previous run
  }

  const server = createServer((socket) => {
    socket.setTimeout(CONNECTION_TIMEOUT_MS, () => socket.destroy());
    let buffered = "";
    let answered = false;
    const answer = (result: BootstrapMintResult) => {
      if (answered) return;
      answered = true;
      socket.end(`${JSON.stringify(result)}\n`);
    };
    socket.on("data", (chunk) => {
      if (answered) return;
      buffered += chunk.toString("utf8");
      if (buffered.length > MAX_REQUEST_BYTES) {
        return answer({ ok: false, error: "request too large" });
      }
      const newline = buffered.indexOf("\n");
      if (newline === -1) return;
      const line = buffered.slice(0, newline);
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return answer({ ok: false, error: "malformed JSON request" });
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return answer({ ok: false, error: "request must be a JSON object" });
      }
      // the mint validates its own fields fail-closed; this cast adds nothing
      answer(mint(parsed as BootstrapMintRequest));
    });
    socket.on("error", () => socket.destroy());
  });

  server.listen(socketPath, () => {
    // private to the socket's owner from the first usable instant
    chmodSync(socketPath, 0o600);
  });
  return server;
}
