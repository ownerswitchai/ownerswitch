/**
 * The BOOTSTRAP invite channel — a permission-protected Unix socket, and
 * deliberately NOT an HTTP route (apps/owner/DESIGN.md §2): minting the
 * first invite is the root-of-trust ceremony, so its transport is filesystem
 * permissions on the host, the boundary the operator already holds.
 *
 * The namespace is defended like the registry's own (the hardened stores'
 * discipline, because reaching this socket IS bootstrap authority):
 *  - the socket path is required absolute, CANONICALISED, and its real
 *    ancestor chain walked — root/this-process owners only, never group- or
 *    world-writable;
 *  - the DIRECT parent must additionally be EXACTLY 0700 and owned by
 *    root/this process: even a transiently permissive socket inode is then
 *    unreachable by any other uid, because traversal already fails at the
 *    parent;
 *  - the parent's identity (dev+ino) is pinned at creation and re-verified
 *    immediately before the socket is published;
 *  - the socket is BOUND AT A RANDOM TEMP NAME in that parent, chmodded
 *    0600 while still unpublished, and only then renamed to its final name
 *    — there is no instant at which the published path names a socket with
 *    open modes, whatever the process umask says.
 *
 * Protocol, one round per connection: the client (the host CLI) writes ONE
 * newline-terminated JSON request — {tokenHash, ownerId, deviceName}, the
 * hash COMMITMENT and labels, never a secret — and reads ONE
 * newline-terminated JSON response (BootstrapMintResult: the complete
 * secret-free creation contract). The invite secret is generated in the
 * CLI's process; it never rides this socket and is never persisted
 * server-side (it is spent exactly once later, as the preimage in the
 * enrolment POST body).
 */
import { randomBytes } from "node:crypto";
import { chmodSync, renameSync, statSync, unlinkSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { basename, dirname, join } from "node:path";
import { canonicalTrustedStandingPath } from "./device-standing.js";
import type { BootstrapMintRequest, BootstrapMintResult } from "./server.js";

/** one request line, counted in WIRE BYTES; anything longer was not written by the CLI */
const MAX_REQUEST_BYTES = 8 * 1024;
const CONNECTION_TIMEOUT_MS = 5_000;

export interface BootstrapSocketOptions {
  /** absolute path for the Unix socket; parent must be private (exactly 0700) */
  socketPath: string;
  /** the control plane's bootstrapMintInvite — the ONLY thing this socket can do */
  mint: (request: BootstrapMintRequest) => BootstrapMintResult;
  /** test-only: skip the trusted-ancestry walk (public tmp roots fail it by design) */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

/**
 * Bind and PUBLISH the bootstrap socket. Resolves only once the socket is
 * live at its final path with mode 0600 behind an exactly-0700 parent —
 * there is no usable instant before the boundary holds. Rejects (and closes
 * the half-made listener) on any namespace surprise.
 */
export async function createBootstrapInviteSocket(opts: BootstrapSocketOptions): Promise<Server> {
  const { socketPath, mint } = opts;
  const canonical = canonicalTrustedStandingPath(
    socketPath,
    {
      ...(opts.unsafeAllowUntrustedAncestryForTests === true
        ? { unsafeAllowUntrustedAncestryForTests: true }
        : {}),
    },
    "bootstrap socket",
  );
  const dir = dirname(canonical);
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
  // EXACTLY 0700: the parent is the boundary that covers the bind-to-chmod
  // window too — with no traversal for anyone else, a transiently
  // permissive socket inode is still unreachable
  if ((dirStat.mode & 0o777) !== 0o700) {
    throw new Error(
      `bootstrap socket parent "${dir}" has mode ${(dirStat.mode & 0o777).toString(8)} — it must be ` +
        "EXACTLY 0700: reaching this socket is bootstrap authority, so its directory is private, full stop",
    );
  }
  const dirDev = dirStat.dev;
  const dirIno = dirStat.ino;

  let existing: ReturnType<typeof statSync> | null = null;
  try {
    existing = statSync(canonical);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (existing !== null) {
    if (!existing.isSocket()) {
      throw new Error(
        `"${canonical}" exists and is not a socket — refusing to unlink somebody else's file`,
      );
    }
    unlinkSync(canonical); // a stale socket from a previous run
  }

  const server = createServer((socket) => {
    socket.setTimeout(CONNECTION_TIMEOUT_MS, () => socket.destroy());
    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let answered = false;
    const answer = (result: BootstrapMintResult) => {
      if (answered) return;
      answered = true;
      socket.end(`${JSON.stringify(result)}\n`);
    };
    socket.on("data", (chunk: Buffer) => {
      if (answered) return;
      // WIRE bytes, before any decoding — multibyte UTF-8 cannot outrun the cap
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_REQUEST_BYTES) {
        return answer({ ok: false, error: "request too large" });
      }
      chunks.push(chunk);
      const buffered = Buffer.concat(chunks).toString("utf8");
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
      // the mint enforces its own EXACT own-key schema; this cast adds nothing
      answer(mint(parsed as BootstrapMintRequest));
    });
    socket.on("error", () => socket.destroy());
  });

  // ATOMIC PUBLISH: bind at a random temp name in the same (0700) parent,
  // pin 0600 on the unpublished inode, re-verify the parent's identity, and
  // only then rename to the final name — the published path never names a
  // socket that is not already private.
  const tempPath = join(dir, `.${basename(canonical)}.${randomBytes(8).toString("hex")}.tmp`);
  return await new Promise<Server>((resolvePromise, rejectPromise) => {
    const fail = (err: Error) => {
      server.close();
      try {
        unlinkSync(tempPath);
      } catch {
        /* best effort — the temp name is random and 0600 in a 0700 dir */
      }
      rejectPromise(err);
    };
    server.once("error", (err) => fail(err instanceof Error ? err : new Error(String(err))));
    server.listen(tempPath, () => {
      try {
        chmodSync(tempPath, 0o600);
        const recheck = statSync(dir);
        if (!recheck.isDirectory() || recheck.dev !== dirDev || recheck.ino !== dirIno) {
          throw new Error(
            `bootstrap socket parent "${dir}" changed identity between check and publish — refusing`,
          );
        }
        renameSync(tempPath, canonical);
        const published = statSync(canonical);
        if (!published.isSocket() || (published.mode & 0o777) !== 0o600) {
          throw new Error(
            `published bootstrap socket has mode ${(published.mode & 0o777).toString(8)} — expected 0600`,
          );
        }
        resolvePromise(server);
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    });
  });
}
