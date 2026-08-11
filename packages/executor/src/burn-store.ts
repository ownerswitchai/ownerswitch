import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const O_DIRECTORY = constants.O_DIRECTORY ?? 0;

/**
 * JtiBurnStore — the broker's DURABLE, ATOMIC single-use ledger.
 *
 * Why a directory and not a Set: an in-memory burn evaporates on restart,
 * and "single-use per process" is not single-use — a grant replayed at a
 * restarted broker (or at a second broker sharing the key) would execute a
 * second time on one owner approval. The burn has to survive the process
 * and be arbitrated between processes, so the filesystem does both:
 *
 *  - BURN = create the jti's record file with O_CREAT|O_EXCL. The kernel
 *    guarantees exactly one creator; every other attempt — same process,
 *    restarted process, sibling broker on a shared directory — sees EEXIST
 *    and refuses. No read-then-write window exists.
 *  - DURABLE = the record is fsynced before the burn is trusted, and the
 *    directory ENTRY is fsynced after it through a directory fd PINNED at
 *    startup. EVERY directory-fsync failure is fatal — a burn a crash
 *    could forget is not a burn, so a failure to persist REFUSES the
 *    merge rather than proceeding on memory alone.
 *  - PATH-STABLE = the directory is opened once and its identity retained:
 *    the final component must not be a symlink, containment checks run on
 *    the POST-realpath result (an intermediate symlink cannot smuggle the
 *    store into the workspace), every ancestor must be trusted (owned by
 *    root or the broker's uid, not group/world-writable — otherwise a
 *    writable ancestor could be renamed away and replaced, redirecting
 *    burns into a fresh namespace), and before every burn the pathname is
 *    re-resolved and required to still denote the PINNED inode (dev+ino
 *    equality against the retained fd). Node exposes no openat(), so
 *    record I/O is by pathname; the trusted-ancestor rule is what removes
 *    the writer who could exploit the residual check-to-open window, and
 *    the inode pin detects any swap that happens anyway.
 *
 * The record also carries the dispatch OUTCOME once known ("performed",
 * "merged-state-observed", "not-performed", or a connector
 * classification), so an in-doubt caller — one whose socket died
 * mid-dispatch — can come back and ask what actually happened
 * ({op:"outcome"} on the broker socket) instead of guessing.
 *
 * Records are pruned only once safely past the grant's own expiry plus a
 * retention slack: until then the jti must stay burned (replay window) and
 * the outcome must stay queryable (in-doubt resolution).
 */

export type BurnState =
  | "dispatching"
  /** GitHub's direct 200 confirmed THIS dispatch performed the merge */
  | "performed"
  /**
   * an ambiguous dispatch, after which a verification read observed the PR
   * merged — that proves the PR's STATE, not that this dispatch did it
   */
  | "merged-state-observed"
  | "connector-error"
  | "not-performed"
  | "unreadable";

export interface BurnRecord {
  jti: string;
  /** the grant's own expiresAt — drives retention, never trust extension */
  expiresAt: number;
  state: BurnState;
  burnedAt: number;
  /** connector classification when state === "connector-error" */
  outcome?: "not-performed" | "unknown";
  merged?: boolean;
  sha?: string;
  message?: string;
  error?: string;
}

export interface JtiBurnStore {
  /**
   * Atomically claim the jti. "burned" — this caller won and may dispatch;
   * "already-burned" — someone (possibly a previous life of this process)
   * already did. Throws when the claim cannot be made DURABLE; the caller
   * must treat that as a refusal, never as a pass.
   */
  burn(jti: string, expiresAt: number): "burned" | "already-burned";
  /** Record the dispatch outcome on an already-burned jti (single writer:
   * only the burn winner calls this). Throws on I/O failure. */
  record(jti: string, patch: Partial<BurnRecord> & { state: BurnState }): void;
  /** The burn record, or undefined when the jti was never burned here. */
  lookup(jti: string): BurnRecord | undefined;
  /** Remove records safely past expiry + retention. Returns count removed. */
  pruneExpired(): number;
  /** Release the pinned directory fd. The store is unusable afterwards. */
  close(): void;
}

export interface BurnStoreOptions {
  now?: () => number;
  /** how long past a grant's expiry its record stays queryable; default 6h */
  retentionMs?: number;
  /**
   * The agent-reachable workspace the store must NOT live under — same rule
   * as the App private key. When set, a burnDir whose RESOLVED real path is
   * inside the resolved workspace is refused (checked after realpath, so an
   * intermediate symlink cannot smuggle it in). A symlinked final component
   * is refused regardless: a retargetable symlink could switch the store's
   * namespace and resurrect spent grants.
   */
  workspaceDir?: string;
  /**
   * TESTS ONLY. Skips the trusted-ancestor requirement (every ancestor
   * owned by root or this uid, no group/world write) so suites can run
   * under tmpdir(), whose /tmp ancestor is world-writable by design.
   * Production paths (the broker CLI) never set this — an untrusted
   * ancestor is exactly the writer who can rename the store away and
   * replay spent grants.
   */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

/** Records are tiny JSON; anything bigger is corruption, not a record. */
const MAX_RECORD_BYTES = 16 * 1024;

export function createJtiBurnStore(rawDir: string, opts: BurnStoreOptions = {}): JtiBurnStore {
  const now = opts.now ?? Date.now;
  const retentionMs = opts.retentionMs ?? 6 * 60 * 60_000;

  // Path stability BEFORE creating anything: a relative path addresses a
  // different directory per cwd. Same placement rule as the App private key.
  if (!isAbsolute(rawDir)) {
    throw new Error(
      `burn store directory must be an absolute path, got "${rawDir}" — a relative path ` +
        `silently addresses a different directory per working directory`,
    );
  }
  mkdirSync(rawDir, { recursive: true, mode: 0o700 });
  // Refuse a symlinked final component: statSync would follow it, so a
  // retargetable link could move the store's namespace after this check.
  const linkStat = lstatSync(rawDir);
  if (linkStat.isSymbolicLink()) {
    throw new Error(
      `burn store directory "${rawDir}" is a symlink — refusing to follow it; a retargetable ` +
        `link could switch the store's namespace and un-burn grants`,
    );
  }
  // Canonicalize and RETAIN the resolved real path; every later operation
  // uses this, not the caller's string.
  const dir = realpathSync(rawDir);
  // Workspace containment is checked on the POST-realpath result, both
  // sides resolved — so an INTERMEDIATE symlink cannot smuggle the store
  // inside the agent workspace while the raw string looks outside it.
  if (opts.workspaceDir !== undefined) {
    let workspace: string;
    try {
      workspace = realpathSync(resolve(opts.workspaceDir));
    } catch {
      workspace = resolve(opts.workspaceDir);
    }
    const rel = relative(workspace, dir);
    if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
      throw new Error(
        `burn store directory "${rawDir}" resolves to "${dir}", inside the agent workspace ` +
          `"${workspace}" — the agent could delete burns and replay spent grants; place it ` +
          `outside the workspace`,
      );
    }
  }
  // Every ANCESTOR must be trusted: owned by root or this uid, and not
  // group/world-writable. A writable ancestor is a writer who can rename
  // the store away and substitute a fresh namespace — no later check on
  // the leaf directory can defend against that.
  if (opts.unsafeAllowUntrustedAncestryForTests !== true) {
    assertTrustedAncestry(dir);
  }
  assertBurnDirHardened(dir);
  // Pin the directory's IDENTITY: open it once and retain the fd. The fd is
  // what gets fsynced (so durability commits into the pinned inode), and
  // before every burn the pathname is re-resolved and required to still
  // denote this dev+ino — a swapped ancestor redirects the path, the pin
  // detects it, and the burn refuses instead of landing in a fresh
  // namespace.
  const dirFd = openSync(dir, constants.O_RDONLY | O_DIRECTORY);
  const pinned = fstatSync(dirFd);
  let closed = false;

  function assertStillPinned(): void {
    if (closed) throw new Error("burn store is closed");
    let live;
    try {
      live = statSync(dir);
    } catch (err) {
      throw new Error(
        `burn store directory "${dir}" is no longer reachable (${err instanceof Error ? err.message : "stat failed"}) — refusing to burn into an unknown namespace`,
      );
    }
    if (live.ino !== pinned.ino || live.dev !== pinned.dev) {
      throw new Error(
        `burn store directory "${dir}" no longer denotes the directory pinned at startup — ` +
          `an ancestor was renamed or replaced; refusing to burn into a substituted namespace`,
      );
    }
  }

  // jti values come from VERIFIED grants (control-plane-authored), but the
  // filename never trusts that: a digest is always path-safe.
  const recordPath = (jti: string): string =>
    join(dir, `${createHash("sha256").update(jti, "utf8").digest("hex")}.json`);

  /**
   * Fsync the PINNED directory fd so the newly-created record's ENTRY is
   * durable — a file's own fsync does not commit its parent directory
   * entry, so without this a crash could lose the burn and resurrect the
   * jti. EVERY failure here throws, on every platform: a burn a crash
   * could forget is not a burn, and swallowing "unsupported" errnos would
   * quietly downgrade the boundary exactly where it matters. (The
   * documented deployment is Linux, where fsync on a directory fd is
   * supported; a platform that cannot do this cannot host the burn store.)
   */
  function fsyncDir(): void {
    fsyncSync(dirFd);
  }

  function writeRecord(path: string, record: BurnRecord, flag: "wx" | "w"): void {
    const fd = openSync(path, flag, 0o600);
    try {
      writeSync(fd, JSON.stringify(record), null, "utf8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  function readRecord(path: string): BurnRecord | undefined {
    let text: string;
    try {
      text = readFileSync(path, { encoding: "utf8" });
    } catch (err) {
      // A genuinely absent record is `undefined` (never burned here); a
      // record that EXISTS but cannot be read is NOT "never presented" — it
      // is a burn whose outcome is unknown, and must read that way, never as
      // a clean miss.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      return { jti: "", expiresAt: 0, state: "unreadable", burnedAt: 0 };
    }
    if (text.length > MAX_RECORD_BYTES) return { jti: "", expiresAt: 0, state: "unreadable", burnedAt: 0 };
    try {
      const parsed = JSON.parse(text) as Partial<BurnRecord>;
      if (typeof parsed.jti !== "string" || typeof parsed.expiresAt !== "number") {
        return { jti: "", expiresAt: 0, state: "unreadable", burnedAt: 0 };
      }
      return parsed as BurnRecord;
    } catch {
      // a half-written record (crash between create and fsync) still counts
      // as burned — existence is the burn; the content is bookkeeping
      return { jti: "", expiresAt: 0, state: "unreadable", burnedAt: 0 };
    }
  }

  return {
    burn(jti: string, expiresAt: number): "burned" | "already-burned" {
      // the burn must land in the directory pinned at startup, not wherever
      // the pathname resolves after an ancestor swap
      assertStillPinned();
      const path = recordPath(jti);
      try {
        writeRecord(path, { jti, expiresAt, state: "dispatching", burnedAt: now() }, "wx");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") return "already-burned";
        throw new Error(
          `the burn store could not persist the single-use burn (${err instanceof Error ? err.message : "write failed"}) — refusing to dispatch on a burn that a restart would forget`,
        );
      }
      // The record file is fsynced (writeRecord); now commit its directory
      // ENTRY too, into the PINNED inode, or the burn is not durable. Any
      // failure here refuses — no platform exemptions.
      try {
        fsyncDir();
      } catch (err) {
        throw new Error(
          `the burn store could not durably commit the single-use burn (${err instanceof Error ? err.message : "dir fsync failed"}) — refusing to dispatch on a burn a crash could forget`,
        );
      }
      return "burned";
    },

    record(jti: string, patch: Partial<BurnRecord> & { state: BurnState }): void {
      assertStillPinned();
      const path = recordPath(jti);
      const existing = readRecord(path);
      const base: BurnRecord =
        existing !== undefined && existing.state !== "unreadable"
          ? existing
          : { jti, expiresAt: 0, state: "dispatching", burnedAt: now() };
      writeRecord(path, { ...base, ...patch }, "w");
      fsyncDir();
    },

    lookup(jti: string): BurnRecord | undefined {
      return readRecord(recordPath(jti));
    },

    pruneExpired(): number {
      let removed = 0;
      let names: string[];
      try {
        names = readdirSync(dir);
      } catch {
        return 0;
      }
      for (const name of names) {
        if (!name.endsWith(".json")) continue;
        const path = join(dir, name);
        const record = readRecord(path);
        if (record === undefined) continue;
        const anchor =
          record.state === "unreadable"
            ? (() => {
                try {
                  return statSync(path).mtimeMs;
                } catch {
                  return now();
                }
              })()
            : record.expiresAt;
        if (now() > anchor + retentionMs) {
          try {
            unlinkSync(path);
            removed += 1;
          } catch {
            /* already gone or unremovable — the next prune retries */
          }
        }
      }
      return removed;
    },

    close(): void {
      if (closed) return;
      closed = true;
      closeSync(dirFd);
    },
  };
}

/**
 * Every ancestor of the store must be trusted: owned by root or this
 * process's uid, and writable by NEITHER group NOR other. Any other writer
 * on the path can rename a component away and substitute its own tree —
 * after which no check on the leaf directory means anything. Sticky
 * world-writable directories (/tmp) are refused too: the sticky bit stops
 * deletion of OTHER users' entries, not the substitution game played one
 * level down.
 */
function assertTrustedAncestry(realDir: string): void {
  const getuid = process.getuid;
  const ourUid = getuid === undefined ? 0 : getuid.call(process);
  let current = realDir;
  for (;;) {
    const parent = dirname(current);
    if (parent === current) break; // reached the filesystem root
    current = parent;
    const stat = statSync(current);
    if (stat.uid !== 0 && stat.uid !== ourUid) {
      throw new Error(
        `burn store ancestor "${current}" is owned by uid ${stat.uid} (not root or this ` +
          `process's uid ${ourUid}) — an untrusted owner of any ancestor can substitute the ` +
          `whole store; place the store under a root-owned path like /var/lib`,
      );
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error(
        `burn store ancestor "${current}" is group- or world-writable (mode ` +
          `${(stat.mode & 0o777).toString(8)}) — any writer on the ancestry can rename the ` +
          `store away and replay spent grants; place the store under a 0755-or-tighter path`,
      );
    }
  }
}

/**
 * The burn directory is part of the single-use boundary: a peer that can
 * delete records un-burns grants. Broker-owned, no group/world access.
 */
function assertBurnDirHardened(dir: string): void {
  const stat = statSync(dir);
  if (!stat.isDirectory()) throw new Error(`burn store path "${dir}" is not a directory`);
  const getuid = process.getuid;
  if (getuid !== undefined && stat.uid !== getuid.call(process)) {
    throw new Error(
      `burn store directory "${dir}" is owned by uid ${stat.uid}, not the broker's uid ` +
        `${getuid.call(process)} — a foreign owner could delete burns and resurrect spent grants`,
    );
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `burn store directory "${dir}" grants group or world access (mode ` +
        `${(stat.mode & 0o777).toString(8)}) — chmod 0700 it; anyone who can unlink a record can ` +
        `un-burn a grant`,
    );
  }
}
