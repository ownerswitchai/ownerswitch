import { createHash } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

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
 *    directory entry is fsynced after it (best-effort on platforms where a
 *    directory fd cannot be fsynced — the file's own fsync is the primary
 *    barrier). A burn a crash could forget is not a burn, so a failure to
 *    persist REFUSES the merge rather than proceeding on memory alone.
 *
 * The record also carries the dispatch OUTCOME once known ("performed",
 * "not-performed", or a connector classification), so an in-doubt caller —
 * one whose socket died mid-dispatch — can come back and ask what actually
 * happened ({op:"outcome"} on the broker socket) instead of guessing.
 *
 * Records are pruned only once safely past the grant's own expiry plus a
 * retention slack: until then the jti must stay burned (replay window) and
 * the outcome must stay queryable (in-doubt resolution).
 */

export type BurnState = "dispatching" | "performed" | "connector-error" | "not-performed" | "unreadable";

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
}

export interface BurnStoreOptions {
  now?: () => number;
  /** how long past a grant's expiry its record stays queryable; default 6h */
  retentionMs?: number;
}

/** Records are tiny JSON; anything bigger is corruption, not a record. */
const MAX_RECORD_BYTES = 16 * 1024;

export function createJtiBurnStore(dir: string, opts: BurnStoreOptions = {}): JtiBurnStore {
  const now = opts.now ?? Date.now;
  const retentionMs = opts.retentionMs ?? 6 * 60 * 60_000;

  mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertBurnDirHardened(dir);

  // jti values come from VERIFIED grants (control-plane-authored), but the
  // filename never trusts that: a digest is always path-safe.
  const recordPath = (jti: string): string =>
    join(dir, `${createHash("sha256").update(jti, "utf8").digest("hex")}.json`);

  function fsyncDirBestEffort(): void {
    // Linux supports fsync on a directory fd (and the deployment doc says
    // Linux); elsewhere this may throw — the file's own fsync already
    // happened, so a directory-entry sync failure downgrades durability
    // rather than correctness, and is tolerated.
    try {
      const fd = openSync(dir, "r");
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    } catch {
      /* tolerated — see above */
    }
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
    } catch {
      return undefined;
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
      const path = recordPath(jti);
      try {
        writeRecord(path, { jti, expiresAt, state: "dispatching", burnedAt: now() }, "wx");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") return "already-burned";
        throw new Error(
          `the burn store could not persist the single-use burn (${err instanceof Error ? err.message : "write failed"}) — refusing to dispatch on a burn that a restart would forget`,
        );
      }
      fsyncDirBestEffort();
      return "burned";
    },

    record(jti: string, patch: Partial<BurnRecord> & { state: BurnState }): void {
      const path = recordPath(jti);
      const existing = readRecord(path);
      const base: BurnRecord =
        existing !== undefined && existing.state !== "unreadable"
          ? existing
          : { jti, expiresAt: 0, state: "dispatching", burnedAt: now() };
      writeRecord(path, { ...base, ...patch }, "w");
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
  };
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
