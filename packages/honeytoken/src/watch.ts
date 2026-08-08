import { randomBytes } from "node:crypto";
import {
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  watch,
  writeFileSync,
  type FSWatcher,
  type Stats,
} from "node:fs";
import { join } from "node:path";
import { scanForHoneytokens } from "./scan.js";

/**
 * File tripwires: any touch of a planted decoy file fires onTrip.
 *
 * How touches are actually detected — stated honestly, because fs.watch alone
 * cannot see reads:
 *
 *  - fs.watch on each path delivers write / replace / delete events promptly
 *    (and, on Linux, metadata events, which is how an atime bump surfaces).
 *  - a stat() poller samples atime and mtime on a short interval. A read is
 *    "atime advanced past the armed baseline" — the only read signal a
 *    portable, dependency-free watcher has.
 *  - relatime (the Linux mount default) only updates atime when atime <= mtime,
 *    so arming PRIMES each file by backdating its atime below its mtime. That
 *    re-cocks the tripwire: the next read — the one that matters — bumps atime.
 *  - on a noatime mount reads never surface at all. Writes, replaces and
 *    deletes still trip. Use fsReportsReads() to probe a directory and warn.
 *
 * Every fs.watch event is classified by stat comparison, never by the event
 * type fs.watch claims: the event stream is documented-unreliable, and our own
 * arming utimes would otherwise read as a touch.
 *
 * One trip per path: the first touch fires onTrip and disarms that path (the
 * response — a kill — is global and already in flight); other paths stay armed
 * so every touched token still reaches the audit log.
 */

export type TripCause = "read" | "write" | "rename" | "unlink";

export interface FileTrip {
  path: string;
  cause: TripCause;
  /** Canary ids found in the file when its tripwire was armed. */
  canaryIds: string[];
  /** Watcher-clock time of detection (ms since epoch). */
  at: number;
  /** Human line for logs and the kill reason. */
  detail: string;
}

export interface WatchHoneytokenFilesOptions {
  /** Planted decoy FILES (not directories). Arming a missing path throws. */
  paths: string[];
  onTrip: (trip: FileTrip) => void;
  /** atime/mtime sampling cadence; default 500 ms. */
  pollMs?: number;
  now?: () => number;
  /** One line per event, loud by default (console.error). */
  log?: (line: string) => void;
}

export interface HoneytokenWatcher {
  close(): void;
}

/** How far below mtime arming pushes atime, so relatime records the next read. */
const PRIME_BACKDATE_MS = 2_000;

const DEFAULT_POLL_MS = 500;

interface ArmedFile {
  canaryIds: string[];
  ino: bigint | number;
  atimeMs: number;
  mtimeMs: number;
  tripped: boolean;
  watcher: FSWatcher;
}

export function watchHoneytokenFiles(opts: WatchHoneytokenFilesOptions): HoneytokenWatcher {
  const now = opts.now ?? Date.now;
  const log = opts.log ?? ((line: string) => console.error(line));
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const armed = new Map<string, ArmedFile>();

  function trip(path: string, state: ArmedFile, cause: TripCause, detail: string): void {
    state.tripped = true;
    state.watcher.close(); // this tripwire has served its purpose
    const ids = state.canaryIds.join("+") || "(none found at arm time)";
    log(`[honeytoken] ⚡ TRIPPED — ${detail} (canary ${ids})`);
    opts.onTrip({ path, cause, canaryIds: [...state.canaryIds], at: now(), detail });
  }

  /** Stat-compare classification — shared by fs.watch events and the poller. */
  function inspect(path: string): void {
    const state = armed.get(path);
    if (state === undefined || state.tripped) return;
    let st: Stats;
    try {
      st = statSync(path);
    } catch {
      trip(path, state, "unlink", `${path} deleted`);
      return;
    }
    if (st.ino !== state.ino) {
      trip(path, state, "rename", `${path} renamed or replaced`);
      return;
    }
    if (st.mtimeMs > state.mtimeMs) {
      trip(path, state, "write", `write to ${path}`);
      return;
    }
    if (st.atimeMs > state.atimeMs) {
      trip(path, state, "read", `read of ${path} (atime advanced)`);
      return;
    }
    // Timestamps moved backwards (another primer, clock step): track the lower
    // bound so the next forward move still reads as a touch.
    if (st.atimeMs < state.atimeMs) state.atimeMs = st.atimeMs;
    if (st.mtimeMs < state.mtimeMs) state.mtimeMs = st.mtimeMs;
  }

  function arm(path: string): void {
    // Arming must fail loudly: a tripwire that silently didn't arm is worse
    // than no tripwire, so any of these throws aborts watchHoneytokenFiles.
    const content = readFileSync(path, "utf8"); // our own read — before priming
    const canaryIds = scanForHoneytokens(content).map((m) => m.canaryId);
    const before = statSync(path);
    if (!before.isFile()) throw new Error(`${path} is not a regular file — cannot arm a tripwire on it`);
    // Prime atime below mtime so relatime mounts record the NEXT read (ours
    // just consumed the free one a fresh file gets).
    utimesSync(path, new Date(before.mtimeMs - PRIME_BACKDATE_MS), new Date(before.mtimeMs));
    const baseline = statSync(path);
    // fs.watch is installed after priming, so our own utimes never reads as an event.
    const watcher = watch(path, () => inspect(path));
    watcher.on("error", (err) => {
      // the poller keeps covering this path — fs.watch is best-effort by design
      log(`[honeytoken] fs.watch error on ${path} (poller still armed): ${String(err)}`);
    });
    armed.set(path, {
      canaryIds,
      ino: baseline.ino,
      atimeMs: baseline.atimeMs,
      mtimeMs: baseline.mtimeMs,
      tripped: false,
      watcher,
    });
    log(
      `[honeytoken] armed ${path} (${canaryIds.length} canary id${canaryIds.length === 1 ? "" : "s"})`,
    );
  }

  try {
    for (const path of opts.paths) arm(path);
  } catch (err) {
    for (const state of armed.values()) state.watcher.close();
    throw err;
  }

  const poller = setInterval(() => {
    for (const path of armed.keys()) inspect(path);
  }, pollMs);
  // never the reason a process can't exit — the fs.watch handles hold it open
  poller.unref?.();

  return {
    close(): void {
      clearInterval(poller);
      for (const state of armed.values()) state.watcher.close();
      armed.clear();
    },
  };
}

/**
 * Probe whether reads surface on `dir`'s filesystem: plant a scratch file,
 * prime its atime the way arming does, read it, and see if atime advanced.
 * False on noatime mounts — where a planted token still trips on write,
 * replace and delete, but NOT on read. Callers should warn the operator.
 */
export function fsReportsReads(dir: string): boolean {
  const probe = join(dir, `.oswt-probe-${randomBytes(4).toString("hex")}`);
  try {
    writeFileSync(probe, "probe");
    const before = statSync(probe);
    const primedAtimeMs = before.mtimeMs - PRIME_BACKDATE_MS;
    utimesSync(probe, new Date(primedAtimeMs), new Date(before.mtimeMs));
    readFileSync(probe);
    const after = statSync(probe);
    return after.atimeMs - primedAtimeMs > 1;
  } catch {
    return false;
  } finally {
    try {
      unlinkSync(probe);
    } catch {
      // best-effort cleanup — a leftover probe file is inert
    }
  }
}
