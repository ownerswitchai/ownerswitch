/**
 * Persistence for the kill switch: killed/not-killed, the kill epoch, and the
 * attributing kill event, in one small JSON file.
 *
 * Why a file: v0 runs the control plane as ONE process on ONE host, and the
 * state that must survive a restart is tiny — a boolean, a counter, one
 * event. A JSON file published atomically (unique temp file + rename in the
 * same directory) is auditable with `cat`, needs no daemon, and cannot
 * half-write: a reader sees the previous state or the new one, never a torn
 * mix. The limits of that choice are deliberate and documented in
 * packages/mcp/THREAT-MODEL.md §4: single instance only, a directory the
 * agent must not be able to write to, and durability only as good as the
 * platform's fsync.
 *
 * Fail direction, in order of appearance below:
 *  - a file that EXISTS but cannot be read, is not a regular file, or does
 *    not parse loads as "corrupt" — the KillSwitch boots KILLED
 *  - a file that is MISSING on an INITIALISED store (the sibling marker file
 *    exists) also loads as "corrupt": deleting the state file must not be a
 *    restore
 *  - only a store with neither file is a genuine first boot ("absent")
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import { KILL_SOURCES, type KillEvent, type KillSource } from "./kill.js";

export interface PersistedKillState {
  version: 1;
  killed: boolean;
  epoch: number;
  /** the kill event in force; present exactly when killed */
  lastKill?: KillEvent;
}

export type KillStateLoad =
  | { outcome: "absent" }
  | { outcome: "loaded"; state: PersistedKillState }
  | { outcome: "corrupt"; detail: string };

/**
 * A save that returned (did not throw) has PUBLISHED the new state — readers
 * see it. It is DURABLE only when every fsync succeeded too; durable: false
 * means a power cut could still resurface the previous state, and the caller
 * must surface that as degraded persistence, not silence.
 */
export type SaveResult = { durable: true } | { durable: false; detail: string };

export interface KillStateStore {
  load(): KillStateLoad;
  /**
   * Must be atomic: a reader sees the previous state or this one, never a
   * torn write. Throws when the state could not be published at all.
   */
  save(state: PersistedKillState): SaveResult;
  /**
   * Called after a FAILED save. Never throws; returns true only when stale
   * on-disk state can no longer pass for healthy — i.e. a later load() is
   * guaranteed to fail closed rather than report a state save() failed to
   * replace. A false return means the caller must treat the store, and the
   * process's own restart, as unsafe.
   */
  degrade(): boolean;
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

/**
 * Hard ceiling on the kill-state file's byte size — see load() below. The
 * state is a boolean, a small integer epoch, and at most one KillEvent
 * (source, an optional free-text reason, a timestamp); 64 KiB is orders of
 * magnitude more than a legitimate file needs while still bounding memory
 * against a corrupted or hostile-sized file on disk.
 */
export const MAX_KILL_STATE_FILE_BYTES = 64 * 1024;

// O_NOFOLLOW is POSIX; there is no portable way to detect its absence ahead
// of time, so on a platform without it the flag silently degrades to 0 and
// open() FOLLOWS a symlink at the state path like normal. The fstat
// regular-file check in load() below does NOT recover any of that
// protection: by the time you have an fd, the kernel has already resolved
// any symlink to reach it, so fstat(fd) reports the FOLLOWED target's type —
// a symlink to a regular file is indistinguishable, from fstat's point of
// view, from a real regular file sitting directly at that path. Plainly
// stated: on a platform lacking O_NOFOLLOW, load() provides NO symlink
// protection at all — it will happily follow a symlink planted at the state
// path and read whatever it points to. This is the same gap
// packages/honeytoken/src/registry.ts's readRegistryFile has (this comment
// made the identical incorrect claim — that fstat guards against symlinks
// when O_NOFOLLOW is unavailable — before the honeytoken round corrected the
// same wrong comment there and flagged this one as out of scope).
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
// New files: never reuse an existing name, never follow a symlink planted at
// it, and 0600 — the kill state is nobody else's to read or replace.
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;

/**
 * Strict shape check. Anything we would not have written ourselves reads as
 * invalid — and invalid loads as corrupt, which boots killed. Surprises fail
 * in the safe direction.
 */
function asPersistedKillState(value: unknown): PersistedKillState | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { version, killed, epoch, lastKill, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (version !== 1) return null;
  if (typeof killed !== "boolean") return null;
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) return null;
  if (killed !== (lastKill !== undefined)) return null;
  if (lastKill === undefined) return { version, killed, epoch };
  if (typeof lastKill !== "object" || lastKill === null || Array.isArray(lastKill)) return null;
  const { source, reason, at, unauthenticated, ...eventRest } = lastKill as Record<string, unknown>;
  if (Object.keys(eventRest).length > 0) return null;
  if (!KILL_SOURCES.includes(source as KillSource)) return null;
  if (reason !== undefined && typeof reason !== "string") return null;
  if (typeof at !== "number" || !Number.isFinite(at)) return null;
  if (unauthenticated !== undefined && unauthenticated !== true) return null;
  const event: KillEvent = {
    source: source as KillSource,
    ...(reason !== undefined ? { reason } : {}),
    at,
    ...(unauthenticated === true ? { unauthenticated: true as const } : {}),
  };
  return { version, killed, epoch, lastKill: event };
}

export class KillStateFileStore implements KillStateStore {
  private warnedDirFsync = false;

  constructor(readonly filePath: string) {}

  /**
   * The initialisation marker. It is created the first time state is written
   * (and healed onto stores that predate it) and never removed: once it
   * exists, a MISSING state file reads as corruption — deleted or moved —
   * and boots killed. Its content is documentation; its existence is the bit.
   */
  get markerPath(): string {
    return `${this.filePath}.initialized`;
  }

  load(): KillStateLoad {
    // Open with O_NOFOLLOW and fstat the open fd — the race-free version of
    // "lstat, then read": the state must be a regular file at a real path,
    // never a symlink an attacker aimed somewhere else.
    let fd: number;
    try {
      fd = openSync(this.filePath, constants.O_RDONLY | O_NOFOLLOW);
    } catch (err) {
      const code = errCode(err);
      if (code === "ENOENT") {
        if (existsSync(this.markerPath)) {
          return {
            outcome: "corrupt",
            detail:
              `${this.filePath} is missing but the store is initialised ` +
              `(${this.markerPath} exists) — the state file was deleted or the path moved`,
          };
        }
        return { outcome: "absent" };
      }
      if (code === "ELOOP") {
        return { outcome: "corrupt", detail: `${this.filePath} is a symlink — refusing to follow it` };
      }
      return { outcome: "corrupt", detail: `cannot read ${this.filePath}: ${message(err)}` };
    }
    let raw: string;
    try {
      if (!fstatSync(fd).isFile()) {
        return { outcome: "corrupt", detail: `${this.filePath} is not a regular file` };
      }
      // Read directly off the descriptor in a bounded loop, into a buffer
      // sized exactly MAX_KILL_STATE_FILE_BYTES + 1, rejecting the instant
      // that extra byte is observed — rather than trusting an fstat size
      // checked before the read, which a concurrent writer could race (grow
      // the file between the stat and the read, or mid-read).
      const limit = MAX_KILL_STATE_FILE_BYTES;
      const buffer = Buffer.alloc(limit + 1);
      let total = 0;
      for (;;) {
        const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break; // EOF, within bounds
        total += bytesRead;
        if (total > limit) {
          return {
            outcome: "corrupt",
            detail:
              `${this.filePath} is at least ${total} bytes, over the ${limit}-byte kill-state ` +
              `limit — refusing to read it into memory`,
          };
        }
      }
      raw = buffer.toString("utf8", 0, total);
    } catch (err) {
      return { outcome: "corrupt", detail: `cannot read ${this.filePath}: ${message(err)}` };
    } finally {
      closeSync(fd);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      return { outcome: "corrupt", detail: `cannot parse ${this.filePath}: ${message(err)}` };
    }
    const state = asPersistedKillState(parsed);
    if (state === null) {
      return { outcome: "corrupt", detail: `unexpected shape in ${this.filePath}` };
    }
    // Heal the marker onto stores written before it existed, so their state
    // file can't silently vanish either. Best-effort: a read-only fs cannot
    // take the marker, and the state file itself still governs.
    try {
      this.ensureMarker();
    } catch {
      /* best effort */
    }
    return { outcome: "loaded", state };
  }

  save(state: PersistedKillState): SaveResult {
    mkdirSync(dirname(this.filePath), { recursive: true });
    // Marker before state: a save that dies half-way can only err toward
    // "initialised but missing", which boots killed — never toward fresh.
    const markerDurable = this.ensureMarker();
    const tmp = `${this.filePath}.${randomBytes(8).toString("hex")}.tmp`;
    const data = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8");
    let fd: number | undefined;
    try {
      fd = openSync(tmp, CREATE_FLAGS, 0o600);
      // A single writeSync() is not guaranteed to write the whole buffer —
      // POSIX write() may return short even for a regular local file, with
      // no error raised. An unchecked short write here would still get
      // fsynced and rename-published as a truncated file: KillStateFileStore
      // would report success while the JSON on disk is corrupt, and that
      // corruption only surfaces on the NEXT boot — as "cannot parse" —
      // which boots killed. Loop until every byte has actually landed.
      let written = 0;
      while (written < data.length) {
        written += writeSync(fd, data, written, data.length - written);
      }
      // rename orders visibility; only fsync orders durability. The file
      // first, then (after the rename) the directory entry — the transition
      // counts as durable only once every one of these fsyncs succeeded.
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tmp, this.filePath);
    } catch (err) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          /* best effort */
        }
      }
      try {
        unlinkSync(tmp);
      } catch {
        /* best effort — the temp name is random, a leftover is inert */
      }
      throw err;
    }
    const dirDurable = this.fsyncDir();
    return markerDurable && dirDurable
      ? { durable: true }
      : {
          durable: false,
          detail:
            `the directory entry for ${this.filePath} could not be fsynced — ` +
            `the new state is visible but a power cut may resurface the previous one`,
        };
  }

  degrade(): boolean {
    // Per the KillStateStore contract: never throws, reports honestly.
    // Making the marker exist and the state file not exist turns any stale
    // on-disk claim into "initialised but missing" — which boots killed.
    let markerOk: boolean;
    try {
      this.ensureMarker();
      markerOk = true;
    } catch {
      markerOk = existsSync(this.markerPath); // pre-existing marker still counts
    }
    let stateGone: boolean;
    try {
      unlinkSync(this.filePath);
      stateGone = true;
    } catch (err) {
      // ENOENT is success (nothing stale to quarantine); anything else is
      // only success if the stale file is verifiably no longer there.
      stateGone = errCode(err) === "ENOENT" ? true : !existsSync(this.filePath);
    }
    return markerOk && stateGone;
  }

  /** Returns true when the marker durably exists (created+fsynced now, or already there). */
  private ensureMarker(): boolean {
    let fd: number;
    try {
      fd = openSync(this.markerPath, CREATE_FLAGS, 0o600);
    } catch (err) {
      if (errCode(err) === "EEXIST") return true; // already initialised (and synced when created)
      throw err;
    }
    try {
      writeSync(
        fd,
        "ownerswitch kill-state store is initialised. If the sibling state file is missing, the control plane boots KILLED.\n",
      );
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return this.fsyncDir();
  }

  /**
   * fsync of the parent directory is what makes a rename (or marker
   * creation) durable. Returns false — and logs once — where the platform
   * cannot do it: the caller must report that as degraded persistence, never
   * accept it silently.
   */
  private fsyncDir(): boolean {
    let fd: number;
    try {
      fd = openSync(dirname(this.filePath), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    } catch (err) {
      this.warnDirFsyncOnce(err);
      return false;
    }
    try {
      fsyncSync(fd);
      return true;
    } catch (err) {
      this.warnDirFsyncOnce(err);
      return false;
    } finally {
      closeSync(fd);
    }
  }

  private warnDirFsyncOnce(err: unknown): void {
    if (this.warnedDirFsync) return;
    this.warnedDirFsync = true;
    console.error(
      `[ownerswitch] cannot fsync ${dirname(this.filePath)} (${message(err)}) — ` +
        `renames that publish kill state are visible but their durability is NOT guaranteed on this platform.`,
    );
  }
}
