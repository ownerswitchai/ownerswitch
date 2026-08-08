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
  readFileSync,
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

export interface KillStateStore {
  load(): KillStateLoad;
  /** Must be atomic: a reader sees the previous state or this one, never a torn write. */
  save(state: PersistedKillState): void;
  /**
   * Called after a FAILED save. Best-effort and non-throwing: make any stale
   * on-disk state unable to pass for healthy, so a later load() fails closed
   * instead of reporting a not-killed state that save() failed to update.
   */
  degrade(): void;
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

// O_NOFOLLOW is POSIX; on a platform without it the flag degrades to 0 and
// the fstat regular-file check below is the remaining guard.
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
  if (typeof epoch !== "number" || !Number.isInteger(epoch) || epoch < 0) return null;
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
      raw = readFileSync(fd, "utf8");
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

  save(state: PersistedKillState): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    // Marker before state: a save that dies half-way can only err toward
    // "initialised but missing", which boots killed — never toward fresh.
    this.ensureMarker();
    const tmp = `${this.filePath}.${randomBytes(8).toString("hex")}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(tmp, CREATE_FLAGS, 0o600);
      writeSync(fd, `${JSON.stringify(state, null, 2)}\n`);
      // rename orders visibility; only fsync orders durability. The file
      // first, then (after the rename) the directory entry.
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
    this.fsyncDir();
  }

  degrade(): void {
    // Per the KillStateStore contract: best-effort, never throws. Making the
    // marker exist and the state file not exist turns any stale on-disk
    // claim into "initialised but missing" — which boots killed.
    try {
      this.ensureMarker();
    } catch {
      /* the disk is already failing; nothing more to do */
    }
    try {
      unlinkSync(this.filePath);
    } catch {
      /* ENOENT or a failing disk — either way, best effort */
    }
  }

  private ensureMarker(): void {
    let fd: number;
    try {
      fd = openSync(this.markerPath, CREATE_FLAGS, 0o600);
    } catch (err) {
      if (errCode(err) === "EEXIST") return; // already initialised
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
    this.fsyncDir();
  }

  private fsyncDir(): void {
    // fsync of the parent directory is what makes the rename itself durable.
    // Platforms that cannot open or fsync a directory get one loud log line
    // instead of a false promise.
    let fd: number;
    try {
      fd = openSync(dirname(this.filePath), constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    } catch (err) {
      this.warnDirFsyncOnce(err);
      return;
    }
    try {
      fsyncSync(fd);
    } catch (err) {
      this.warnDirFsyncOnce(err);
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
