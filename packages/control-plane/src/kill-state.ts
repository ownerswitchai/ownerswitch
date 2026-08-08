/**
 * Persistence for the kill switch: killed/not-killed, the kill epoch, and the
 * attributing kill event, in one small JSON file.
 *
 * Why a file: v0 runs the control plane as ONE process on ONE host, and the
 * state that must survive a restart is tiny — a boolean, a counter, one
 * event. A JSON file written atomically (temp file + rename in the same
 * directory) is auditable with `cat`, needs no daemon, and cannot half-write:
 * a reader sees the previous state or the new one, never a torn mix. The
 * limits of that choice are deliberate and documented in
 * packages/mcp/THREAT-MODEL.md §4: single instance only, local-disk trust,
 * no fsync.
 *
 * Fail direction: a file that EXISTS but cannot be read or parsed loads as
 * "corrupt", and the KillSwitch boots KILLED — kill state in doubt stops the
 * fleet, it never frees it. Only a file that does not exist is a first boot.
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

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
  constructor(readonly filePath: string) {}

  load(): KillStateLoad {
    let raw: string;
    try {
      raw = readFileSync(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { outcome: "absent" };
      return { outcome: "corrupt", detail: `cannot read ${this.filePath}: ${message(err)}` };
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
    return { outcome: "loaded", state };
  }

  save(state: PersistedKillState): void {
    // Temp file + rename IN THE SAME DIRECTORY: rename(2) is atomic within a
    // filesystem, so a crash mid-save leaves the previous file intact.
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, "utf8");
    renameSync(tmp, this.filePath);
  }
}
