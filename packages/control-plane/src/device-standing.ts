/**
 * Durable standing registry for enrolled owner devices: {generation,
 * revokedAt} per deviceId, in one small JSON file — the persistence that
 * makes a revocation SURVIVE a control-plane restart. Key MATERIAL stays in
 * the operator-provisioned SPKI keys file (owner-device-file.ts); this file
 * holds only standing, so the two concerns rotate independently and the
 * escalation service can share the standing without ever holding a key it
 * does not need.
 *
 * The persistence discipline is kill-state.ts's, deliberately verbatim in
 * miniature (same threat model, same single-host v0 scope):
 *  - atomic publish: unique temp file, full-write loop, fsync, rename,
 *    directory fsync — a reader sees the previous standing or the new one,
 *    never a torn mix;
 *  - an `.initialized` marker so a DELETED standing file reads as corruption
 *    (removing the file must not resurrect a revoked phone), while a store
 *    with neither file is a genuine first boot;
 *  - O_NOFOLLOW + fstat regular-file + bounded read on load.
 *
 * Fail direction: "corrupt" means the CALLER must treat EVERY device as
 * revoked — the permissive ack lane dies, windows walk to held/passkey, and
 * every stop path is untouched. Surprises fail closed.
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
import type { SaveResult } from "./kill-state.js";

export interface DeviceStanding {
  /** 1 at enrolment; bumped atomically by every revocation */
  generation: number;
  /** ms since epoch, or null while the device is in good standing */
  revokedAt: number | null;
}

export interface PersistedDeviceStanding {
  version: 1;
  devices: Record<string, DeviceStanding>;
}

export type DeviceStandingLoad =
  | { outcome: "absent" }
  | { outcome: "loaded"; state: PersistedDeviceStanding }
  | { outcome: "corrupt"; detail: string };

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

/** Generous ceiling for a per-device standing map; bounds a hostile file. */
export const MAX_DEVICE_STANDING_FILE_BYTES = 256 * 1024;

// Same platform caveat as kill-state.ts: without O_NOFOLLOW support there is
// no symlink protection here at all.
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;

/** Strict shape check — anything we would not have written reads as corrupt. */
function asPersistedDeviceStanding(value: unknown): PersistedDeviceStanding | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { version, devices, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (version !== 1) return null;
  if (typeof devices !== "object" || devices === null || Array.isArray(devices)) return null;
  const out: Record<string, DeviceStanding> = {};
  for (const [deviceId, standing] of Object.entries(devices)) {
    if (deviceId === "" || deviceId.includes(":")) return null;
    if (typeof standing !== "object" || standing === null || Array.isArray(standing)) return null;
    const { generation, revokedAt, ...standingRest } = standing as Record<string, unknown>;
    if (Object.keys(standingRest).length > 0) return null;
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1) return null;
    if (revokedAt !== null && (typeof revokedAt !== "number" || !Number.isFinite(revokedAt))) return null;
    out[deviceId] = { generation, revokedAt: revokedAt as number | null };
  }
  return { version: 1, devices: out };
}

export class DeviceStandingFileStore {
  private warnedDirFsync = false;

  constructor(readonly filePath: string) {}

  /** Once this exists, a MISSING standing file is corruption, not a fresh boot. */
  get markerPath(): string {
    return `${this.filePath}.initialized`;
  }

  load(): DeviceStandingLoad {
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
              `(${this.markerPath} exists) — deleting the standing file must not resurrect a revoked device`,
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
      const limit = MAX_DEVICE_STANDING_FILE_BYTES;
      const buffer = Buffer.alloc(limit + 1);
      let total = 0;
      for (;;) {
        const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
        if (total > limit) {
          return {
            outcome: "corrupt",
            detail: `${this.filePath} exceeds the ${limit}-byte standing limit — refusing to read it`,
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
    const state = asPersistedDeviceStanding(parsed);
    if (state === null) {
      return { outcome: "corrupt", detail: `unexpected shape in ${this.filePath}` };
    }
    try {
      this.ensureMarker();
    } catch {
      /* best effort — the state file still governs */
    }
    return { outcome: "loaded", state };
  }

  save(state: PersistedDeviceStanding): SaveResult {
    mkdirSync(dirname(this.filePath), { recursive: true });
    // Marker before state: a save that dies half-way errs toward "initialised
    // but missing" — which loads corrupt and revokes everyone, never toward a
    // fresh boot that resurrects.
    const markerDurable = this.ensureMarker();
    const tmp = `${this.filePath}.${randomBytes(8).toString("hex")}.tmp`;
    const data = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8");
    let fd: number | undefined;
    try {
      fd = openSync(tmp, CREATE_FLAGS, 0o600);
      let written = 0;
      while (written < data.length) {
        written += writeSync(fd, data, written, data.length - written);
      }
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
            `the directory entry for ${this.filePath} could not be fsynced — the new standing is ` +
            `visible but a power cut may resurface the previous one`,
        };
  }

  /** true when the marker exists AND its directory entry was fsynced. */
  private ensureMarker(): boolean {
    if (existsSync(this.markerPath)) return true;
    let fd: number | undefined;
    try {
      fd = openSync(this.markerPath, CREATE_FLAGS, 0o600);
      const note = Buffer.from(
        "This marker records that the OwnerSwitch device-standing store has been written.\n" +
          "While it exists, a missing standing file loads as CORRUPT (all devices revoked).\n",
        "utf8",
      );
      let written = 0;
      while (written < note.length) {
        written += writeSync(fd, note, written, note.length - written);
      }
      fsyncSync(fd);
    } catch (err) {
      if (errCode(err) === "EEXIST") return true;
      throw err;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
    return this.fsyncDir();
  }

  private fsyncDir(): boolean {
    let fd: number | undefined;
    try {
      fd = openSync(dirname(this.filePath), constants.O_RDONLY);
      fsyncSync(fd);
      return true;
    } catch {
      if (!this.warnedDirFsync) {
        this.warnedDirFsync = true;
        console.error(
          `[ownerswitch] cannot fsync ${dirname(this.filePath)} — device-standing durability is degraded`,
        );
      }
      return false;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }
}
