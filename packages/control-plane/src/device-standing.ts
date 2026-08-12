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
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
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

export interface TrustedStandingPathOptions {
  getuid?: () => number;
  /**
   * Extra uids whose ownership of ancestors is trusted — the distinct-UID
   * reader model: the escalation service (its own uid) walks a chain owned
   * by the CONTROL PLANE's uid, which the operator names explicitly
   * (OWNERSWITCH_OWNER_DEVICE_STANDING_TRUSTED_UID). Never guessed from the
   * filesystem — an attacker-owned ancestor must not become trusted by
   * merely existing.
   */
  alsoTrustUids?: number[];
  /** test-only: skip the trusted-ancestry walk (public tmp roots fail it by design) */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

/**
 * Resolve the standing path to its CANONICAL form and prove the chain that
 * reaches it is a real security boundary — the same discipline as the
 * owner-device keys file (owner-device-file.ts), because this file is
 * positive authorization state: whoever can swap a component of its path
 * points the control plane at a registry where revokedAt is null again.
 *  - absolute path required;
 *  - the PARENT is realpath-resolved (the file itself may not exist yet on
 *    first boot), and the returned path is canonical — every later open goes
 *    through the resolved chain, not the lexical one, so a post-check rename
 *    or symlink swap of an ancestor cannot silently redirect the store;
 *  - every real ancestor must be owned by root, this process, or an
 *    explicitly named trusted uid, and must not be group- or world-writable.
 * The leaf itself is still opened O_NOFOLLOW by the store.
 */
export function canonicalTrustedStandingPath(
  path: string,
  options: TrustedStandingPathOptions = {},
): string {
  if (!isAbsolute(path)) {
    throw new Error(`device-standing path must be absolute, got "${path}"`);
  }
  let realParent: string;
  try {
    realParent = realpathSync(dirname(path));
  } catch (err) {
    throw new Error(
      `device-standing directory "${dirname(path)}" cannot be resolved: ${err instanceof Error ? err.message : "failed"}`,
    );
  }
  if (options.unsafeAllowUntrustedAncestryForTests !== true) {
    const getuid = options.getuid ?? process.getuid;
    const ourUid = getuid === undefined ? 0 : getuid.call(process);
    const trusted = new Set([0, ourUid, ...(options.alsoTrustUids ?? [])]);
    let current = realParent;
    for (;;) {
      let stat;
      try {
        stat = statSync(current);
      } catch {
        throw new Error(`device-standing ancestor "${current}" is unreadable`);
      }
      if (!trusted.has(stat.uid)) {
        throw new Error(
          `device-standing ancestor "${current}" is owned by uid ${stat.uid} — not root, this process, ` +
            "or an explicitly trusted uid; an untrusted owner could swap the registry path",
        );
      }
      if ((stat.mode & 0o022) !== 0) {
        throw new Error(
          `device-standing ancestor "${current}" is group- or world-writable (mode ` +
            `${(stat.mode & 0o777).toString(8)}) — a writable ancestor lets the registry be replaced wholesale`,
        );
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return join(realParent, basename(path));
}

export interface DeviceStandingStoreOptions {
  /**
   * Mode of the published standing file (and marker). Default 0600 — private
   * to the control plane. Set 0640 for the DISTINCT-UID deployment model:
   * the control plane owns and writes the file, the escalation service runs
   * as a different user in a dedicated read-only group, the parent directory
   * is 0750 owned by the control-plane user with that group. Standing is
   * positive authorization state, so group WRITE is never granted here —
   * only these two read models exist.
   */
  fileMode?: 0o600 | 0o640;
  /**
   * The gid the published file (and marker) must belong to — the escalation
   * read-only group of the 0640 model. fchmod alone sets only the mode bits:
   * without an explicit group the file keeps the writing process's default
   * gid, the separate-UID escalation reads EACCES → corrupt → everyone
   * revoked, and the "distinct-UID read model" silently does not exist.
   * Applied with fchown on the fd BEFORE the rename, and VERIFIED with stat
   * after publication — a save whose on-disk uid/gid/mode do not match what
   * was requested reports durable:false rather than claiming the boundary.
   */
  group?: number;
}

export class DeviceStandingFileStore {
  private warnedDirFsync = false;
  private readonly fileMode: number;
  private readonly group: number | undefined;

  constructor(
    readonly filePath: string,
    opts: DeviceStandingStoreOptions = {},
  ) {
    this.fileMode = opts.fileMode ?? 0o600;
    this.group = opts.group;
  }

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
      fd = openSync(tmp, CREATE_FLAGS, this.fileMode);
      // umask may have masked bits at create — pin the EXACT mode (and the
      // read-only group, when one is named) on the fd BEFORE the rename
      // publishes it, so the escalation group's read access exists from the
      // first visible instant, never as a later chmod race.
      fchmodSync(fd, this.fileMode);
      if (this.group !== undefined) fchownSync(fd, -1, this.group);
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
    // VERIFY the published boundary: the file on disk must actually carry
    // the mode (and group, when one is named) that was requested — a save
    // that "succeeded" with the wrong gid means the distinct-UID reader gets
    // EACCES → corrupt → everyone revoked (fail closed but non-functional),
    // and that must be reported here, not discovered in the other process.
    let boundaryOk = true;
    let boundaryDetail = "";
    try {
      const published = statSync(this.filePath);
      if ((published.mode & 0o777) !== this.fileMode) {
        boundaryOk = false;
        boundaryDetail = `published mode ${(published.mode & 0o777).toString(8)} != requested ${this.fileMode.toString(8)}`;
      } else if (this.group !== undefined && published.gid !== this.group) {
        boundaryOk = false;
        boundaryDetail = `published gid ${published.gid} != requested ${this.group}`;
      }
    } catch (err) {
      boundaryOk = false;
      boundaryDetail = `cannot stat the published file: ${message(err)}`;
    }
    if (!boundaryOk) return { durable: false, detail: `standing published but boundary wrong — ${boundaryDetail}` };
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
      fd = openSync(this.markerPath, CREATE_FLAGS, this.fileMode);
      // the marker gets the same mode/group pinning as the state file — the
      // reader's existsSync needs only the ancestry, but consistency keeps
      // the boundary auditable with one ls -l
      fchmodSync(fd, this.fileMode);
      if (this.group !== undefined) fchownSync(fd, -1, this.group);
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
