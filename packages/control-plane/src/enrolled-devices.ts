/**
 * The DURABLE enrolled-device registry — the persistence half of the
 * enrollment ceremony (apps/owner/DESIGN.md §2 step 5: "stores ONE
 * EnrolledDevice record holding both credentials"), and the ONLY place a
 * mint/spend can happen at all. Four jobs, each a review-pinned
 * requirement:
 *
 *  1. THE SPEND PATH IS REGISTRY-PRIVATE. The registry OWNS its
 *     InviteStore — the package exports neither the store, nor the
 *     low-level spend function, nor a way to hand in a witness: the only
 *     public mint is mintInvite() and the only public spend is
 *     commitEnrollment(), so an HTTP handler cannot fabricate live state
 *     or route around the kill/bootstrap/issuer-standing boundary.
 *
 *  2. WITNESS AND OWNER FROM LIVE STATE ONLY. Witnesses are assembled
 *     here, synchronously, from the loaded durable registry plus a
 *     shape-validated kill snapshot the server reads off the real
 *     KillSwitch. The invite's ownerId comes from the ISSUER: a
 *     device-minted invite inherits the issuing device's persisted
 *     ownerId (the caller cannot name one), and only the bootstrap
 *     variant — the operator's own trusted channel — states it.
 *
 *  3. CRASH-ATOMIC ADMIT. A successful ceremony admits a device by ONE
 *     atomic file publish carrying the new device AND the bootstrap
 *     generation bump (temp + fsync + rename + dir-fsync). Memory changes
 *     only AFTER the publish proves durable. A failed publish refuses
 *     with the invite already burned (the safe direction — re-mint,
 *     never an unpersisted device); an UNPROVEN publish (visible but the
 *     directory entry's durability unverifiable) QUARANTINES the whole
 *     registry — no standing, no witness, no mint, no enrollment — until
 *     a recovery PROVES durability: load() itself ends with a durability
 *     barrier (fsync of the state file's open fd, then of the directory
 *     entry), so no state — in-process recovery and process restart
 *     alike — is ever served while a power cut could still undo it.
 *
 *  4. FAIL-CLOSED REGISTRY, WHOLE-NAMESPACE. The file store demands an
 *     absolute path, canonicalises it, walks the REAL ancestor chain
 *     (root/this-process/named-uid owners, never group- or
 *     world-writable — the same boundary as the standing store), PINS the
 *     directory identity (dev+ino) and re-verifies it on every load and
 *     save; the leaf and the `.initialized` marker are both opened
 *     O_NOFOLLOW and validated (regular file, trusted owner, mode
 *     EXACTLY 0600, bounded size). A parse that meets `__proto__`,
 *     `constructor`, or `prototype` as a device id is corrupt, and the
 *     in-memory device table is null-prototype with own-property lookups
 *     only. A marker that is missing next to an existing registry and
 *     cannot be re-established durably is corruption, not best effort.
 *
 * SINGLE WRITER, stated plainly: exactly one control-plane process owns
 * this file — there is no cross-process lock or CAS. Running two
 * concurrent writers is an unsupported deployment, the same invariant as
 * the kill-state and standing stores.
 *
 * Scope: this registry IS in the production auth path — the control
 * plane resolves dev_* signing identities from it live (server.ts
 * resolveOwnerDevice) and revokes through revoke() below, with the same
 * durable-or-quarantine rules as the admit path. The remaining ceremony
 * slices (device-minted invites over HTTP, lost-201 reconciliation) are
 * still behind the review gate.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  openSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import type { SaveResult } from "./kill-state.js";
import { canonicalTrustedStandingPath } from "./device-standing.js";
import {
  performEnrollment,
  InviteStore,
  type InviteRecord,
  type InviteSpendWitness,
} from "./invite.js";
import { storedSpkiToPem } from "./webauthn-register.js";

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

/** One enrolled device, exactly as persisted — both credentials, one record. */
export interface PersistedEnrolledDevice {
  deviceId: string;
  ownerId: string;
  /** the mint-committed display label, verified at enrolment */
  deviceName: string;
  /** WebAuthn credential id, canonical base64url */
  credentialId: string;
  /** WebAuthn public key, canonical base64url SPKI DER */
  publicKeySpki: string;
  /** cheap-lane (ack-signing) public key, canonical base64url SPKI DER */
  cheapLaneKeySpki: string;
  /** the possession assertion's signed counter at enrolment */
  signCount: number;
  /** authenticator transports — stored as a hint, never as proof */
  transports?: string[];
  /** the credential's user.id echo — opaque metadata, never proof */
  userHandle?: string;
  /** 1 at enrolment; bumped atomically by every revocation */
  generation: number;
  /** ms since epoch, or null while the device is in good standing */
  revokedAt: number | null;
  /** ms since epoch */
  enrolledAt: number;
}

export interface PersistedEnrolledDevices {
  version: 2;
  /**
   * The bootstrap generation — bumped in the SAME atomic publish as a
   * successful bootstrap enrolment, so the bootstrap lane self-closes
   * durably: any bootstrap invite recorded under the old generation is
   * dead at its spend, across restarts.
   */
  bootstrapGeneration: number;
  devices: Record<string, PersistedEnrolledDevice>;
  /**
   * Per-owner WebAuthn user handles: `userId` is an OPAQUE CSPRNG value
   * (never the ownerId re-encoded, never PII — the pinned EnrollmentInvite
   * user entity), STABLE per owner because it is minted once, durably,
   * with the owner's first invite. 16–64 decoded bytes, canonical
   * base64url, unique across owners.
   */
  owners: Record<string, { userId: string }>;
}

export type EnrolledDevicesLoad =
  | { outcome: "absent" }
  | { outcome: "loaded"; state: PersistedEnrolledDevices }
  | {
      /**
       * A well-formed PRE-OWNERS registry (schema v1, written by the
       * unreleased v18–v21 line): everything except the per-owner user
       * handles. Served to NOBODY — initialize() migrates it to v2 (one
       * durable publish, same durability rules as every other write) and
       * only the migrated state is ever used.
       */
      outcome: "legacy-v1";
      state: { bootstrapGeneration: number; devices: Record<string, PersistedEnrolledDevice> };
    }
  | { outcome: "corrupt"; detail: string };

/** Generous ceiling for a household-scale device registry; bounds a hostile file. */
export const MAX_ENROLLED_DEVICES_FILE_BYTES = 512 * 1024;
/** Active-device ceiling (flood backstop) — households, not fleets. */
export const MAX_ACTIVE_DEVICES = 64;
/** Owner-handle ceiling — the same order of magnitude, same reasoning. */
export const MAX_OWNERS = 128;
/** The marker is a short fixed note; anything bigger was not written by us. */
const MAX_MARKER_BYTES = 4096;
/** the EXACT marker body this store writes — anything else is not our marker */
const MARKER_NOTE =
  "This marker records that the OwnerSwitch enrolled-device registry has been written.\n" +
  "While it exists, a missing registry file loads as CORRUPT (no enrollment, no witness).\n";

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;

/**
 * Property names that collide with Object.prototype machinery: a registry
 * file using one as a device id is hostile by definition — `out[deviceId]`
 * on a normal object would hit the prototype SETTER and vanish from every
 * own-property enumeration while still answering inherited lookups.
 */
const FORBIDDEN_DEVICE_IDS = new Set(["__proto__", "constructor", "prototype"]);

/** canonical unpadded base64url, by ROUND-TRIP — the same rule as the wire */
function isCanonicalB64url(value: string, minBytes: number, maxBytes: number): boolean {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return (
    decoded.length >= minBytes &&
    decoded.length <= maxBytes &&
    decoded.toString("base64url") === value
  );
}

/** null-prototype copy — the ONLY shape the in-memory device table takes */
function nullProtoDevices(
  entries: Iterable<readonly [string, PersistedEnrolledDevice]>,
): Record<string, PersistedEnrolledDevice> {
  const out: Record<string, PersistedEnrolledDevice> = Object.create(null);
  for (const [deviceId, device] of entries) out[deviceId] = device;
  return out;
}

function cloneDevice(device: PersistedEnrolledDevice): PersistedEnrolledDevice {
  return {
    ...device,
    ...(device.transports !== undefined ? { transports: [...device.transports] } : {}),
  };
}

/** Strict shape check — anything we would not have written reads as corrupt. */
function asPersistedEnrolledDevices(
  value: unknown,
  opts: { maxOwners?: number } = {},
): PersistedEnrolledDevices | null {
  const maxOwners = opts.maxOwners ?? MAX_OWNERS;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { version, bootstrapGeneration, devices, owners, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (version !== 2) return null;
  if (
    typeof bootstrapGeneration !== "number" ||
    !Number.isSafeInteger(bootstrapGeneration) ||
    bootstrapGeneration < 1
  ) {
    return null;
  }
  if (typeof devices !== "object" || devices === null || Array.isArray(devices)) return null;
  const entries: Array<readonly [string, PersistedEnrolledDevice]> = [];
  const seenCredentials = new Set<string>();
  const seenCheapLaneKeys = new Set<string>();
  // Object.keys/entries see OWN properties only (JSON.parse defines own
  // properties, never setters) — the danger is what WE would do with a
  // hostile key, so those keys are refused outright, before any table is
  // built at all.
  for (const [deviceId, record] of Object.entries(devices)) {
    if (deviceId === "" || deviceId.length > 128) return null;
    if (FORBIDDEN_DEVICE_IDS.has(deviceId)) return null;
    if (typeof record !== "object" || record === null || Array.isArray(record)) return null;
    const {
      deviceId: innerId,
      ownerId,
      deviceName,
      credentialId,
      publicKeySpki,
      cheapLaneKeySpki,
      signCount,
      transports,
      userHandle,
      generation,
      revokedAt,
      enrolledAt,
      ...deviceRest
    } = record as Record<string, unknown>;
    if (Object.keys(deviceRest).length > 0) return null;
    if (innerId !== deviceId) return null;
    if (typeof ownerId !== "string" || ownerId === "" || ownerId.length > 256) return null;
    if (typeof deviceName !== "string" || deviceName === "" || deviceName.length > 200) return null;
    if (typeof credentialId !== "string" || !isCanonicalB64url(credentialId, 1, 1024)) return null;
    // both stored keys must be REAL P-256 SPKI DER, full-consumption — the
    // same hardened validator the ceremony used at admit (a registry field
    // that merely LOOKS like base64url must not reach the auth wiring)
    if (typeof publicKeySpki !== "string" || !storedSpkiToPem(publicKeySpki).ok) return null;
    if (typeof cheapLaneKeySpki !== "string" || !storedSpkiToPem(cheapLaneKeySpki).ok) return null;
    if (typeof signCount !== "number" || !Number.isSafeInteger(signCount) || signCount < 0) return null;
    if (transports !== undefined) {
      if (!Array.isArray(transports) || transports.length > 8) return null;
      for (const t of transports) {
        if (typeof t !== "string" || t === "" || t.length > 32) return null;
      }
    }
    if (userHandle !== undefined) {
      if (typeof userHandle !== "string" || !isCanonicalB64url(userHandle, 1, 64)) return null;
    }
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1) return null;
    if (revokedAt !== null && (typeof revokedAt !== "number" || !Number.isFinite(revokedAt))) return null;
    if (typeof enrolledAt !== "number" || !Number.isFinite(enrolledAt)) return null;
    // ONE credential / cheap-lane key, ONE device — across the WHOLE
    // history, revoked records included: a registry claiming otherwise is
    // corrupt (the same historical-ban rule the admit path enforces)
    if (seenCredentials.has(credentialId)) return null;
    if (seenCheapLaneKeys.has(cheapLaneKeySpki)) return null;
    seenCredentials.add(credentialId);
    seenCheapLaneKeys.add(cheapLaneKeySpki);
    entries.push([
      deviceId,
      {
        deviceId,
        ownerId,
        deviceName,
        credentialId,
        publicKeySpki,
        cheapLaneKeySpki,
        signCount,
        ...(transports !== undefined ? { transports: [...(transports as string[])] } : {}),
        ...(userHandle !== undefined ? { userHandle: userHandle as string } : {}),
        generation,
        revokedAt: revokedAt as number | null,
        enrolledAt,
      },
    ] as const);
  }
  // the durable shape enforces the same active ceiling the admit path does —
  // a file claiming more active devices than the system would ever admit was
  // not written by this code
  let active = 0;
  for (const [, device] of entries) {
    if (device.revokedAt === null) active += 1;
  }
  if (active > MAX_ACTIVE_DEVICES) return null;
  // per-owner user handles: same prototype-safety and canonicality rules as
  // the device table, plus cross-owner uniqueness — a handle is an identity
  if (typeof owners !== "object" || owners === null || Array.isArray(owners)) return null;
  const ownerEntries: Array<readonly [string, { userId: string }]> = [];
  const seenUserIds = new Set<string>();
  for (const [ownerId, handle] of Object.entries(owners)) {
    if (ownerId === "" || ownerId.length > 256) return null;
    if (FORBIDDEN_DEVICE_IDS.has(ownerId)) return null;
    if (typeof handle !== "object" || handle === null || Array.isArray(handle)) return null;
    const { userId, ...handleRest } = handle as Record<string, unknown>;
    if (Object.keys(handleRest).length > 0) return null;
    if (typeof userId !== "string" || !isCanonicalB64url(userId, 16, 64)) return null;
    if (seenUserIds.has(userId)) return null;
    seenUserIds.add(userId);
    ownerEntries.push([ownerId, { userId }] as const);
  }
  if (ownerEntries.length > maxOwners) return null;
  const ownersOut: Record<string, { userId: string }> = Object.create(null);
  for (const [ownerId, handle] of ownerEntries) ownersOut[ownerId] = handle;
  // REFERENTIAL integrity: every device's owner must hold a handle — a v2
  // state that names an owner without one was not written by this code, and
  // accepting it would let a later mint generate a SECOND user identity for
  // the same owner (breaking the stable-WebAuthn-user-handle invariant)
  for (const [, device] of entries) {
    if (!Object.hasOwn(ownersOut, device.ownerId)) return null;
  }
  return { version: 2, bootstrapGeneration, devices: nullProtoDevices(entries), owners: ownersOut };
}

/**
 * The UNRELEASED v1 shape (v18–v21): exactly the v2 shape minus `owners`.
 * Parsed by wrapping the same strict validator — the device table gets the
 * identical field-by-field treatment, and only a file that would have
 * validated under the old code reads as legacy.
 */
function asLegacyV1(value: unknown): { bootstrapGeneration: number; devices: Record<string, PersistedEnrolledDevice> } | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 3 || keys[0] !== "bootstrapGeneration" || keys[1] !== "devices" || keys[2] !== "version") {
    return null;
  }
  if (record.version !== 1) return null;
  // synthesize a PLACEHOLDER handle per named owner, purely so the shared
  // strict validator can check everything else (its referential-integrity
  // rule demands owner coverage); the placeholders are discarded — the
  // MIGRATION mints the real handles, and its own explicit ceiling check
  // refuses an over-limit owner population with a named reason, which is
  // why the ceiling is not enforced here (maxOwners: unbounded).
  const syntheticOwners: Record<string, { userId: string }> = {};
  const taken = new Set<string>();
  if (typeof record.devices === "object" && record.devices !== null && !Array.isArray(record.devices)) {
    for (const device of Object.values(record.devices as Record<string, unknown>)) {
      if (typeof device !== "object" || device === null) continue;
      const ownerId = (device as Record<string, unknown>).ownerId;
      if (typeof ownerId !== "string" || ownerId === "") continue;
      if (Object.prototype.hasOwnProperty.call(syntheticOwners, ownerId)) continue;
      if (FORBIDDEN_DEVICE_IDS.has(ownerId)) continue; // the validator will refuse the device itself
      let userId = randomBytes(24).toString("base64url");
      while (taken.has(userId)) userId = randomBytes(24).toString("base64url");
      taken.add(userId);
      syntheticOwners[ownerId] = { userId };
    }
  }
  const upgraded = asPersistedEnrolledDevices(
    {
      version: 2,
      bootstrapGeneration: record.bootstrapGeneration,
      devices: record.devices,
      owners: syntheticOwners,
    },
    { maxOwners: Number.MAX_SAFE_INTEGER },
  );
  if (upgraded === null) return null;
  return { bootstrapGeneration: upgraded.bootstrapGeneration, devices: upgraded.devices };
}

export interface EnrolledDeviceStoreOptions {
  /**
   * The uids allowed to OWN the registry file and marker (checked at LOAD,
   * fstat on the open fd). Default: root and this process. Mode is pinned
   * to EXACTLY 0600, no group model: nothing else reads this file (the
   * escalation service consumes standing through the standing store).
   */
  trustedOwnerUids?: number[];
  /** extra uids trusted to own ancestors (the distinct-UID model's operator-named uid) */
  alsoTrustAncestorUids?: number[];
  /** test-only: skip the trusted-ancestry walk (public tmp roots fail it by design) */
  unsafeAllowUntrustedAncestryForTests?: boolean;
}

/**
 * The registry FILE — kill-state.ts's persistence discipline plus the
 * whole-namespace boundary: canonical absolute path, trusted non-writable
 * ancestors, pinned directory identity re-verified on every touch, and a
 * marker that is validated as strictly as the state itself.
 */
export class EnrolledDeviceFileStore {
  private warnedDirFsync = false;
  private readonly trustedOwnerUids: ReadonlySet<number>;
  /** canonical path — every open goes through the resolved chain */
  readonly filePath: string;
  private readonly dirPath: string;
  /** the directory's pinned identity: a swapped directory is a broken boundary */
  private readonly dirDev: number;
  private readonly dirIno: number;

  constructor(filePath: string, opts: EnrolledDeviceStoreOptions = {}) {
    this.filePath = canonicalTrustedStandingPath(
      filePath,
      {
        alsoTrustUids: opts.alsoTrustAncestorUids,
        unsafeAllowUntrustedAncestryForTests: opts.unsafeAllowUntrustedAncestryForTests,
      },
      "enrolled-device registry",
    );
    this.dirPath = dirname(this.filePath);
    const dirStat = statSync(this.dirPath);
    if (!dirStat.isDirectory()) {
      throw new Error(`enrolled-device registry parent "${this.dirPath}" is not a directory`);
    }
    this.dirDev = dirStat.dev;
    this.dirIno = dirStat.ino;
    const ourUid = typeof process.getuid === "function" ? process.getuid() : 0;
    this.trustedOwnerUids = new Set(opts.trustedOwnerUids ?? [0, ourUid]);
  }

  get markerPath(): string {
    return `${this.filePath}.initialized`;
  }

  /** the pinned directory must still BE the pinned directory */
  private dirIdentityViolation(): string | null {
    let stat;
    try {
      stat = statSync(this.dirPath);
    } catch (err) {
      return `registry directory "${this.dirPath}" is gone: ${message(err)}`;
    }
    if (!stat.isDirectory() || stat.dev !== this.dirDev || stat.ino !== this.dirIno) {
      return `registry directory "${this.dirPath}" is not the directory this store was opened with — the namespace was swapped`;
    }
    return null;
  }

  private leafViolation(stat: {
    uid: number;
    mode: number;
    isFile: () => boolean;
  }, what: string): string | null {
    if (!stat.isFile()) return `${what} is not a regular file`;
    if (!this.trustedOwnerUids.has(stat.uid)) {
      return `${what} is owned by uid ${stat.uid} — not root, this process, or a configured trusted uid`;
    }
    if ((stat.mode & 0o7777) !== 0o600) {
      return `${what} has mode ${(stat.mode & 0o7777).toString(8)} — this registry is private to the control plane, EXACTLY 0600`;
    }
    return null;
  }

  /**
   * The marker, validated as strictly as the state: O_NOFOLLOW, regular
   * file, trusted owner, mode exactly 0600, bounded size. "absent" is a
   * fact only when the open says ENOENT — every other surprise is corrupt.
   */
  private markerState(): "absent" | "valid" | { corrupt: string } {
    let fd: number;
    try {
      fd = openSync(this.markerPath, constants.O_RDONLY | O_NOFOLLOW);
    } catch (err) {
      const code = errCode(err);
      if (code === "ENOENT") return "absent";
      if (code === "ELOOP") return { corrupt: `${this.markerPath} is a symlink — refusing to follow it` };
      return { corrupt: `cannot open ${this.markerPath}: ${message(err)}` };
    }
    try {
      const stat = fstatSync(fd);
      const violation = this.leafViolation(stat, this.markerPath);
      if (violation !== null) return { corrupt: violation };
      if (stat.size > MAX_MARKER_BYTES) {
        return { corrupt: `${this.markerPath} is ${stat.size} bytes — not the marker this store writes` };
      }
      // EXACT content: the marker is a constant note, so "is this our
      // marker" is a byte-equality fact, not a heuristic
      const buffer = Buffer.alloc(MAX_MARKER_BYTES + 1);
      let total = 0;
      for (;;) {
        const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      if (buffer.toString("utf8", 0, total) !== MARKER_NOTE) {
        return { corrupt: `${this.markerPath} does not carry this store's marker note` };
      }
      return "valid";
    } catch (err) {
      return { corrupt: `cannot stat ${this.markerPath}: ${message(err)}` };
    } finally {
      closeSync(fd);
    }
  }

  load(): EnrolledDevicesLoad {
    const dirViolation = this.dirIdentityViolation();
    if (dirViolation !== null) return { outcome: "corrupt", detail: dirViolation };
    const marker = this.markerState();
    if (typeof marker === "object") return { outcome: "corrupt", detail: marker.corrupt };
    let fd: number;
    try {
      fd = openSync(this.filePath, constants.O_RDONLY | O_NOFOLLOW);
    } catch (err) {
      const code = errCode(err);
      if (code === "ENOENT") {
        if (marker === "valid") {
          return {
            outcome: "corrupt",
            detail:
              `${this.filePath} is missing but the store is initialised ` +
              `(${this.markerPath} exists) — deleting the registry must not un-enroll silently`,
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
      const stat = fstatSync(fd);
      const violation = this.leafViolation(stat, this.filePath);
      if (violation !== null) return { outcome: "corrupt", detail: violation };
      const limit = MAX_ENROLLED_DEVICES_FILE_BYTES;
      const buffer = Buffer.alloc(limit + 1);
      let total = 0;
      for (;;) {
        const bytesRead = readSync(fd, buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
        if (total > limit) {
          return {
            outcome: "corrupt",
            detail: `${this.filePath} exceeds the ${limit}-byte registry limit — refusing to read it`,
          };
        }
      }
      raw = buffer.toString("utf8", 0, total);
      // DURABILITY BARRIER, part 1: the state file's own data. A state is
      // only ever SERVED once its durability is proven at read time — this
      // is what makes quarantine recovery honest: re-reading a visible but
      // unproven publish (in this process or after a restart) must not
      // resurrect authority a power cut could still undo.
      try {
        fsyncSync(fd);
      } catch (err) {
        return {
          outcome: "corrupt",
          detail: `${this.filePath} is visible but cannot be fsynced (${message(err)}) — refusing to serve a state a power cut may undo`,
        };
      }
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
    const state = asPersistedEnrolledDevices(parsed);
    let legacy: ReturnType<typeof asLegacyV1> = null;
    if (state === null) {
      legacy = asLegacyV1(parsed);
      if (legacy === null) {
        return { outcome: "corrupt", detail: `unexpected shape in ${this.filePath}` };
      }
    }
    if (marker === "absent") {
      // a registry with state but no marker: the marker must be
      // RE-ESTABLISHED durably before this state is trusted — otherwise a
      // later deletion of the state file reads as a fresh boot, which
      // forgets devices and REOPENS the bootstrap lane. Not best effort.
      let markerDurable: boolean;
      try {
        markerDurable = this.ensureMarker();
      } catch (err) {
        return {
          outcome: "corrupt",
          detail: `registry state exists but its marker cannot be established: ${message(err)}`,
        };
      }
      if (!markerDurable) {
        return {
          outcome: "corrupt",
          detail: "registry state exists but its marker could not be established DURABLY (fsync failed)",
        };
      }
    }
    // DURABILITY BARRIER, part 2: the DIRECTORY ENTRY naming this file.
    // This is the exact half an unproven publish is missing — if it cannot
    // be established now, the visible state stays unserved and the caller
    // stays quarantined, however many times it retries or restarts.
    if (!this.fsyncDir()) {
      return {
        outcome: "corrupt",
        detail:
          `the directory entry for ${this.filePath} could not be fsynced — the visible registry is ` +
          "UNPROVEN and will not be served (a power cut could resurface older state)",
      };
    }
    if (legacy !== null) return { outcome: "legacy-v1", state: legacy };
    return { outcome: "loaded", state: state as PersistedEnrolledDevices };
  }

  save(state: PersistedEnrolledDevices): SaveResult {
    const dirViolation = this.dirIdentityViolation();
    if (dirViolation !== null) {
      throw new Error(`refusing to publish: ${dirViolation}`);
    }
    const data = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8");
    // what we write must be what load() will accept — a registry that grew
    // past its own read limit would publish fine and then load corrupt
    if (data.length > MAX_ENROLLED_DEVICES_FILE_BYTES) {
      throw new Error(
        `refusing to publish: serialized registry is ${data.length} bytes, over the ${MAX_ENROLLED_DEVICES_FILE_BYTES}-byte load limit`,
      );
    }
    // ...and the EXACT bytes must pass the loader's own strict validator —
    // save() can never publish a state its own load() would call corrupt
    // (the review's scenario: a migration minting more owner handles than
    // MAX_OWNERS would otherwise "succeed" durably into a self-inflicted
    // quarantine on the next restart)
    if (asPersistedEnrolledDevices(JSON.parse(data.toString("utf8"))) === null) {
      throw new Error(
        "refusing to publish: the serialized registry does not satisfy the loader's schema — a publish " +
          "the next restart would refuse is not a publish",
      );
    }
    // Marker before state: a save that dies half-way errs toward
    // "initialised but missing" — which loads corrupt and refuses all
    // enrollment, never toward a fresh boot that forgets devices.
    const markerDurable = this.ensureMarker();
    const tmp = `${this.filePath}.${randomBytes(8).toString("hex")}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(tmp, CREATE_FLAGS, 0o600);
      fchmodSync(fd, 0o600); // umask may have masked bits at create
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
            `the directory entry for ${this.filePath} could not be fsynced — the new registry is ` +
            `visible but a power cut may resurface the previous one`,
        };
  }

  private ensureMarker(): boolean {
    const existing = this.markerState();
    if (existing === "valid") return true;
    if (typeof existing === "object") {
      throw new Error(`marker unusable: ${existing.corrupt}`);
    }
    let fd: number | undefined;
    try {
      fd = openSync(this.markerPath, CREATE_FLAGS, 0o600);
      fchmodSync(fd, 0o600);
      const note = Buffer.from(MARKER_NOTE, "utf8");
      let written = 0;
      while (written < note.length) {
        written += writeSync(fd, note, written, note.length - written);
      }
      fsyncSync(fd);
    } catch (err) {
      if (errCode(err) === "EEXIST") {
        // a marker appeared between the check and the create — accept it
        // only if it VALIDATES; anything else is the corrupt path
        const raced = this.markerState();
        if (raced === "valid") return true;
        throw new Error(
          `marker unusable: ${typeof raced === "object" ? raced.corrupt : "vanished during creation"}`,
        );
      }
      throw err;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
    return this.fsyncDir();
  }

  private fsyncDir(): boolean {
    let fd: number | undefined;
    try {
      fd = openSync(this.dirPath, constants.O_RDONLY);
      fsyncSync(fd);
      return true;
    } catch {
      if (!this.warnedDirFsync) {
        this.warnedDirFsync = true;
        console.error(
          `[ownerswitch] cannot fsync ${this.dirPath} — enrolled-device durability is degraded`,
        );
      }
      return false;
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }
}

/**
 * The kill switch's live answer, read by the CALLER (the server, holding
 * the real KillSwitch) immediately before the registry call — the registry
 * validates the shape fail-closed and builds the witness itself. Nothing
 * on any wire ever becomes part of a witness.
 */
export interface LiveKillState {
  killed: boolean;
  epoch: number;
}

function killStateIsMalformed(kill: LiveKillState): boolean {
  return (
    (kill.killed !== false && kill.killed !== true) ||
    !Number.isSafeInteger(kill.epoch) ||
    kill.epoch < 0
  );
}

/**
 * What the server hands the registry to mint an invite — the ceremony
 * contract and WHO mints, nothing more. The authority facts (kill epoch,
 * bootstrap generation, the issuer's CURRENT revocation generation) are
 * filled in from live state, and the OWNER comes from the issuer: an
 * enrolled device can only ever invite into its own ownerId (read from its
 * persisted record — there is no field to claim another), while the
 * bootstrap variant states it because the operator's host channel IS the
 * root of trust being established.
 */
export interface MintInviteRequest {
  inviteId: string;
  /** SHA-256 of the locally generated secret, canonical base64url (the commitment) */
  tokenHash: string;
  deviceName: string;
  challenge: string;
  assertionChallenge: string;
  issuer:
    | { kind: "bootstrap"; ownerId: string }
    | { kind: "device"; deviceId: string };
}

export type CommitEnrollmentOutcome =
  | {
      ok: true;
      device: PersistedEnrolledDevice;
      /** true when the atomic publish reported full durability (dir fsync included) */
      durable: true;
    }
  | { ok: false; reason: string; inviteSurvives: boolean };

export interface CommitEnrollmentOptions {
  /** the live kill snapshot, read from the real KillSwitch by the caller */
  kill: LiveKillState;
  rpId: string;
  expectedOrigin: string;
}

export interface EnrolledDeviceRegistryOptions {
  now?: () => number;
  /** invite lifetime; default 10 minutes (the invite store's own default) */
  inviteTtlMs?: number;
  /** live-invite ceiling; default 32 */
  maxInvites?: number;
  /** test-only deterministic device ids */
  deviceIdFactory?: () => string;
}

/**
 * The registry RUNTIME: loads the durable state once, answers standing
 * queries from memory, owns the invite store, assembles every witness, and
 * owns the crash-atomic enrollment commit. Every mutating path publishes
 * durably BEFORE memory changes; every refusal names whether the invite
 * survived; every durability surprise quarantines rather than guesses.
 */
export class EnrolledDeviceRegistry {
  readonly #store: EnrolledDeviceFileStore;
  readonly #invites: InviteStore;
  readonly #now: () => number;
  readonly #deviceIdFactory: () => string;
  #state: PersistedEnrolledDevices | null = null;
  #corruptDetail: string | null = null;

  constructor(store: EnrolledDeviceFileStore, opts: EnrolledDeviceRegistryOptions = {}) {
    this.#store = store;
    this.#now = opts.now ?? Date.now;
    this.#invites = new InviteStore({
      ...(opts.now !== undefined ? { now: opts.now } : {}),
      ...(opts.inviteTtlMs !== undefined ? { ttlMs: opts.inviteTtlMs } : {}),
      ...(opts.maxInvites !== undefined ? { maxInvites: opts.maxInvites } : {}),
    });
    this.#deviceIdFactory = opts.deviceIdFactory ?? (() => `dev_${randomBytes(12).toString("base64url")}`);
  }

  /**
   * Load the durable state (or persist the first-boot state so the marker
   * exists from the first instant). An unusable registry stays unusable —
   * there is no in-memory fallback to enroll into. This is ALSO the
   * recovery step after a quarantine: it establishes what actually
   * survived on disk and resumes from exactly that.
   */
  initialize(): { ok: true } | { ok: false; detail: string } {
    const loaded = this.#store.load();
    if (loaded.outcome === "corrupt") {
      this.#quarantine(loaded.detail);
      return { ok: false, detail: loaded.detail };
    }
    if (loaded.outcome === "loaded") {
      this.#state = loaded.state;
      this.#corruptDetail = null;
      return { ok: true };
    }
    if (loaded.outcome === "legacy-v1") {
      // V1 -> V2 MIGRATION, before anything is served: mint a durable opaque
      // user handle for every owner the device table names, publish the
      // migrated registry with the same durable-or-refuse / quarantine-on-
      // unproven rules as every other write, and only then serve. Handles
      // minted here are the ones every later mint and restart will see.
      const distinctOwners = new Set(
        Object.values(loaded.state.devices).map((device) => device.ownerId),
      );
      if (distinctOwners.size > MAX_OWNERS) {
        const detail =
          `v1 -> v2 registry migration refused: ${distinctOwners.size} distinct owners exceed the ` +
          `${MAX_OWNERS} owner-handle ceiling — nothing was published (fail closed)`;
        this.#quarantine(detail);
        return { ok: false, detail };
      }
      const owners: Record<string, { userId: string }> = Object.create(null);
      const taken = new Set<string>();
      for (const device of Object.values(loaded.state.devices)) {
        if (Object.hasOwn(owners, device.ownerId)) continue;
        let userId = randomBytes(32).toString("base64url");
        while (taken.has(userId)) userId = randomBytes(32).toString("base64url");
        taken.add(userId);
        owners[device.ownerId] = { userId };
      }
      const migrated: PersistedEnrolledDevices = {
        version: 2,
        bootstrapGeneration: loaded.state.bootstrapGeneration,
        devices: loaded.state.devices,
        owners,
      };
      let saved: SaveResult;
      try {
        saved = this.#store.save(migrated);
      } catch (err) {
        const detail = `v1 -> v2 registry migration persist failed: ${message(err)}`;
        this.#quarantine(detail);
        return { ok: false, detail };
      }
      if (!saved.durable) {
        const detail = `v1 -> v2 registry migration not durable: ${saved.detail}`;
        this.#quarantine(detail);
        return { ok: false, detail };
      }
      console.error(
        `[ownerswitch] enrolled-device registry migrated v1 -> v2 (${Object.keys(owners).length} owner handle(s) minted durably)`,
      );
      this.#state = migrated;
      this.#corruptDetail = null;
      return { ok: true };
    }
    // genuine first boot: bootstrap generation starts at 1, persisted NOW —
    // from here on a missing file is corruption, not a fresh start
    const initial: PersistedEnrolledDevices = {
      version: 2,
      bootstrapGeneration: 1,
      devices: nullProtoDevices([]),
      owners: Object.create(null) as Record<string, { userId: string }>,
    };
    let saved: SaveResult;
    try {
      saved = this.#store.save(initial);
    } catch (err) {
      const detail = `first-boot registry persist failed: ${message(err)}`;
      this.#quarantine(detail);
      return { ok: false, detail };
    }
    if (!saved.durable) {
      const detail = `first-boot registry persist not durable: ${saved.detail}`;
      this.#quarantine(detail);
      return { ok: false, detail };
    }
    this.#state = initial;
    this.#corruptDetail = null;
    return { ok: true };
  }

  #quarantine(detail: string): void {
    this.#state = null;
    this.#corruptDetail = detail;
  }

  get usable(): boolean {
    return this.#state !== null;
  }

  get corruptDetail(): string | null {
    return this.#corruptDetail;
  }

  #usableState(): PersistedEnrolledDevices {
    if (this.#state === null) {
      throw new Error(
        `enrolled-device registry is not usable${this.#corruptDetail !== null ? `: ${this.#corruptDetail}` : " (initialize() first)"}`,
      );
    }
    return this.#state;
  }

  get bootstrapGeneration(): number {
    return this.#usableState().bootstrapGeneration;
  }

  get activeDeviceCount(): number {
    let count = 0;
    for (const device of Object.values(this.#usableState().devices)) {
      if (device.revokedAt === null) count += 1;
    }
    return count;
  }

  /** Enrolled, unrevoked, at EXACTLY this generation — the standing answer. */
  standing(deviceId: string, generation: number): boolean {
    const devices = this.#usableState().devices;
    if (!Object.hasOwn(devices, deviceId)) return false;
    const device = devices[deviceId];
    return device.revokedAt === null && device.generation === generation;
  }

  get(deviceId: string): PersistedEnrolledDevice | null {
    const devices = this.#usableState().devices;
    return Object.hasOwn(devices, deviceId) ? cloneDevice(devices[deviceId]) : null;
  }

  /**
   * REVOKE an enrolled device — the durable severing of a dev_* identity,
   * with the admit path's exact publish discipline turned around:
   *  - the revocation (revokedAt + generation bump) is published durably
   *    FIRST; memory changes only after the publish proves durable, so a
   *    crash between the two leaves the SAFE state on disk (revoked);
   *  - a FAILED publish quarantines the registry: unlike the admit path
   *    (where refusing the new device is safe), here the stale file still
   *    holds the device ACTIVE, so serving from memory-only revocation
   *    would let a restart resurrect it — the caller must treat this as
   *    the same emergency as a standing-persist failure (durable kill);
   *  - an UNPROVEN publish (visible, durability unverifiable) quarantines
   *    for the same reason as everywhere else;
   *  - idempotent: re-revoking an already-revoked device is a successful
   *    no-op (relays may blind-retry).
   */
  revoke(
    deviceId: string,
    revokedAt: number,
  ):
    | { outcome: "revoked" | "already-revoked"; generation: number }
    | { outcome: "unknown" }
    | { outcome: "publish-failed"; detail: string } {
    const state = this.#usableState();
    if (!Object.hasOwn(state.devices, deviceId)) return { outcome: "unknown" };
    const device = state.devices[deviceId];
    if (device.revokedAt !== null) {
      return { outcome: "already-revoked", generation: device.generation };
    }
    const revoked: PersistedEnrolledDevice = {
      ...cloneDevice(device),
      revokedAt,
      generation: device.generation + 1,
    };
    const next: PersistedEnrolledDevices = {
      ...state,
      devices: nullProtoDevices(
        Object.entries(state.devices).map(([id, d]) =>
          id === deviceId ? ([id, revoked] as const) : ([id, d] as const),
        ),
      ),
    };
    let saved: SaveResult;
    try {
      saved = this.#store.save(next);
    } catch (err) {
      const detail = `revocation publish FAILED (${message(err)})`;
      this.#quarantine(detail);
      return { outcome: "publish-failed", detail };
    }
    if (!saved.durable) {
      const detail = `revocation publish durability UNPROVEN: ${saved.detail}`;
      this.#quarantine(detail);
      return { outcome: "publish-failed", detail };
    }
    this.#state = next;
    return { outcome: "revoked", generation: revoked.generation };
  }

  list(): PersistedEnrolledDevice[] {
    return Object.values(this.#usableState().devices).map(cloneDevice);
  }

  /** KILL HOOK: sweep invites minted under any other epoch (see InviteStore). */
  invalidateSupersededEpoch(currentEpoch: number): number {
    return this.#invites.invalidateSupersededEpoch(currentEpoch);
  }

  /**
   * Read an invite WITHOUT spending it — the server's non-consuming
   * PREFLIGHT (GET /devices/enroll/contract/:id): the phone verifies the
   * pasted payload against the control plane's own record BEFORE any
   * platform prompt is raised, so an unauthenticated QR/paste can never
   * steer rpId, the user entity, or a challenge into WebAuthn. A frozen
   * copy; the spend still runs the whole proof chain later.
   */
  peekInvite(inviteId: string): InviteRecord | null {
    this.#usableState();
    return this.#invites.peek(inviteId);
  }

  /**
   * The ONE witness assembly — live kill snapshot + this registry's loaded
   * durable state, nothing else. Module-private consumers only; the
   * public paths are mintInvite and commitEnrollment.
   */
  #liveWitness(kill: LiveKillState): InviteSpendWitness {
    const state = this.#usableState();
    if (killStateIsMalformed(kill)) {
      throw new Error("malformed live kill state — no witness (fail closed)");
    }
    let active = 0;
    for (const device of Object.values(state.devices)) {
      if (device.revokedAt === null) active += 1;
    }
    return {
      killed: kill.killed,
      killEpoch: kill.epoch,
      bootstrapGeneration: state.bootstrapGeneration,
      activeDeviceCount: active,
      deviceStanding: (deviceId, generation) => this.standing(deviceId, generation),
    };
  }

  /** The owner's stable opaque WebAuthn user handle, or null before their first mint. */
  ownerUserId(ownerId: string): string | null {
    const owners = this.#usableState().owners;
    return Object.hasOwn(owners, ownerId) ? owners[ownerId].userId : null;
  }

  /**
   * Ensure the owner has a DURABLE opaque user handle before an invite for
   * them exists: generated from the CSPRNG (never derived from the
   * ownerId), published atomically with the same durable-or-refuse /
   * quarantine-on-unproven rules as the admit path, and only then adopted
   * in memory. Idempotent for owners that already have one.
   */
  #ensureOwnerUserId(ownerId: string): string {
    const state = this.#usableState();
    if (Object.hasOwn(state.owners, ownerId)) return state.owners[ownerId].userId;
    if (Object.keys(state.owners).length >= MAX_OWNERS) {
      throw new Error(`owner-handle ceiling reached (${MAX_OWNERS}) — nothing mints for new owners`);
    }
    let userId = randomBytes(32).toString("base64url");
    const taken = new Set(Object.values(state.owners).map((handle) => handle.userId));
    while (taken.has(userId)) userId = randomBytes(32).toString("base64url");
    const ownersOut: Record<string, { userId: string }> = Object.create(null);
    for (const [id, handle] of Object.entries(state.owners)) ownersOut[id] = handle;
    ownersOut[ownerId] = { userId };
    const next: PersistedEnrolledDevices = { ...state, owners: ownersOut };
    let saved: SaveResult;
    try {
      saved = this.#store.save(next);
    } catch (err) {
      throw new Error(`owner user-handle persist FAILED (${message(err)}) — nothing mints`);
    }
    if (!saved.durable) {
      this.#quarantine(`owner user-handle publish durability UNPROVEN: ${saved.detail}`);
      throw new Error(
        `owner user-handle publish durability UNPROVEN (${saved.detail}) — registry quarantined until recovery`,
      );
    }
    this.#state = next;
    return userId;
  }

  /**
   * Mint an invite with the authority fields AND the owner filled from
   * LIVE state (see MintInviteRequest). register()'s own live-witness
   * gate then re-checks everything it is handed — a killed system, a
   * stale fact, or an out-of-standing issuer throws, and nothing minted.
   * The owner's durable user handle is established here too, BEFORE the
   * invite exists — the mint response must carry the complete WebAuthn
   * creation contract, and the handle in it must be the one every later
   * ceremony for this owner will see.
   */
  mintInvite(kill: LiveKillState, request: MintInviteRequest): InviteRecord {
    const state = this.#usableState();
    if (killStateIsMalformed(kill)) {
      throw new Error("malformed live kill state — nothing mints unproven (fail closed)");
    }
    let origin: InviteRecord["origin"];
    let ownerId: string;
    if (request.issuer.kind === "bootstrap") {
      origin = { kind: "bootstrap", bootstrapGeneration: state.bootstrapGeneration };
      ownerId = request.issuer.ownerId;
    } else {
      const devices = state.devices;
      const issuer = Object.hasOwn(devices, request.issuer.deviceId)
        ? devices[request.issuer.deviceId]
        : undefined;
      if (issuer === undefined || issuer.revokedAt !== null) {
        throw new Error("the inviting device is not enrolled and in standing — nothing mints");
      }
      origin = { kind: "device", deviceId: issuer.deviceId, deviceGeneration: issuer.generation };
      // the OWNER is the issuer's persisted owner — a device invites into
      // its own household, never someone else's (there is no request field
      // to claim otherwise; this line is where the fact comes from)
      ownerId = issuer.ownerId;
    }
    this.#ensureOwnerUserId(ownerId);
    return this.#invites.register(
      {
        inviteId: request.inviteId,
        tokenHash: request.tokenHash,
        ownerId,
        deviceName: request.deviceName,
        challenge: request.challenge,
        assertionChallenge: request.assertionChallenge,
        killEpoch: kill.epoch,
        origin,
      },
      this.#liveWitness(kill),
    );
  }

  /**
   * THE crash-atomic enrollment commit: run the full proof chain (which
   * burns the invite exactly once, in memory), then publish the new device
   * AND — for a bootstrap spend — the bootstrap generation bump in ONE
   * atomic file write, and only then update memory. Order and its honesty:
   *
   *   proof chain + burn  →  duplicate checks  →  atomic publish  →  memory
   *
   * A failed publish refuses with the invite already burned
   * (inviteSurvives: false — the safe direction: re-mint, never an
   * unpersisted device). An UNPROVEN publish (visible, but the directory
   * entry could not be fsynced — a power cut may resurface the old state)
   * QUARANTINES the registry: memory serves NOTHING until a fresh
   * initialize() establishes what actually survived. An unusable registry
   * refuses BEFORE the chain runs, invite untouched.
   */
  commitEnrollment(submission: unknown, opts: CommitEnrollmentOptions): CommitEnrollmentOutcome {
    if (this.#state === null) {
      return {
        ok: false,
        reason: `enrolled-device registry is not usable${this.#corruptDetail !== null ? `: ${this.#corruptDetail}` : ""} — nothing enrolls`,
        inviteSurvives: true,
      };
    }
    if (killStateIsMalformed(opts.kill)) {
      return {
        ok: false,
        reason: "malformed live kill state — nothing enrolls unproven (fail closed)",
        inviteSurvives: true,
      };
    }
    const state = this.#state;
    if (this.activeDeviceCount >= MAX_ACTIVE_DEVICES) {
      return {
        ok: false,
        reason: `device ceiling reached (${MAX_ACTIVE_DEVICES}) — revoke before enrolling more`,
        inviteSurvives: true,
      };
    }
    const outcome = performEnrollment(submission, {
      store: this.#invites,
      witness: this.#liveWitness(opts.kill),
      rpId: opts.rpId,
      expectedOrigin: opts.expectedOrigin,
    });
    if (!outcome.ok) {
      return { ok: false, reason: outcome.reason, inviteSurvives: outcome.inviteSurvives };
    }
    // ONE CREDENTIAL / CHEAP-LANE KEY, ONE DEVICE — across the WHOLE
    // history, revoked records included: re-enrolling a phone means fresh
    // keys, so a credential that ever lived here refuses. The invite is
    // already burned at this point, honestly reported: a re-played
    // credential costs the invite, by design.
    for (const existing of Object.values(state.devices)) {
      if (existing.credentialId === outcome.credential.credentialId) {
        return {
          ok: false,
          reason: "this WebAuthn credential was already enrolled here — re-enrolment requires fresh keys",
          inviteSurvives: false,
        };
      }
      if (existing.cheapLaneKeySpki === outcome.cheapLaneKeySpki) {
        return {
          ok: false,
          reason: "this cheap-lane key was already enrolled here — re-enrolment requires fresh keys",
          inviteSurvives: false,
        };
      }
    }
    let deviceId = this.#deviceIdFactory();
    while (Object.hasOwn(state.devices, deviceId) || FORBIDDEN_DEVICE_IDS.has(deviceId)) {
      deviceId = this.#deviceIdFactory();
    }
    const device: PersistedEnrolledDevice = {
      deviceId,
      ownerId: outcome.invite.ownerId,
      deviceName: outcome.invite.deviceName,
      credentialId: outcome.credential.credentialId,
      publicKeySpki: outcome.credential.publicKeySpki,
      cheapLaneKeySpki: outcome.cheapLaneKeySpki,
      signCount: outcome.credential.signCount,
      ...(outcome.credential.transports !== undefined
        ? { transports: [...outcome.credential.transports] }
        : {}),
      ...(outcome.credential.userHandle !== undefined
        ? { userHandle: outcome.credential.userHandle }
        : {}),
      generation: 1,
      revokedAt: null,
      enrolledAt: this.#now(),
    };
    // the next durable state: the device, and — bootstrap — the generation
    // bump, in the SAME publish: the lane closes durably with the admit
    const next: PersistedEnrolledDevices = {
      version: 2,
      bootstrapGeneration:
        outcome.invite.origin.kind === "bootstrap"
          ? state.bootstrapGeneration + 1
          : state.bootstrapGeneration,
      devices: nullProtoDevices([...Object.entries(state.devices), [deviceId, device] as const]),
      owners: state.owners,
    };
    let saved: SaveResult;
    try {
      saved = this.#store.save(next);
    } catch (err) {
      // invite burned, device NOT admitted — the safe direction; memory
      // unchanged, so the registry still matches the durable file
      return {
        ok: false,
        reason: `enrollment not admitted: durable registry publish FAILED (${message(err)}) — the invite is spent, mint a new one`,
        inviteSurvives: false,
      };
    }
    if (!saved.durable) {
      // The publish is VISIBLE but its durability is UNPROVEN (dir-fsync
      // failed): after a power cut either state may be on disk. Guessing
      // in memory — old OR new — could disagree with what survives, so
      // the registry QUARANTINES: no standing, no witness, no mint, no
      // enrollment, until a fresh initialize() reads what disk actually
      // holds. The client's refusal is honest: the invite is spent.
      this.#quarantine(`enrollment publish durability UNPROVEN: ${saved.detail}`);
      return {
        ok: false,
        reason: `enrollment not admitted: durable registry publish UNPROVEN (${saved.detail}) — registry quarantined until recovery, the invite is spent`,
        inviteSurvives: false,
      };
    }
    this.#state = next;
    return { ok: true, device: cloneDevice(device), durable: true };
  }
}
