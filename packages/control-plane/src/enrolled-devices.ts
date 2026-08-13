/**
 * The DURABLE enrolled-device registry — the persistence half of the
 * enrollment ceremony (apps/owner/DESIGN.md §2 step 5: "stores ONE
 * EnrolledDevice record holding both credentials"), and the ONLY place a
 * mint/spend witness is assembled. Three jobs, each a review-pinned
 * requirement:
 *
 *  1. WITNESS FROM LIVE STATE ONLY. The InviteSpendWitness handed to the
 *     invite store is built HERE, synchronously, from the loaded durable
 *     registry plus the caller's live kill snapshot — there is no API that
 *     accepts a witness from outside, so an HTTP handler cannot relay a
 *     wire-supplied one (the exact hole the review named).
 *
 *  2. CRASH-ATOMIC COMMIT. A successful ceremony admits a device by ONE
 *     atomic file publish that carries the new device AND the bootstrap
 *     generation bump together (temp + fsync + rename + dir-fsync — the
 *     kill-state discipline). In-memory state changes only AFTER the
 *     publish reports durable. The crash window is honest and fails in the
 *     safe direction: the invite burns in memory BEFORE the write, so a
 *     crash (or a failed persist) between burn and publish loses the
 *     INVITE, never admits an unpersisted device — the owner re-mints; a
 *     crash after publish before the response leaves a durably enrolled
 *     device the client discovers on the device list.
 *
 *  3. FAIL-CLOSED REGISTRY. A corrupt, missing-after-initialized, or
 *     boundary-violating registry file makes the registry UNUSABLE: no
 *     witness, no mint, no enrollment — refused before any proof chain
 *     runs, with the invite left alone. Same load discipline as the
 *     standing store: O_NOFOLLOW, bounded read, strict shape (canonical
 *     base64url re-checked field by field), owner + mode 0600 exactly.
 *
 * Scope, stated plainly: this registry is the durable source of truth for
 * CEREMONY-enrolled devices. Wiring it into the request-auth path, remote
 * revocation, and the reconciliation with the operator-provisioned keys
 * file (owner-device-file.ts) belong to the HTTP slice — nothing reads
 * this registry for authentication yet, so its records grant nothing until
 * that slice lands behind the same review gate.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
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
import {
  performEnrollment,
  type InviteRecord,
  type InviteSpendWitness,
  type InviteStore,
} from "./invite.js";

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
  version: 1;
  /**
   * The bootstrap generation — bumped in the SAME atomic publish as a
   * successful bootstrap enrolment, so the bootstrap lane self-closes
   * durably: any bootstrap invite recorded under the old generation is
   * dead at its spend, across restarts.
   */
  bootstrapGeneration: number;
  devices: Record<string, PersistedEnrolledDevice>;
}

export type EnrolledDevicesLoad =
  | { outcome: "absent" }
  | { outcome: "loaded"; state: PersistedEnrolledDevices }
  | { outcome: "corrupt"; detail: string };

/** Generous ceiling for a household-scale device registry; bounds a hostile file. */
export const MAX_ENROLLED_DEVICES_FILE_BYTES = 512 * 1024;
/** Active-device ceiling (flood backstop) — households, not fleets. */
export const MAX_ACTIVE_DEVICES = 64;

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;

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

/** Strict shape check — anything we would not have written reads as corrupt. */
function asPersistedEnrolledDevices(value: unknown): PersistedEnrolledDevices | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { version, bootstrapGeneration, devices, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (version !== 1) return null;
  if (
    typeof bootstrapGeneration !== "number" ||
    !Number.isSafeInteger(bootstrapGeneration) ||
    bootstrapGeneration < 1
  ) {
    return null;
  }
  if (typeof devices !== "object" || devices === null || Array.isArray(devices)) return null;
  const out: Record<string, PersistedEnrolledDevice> = {};
  const seenCredentials = new Set<string>();
  for (const [deviceId, record] of Object.entries(devices)) {
    if (deviceId === "" || deviceId.length > 128) return null;
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
    if (typeof publicKeySpki !== "string" || !isCanonicalB64url(publicKeySpki, 1, 4096)) return null;
    if (typeof cheapLaneKeySpki !== "string" || !isCanonicalB64url(cheapLaneKeySpki, 1, 4096)) {
      return null;
    }
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
    // one credential, one device: a registry claiming otherwise is corrupt
    if (seenCredentials.has(credentialId)) return null;
    seenCredentials.add(credentialId);
    out[deviceId] = {
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
    };
  }
  return { version: 1, bootstrapGeneration, devices: out };
}

export interface EnrolledDeviceStoreOptions {
  /**
   * The uids allowed to OWN the registry file (checked at LOAD, fstat on
   * the open fd). Default: root and this process. The registry is positive
   * authorization state-to-be — mode is pinned to EXACTLY 0600, no group
   * model: nothing else reads it (the escalation service consumes standing
   * through the standing store, not this file).
   */
  trustedOwnerUids?: number[];
}

/**
 * The registry FILE — kill-state.ts's persistence discipline, verbatim in
 * miniature (atomic publish, `.initialized` marker so deletion reads as
 * corruption, O_NOFOLLOW + fstat + bounded read on load, strict shape).
 */
export class EnrolledDeviceFileStore {
  private warnedDirFsync = false;
  private readonly trustedOwnerUids: ReadonlySet<number>;

  constructor(
    readonly filePath: string,
    opts: EnrolledDeviceStoreOptions = {},
  ) {
    const ourUid = typeof process.getuid === "function" ? process.getuid() : 0;
    this.trustedOwnerUids = new Set(opts.trustedOwnerUids ?? [0, ourUid]);
  }

  get markerPath(): string {
    return `${this.filePath}.initialized`;
  }

  load(): EnrolledDevicesLoad {
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
      if (!stat.isFile()) {
        return { outcome: "corrupt", detail: `${this.filePath} is not a regular file` };
      }
      if (!this.trustedOwnerUids.has(stat.uid)) {
        return {
          outcome: "corrupt",
          detail: `${this.filePath} is owned by uid ${stat.uid} — not root, this process, or a configured trusted uid`,
        };
      }
      if ((stat.mode & 0o7777) !== 0o600) {
        return {
          outcome: "corrupt",
          detail:
            `${this.filePath} has mode ${(stat.mode & 0o7777).toString(8)} — the enrolled-device ` +
            "registry is private to the control plane, EXACTLY 0600",
        };
      }
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

  save(state: PersistedEnrolledDevices): SaveResult {
    mkdirSync(dirname(this.filePath), { recursive: true });
    // Marker before state: a save that dies half-way errs toward
    // "initialised but missing" — which loads corrupt and refuses all
    // enrollment, never toward a fresh boot that forgets devices.
    const markerDurable = this.ensureMarker();
    const tmp = `${this.filePath}.${randomBytes(8).toString("hex")}.tmp`;
    const data = Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8");
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
    if (existsSync(this.markerPath)) return true;
    let fd: number | undefined;
    try {
      fd = openSync(this.markerPath, CREATE_FLAGS, 0o600);
      fchmodSync(fd, 0o600);
      const note = Buffer.from(
        "This marker records that the OwnerSwitch enrolled-device registry has been written.\n" +
          "While it exists, a missing registry file loads as CORRUPT (no enrollment, no witness).\n",
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
          `[ownerswitch] cannot fsync ${dirname(this.filePath)} — enrolled-device durability is degraded`,
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

/** What the server hands the registry to mint an invite — NO authority fields. */
export interface MintInviteRequest {
  inviteId: string;
  /** SHA-256 of the locally generated secret, canonical base64url (the commitment) */
  tokenHash: string;
  ownerId: string;
  deviceName: string;
  challenge: string;
  assertionChallenge: string;
  /**
   * Who is minting: the host (bootstrap) or an enrolled device. The
   * authority facts — kill epoch, bootstrap generation, the issuer's
   * CURRENT revocation generation — are filled in HERE from live state,
   * never accepted from the caller.
   */
  issuer: { kind: "bootstrap" } | { kind: "device"; deviceId: string };
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
  invites: InviteStore;
  /** the live kill snapshot, read from the real KillSwitch by the caller */
  kill: LiveKillState;
  rpId: string;
  expectedOrigin: string;
}

export interface EnrolledDeviceRegistryOptions {
  now?: () => number;
  /** test-only deterministic device ids */
  deviceIdFactory?: () => string;
}

/**
 * The registry RUNTIME: loads the durable state once, answers standing
 * queries from memory, assembles every witness, and owns the crash-atomic
 * enrollment commit. Every mutating path publishes durably BEFORE memory
 * changes; every refusal names whether the invite survived.
 */
export class EnrolledDeviceRegistry {
  readonly #store: EnrolledDeviceFileStore;
  readonly #now: () => number;
  readonly #deviceIdFactory: () => string;
  #state: PersistedEnrolledDevices | null = null;
  #corruptDetail: string | null = null;

  constructor(store: EnrolledDeviceFileStore, opts: EnrolledDeviceRegistryOptions = {}) {
    this.#store = store;
    this.#now = opts.now ?? Date.now;
    this.#deviceIdFactory = opts.deviceIdFactory ?? (() => `dev_${randomBytes(12).toString("base64url")}`);
  }

  /**
   * Load the durable state (or persist the first-boot state so the marker
   * exists from the first instant). An unusable registry stays unusable —
   * there is no in-memory fallback to enroll into.
   */
  initialize(): { ok: true } | { ok: false; detail: string } {
    const loaded = this.#store.load();
    if (loaded.outcome === "corrupt") {
      this.#state = null;
      this.#corruptDetail = loaded.detail;
      return { ok: false, detail: loaded.detail };
    }
    if (loaded.outcome === "loaded") {
      this.#state = loaded.state;
      this.#corruptDetail = null;
      return { ok: true };
    }
    // genuine first boot: bootstrap generation starts at 1, persisted NOW —
    // from here on a missing file is corruption, not a fresh start
    const initial: PersistedEnrolledDevices = { version: 1, bootstrapGeneration: 1, devices: {} };
    let saved: SaveResult;
    try {
      saved = this.#store.save(initial);
    } catch (err) {
      this.#state = null;
      this.#corruptDetail = `first-boot registry persist failed: ${message(err)}`;
      return { ok: false, detail: this.#corruptDetail };
    }
    if (!saved.durable) {
      this.#state = null;
      this.#corruptDetail = `first-boot registry persist not durable: ${saved.detail}`;
      return { ok: false, detail: this.#corruptDetail };
    }
    this.#state = initial;
    this.#corruptDetail = null;
    return { ok: true };
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
    const device = this.#usableState().devices[deviceId];
    return device !== undefined && device.revokedAt === null && device.generation === generation;
  }

  get(deviceId: string): PersistedEnrolledDevice | null {
    const device = this.#usableState().devices[deviceId];
    return device === undefined ? null : { ...device };
  }

  list(): PersistedEnrolledDevice[] {
    return Object.values(this.#usableState().devices).map((device) => ({ ...device }));
  }

  /**
   * The ONE witness assembly — live kill snapshot + this registry's loaded
   * durable state, nothing else. Throws on an unusable registry or a
   * malformed kill snapshot (fail closed): no witness, no spend.
   */
  liveWitness(kill: LiveKillState): InviteSpendWitness {
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

  /**
   * Mint an invite with the authority fields filled from LIVE state: the
   * caller names WHO mints (bootstrap host / an enrolled device) and the
   * ceremony contract; the kill epoch, bootstrap generation, and the
   * issuer's current revocation generation come from here. register()'s
   * own live-witness gate then re-checks everything it is handed — a
   * killed system, a stale fact, or an out-of-standing issuer throws.
   */
  mintInvite(invites: InviteStore, kill: LiveKillState, request: MintInviteRequest): InviteRecord {
    const state = this.#usableState();
    if (killStateIsMalformed(kill)) {
      throw new Error("malformed live kill state — nothing mints unproven (fail closed)");
    }
    let origin: InviteRecord["origin"];
    if (request.issuer.kind === "bootstrap") {
      origin = { kind: "bootstrap", bootstrapGeneration: state.bootstrapGeneration };
    } else {
      const issuer = state.devices[request.issuer.deviceId];
      if (issuer === undefined || issuer.revokedAt !== null) {
        throw new Error("the inviting device is not enrolled and in standing — nothing mints");
      }
      origin = { kind: "device", deviceId: issuer.deviceId, deviceGeneration: issuer.generation };
    }
    return invites.register(
      {
        inviteId: request.inviteId,
        tokenHash: request.tokenHash,
        ownerId: request.ownerId,
        deviceName: request.deviceName,
        challenge: request.challenge,
        assertionChallenge: request.assertionChallenge,
        killEpoch: kill.epoch,
        origin,
      },
      this.liveWitness(kill),
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
   * A failed or non-durable publish refuses the enrollment with the invite
   * already burned (inviteSurvives: false — the safe direction: re-mint,
   * never an unpersisted device that evaporates on restart). An unusable
   * registry refuses BEFORE the chain runs, invite untouched.
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
      store: opts.invites,
      witness: this.liveWitness(opts.kill),
      rpId: opts.rpId,
      expectedOrigin: opts.expectedOrigin,
    });
    if (!outcome.ok) {
      return { ok: false, reason: outcome.reason, inviteSurvives: outcome.inviteSurvives };
    }
    // ONE CREDENTIAL, ONE DEVICE: a ceremony that verified against a
    // credential (or cheap-lane key) already enrolled on an ACTIVE device
    // is refused — the invite is already burned at this point, honestly
    // reported: a re-played credential costs the invite, by design.
    for (const existing of Object.values(state.devices)) {
      if (existing.revokedAt !== null) continue;
      if (existing.credentialId === outcome.credential.credentialId) {
        return {
          ok: false,
          reason: "this WebAuthn credential is already enrolled on an active device",
          inviteSurvives: false,
        };
      }
      if (existing.cheapLaneKeySpki === outcome.cheapLaneKeySpki) {
        return {
          ok: false,
          reason: "this cheap-lane key is already enrolled on an active device",
          inviteSurvives: false,
        };
      }
    }
    let deviceId = this.#deviceIdFactory();
    while (state.devices[deviceId] !== undefined) deviceId = this.#deviceIdFactory();
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
      version: 1,
      bootstrapGeneration:
        outcome.invite.origin.kind === "bootstrap"
          ? state.bootstrapGeneration + 1
          : state.bootstrapGeneration,
      devices: { ...state.devices, [deviceId]: device },
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
      // The publish is VISIBLE but its durability could not be proven
      // (dir-fsync failed). Admitting from memory while the file might
      // resurface the old state after a power cut would be a lie in the
      // permissive direction — refuse, and RELOAD the store's view so
      // memory keeps matching whatever the file now says.
      const reload = this.#store.load();
      if (reload.outcome === "loaded") this.#state = reload.state;
      return {
        ok: false,
        reason: `enrollment not admitted: durable registry publish UNPROVEN (${saved.detail}) — the invite is spent, mint a new one`,
        inviteSurvives: false,
      };
    }
    this.#state = next;
    return { ok: true, device: { ...device }, durable: true };
  }
}
