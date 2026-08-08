import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync as fsReadFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import type { Honeytoken, HoneytokenKind } from "./generate.js";

/**
 * A deployment-scoped registry of planted honeytokens.
 *
 * Recognition is exact membership: a text trips only if it contains a value
 * that was actually planted for THIS deployment. There is no short
 * self-validating checksum an attacker could brute-force, and no per-candidate
 * HMAC to grind — matching is a bounded set of substring checks.
 *
 * The registry is bound to a deployment two ways (fix for the "wrong key by
 * default" review):
 *  - a DEDICATED canary key, provisioned explicitly. There is no fallback to
 *    the device secret: sharing that secret across gateways would make
 *    cross-deployment matching accidental, and differing device secrets would
 *    stop two gateways of the SAME deployment recognising each other's
 *    tokens. The canary key is its own thing.
 *  - an immutable deploymentId, mixed into the integrity MAC's domain
 *    separation. A registry file minted for deployment A is rejected at load
 *    under deployment B's id even if the key happened to match.
 *
 * The serialized file is MAC'd with the canary key so a tampered registry
 * (entries added to force false kills, or removed to blind the tripwire) is
 * rejected at load. The plaintext values live in the file and in any gateway
 * that loads it — a deliberate trade: the gateway is the enforcement point,
 * and a compromise there already defeats honeytokens (see README).
 *
 * The MAC gives INTEGRITY, not FRESHNESS: it proves the entries were minted
 * by whoever holds the canary key, not that this is the CURRENT registry. An
 * old-but-validly-signed file replayed back over a rotated one still verifies
 * for the same deployment — there is no version counter or timestamp bound
 * into the MAC. See README.md for what that means for where this file lives.
 *
 * readRegistryFile / writeRegistryFile below mirror the safety properties of
 * control-plane's kill-state store: reads refuse to follow a symlink and are
 * capped in size before the bytes are ever handed to JSON.parse, and writes
 * land at 0600 via an atomic temp-file-then-rename (which itself can never be
 * tricked into writing through a symlink at the destination — rename(2)
 * replaces the link, it never follows it).
 */

const REGISTRY_VERSION = 1;
const MAC_DOMAIN = "ownerswitch-honeytoken-registry-v1";

/** Hard ceiling on the number of entries a registry may hold — see loadRegistry(). */
export const MAX_REGISTRY_ENTRIES = 10_000;
/** Hard ceiling on the registry file's byte size — see readRegistryFile(). */
export const MAX_REGISTRY_FILE_BYTES = 8 * 1024 * 1024;

export interface RegistryEntry {
  canaryId: string;
  kind: HoneytokenKind;
  label?: string;
  /** The full planted decoy value — what match() looks for. */
  value: string;
}

export interface HoneytokenMatch {
  /** Public label of the matched token — names it in the audit/kill reason. */
  canaryId: string;
  kind: HoneytokenKind;
  /** The matched decoy value. */
  value: string;
  /** Character offset of the first occurrence in the scanned text. */
  index: number;
}

export interface RegistryIdentity {
  /** Dedicated per-deployment canary key. NEVER the device secret. */
  canaryKey: string;
  /** Immutable deployment identifier, bound into the integrity MAC. */
  deploymentId: string;
}

const MIN_KEY_LENGTH = 24;

// Values that "look provisioned" but aren't — a config left at its example.
const WEAK_KEYS = new Set(
  [
    "changeme",
    "change-me",
    "secret",
    "password",
    "passphrase",
    "test",
    "testing",
    "example",
    "sample",
    "canary",
    "canarykey",
    "canary-key",
    "honeytoken",
    "deployment",
    "default",
    "devsecret",
    "dev-secret",
    "devicesecret",
    "device-secret",
    "your-secret",
    "your-secret-here",
    "your-canary-key",
    "placeholder",
    "todo",
    "0123456789abcdef",
  ].map((s) => s.toLowerCase()),
);

/**
 * Reject an absent, too-short, low-entropy, or obviously-sample canary key.
 * A weak key defeats both the tamper MAC and the deployment scoping, so this
 * fails loudly at config time rather than shipping a forgeable tripwire.
 */
export function requireCanaryKey(canaryKey: unknown, deploymentId?: string): asserts canaryKey is string {
  if (typeof canaryKey !== "string" || canaryKey === "") {
    throw new Error(
      "a dedicated per-deployment canary key is required (there is no fallback to the device secret)",
    );
  }
  if (canaryKey.length < MIN_KEY_LENGTH) {
    throw new Error(
      `canary key is too short (${canaryKey.length} chars) — use at least ${MIN_KEY_LENGTH} random characters`,
    );
  }
  const norm = canaryKey.trim().toLowerCase();
  if (WEAK_KEYS.has(norm)) {
    throw new Error("canary key is a weak or sample value — provision a real random secret");
  }
  if (/^(.)\1*$/.test(canaryKey)) {
    throw new Error("canary key is a single repeated character — provision a real random secret");
  }
  if (deploymentId !== undefined && canaryKey === deploymentId) {
    throw new Error("canary key must not equal the deployment id — they are separate secrets");
  }
}

export function requireDeploymentId(deploymentId: unknown): asserts deploymentId is string {
  if (typeof deploymentId !== "string" || deploymentId.trim().length < 3) {
    throw new Error("a deployment id of at least 3 characters is required");
  }
}

export class HoneytokenRegistry {
  private readonly entries: RegistryEntry[];

  constructor(
    private readonly canaryKey: string,
    readonly deploymentId: string,
    entries: RegistryEntry[] = [],
  ) {
    requireCanaryKey(canaryKey, deploymentId);
    requireDeploymentId(deploymentId);
    this.entries = [...entries];
  }

  get size(): number {
    return this.entries.length;
  }

  /** Register a freshly minted token. */
  add(token: Honeytoken): void {
    this.entries.push({
      canaryId: token.canaryId,
      kind: token.kind,
      ...(token.label !== undefined ? { label: token.label } : {}),
      value: token.value,
    });
  }

  /** Public labels of every registered token (for logging / arm-time labeling). */
  canaryIds(): string[] {
    return this.entries.map((e) => e.canaryId);
  }

  /**
   * Every registered value that appears in `text`, deduped by canaryId, in
   * order of first occurrence. Empty = clean. Cost is O(entries × |text|):
   * bounded by the number of planted tokens, never by attacker payload size.
   */
  match(text: string): HoneytokenMatch[] {
    const out: HoneytokenMatch[] = [];
    const seen = new Set<string>();
    for (const e of this.entries) {
      if (seen.has(e.canaryId)) continue;
      const index = text.indexOf(e.value);
      if (index >= 0) {
        seen.add(e.canaryId);
        out.push({ canaryId: e.canaryId, kind: e.kind, value: e.value, index });
      }
    }
    return out.sort((a, b) => a.index - b.index);
  }

  /** Domain-separated integrity tag over (deploymentId, entries). */
  private computeMac(): string {
    const canonical = JSON.stringify(
      this.entries.map((e) => [e.canaryId, e.kind, e.label ?? null, e.value]),
    );
    return createHmac("sha256", this.canaryKey)
      .update(`${MAC_DOMAIN}\n${this.deploymentId}\n${canonical}`)
      .digest("hex");
  }

  /** Constant-time check that `mac` is this registry's integrity tag. */
  verifyMac(mac: string): boolean {
    return equalHex(this.computeMac(), mac);
  }

  /** Serialize to a signed JSON file (keep it OUT of the planted directory). */
  serialize(): string {
    return `${JSON.stringify(
      { version: REGISTRY_VERSION, deploymentId: this.deploymentId, entries: this.entries, mac: this.computeMac() },
      null,
      2,
    )}\n`;
  }
}

function equalHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

function isEntry(v: unknown): v is RegistryEntry {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.canaryId === "string" &&
    typeof e.kind === "string" &&
    typeof e.value === "string" &&
    (e.label === undefined || typeof e.label === "string")
  );
}

/**
 * Load and verify a serialized registry. Throws loudly on: wrong version, a
 * deploymentId that isn't the one we expect, malformed entries, or a MAC that
 * doesn't verify under `canaryKey` (tampered file or wrong key). A tripwire
 * that silently loaded a bad registry would be worse than none.
 */
export function loadRegistry(serialized: string, identity: RegistryIdentity): HoneytokenRegistry {
  requireCanaryKey(identity.canaryKey, identity.deploymentId);
  requireDeploymentId(identity.deploymentId);

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("honeytoken registry is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("honeytoken registry must be a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== REGISTRY_VERSION) {
    throw new Error(`unsupported honeytoken registry version ${String(obj.version)}`);
  }
  if (obj.deploymentId !== identity.deploymentId) {
    throw new Error(
      `honeytoken registry is for deployment "${String(obj.deploymentId)}", not "${identity.deploymentId}"`,
    );
  }
  if (!Array.isArray(obj.entries)) {
    throw new Error("honeytoken registry entries must be an array");
  }
  // Reject an oversized entry count BEFORE the O(n) shape-validation pass
  // below: a huge array is itself the resource-exhaustion risk (parse-time
  // memory plus per-call match() cost scales with entry count), so the size
  // check has to run first, not after paying to validate every element.
  if (obj.entries.length > MAX_REGISTRY_ENTRIES) {
    throw new Error(
      `honeytoken registry has ${obj.entries.length} entries, over the ${MAX_REGISTRY_ENTRIES}-entry limit`,
    );
  }
  if (!obj.entries.every(isEntry)) {
    throw new Error("honeytoken registry entries are malformed");
  }
  if (typeof obj.mac !== "string") {
    throw new Error("honeytoken registry is missing its integrity MAC");
  }
  const registry = new HoneytokenRegistry(
    identity.canaryKey,
    identity.deploymentId,
    obj.entries as RegistryEntry[],
  );
  if (!registry.verifyMac(obj.mac)) {
    throw new Error(
      "honeytoken registry MAC does not verify — the file was tampered with or the canary key is wrong",
    );
  }
  return registry;
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const errCode = (err: unknown): string | undefined => (err as NodeJS.ErrnoException).code;

// O_NOFOLLOW is POSIX; on a platform without it the flag degrades to 0 and
// the fstat regular-file check in readRegistryFile is the remaining guard —
// same fallback control-plane's kill-state store uses.
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
// New files only: never reuse an existing name, never follow a symlink
// planted at it, and 0600 — a honeytoken registry is nobody else's to read.
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;

/**
 * Read a registry file the way it must be read: refuse to follow a symlink
 * at `path` (O_NOFOLLOW — the race-free version of "lstat, then read"), and
 * refuse anything over MAX_REGISTRY_FILE_BYTES BEFORE the bytes are pulled
 * into memory, let alone handed to JSON.parse. A locally-replaced huge file
 * is rejected on its size, not after the read+parse already paid for it.
 */
export function readRegistryFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | O_NOFOLLOW);
  } catch (err) {
    if (errCode(err) === "ELOOP") {
      throw new Error(`${path} is a symlink — refusing to follow it`);
    }
    throw new Error(`cannot open honeytoken registry ${path}: ${message(err)}`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new Error(`${path} is not a regular file`);
    }
    if (stat.size > MAX_REGISTRY_FILE_BYTES) {
      throw new Error(
        `${path} is ${stat.size} bytes, over the ${MAX_REGISTRY_FILE_BYTES}-byte honeytoken registry ` +
          `limit — refusing to read it into memory`,
      );
    }
    return fsReadFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Write a registry file the way it must be written: a temp file created with
 * O_EXCL|O_NOFOLLOW at 0600, fsynced, then published with an atomic rename.
 * The rename is itself symlink-safe on the destination side by construction
 * — rename(2) replaces whatever sits at `path`, including a symlink, rather
 * than following it — so this can't be tricked into writing through a link
 * planted at the destination.
 */
export function writeRegistryFile(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${randomBytes(8).toString("hex")}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(tmp, CREATE_FLAGS, 0o600);
    writeSync(fd, contents);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
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
}
