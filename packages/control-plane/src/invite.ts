/**
 * Enrolment invites — the HASH-COMMITMENT store (apps/owner/DESIGN.md §2,
 * types.ts InviteMintRequest). The inviting side (an enrolled device, or the
 * host CLI for bootstrap) generates the ≥128-bit secret LOCALLY and submits
 * only its SHA-256; this store never sees, stores, or returns the secret —
 * a captured mint request, a raced response, or a read of this process's
 * memory yields a hash that opens nothing. The secret travels
 * device-to-device (QR / typed code) and comes back exactly once, as the
 * preimage inside POST /devices/enroll.
 *
 * Spend discipline: consume() is a single SYNCHRONOUS check-and-burn — the
 * caller runs it ONLY AFTER the registration and the proof-of-possession
 *verified, so a failed attempt leaves the invite alive (a typo must not
 * burn the owner's only invite) while a success burns it atomically before
 * anything else can race it. TTL-expired and spent invites are refused and
 * swept; the store is capped as a flood backstop.
 */
import { createHash, timingSafeEqual } from "node:crypto";

export interface InviteOrigin {
  /** who minted it: the host (bootstrap, zero devices) or an enrolled device */
  kind: "bootstrap" | "device";
  /** minting device id (kind "device"); re-checked at spend by the caller */
  deviceId?: string;
  /** the minting device's revocation generation at mint (kind "device") */
  deviceGeneration?: number;
}

export interface InviteRecord {
  inviteId: string;
  /** SHA-256 of the invite secret, base64url — the commitment, never the secret */
  tokenHash: string;
  /** the owner this device will act for — bound at mint, never claimed by the phone */
  ownerId: string;
  /** human label for the device being invited (display only) */
  deviceName: string;
  /** base64url WebAuthn creation challenge minted alongside the invite */
  challenge: string;
  expiresAt: number;
  origin: InviteOrigin;
}

export type InviteConsume =
  | { ok: true; record: InviteRecord }
  | { ok: false; reason: string };

export interface InviteStoreOptions {
  now?: () => number;
  /** invite lifetime; default 10 minutes — short, because possession IS proof */
  ttlMs?: number;
  /** live-invite ceiling (flood backstop); default 32 */
  maxInvites?: number;
}

const DEFAULT_TTL_MS = 10 * 60_000;
const DEFAULT_MAX = 32;

export class InviteStore {
  private readonly invites = new Map<string, InviteRecord>();
  private readonly now: () => number;
  readonly ttlMs: number;
  private readonly maxInvites: number;

  constructor(opts: InviteStoreOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    this.maxInvites = opts.maxInvites ?? DEFAULT_MAX;
  }

  /** Sweep dead invites so the cap only ever counts live ones. */
  private sweep(): void {
    for (const [id, record] of this.invites) {
      if (this.now() >= record.expiresAt) this.invites.delete(id);
    }
  }

  /**
   * Register a minted invite. The caller provides the tokenHash it received
   * (the commitment) — never a secret. Refuses a duplicate id and the cap.
   */
  register(record: Omit<InviteRecord, "expiresAt">): InviteRecord {
    this.sweep();
    if (record.inviteId === "") throw new Error("inviteId must be non-empty");
    if (this.invites.has(record.inviteId)) {
      throw new Error(`invite "${record.inviteId}" already exists`);
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(record.tokenHash)) {
      // base64url SHA-256 is exactly 43 chars unpadded; anything else is not
      // a commitment this store can compare in constant time
      throw new Error("tokenHash must be an unpadded base64url SHA-256 (43 chars)");
    }
    if (record.ownerId === "") throw new Error("ownerId must be non-empty");
    if (this.invites.size >= this.maxInvites) {
      throw new Error(`too many live invites (${this.maxInvites}) — spend or let them expire`);
    }
    const full: InviteRecord = { ...record, expiresAt: this.now() + this.ttlMs };
    this.invites.set(full.inviteId, full);
    return full;
  }

  /** Read without spending — the enroll handler verifies against this first. */
  peek(inviteId: string): InviteRecord | null {
    const record = this.invites.get(inviteId);
    if (record === undefined) return null;
    if (this.now() >= record.expiresAt) {
      this.invites.delete(inviteId);
      return null;
    }
    return record;
  }

  /**
   * Check-and-burn, in one synchronous step: the submitted SECRET must be
   * the preimage of the stored commitment (constant-time over the hashes),
   * the invite must be live — then it is GONE before anything can race a
   * second spend. Call only after every other enrolment check has passed.
   */
  consume(inviteId: string, tokenSecret: string): InviteConsume {
    const record = this.invites.get(inviteId);
    if (record === undefined) return { ok: false, reason: "unknown or already-spent invite" };
    if (this.now() >= record.expiresAt) {
      this.invites.delete(inviteId);
      return { ok: false, reason: "invite expired" };
    }
    const submitted = createHash("sha256").update(tokenSecret, "utf8").digest();
    const committed = Buffer.from(record.tokenHash, "base64url");
    if (submitted.length !== committed.length || !timingSafeEqual(submitted, committed)) {
      return { ok: false, reason: "invite secret does not match the commitment" };
    }
    this.invites.delete(inviteId); // burn — atomic with the check above
    return { ok: true, record };
  }

  /**
   * A SUCCESSFUL bootstrap enrolment invalidates every sibling bootstrap
   * invite (types.ts /devices/enroll): the first phone in wins the root of
   * trust; a second bootstrap secret lying in a drawer must not enroll a
   * second root later. Device-minted invites are untouched.
   */
  invalidateBootstrapSiblings(): number {
    let removed = 0;
    for (const [id, record] of this.invites) {
      if (record.origin.kind === "bootstrap") {
        this.invites.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    this.sweep();
    return this.invites.size;
  }
}
