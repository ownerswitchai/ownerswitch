/**
 * Enrolment invites — the HASH-COMMITMENT store (apps/owner/DESIGN.md §2;
 * the wire contract is apps/owner/src/types.ts InviteMintRequest, whose
 * `tokenHash` field this store's records mirror). The inviting side (an
 * enrolled device, or the host CLI for bootstrap) generates the ≥128-bit
 * secret LOCALLY and submits only its SHA-256. Precisely stated: this store
 * never sees the secret AT MINT and never PERSISTS it anywhere — at
 * redemption the secret arrives exactly once as the preimage in the enroll
 * request, is hashed, compared, and dropped. A captured mint request, a
 * raced mint response, or a read of this process's memory between mint and
 * spend therefore yields only a hash that opens nothing.
 *
 * AUTHORITY STATE rides the record, not the caller's memory: every invite
 * binds the KILL EPOCH in force at mint (an invite minted before a kill is
 * dead after it — even after a restore, like every other pre-kill
 * authority), and its ISSUER at the issuer's then-current standing — the
 * host's bootstrap generation, or the minting device at its revocation
 * generation. consume() re-checks BOTH against live witnesses in the same
 * synchronous step as the burn, so a revoked issuer's invite, a
 * generation-bumped issuer's invite, and a cross-epoch invite all refuse.
 *
 * Spend discipline: consume() is one synchronous check-and-burn, run ONLY
 * AFTER the registration, the fresh-assertion possession proof, and the
 * cheap-lane PoP verified — a failed attempt leaves the invite alive (a
 * typo must not burn the owner's only invite), a success burns it before
 * anything can race a second spend, and a successful BOOTSTRAP spend burns
 * every sibling bootstrap invite IN THE SAME STEP: the first phone in wins
 * the root of trust; a second bootstrap secret in a drawer enrolls nothing.
 */
import { createHash, timingSafeEqual } from "node:crypto";

/**
 * The spend authorization — proof that the full enrolment verification chain
 * ran for ONE invite — enforced as a REAL JavaScript boundary, not a
 * TypeScript fiction: a TS `private constructor` compiles away, so
 * `Reflect.construct`, `new`, and `Object.create(SpendAuthorization.prototype)`
 * all produce objects that pass an instanceof check. What cannot be forged is
 * MEMBERSHIP in this module-private WeakSet: only mintings that went through
 * the claimed minter (below) are in it, and consume() checks the set, never
 * the prototype chain. There is no exported brand to deep-import either —
 * the minter is handed out ONCE, at module-load time, to the first claimant
 * (enrollment.ts imports invite.js and claims in its module initializer); a
 * later claimant throws. The residual truth, stated plainly: code running IN
 * THIS PROCESS with import access could still race the claim or patch these
 * modules — in-process code is the trust domain here, the same as for the
 * kill switch's own Map. The boundary this closes is the API one: no
 * consumer of the package, and no plain-JS object forgery, reaches the burn
 * around the proofs.
 */
const MINTED_AUTHORIZATIONS = new WeakSet<SpendAuthorization>();
let mintAuthorization: (inviteId: string) => SpendAuthorization;
let minterClaimed = false;

export class SpendAuthorization {
  private constructor(readonly inviteId: string) {}
  static {
    // the one factory, captured by claimSpendMinter below — the class itself
    // exposes no way to mint
    mintAuthorization = (inviteId: string) => {
      const authorization = new SpendAuthorization(inviteId);
      MINTED_AUTHORIZATIONS.add(authorization);
      return authorization;
    };
  }
}

/**
 * Hand out the ONE spend-minter, exactly once per module instance.
 * enrollment.ts claims it in its module initializer; any later call —
 * including a deep import racing it — throws. @internal
 */
export function claimSpendMinter(): (inviteId: string) => SpendAuthorization {
  if (minterClaimed) {
    throw new Error("the spend minter is already claimed (enrollment.ts) — there is exactly one");
  }
  minterClaimed = true;
  return mintAuthorization;
}

/** Membership check — the ONLY thing consume() trusts about an authorization. */
export function isMintedAuthorization(value: unknown): value is SpendAuthorization {
  return MINTED_AUTHORIZATIONS.has(value as SpendAuthorization);
}

export type InviteOrigin =
  | {
      kind: "bootstrap";
      /** the host's bootstrap generation at mint — re-checked at spend */
      bootstrapGeneration: number;
    }
  | {
      kind: "device";
      deviceId: string;
      /** the minting device's revocation generation at mint — re-checked at spend */
      deviceGeneration: number;
    };

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
  /**
   * base64url challenge for the ceremony's SECOND proof: the fresh
   * webauthn.get assertion with the newly created credential — the
   * possession-and-UV evidence attestation "none" cannot give (see
   * enrollment.ts). Minted with the invite, single-use with it.
   */
  assertionChallenge: string;
  /** the kill epoch in force at mint — the invite dies with it */
  killEpoch: number;
  expiresAt: number;
  origin: InviteOrigin;
}

/**
 * The LIVE facts consume() checks in the same synchronous step as the burn.
 * All three are REQUIRED — an invite spend without a witness would be a
 * spend that ignores kills and revocations, which is the exact bug class
 * the standing registry exists to kill.
 */
export interface InviteSpendWitness {
  /** is the kill switch ENGAGED right now? true refuses every spend */
  killed: boolean;
  /** the CURRENT kill epoch — must equal the one recorded at mint */
  killEpoch: number;
  /** the CURRENT bootstrap generation (bootstrap-minted invites) */
  bootstrapGeneration: number;
  /**
   * How many devices are enrolled AND unrevoked right now. The pinned
   * bootstrap invariant (DESIGN.md §2) is generation-current AND ZERO
   * active devices — a bootstrap invite must not add a second root next
   * to a live phone.
   */
  activeDeviceCount: number;
  /**
   * Is this device still enrolled, unrevoked, at EXACTLY this generation?
   * (device-minted invites; the server passes its witnessStanding)
   */
  deviceStanding: (deviceId: string, generation: number) => boolean;
}

/**
 * The invite's FATE is an explicit fact of the result, never inferred from
 * reason text: "alive" — the spend failed before the reserve and the owner
 * can retry (wrong secret, malformed input); "burned" — the invite is gone
 * (spent, or reserved and then refused on authority: dead epoch, dead
 * issuer, kill engaged, callback failure); "absent" — there was nothing to
 * spend (unknown id, expired, already spent).
 */
export type InviteFate = "alive" | "burned" | "absent";

export type InviteConsume =
  | { ok: true; record: InviteRecord }
  | { ok: false; reason: string; fate: InviteFate };

export interface InviteStoreOptions {
  now?: () => number;
  /** invite lifetime; default 10 minutes — short, because possession IS proof */
  ttlMs?: number;
  /** live-invite ceiling (flood backstop); default 32 */
  maxInvites?: number;
}

const DEFAULT_TTL_MS = 10 * 60_000;
const DEFAULT_MAX = 32;
/**
 * The minimum SECRET the redemption accepts: canonical base64url of ≥16
 * CSPRNG bytes is ≥22 chars. The hash commitment cannot prove entropy, but
 * refusing shorter preimages outright means a human-typed "1234" can never
 * even reach the comparison — the mint contract (device/CLI side) generates
 * ≥128-bit tokens in exactly this alphabet.
 */
const SECRET_FORMAT = /^[A-Za-z0-9_-]{22,128}$/;

function frozenCopy(record: InviteRecord): InviteRecord {
  return Object.freeze({ ...record, origin: Object.freeze({ ...record.origin }) });
}

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
   * (the commitment) — never a secret — plus the FULL authority context:
   * kill epoch and a complete, validated origin. Refuses duplicates, the
   * cap, and any missing/malformed authority field.
   */
  register(record: Omit<InviteRecord, "expiresAt">): InviteRecord {
    this.sweep();
    if (record.inviteId === "") throw new Error("inviteId must be non-empty");
    if (this.invites.has(record.inviteId)) {
      throw new Error(`invite "${record.inviteId}" already exists`);
    }
    // canonical base64url SHA-256, checked by ROUND-TRIP, not regex alone:
    // base64url's final character carries unused bits, so two different
    // 43-char strings can decode to the same 32 bytes — only the canonical
    // re-encoding is accepted as a commitment
    const decodedHash = Buffer.from(record.tokenHash, "base64url");
    if (
      !/^[A-Za-z0-9_-]{43}$/.test(record.tokenHash) ||
      decodedHash.length !== 32 ||
      decodedHash.toString("base64url") !== record.tokenHash
    ) {
      throw new Error("tokenHash must be the canonical unpadded base64url of a SHA-256 (43 chars)");
    }
    if (record.challenge === "" || record.assertionChallenge === "") {
      throw new Error("an invite carries BOTH ceremony challenges (creation + possession assertion)");
    }
    // the pinned contract's REQUIRED display label (types.ts InviteMintRequest
    // deviceName) — bounded, display-only, but never silently absent
    if (record.deviceName === "" || record.deviceName.length > 200) {
      throw new Error("deviceName is required (non-empty, <= 200 chars)");
    }
    if (record.ownerId === "") throw new Error("ownerId must be non-empty");
    if (!Number.isSafeInteger(record.killEpoch) || record.killEpoch < 0) {
      throw new Error("killEpoch must be a non-negative safe integer");
    }
    const origin = record.origin;
    if (origin.kind === "bootstrap") {
      if (!Number.isSafeInteger(origin.bootstrapGeneration) || origin.bootstrapGeneration < 0) {
        throw new Error("bootstrap invites must record a non-negative bootstrapGeneration");
      }
    } else if (origin.kind === "device") {
      if (origin.deviceId === "") throw new Error("device-minted invites must record the deviceId");
      if (!Number.isSafeInteger(origin.deviceGeneration) || origin.deviceGeneration < 1) {
        throw new Error("device-minted invites must record the issuer's generation (>= 1)");
      }
    } else {
      throw new Error("invite origin must be bootstrap or device");
    }
    if (this.invites.size >= this.maxInvites) {
      throw new Error(`too many live invites (${this.maxInvites}) — spend or let them expire`);
    }
    // DEEP copy into the map: the store's authority state must be its OWN —
    // a caller holding the input object must not be able to rewrite the
    // stored origin's kind/generation after registration
    const full: InviteRecord = {
      ...record,
      origin: { ...record.origin },
      expiresAt: this.now() + this.ttlMs,
    };
    this.invites.set(full.inviteId, full);
    return frozenCopy(full);
  }

  /** Read without spending — the enroll handler verifies against this first. */
  peek(inviteId: string): InviteRecord | null {
    const record = this.invites.get(inviteId);
    if (record === undefined) return null;
    if (this.now() >= record.expiresAt) {
      this.invites.delete(inviteId);
      return null;
    }
    return frozenCopy(record);
  }

  /**
   * Check-and-burn, in ONE synchronous step, and ONLY under a
   * SpendAuthorization minted by the enrollment verifier — the proof that
   * registration, the fresh possession assertion, and the cheap-lane PoP
   * all passed for THIS invite (enrollment.ts; the minting brand is not
   * exported from the package root, so no handler can spend an invite
   * around the proof chain). The submitted SECRET must be the preimage of
   * the stored commitment (constant-time over the hashes) and the invite
   * live; then the record is REMOVED — reserved — BEFORE any caller-
   * provided witness callback runs, so a reentrant consume() from inside
   * deviceStanding() finds nothing and exactly one spend can ever succeed.
   * The live-authority checks then run against the reserved record: kill
   * switch DISENGAGED, current kill epoch, and — bootstrap — current
   * bootstrap generation AND zero active devices (the pinned DESIGN §2
   * invariant), or — device-minted — the issuer standing at EXACTLY its
   * minting generation. Any authority failure leaves the invite burned
   * (dead epochs and dead issuers do not revive), while a wrong secret
   * left it alive above. A successful bootstrap spend burns every
   * bootstrap sibling in the same step.
   */
  consume(
    inviteId: string,
    tokenSecret: string,
    witness: InviteSpendWitness,
    authorization: SpendAuthorization,
  ): InviteConsume {
    // MEMBERSHIP, not instanceof: Object.create(prototype), Reflect.construct,
    // and any other plain-JS forgery share the prototype but are not in the
    // module-private WeakSet — only the claimed minter's output is.
    if (!isMintedAuthorization(authorization) || authorization.inviteId !== inviteId) {
      return {
        ok: false,
        reason: "spend refused: no enrollment-verifier authorization for this invite",
        fate: "alive",
      };
    }
    // The witness is VALIDATED, fail-closed, before anything is judged with
    // it: a malformed witness proves nothing, so it spends nothing.
    if (
      witness.killed !== false ||
      !Number.isSafeInteger(witness.killEpoch) ||
      witness.killEpoch < 0 ||
      !Number.isSafeInteger(witness.bootstrapGeneration) ||
      !Number.isSafeInteger(witness.activeDeviceCount) ||
      witness.activeDeviceCount < 0 ||
      typeof witness.deviceStanding !== "function"
    ) {
      const reason =
        witness.killed === true
          ? "the kill switch is engaged — nothing enrolls while killed"
          : "spend refused: malformed live witness (fail closed)";
      return { ok: false, reason, fate: "alive" };
    }
    const record = this.invites.get(inviteId);
    if (record === undefined) {
      return { ok: false, reason: "unknown or already-spent invite", fate: "absent" };
    }
    if (this.now() >= record.expiresAt) {
      this.invites.delete(inviteId);
      return { ok: false, reason: "invite expired", fate: "absent" };
    }
    // canonical opaque token: the exact base64url alphabet, and a round-trip
    // so non-canonical final-character bits never reach the comparison
    const decodedSecret = Buffer.from(tokenSecret, "base64url");
    if (
      !/^[A-Za-z0-9_-]{22,128}$/.test(tokenSecret) ||
      decodedSecret.toString("base64url") !== tokenSecret
    ) {
      return {
        ok: false,
        reason: "invite secret is not a canonical token (base64url, >= 22 chars)",
        fate: "alive",
      };
    }
    const submitted = createHash("sha256").update(tokenSecret, "utf8").digest();
    const committed = Buffer.from(record.tokenHash, "base64url");
    if (submitted.length !== committed.length || !timingSafeEqual(submitted, committed)) {
      return { ok: false, reason: "invite secret does not match the commitment", fate: "alive" };
    }
    // RESERVE before any callback: from here the invite is gone, whatever
    // happens next — a reentrant consume() cannot race a second success,
    // and every authority failure below stays burned.
    this.invites.delete(inviteId);
    if (record.killEpoch !== witness.killEpoch) {
      return { ok: false, reason: "invite was minted under a superseded kill epoch", fate: "burned" };
    }
    if (record.origin.kind === "bootstrap") {
      if (record.origin.bootstrapGeneration !== witness.bootstrapGeneration) {
        return {
          ok: false,
          reason: "invite was minted under a superseded bootstrap generation",
          fate: "burned",
        };
      }
      if (witness.activeDeviceCount !== 0) {
        return {
          ok: false,
          reason: "bootstrap invites enroll only into an EMPTY registry — an active device exists",
          fate: "burned",
        };
      }
    } else {
      // the standing callback is CALLER code running inside the spend: a
      // throw is a failed standing check (burned — the record was reserved),
      // never an exception that escapes with the invite's fate undecided;
      // and only the literal `true` is standing
      let standing: unknown;
      try {
        standing = witness.deviceStanding(record.origin.deviceId, record.origin.deviceGeneration);
      } catch {
        return {
          ok: false,
          reason: "issuer standing check FAILED (threw) — refusing the spend, invite burned",
          fate: "burned",
        };
      }
      if (standing !== true) {
        return {
          ok: false,
          reason: "the inviting device is no longer in standing at its minting generation",
          fate: "burned",
        };
      }
    }
    if (record.origin.kind === "bootstrap") {
      // FIRST PHONE WINS, atomically: no second bootstrap secret — spent
      // between this consume and any later bookkeeping — may enroll a
      // second root of trust. Same synchronous step as the burn.
      for (const [id, sibling] of this.invites) {
        if (sibling.origin.kind === "bootstrap") this.invites.delete(id);
      }
    }
    return { ok: true, record: frozenCopy(record) };
  }

  /**
   * KILL HOOK: a kill (or restore) advanced the epoch — every invite minted
   * under any other epoch is dead anyway; sweep it now so it does not sit
   * in the cap until TTL. Returns how many were removed.
   */
  invalidateSupersededEpoch(currentEpoch: number): number {
    let removed = 0;
    for (const [id, record] of this.invites) {
      if (record.killEpoch !== currentEpoch) {
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
