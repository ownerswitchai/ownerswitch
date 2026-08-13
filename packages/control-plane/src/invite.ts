/**
 * Enrolment invites AND the enrolment spend path — ONE module, on purpose.
 *
 * THE HASH-COMMITMENT STORE (apps/owner/DESIGN.md §2; the wire contract is
 * apps/owner/src/types.ts InviteMintRequest, whose `tokenHash` field this
 * store's records mirror). The inviting side (an enrolled device, or the
 * host CLI for bootstrap) generates the ≥128-bit secret LOCALLY and submits
 * only its SHA-256. Precisely stated: this store never sees the secret AT
 * MINT and never PERSISTS it anywhere — at redemption the secret arrives
 * exactly once as the preimage in the enroll request, is hashed, compared,
 * and dropped. A captured mint request, a raced mint response, or a read of
 * this process's memory between mint and spend therefore yields only a hash
 * that opens nothing.
 *
 * AUTHORITY STATE rides the record, not the caller's memory: every invite
 * binds the KILL EPOCH in force at mint (an invite minted before a kill is
 * dead after it — even after a restore, like every other pre-kill
 * authority), and its ISSUER at the issuer's then-current standing — the
 * host's bootstrap generation, or the minting device at its revocation
 * generation. MINT AND SPEND ARE BOTH BOUND TO LIVE STATE: register()
 * demands a live mint witness (nothing mints while the kill switch is
 * engaged, under a stale epoch, under a stale bootstrap generation, or for
 * an issuer out of standing), and the spend re-checks all of it in the same
 * synchronous step as the burn. A spend attempted while KILLED burns the
 * invite outright — an invite is born and spent inside one live state,
 * never held open across a kill into whatever comes after it.
 *
 * WHY THE SPEND PATH LIVES IN THIS FILE: the burn must be reachable ONLY
 * after the full proof chain (registration, fresh possession assertion,
 * cheap-lane PoP). Any design that hands a spend capability across a module
 * boundary — an exported brand, a claim-once minter, a friend function — is
 * a first-import race, not an exclusive capability: whoever imports first
 * owns it. So there is nothing to hand out. The consume step is an
 * ECMAScript #private method of InviteStore, its only accessor is a
 * module-scoped variable captured in a static block, and performEnrollment
 * — defined BELOW IN THIS SAME MODULE — is the one function that can reach
 * it. No package API, no deep import, and no plain-JS object forgery
 * touches the burn around the proofs. The residual truth, stated plainly:
 * code running IN THIS PROCESS could still patch these modules — in-process
 * code is the trust domain here, the same as for the kill switch's own Map.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { verifyOwnerAssertion, type WebAuthnAssertion } from "./webauthn.js";
import {
  enrolledOwnerDeviceFromSpki,
  verifyEnrollProofOfPossession,
} from "./owner-device.js";
import { storedSpkiToPem, verifyOwnerRegistration } from "./webauthn-register.js";

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
  /**
   * Human label for the device being invited — COMMITTED at mint
   * (InviteMintRequest.deviceName) and authoritative: the enrolment request
   * must repeat it exactly (EnrollmentRequest.deviceName) as confirmation
   * the phone is redeeming the invite it was actually shown.
   */
  deviceName: string;
  /** base64url WebAuthn creation challenge minted alongside the invite */
  challenge: string;
  /**
   * base64url challenge for the ceremony's SECOND proof: the fresh
   * webauthn.get assertion with the newly created credential — the
   * possession-and-UV evidence attestation "none" cannot give. Minted with
   * the invite, single-use with it.
   */
  assertionChallenge: string;
  /** the kill epoch in force at mint — the invite dies with it */
  killEpoch: number;
  expiresAt: number;
  origin: InviteOrigin;
}

/**
 * The LIVE facts bound at BOTH ends of an invite's life: register() demands
 * them at mint, and the spend re-checks them in the same synchronous step
 * as the burn. All fields are REQUIRED — an invite minted or spent without
 * a witness would be one that ignores kills and revocations, which is the
 * exact bug class the standing registry exists to kill.
 */
export interface InviteSpendWitness {
  /** is the kill switch ENGAGED right now? true refuses mint AND spend */
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
 * (spent; reserved and then refused on authority: dead epoch, dead issuer,
 * callback failure; or attempted under an ENGAGED kill switch, which burns
 * outright); "absent" — there was nothing to spend (unknown id, expired,
 * already spent).
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

function frozenCopy(record: InviteRecord): InviteRecord {
  return Object.freeze({ ...record, origin: Object.freeze({ ...record.origin }) });
}

/**
 * Shared witness-shape validation (killed is judged separately at each
 * site, because mint and spend answer an engaged kill differently: mint
 * refuses to create, spend burns what was attempted).
 */
function witnessIsMalformed(witness: InviteSpendWitness): boolean {
  return (
    witness.killed !== false ||
    !Number.isSafeInteger(witness.killEpoch) ||
    witness.killEpoch < 0 ||
    !Number.isSafeInteger(witness.bootstrapGeneration) ||
    !Number.isSafeInteger(witness.activeDeviceCount) ||
    witness.activeDeviceCount < 0 ||
    typeof witness.deviceStanding !== "function"
  );
}

// The ONE door to the burn, captured from the class's static block below.
// Module-scoped, never exported: only code in THIS file — performEnrollment
// — can call it, and #consume itself is an ECMAScript private method that
// no property access, prototype walk, or cast can reach from outside.
let consumeInvite!: (
  store: InviteStore,
  inviteId: string,
  tokenSecret: string,
  witness: InviteSpendWitness,
) => InviteConsume;

export class InviteStore {
  // REAL private state (#, not TS `private`): `(store as any).invites` from
  // a package consumer must find nothing — a reachable record map would be
  // a register()-bypassing mint and a proof-bypassing burn in one.
  readonly #invites = new Map<string, InviteRecord>();
  readonly #now: () => number;
  readonly ttlMs: number;
  readonly #maxInvites: number;

  static {
    consumeInvite = (store, inviteId, tokenSecret, witness) =>
      store.#consume(inviteId, tokenSecret, witness);
  }

  constructor(opts: InviteStoreOptions = {}) {
    this.#now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    this.#maxInvites = opts.maxInvites ?? DEFAULT_MAX;
  }

  /** Sweep dead invites so the cap only ever counts live ones. */
  #sweep(): void {
    for (const [id, record] of this.#invites) {
      if (this.#now() >= record.expiresAt) this.#invites.delete(id);
    }
  }

  /**
   * Register a minted invite. The caller provides the tokenHash it received
   * (the commitment) — never a secret — plus the FULL authority context:
   * kill epoch and a complete, validated origin — AND the live mint
   * witness, which must agree with all of it. Nothing mints while the kill
   * switch is engaged: an invite created during a kill would be a fresh
   * capability born inside a frozen system, spendable after a restore that
   * may not advance the epoch — so it is refused at the source. Refuses
   * duplicates, the cap, and any missing/malformed authority field.
   */
  register(record: Omit<InviteRecord, "expiresAt">, mintWitness: InviteSpendWitness): InviteRecord {
    this.#sweep();
    if (record.inviteId === "") throw new Error("inviteId must be non-empty");
    if (this.#invites.has(record.inviteId)) {
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
    // MINT IS BOUND TO LIVE STATE, fail-closed, same discipline as the
    // spend: killed refuses outright, and the recorded authority facts must
    // BE the live ones — an invite must never be born already stale.
    if (mintWitness.killed === true) {
      throw new Error("the kill switch is engaged — nothing MINTS while killed");
    }
    if (witnessIsMalformed(mintWitness)) {
      throw new Error("malformed mint witness (fail closed) — nothing mints unproven");
    }
    if (record.killEpoch !== mintWitness.killEpoch) {
      throw new Error("invite killEpoch must be the CURRENT kill epoch at mint");
    }
    if (origin.kind === "bootstrap") {
      if (origin.bootstrapGeneration !== mintWitness.bootstrapGeneration) {
        throw new Error("bootstrap invites must record the CURRENT bootstrap generation at mint");
      }
      if (mintWitness.activeDeviceCount !== 0) {
        throw new Error("bootstrap invites mint only into an EMPTY registry — an active device exists");
      }
    } else {
      let standing: unknown;
      try {
        standing = mintWitness.deviceStanding(origin.deviceId, origin.deviceGeneration);
      } catch {
        throw new Error("issuer standing check FAILED at mint — refusing to mint");
      }
      if (standing !== true) {
        throw new Error("the inviting device is not in standing at its claimed generation");
      }
    }
    if (this.#invites.size >= this.#maxInvites) {
      throw new Error(`too many live invites (${this.#maxInvites}) — spend or let them expire`);
    }
    // DEEP copy into the map: the store's authority state must be its OWN —
    // a caller holding the input object must not be able to rewrite the
    // stored origin's kind/generation after registration
    const full: InviteRecord = {
      ...record,
      origin: { ...record.origin },
      expiresAt: this.#now() + this.ttlMs,
    };
    this.#invites.set(full.inviteId, full);
    return frozenCopy(full);
  }

  /** Read without spending — the enrolment verifier checks against this first. */
  peek(inviteId: string): InviteRecord | null {
    const record = this.#invites.get(inviteId);
    if (record === undefined) return null;
    if (this.#now() >= record.expiresAt) {
      this.#invites.delete(inviteId);
      return null;
    }
    return frozenCopy(record);
  }

  /**
   * Check-and-burn, in ONE synchronous step — reachable ONLY through the
   * module-scoped accessor above, i.e. only from performEnrollment in this
   * same file, which runs the full proof chain first. The submitted SECRET
   * must be the preimage of the stored commitment (constant-time over the
   * hashes) and the invite live; then the record is REMOVED — reserved —
   * BEFORE any caller-provided witness callback runs, so a reentrant spend
   * from inside deviceStanding() finds nothing and exactly one spend can
   * ever succeed. The live-authority checks then run against the reserved
   * record: current kill epoch, and — bootstrap — current bootstrap
   * generation AND zero active devices (the pinned DESIGN §2 invariant),
   * or — device-minted — the issuer standing at EXACTLY its minting
   * generation. Any authority failure leaves the invite burned (dead
   * epochs and dead issuers do not revive), while a wrong secret left it
   * alive above. An ENGAGED kill switch burns the attempted invite
   * outright — mint under kill is already impossible through register(),
   * and this closes the other half: nothing minted before a kill is held
   * open through it, whatever the epoch does on restore. A successful
   * bootstrap spend burns every bootstrap sibling in the same step.
   */
  #consume(inviteId: string, tokenSecret: string, witness: InviteSpendWitness): InviteConsume {
    // KILLED: defense in depth at the store's own boundary — the attempted
    // invite is burned, not refused-and-kept. Only the literal `true`
    // triggers the burn; any other non-false shape is a malformed witness
    // that proves nothing and burns nothing (below).
    if (witness.killed === true) {
      const existed = this.#invites.delete(inviteId);
      return {
        ok: false,
        reason:
          "the kill switch is engaged — nothing enrolls while killed, and the attempted invite is burned",
        fate: existed ? "burned" : "absent",
      };
    }
    // The witness is VALIDATED, fail-closed, before anything is judged with
    // it: a malformed witness proves nothing, so it spends nothing.
    if (witnessIsMalformed(witness)) {
      return { ok: false, reason: "spend refused: malformed live witness (fail closed)", fate: "alive" };
    }
    const record = this.#invites.get(inviteId);
    if (record === undefined) {
      return { ok: false, reason: "unknown or already-spent invite", fate: "absent" };
    }
    if (this.#now() >= record.expiresAt) {
      this.#invites.delete(inviteId);
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
    // happens next — a reentrant spend cannot race a second success, and
    // every authority failure below stays burned.
    this.#invites.delete(inviteId);
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
      for (const [id, sibling] of this.#invites) {
        if (sibling.origin.kind === "bootstrap") this.#invites.delete(id);
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
    for (const [id, record] of this.#invites) {
      if (record.killEpoch !== currentEpoch) {
        this.#invites.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    this.#sweep();
    return this.#invites.size;
  }
}

/* ========================================================================
 * THE enrolment spend path — same module as the store, by design (see the
 * file header): performEnrollment is the ONE function that can reach the
 * burn, and it runs the full proof chain the ceremony contract requires
 * (apps/owner/DESIGN.md §2, types.ts EnrollmentRequest), in order:
 *
 *  1. WIRE ENVELOPE — the submission is `unknown`; exact OWN keys (a
 *     required field satisfied by an inherited property is a refusal),
 *     strings, size caps; every malformed shape is a refusal, never a
 *     throw. deviceName must repeat the invite's committed label.
 *  2. REGISTRATION (structural) — verifyOwnerRegistration() against the
 *     invite's CREATION challenge: canonical credential id + canonical
 *     SPKI, with attestation "none" honestly treated as parsing, not
 *     possession proof.
 *  3. POSSESSION ASSERTION — a FRESH webauthn.get with the NEWLY created
 *     credential over the invite's SECOND challenge, verified with
 *     webauthn.ts's verifyOwnerAssertion against the key step 2 returned.
 *     THIS is the proof the client holds the new private key and a human
 *     passed user verification — the evidence fmt:"none" cannot give.
 *  4. CHEAP-LANE PoP — the ack-signing key proves possession over the
 *     ceremony transcript (invite, owner, credential, canonical SPKI).
 *  5. CONSUME — the module-private burn, with the live witness (kill
 *     state, epoch, bootstrap generation + zero-active-devices, issuer
 *     standing). Skipping a proof is not possible from any import.
 *
 * A refusal reports whether the invite SURVIVES (steps 1–4 fail: yes — a
 * stranger's garbage must not burn the owner's capability) or not, from
 * the store's explicit fate (dead epoch/issuer, killed, absent: no).
 * ===================================================================== */

export interface PerformEnrollmentOptions {
  store: InviteStore;
  witness: InviteSpendWitness;
  rpId: string;
  expectedOrigin: string;
}

export type EnrollmentOutcome =
  | {
      ok: true;
      invite: InviteRecord;
      /**
       * The verified WebAuthn credential, in the canonical stored forms.
       * `signCount` is the POSSESSION ASSERTION's counter — the newest value
       * the authenticator actually signed — not the unsigned registration
       * field; storing the older one would let the next assertion replay a
       * counter that should already be spent. `transports` is the pinned
       * hint (stored, never trusted). `userHandle`, when the authenticator
       * returned one, is the credential's user.id echo — validated as
       * canonical base64url of 1–64 bytes and carried for storage; it is
       * opaque metadata, never proof.
       */
      credential: {
        credentialId: string;
        publicKeySpki: string;
        signCount: number;
        transports?: string[];
        userHandle?: string;
      };
      /** the cheap-lane public key, canonical SPKI DER base64url */
      cheapLaneKeySpki: string;
    }
  | { ok: false; reason: string; inviteSurvives: boolean };

const MAX_FIELD_CHARS = 128 * 1024;
const SUBMISSION_KEYS: ReadonlySet<string> = new Set([
  "inviteId",
  "token",
  "registration",
  "possessionAssertion",
  "cheapLaneKey",
  "cheapLaneKeyProof",
  "deviceName",
]);

function stringField(value: unknown, cap = 4096): string | null {
  return typeof value === "string" && value !== "" && value.length <= cap ? value : null;
}

/** The assertion's own wire envelope — strings only, before webauthn.ts sees it. */
function assertionFrom(value: unknown): WebAuthnAssertion | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  // OWN properties only, and the required ones must BE own: with a crafted
  // prototype, `record.credentialId` could read an INHERITED value the
  // own-key allowlist never saw — so presence and reads both go through the
  // own-property door.
  const own = (key: string): unknown =>
    Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
  const allowed = new Set([
    "credentialId",
    "clientDataJSON",
    "authenticatorData",
    "signature",
    "userHandle",
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key))) return null;
  const credentialId = stringField(own("credentialId"));
  const clientDataJSON = stringField(own("clientDataJSON"), 64 * 1024);
  const authenticatorData = stringField(own("authenticatorData"), 8 * 1024);
  const signature = stringField(own("signature"), 4 * 1024);
  if (credentialId === null || clientDataJSON === null || authenticatorData === null || signature === null) {
    return null;
  }
  // userHandle (pinned contract, types.ts WebAuthnAssertion): optional, and
  // when present it must be CANONICAL base64url of 1–64 decoded bytes (the
  // WebAuthn user.id bound) — a repairable encoding is a refusal, the same
  // rule as every other base64url field on this wire.
  const userHandleRaw = own("userHandle");
  let userHandle: string | undefined;
  if (userHandleRaw !== undefined) {
    const handle = stringField(userHandleRaw, 256);
    if (handle === null || !/^[A-Za-z0-9_-]+$/.test(handle)) return null;
    const decoded = Buffer.from(handle, "base64url");
    if (decoded.length < 1 || decoded.length > 64 || decoded.toString("base64url") !== handle) {
      return null;
    }
    userHandle = handle;
  }
  return {
    credentialId,
    clientDataJSON,
    authenticatorData,
    signature,
    ...(userHandle !== undefined ? { userHandle } : {}),
  };
}

export function performEnrollment(submission: unknown, opts: PerformEnrollmentOptions): EnrollmentOutcome {
  try {
    return performEnrollmentInner(submission, opts);
  } catch (err) {
    // the never-throws backstop: whatever slipped past the envelope checks
    // is a refusal that leaves the invite alone
    return {
      ok: false,
      reason: `malformed enrolment: ${err instanceof Error ? err.message : "unparseable"}`,
      inviteSurvives: true,
    };
  }
}

function performEnrollmentInner(submission: unknown, opts: PerformEnrollmentOptions): EnrollmentOutcome {
  const survive = (reason: string): EnrollmentOutcome => ({ ok: false, reason, inviteSurvives: true });

  /* 1 — the wire envelope: exact OWN keys, every read through the
     own-property door — a required field satisfied only by an inherited
     property (Object.create({...})) is a refusal, not a submission */
  if (typeof submission !== "object" || submission === null || Array.isArray(submission)) {
    return survive("enrolment must be a JSON object");
  }
  const record = submission as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!SUBMISSION_KEYS.has(key)) return survive(`unexpected enrolment property ${JSON.stringify(key)}`);
  }
  const own = (key: string): unknown =>
    Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
  const inviteId = stringField(own("inviteId"), 256);
  const token = stringField(own("token"), 256);
  const cheapLaneKey = stringField(own("cheapLaneKey"), 8 * 1024);
  const cheapLaneKeyProof = stringField(own("cheapLaneKeyProof"), 1024);
  const deviceName = stringField(own("deviceName"), 200);
  if (inviteId === null) return survive("inviteId must be a non-empty string");
  if (token === null) return survive("token must be a non-empty string");
  if (cheapLaneKey === null) return survive("cheapLaneKey must be a non-empty string");
  if (cheapLaneKeyProof === null) return survive("cheapLaneKeyProof must be a non-empty string");
  if (deviceName === null) {
    return survive("deviceName is required — the label committed at mint, repeated as confirmation");
  }
  const registrationWire = own("registration");
  if (registrationWire === undefined) return survive("registration is required");
  const possessionWire = own("possessionAssertion");
  if (possessionWire === undefined) {
    return survive(
      "possessionAssertion is required — with attestation \"none\" only a fresh assertion with the " +
        "new credential proves the client holds its private key",
    );
  }
  if (typeof registrationWire === "string" && registrationWire.length > MAX_FIELD_CHARS) {
    return survive("registration is oversized");
  }

  /* the invite this ceremony claims — read-only until the burn */
  const invite = opts.store.peek(inviteId);
  if (invite === null) {
    // there is NOTHING here for the caller to retry against — an unknown,
    // expired, or already-spent id has no surviving capability, and saying
    // "survives" for it would be a lie about a resource that does not exist
    return { ok: false, reason: "unknown, expired, or already-spent invite", inviteSurvives: false };
  }
  // the deviceName rule (types.ts EnrollmentRequest): the mint-time label is
  // authoritative; the enrolling phone repeats it EXACTLY, confirming it is
  // redeeming the invite it was shown — a mismatch refuses, invite alive
  if (deviceName !== invite.deviceName) {
    return survive("deviceName does not match the label committed at mint");
  }

  /* 2 — registration, against the invite's CREATION challenge */
  const registration = verifyOwnerRegistration(registrationWire, {
    rpId: opts.rpId,
    expectedOrigin: opts.expectedOrigin,
    expectedChallenge: invite.challenge,
  });
  if (!registration.ok) return survive(`registration refused: ${registration.reason}`);

  /* 3 — possession: a FRESH assertion with the NEW credential */
  const assertion = assertionFrom(possessionWire);
  if (assertion === null) return survive("possessionAssertion is malformed");
  const pem = storedSpkiToPem(registration.publicKeySpki);
  if (!pem.ok) return survive(`registration key unusable: ${pem.reason}`);
  const possession = verifyOwnerAssertion(assertion, {
    passkey: { credentialId: registration.credentialId, publicKeyPem: pem.pem },
    rpId: opts.rpId,
    expectedOrigin: opts.expectedOrigin,
    expectedChallenge: invite.assertionChallenge,
    lastSignCount: registration.signCount,
  });
  if (!possession.ok) return survive(`possession assertion refused: ${possession.reason}`);

  /* 4 — cheap-lane proof of possession over the ceremony transcript */
  let cheapLaneDevice;
  try {
    cheapLaneDevice = enrolledOwnerDeviceFromSpki("enrolling-device", cheapLaneKey);
  } catch (err) {
    return survive(`cheapLaneKey refused: ${err instanceof Error ? err.message : "unparseable"}`);
  }
  const popOk = verifyEnrollProofOfPossession({
    inviteId,
    ownerId: invite.ownerId,
    credentialId: registration.credentialId,
    device: cheapLaneDevice,
    proof: cheapLaneKeyProof,
  });
  if (!popOk) return survive("cheap-lane proof of possession refused");

  /* 5 — the burn, through the module-private door only this file holds */
  const consumed = consumeInvite(opts.store, inviteId, token, opts.witness);
  if (!consumed.ok) {
    // the store REPORTS the invite's fate as an explicit fact — never
    // inferred from reason text: "alive" survives for the honest retry,
    // "burned" and "absent" do not
    return { ok: false, reason: consumed.reason, inviteSurvives: consumed.fate === "alive" };
  }

  return {
    ok: true,
    invite: consumed.record,
    credential: {
      credentialId: registration.credentialId,
      publicKeySpki: registration.publicKeySpki,
      // the POSSESSION assertion's counter — the newest signed value; the
      // registration's field is unsigned under fmt:"none" and may be older
      signCount: possession.signCount,
      ...(registration.transports !== undefined ? { transports: registration.transports } : {}),
      ...(assertion.userHandle !== undefined ? { userHandle: assertion.userHandle } : {}),
    },
    cheapLaneKeySpki: Buffer.from(
      cheapLaneDevice.publicKey.export({ type: "spki", format: "der" }),
    ).toString("base64url"),
  };
}
