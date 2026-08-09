/**
 * Wire types of the owner app — the contract between the phone and the
 * control plane, written down before either side implements it.
 *
 * These are WIRE formats, deliberately self-contained: no import from
 * @ownerswitchai/shared, because what crosses the network to a phone is a
 * serialization boundary, not an in-process type. Binary WebAuthn fields
 * travel base64url-encoded.
 *
 * Nothing in this package sends or receives any of this yet — see
 * DESIGN.md §6. The control-plane routes these types describe are listed
 * in OWNER_APP_ENDPOINTS below and are NOT implemented in this PR.
 */

/** base64url-encoded bytes (RFC 4648 §5, no padding). */
export type Base64Url = string;

/** ms since epoch, like every timestamp in this repo. */
export type UnixMs = number;

/* ------------------------------------------------------------------ */
/* Enrolment — the root of trust (DESIGN.md §2)                        */
/* ------------------------------------------------------------------ */

/**
 * A single-use enrolment invite, minted by the control plane and carried
 * out-of-band to the phone (QR / URL). Possession of a live invite IS the
 * proof at enrolment time — which is why its TTL is short, its spend is
 * atomic, and a leak of one is total compromise of the owner surface.
 */
export interface EnrollmentInvite {
  inviteId: string;
  /**
   * single-use bearer capability, ≥128 bits from a CSPRNG. Travels ONLY
   * in the URL fragment (never query or path — fragments stay out of
   * access logs and the Referer header), is cleared from the address bar
   * with history.replaceState the moment the app reads it, is spent in a
   * POST body, and is never written to a log on either end. Burned
   * atomically and only on a SUCCESSFUL registration — a failed attempt
   * does not consume it (DESIGN.md §2).
   */
  token: string;
  expiresAt: UnixMs;
  /** the owner this device will act for — bound at mint, not claimed by the phone */
  ownerId: string;
  /** WebAuthn rpId the credential must be created under */
  rpId: string;
  /** creation challenge for navigator.credentials.create() */
  challenge: Base64Url;
}

/** The phone's WebAuthn registration, as produced by credentials.create(). */
export interface WebAuthnRegistration {
  credentialId: Base64Url;
  clientDataJSON: Base64Url;
  attestationObject: Base64Url;
  /** e.g. ["internal", "hybrid"] — stored as a hint, never as proof */
  transports?: string[];
}

/** POST /devices/enroll — spends the invite, registers the credential. */
export interface EnrollmentRequest {
  inviteId: string;
  token: string;
  /** human label shown in the device list, e.g. "Adam's phone" */
  deviceName: string;
  registration: WebAuthnRegistration;
  /**
   * SPKI public key of the SECOND, non-exportable WebCrypto keypair
   * (ECDSA P-256, extractable: false) the device generated for the cheap
   * lane — the REQUIRED mode: the server then holds only public keys and
   * there is no raw key material for an origin compromise to steal
   * (DESIGN.md §4). Omitted only on platforms that cannot hold a
   * non-exportable key, which puts the device in HMAC-fallback mode.
   */
  cheapLaneKey?: Base64Url;
}

/**
 * Returned exactly once, on successful enrolment. `deviceSecret` exists
 * ONLY for HMAC-fallback devices (no cheapLaneKey in the request): the
 * shared secret verified by packages/control-plane/src/auth.ts, kept by
 * the server too, stored on-device, never returned again — and readable
 * by whatever JavaScript the origin serves, which is why fallback mode
 * is priced as permanently-impersonable on origin compromise
 * (DESIGN.md §4). In the required (cheapLaneKey) mode it is absent.
 */
export interface EnrollmentResponse {
  deviceId: string;
  deviceSecret?: string;
}

/**
 * What the control plane stores per enrolled device. Everything downstream
 * — ack, veto, approve, GO 2 — reduces to "is there a live record here".
 * The passkey half is asymmetric (server holds only the public key); the
 * cheap-lane secret is symmetric and lives on both ends — the trade-off is
 * stated in DESIGN.md §4.
 */
export interface EnrolledDevice {
  deviceId: string;
  ownerId: string;
  name: string;
  credentialId: Base64Url;
  /** COSE public key — verifies every future assertion */
  publicKey: Base64Url;
  /**
   * SPKI public key verifying cheap-lane signatures (required mode).
   * null = HMAC-fallback device; the shared secret is held server-side,
   * off this record, and the trade-off is stated in DESIGN.md §4.
   */
  cheapLaneKey: Base64Url | null;
  /**
   * last accepted authenticator signature counter. A regression flags
   * cloning; synced passkeys legitimately report 0 or a frozen counter,
   * so this is a tripwire, not a guarantee.
   */
  signCount: number;
  transports: string[];
  enrolledAt: UnixMs;
  /**
   * bumped atomically by revocation. Sessions and assertion challenges
   * record the generation they were minted under and are re-checked
   * against it on EVERY use — so revoking a device kills its live
   * sessions and outstanding challenges at the next request, not at
   * token expiry (DESIGN.md §2).
   */
  revocationGeneration: number;
  /**
   * set once by revocation; a revoked device authenticates nothing —
   * including sessions and challenges it minted before revocation, which
   * die with its generation.
   */
  revokedAt: UnixMs | null;
  /** present once notification permission was granted and registered */
  pushSubscription: PushSubscriptionRecord | null;
}

/**
 * The Web Push subscription, as the Push API hands it out. `endpoint` is
 * an attacker-influenceable URL the dispatcher will later call — an SSRF
 * surface, never a plain string. It is validated at upsert AND re-checked
 * at send time: HTTPS only, known push-service endpoint shapes, rejection
 * of localhost/private/link-local/metadata addresses both before and
 * after DNS resolution, no redirect following, hard size and timeout
 * caps (DESIGN.md §5, rows 7 and 11).
 */
export interface PushSubscriptionRecord {
  endpoint: string;
  keys: {
    p256dh: Base64Url;
    auth: Base64Url;
  };
}

/* ------------------------------------------------------------------ */
/* The alert — a held veto window reaches the phone (DESIGN.md §1, §4) */
/* ------------------------------------------------------------------ */

/**
 * The encrypted push payload. Deliberately minimal: a pointer, not the
 * content. The service worker fetches the renderable detail with a
 * device-signed read, so a payload captured or logged en route names a
 * window id and nothing about the action.
 */
export interface OwnerAlertPush {
  kind: "veto-window";
  windowId: string;
  /** hint for notification scheduling; the fetched detail is authoritative */
  deadline: UnixMs;
}

/**
 * Device-signed GET /veto/:id — the renderable truth about a held window.
 * The existing open (unauthenticated) read stays status-only; this shape
 * is for enrolled devices.
 */
export interface HeldWindowDetail {
  windowId: string;
  status: "pending" | "vetoed" | "released" | "extended" | "held";
  /** who is acting and what they asked for — rendered verbatim to the owner */
  agentId: string;
  tool: string;
  /** short server-produced summary of the args */
  summary: string;
  /** when silence releases (delivered) or extends/holds (not delivered) */
  deadline: UnixMs;
  delivered: boolean;
}

/**
 * POST /veto/:id/seen — the ack; the production caller of markDelivered().
 * Sent device-signed, only after a notification carrying the CONCRETE
 * action summary rendered (a generic fallback render must not ack —
 * DESIGN.md §4). Proves rendered-on-enrolled-device; nothing more.
 * Accepted only while the window is still pending/extended on the
 * SERVER's clock and only from a device enrolled to the window's owner;
 * after the deadline an ack is recorded in the audit trail and ignored.
 */
export interface SeenAck {
  windowId: string;
  /**
   * when the summary was rendered on this device — AUDIT DATA ONLY. The
   * server's own receive time and the window's live state decide whether
   * the ack counts; nothing the phone asserts moves the deadline.
   */
  renderedAt: UnixMs;
  /** where it rendered */
  surface: "notification" | "app";
}

/**
 * POST /veto/:id, device-signed — the one-tap stop. Cheap forever, and
 * IDEMPOTENT: re-vetoing an already-vetoed window succeeds as a no-op,
 * so the service worker can blind-retry a send it cannot prove arrived
 * (DESIGN.md §3).
 */
export interface VetoTap {
  windowId: string;
  tappedAt: UnixMs;
}

/* ------------------------------------------------------------------ */
/* The expensive lane — fresh, bound assertions (DESIGN.md §3)         */
/* ------------------------------------------------------------------ */

/**
 * What a fresh assertion is FOR. The challenge binds to one purpose and
 * one subject; an assertion minted for ceremony A is useless for
 * ceremony B, for an approval, or for tomorrow.
 */
export type AssertionPurpose = "approve" | "restore-go2" | "session";

/** POST /assert/challenge — device-signed request for a bound challenge. */
export interface AssertionChallengeRequest {
  purpose: AssertionPurpose;
  /** approvalId for "approve", ceremonyId for "restore-go2", absent for "session" */
  subjectId?: string;
}

/**
 * The minted challenge. Single-use, short TTL; the {purpose, subjectId}
 * binding lives server-side keyed by challengeId — the phone repeating it
 * back is convenience, never trusted. A challenge also records the
 * minting device's revocation generation and dies with it: revoking the
 * device voids its outstanding challenges (DESIGN.md §2).
 */
export interface AssertionChallenge {
  challengeId: string;
  challenge: Base64Url;
  purpose: AssertionPurpose;
  subjectId?: string;
  expiresAt: UnixMs;
}

/** The authenticator's answer, as produced by credentials.get(). */
export interface WebAuthnAssertion {
  credentialId: Base64Url;
  clientDataJSON: Base64Url;
  authenticatorData: Base64Url;
  signature: Base64Url;
  userHandle?: Base64Url;
}

/**
 * A fresh assertion presented to the control plane: GO 2 confirmation
 * (POST /restore gains this field), approve-lane confirmation (when the
 * approval queue exists), and passkey-gated session minting. Verification:
 * stored public key, rpId hash, UP+UV flags required, challenge matched
 * and burned, signature counter monotonic where provided.
 */
export interface BoundAssertion {
  challengeId: string;
  assertion: WebAuthnAssertion;
}

/**
 * POST /session response — the owner session, passkey-gated. The session
 * is bound at mint to the device that produced the assertion AND to that
 * device's revocation generation; EVERY session check re-verifies the
 * device is still enrolled and the generation unchanged, so revoking the
 * device kills its sessions at the next request — a stolen phone's
 * session cannot outlive the phone's standing (DESIGN.md §2).
 */
export interface MintedSession {
  /** opaque bearer token, short TTL (15 min today) */
  token: string;
  ownerId: string;
  /** the enrolled device this session is bound to */
  deviceId: string;
  expiresAt: UnixMs;
}

/* ------------------------------------------------------------------ */
/* The endpoint contract (DESIGN.md §5) — listed, NOT implemented      */
/* ------------------------------------------------------------------ */

/**
 * Every control-plane route the owner app needs, as data — so the scoped
 * control-plane PRs and this app agree on one list. `status` says what
 * exists on main today vs. what DESIGN.md §5 scopes as an addition.
 */
export const OWNER_APP_ENDPOINTS = [
  {
    method: "POST",
    path: "/veto/:id/seen",
    auth: "device-signed",
    status: "addition",
    purpose:
      "delivery ack — the production caller of markDelivered(); accepted only while the window is pending/extended on the SERVER's clock and only from a device enrolled to the window's owner; renderedAt is audit-only; late acks recorded and ignored",
  },
  {
    method: "POST",
    path: "/veto/:id",
    auth: "device-signed | owner-session",
    status: "extension",
    purpose:
      "one-tap veto; today owner-session only — the device-signed relay is the addition; idempotent (re-veto of a vetoed window is a successful no-op) so the worker can retry blindly",
  },
  {
    method: "GET",
    path: "/veto/:id",
    auth: "device-signed for detail; open read stays status-only",
    status: "extension",
    purpose: "deadline + delivered + call summary, for enrolled devices only",
  },
  {
    method: "POST",
    path: "/devices/invite",
    auth: "owner-session; bootstrap/no-devices-left recovery via host CLI or permission-protected Unix socket — NEVER an HTTP loopback bypass",
    status: "addition",
    purpose:
      "mint a single-use enrolment invite + creation challenge; token rides in the URL fragment, is spent in a POST body, and is never logged",
  },
  {
    method: "POST",
    path: "/devices/enroll",
    auth: "invite-token",
    status: "addition",
    purpose:
      "verify registration, register both lane keys (cheap-lane public key preferred; HMAC secret only for fallback devices, returned once), store EnrolledDevice; the invite burns atomically and only on success",
  },
  {
    method: "GET",
    path: "/devices",
    auth: "owner-session",
    status: "addition",
    purpose: "list enrolled devices",
  },
  {
    method: "POST",
    path: "/devices/:id/revoke",
    auth: "owner-session (host CLI / Unix socket can always revoke)",
    status: "addition",
    purpose:
      "kill a device's standing: bump its revocation generation and atomically void credentials, push subscription, live sessions, and outstanding challenges",
  },
  {
    method: "PUT",
    path: "/devices/:id/push-subscription",
    auth: "device-signed",
    status: "addition",
    purpose:
      "store / refresh the Web Push subscription; endpoint validated as an SSRF surface (HTTPS, known push-service shapes, no private/metadata addresses)",
  },
  {
    method: "POST",
    path: "/assert/challenge",
    auth: "device-signed",
    status: "addition",
    purpose:
      "mint a single-use challenge bound to {purpose, subjectId}; dies with the minting device's revocation generation",
  },
  {
    method: "POST",
    path: "/session",
    auth: "verified assertion (purpose: session)",
    status: "addition",
    purpose:
      "passkey-gated session minting — closes TODO(passkey) in auth.ts; session binds to deviceId + revocation generation and is re-checked against the device on every use",
  },
  {
    method: "POST",
    path: "/restore",
    auth: "owner-session + verified assertion (purpose: restore-go2, subject: ceremonyId)",
    status: "extension",
    purpose: "GO 2 stops accepting the bearer token GO 1 already saw",
  },
] as const;

export type OwnerAppEndpoint = (typeof OWNER_APP_ENDPOINTS)[number];
