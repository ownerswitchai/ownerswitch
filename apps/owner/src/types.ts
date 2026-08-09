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

/**
 * Domain label of the enrolment proof of possession (DESIGN.md §2).
 * Pinned format: ECDSA P-256 with SHA-256; signature is WebCrypto's raw
 * IEEE P1363 r||s (64 bytes, two 32-byte big-endian integers — NOT DER),
 * base64url (RFC 4648 §5, no padding). Transcript: concatenation of
 * length-prefixed fields (4-byte big-endian unsigned byte counts), in
 * order: this label (UTF-8), inviteId (UTF-8), ownerId (UTF-8), the
 * WebAuthn credentialId (RAW bytes, base64url-decoded), the SPKI key
 * (RAW bytes). Length-prefixing keeps the encoding injective.
 */
export const ENROLL_POP_LABEL = "ownerswitch/enroll-cheap-lane/v1";

/**
 * Domain label of every cheap-lane device signature (DESIGN.md §3).
 * Same algorithm and signature encoding as the enrolment proof.
 * Preimage: length-prefixed fields (4-byte big-endian counts), in order:
 * this label (UTF-8), deviceId (UTF-8), upper-case HTTP method (UTF-8),
 * request path+query byte-exact as sent (UTF-8), SHA-256 of the exact
 * body bytes (32 raw bytes; empty body = hash of zero bytes — so a
 * body-less GET /veto/:id is still bound to its method and id), decimal
 * timestamp (UTF-8), nonce (UTF-8). The physical button's dot-joined
 * HMAC shape binds none of method/path — which is why the app does not
 * reuse it, and why the button is a distinct server-side credential
 * class never authorised for /seen, detail reads, /assert/challenge, or
 * push-subscription writes (the server record decides the class, never
 * a client field).
 */
export const DEVICE_SIG_LABEL = "ownerswitch/device-sig/v1";

/* ------------------------------------------------------------------ */
/* Enrolment — the root of trust (DESIGN.md §2)                        */
/* ------------------------------------------------------------------ */

/**
 * A single-use enrolment invite, minted by the control plane and handed
 * off INTO the installed app (in-app QR scan or typed code — never a
 * browser navigation, which would land in the wrong storage partition;
 * DESIGN.md §2 step 1). Possession of a live invite IS the proof at
 * enrolment time — which is why its TTL is short, its spend is atomic,
 * and a leak of one is total compromise of the owner surface. Minting a
 * non-bootstrap invite requires an owner session PLUS a fresh UV
 * assertion (purpose "device-invite"); the server-side invite record
 * stores the issuing device's {deviceId, revocationGeneration} —
 * re-checked atomically at spend — or, for host-minted bootstrap
 * invites, the bootstrap generation (DESIGN.md §2).
 */
export interface EnrollmentInvite {
  inviteId: string;
  /**
   * single-use bearer capability, ≥128 bits from a CSPRNG. Where a URL
   * form exists it travels ONLY in the fragment (never query or path —
   * fragments stay out of access logs and the Referer header), is
   * cleared with history.replaceState the moment the app reads it, is
   * spent in a POST body, and is never written to a log on either end.
   * Burned atomically and only on a SUCCESSFUL registration — a failed
   * attempt does not consume it (DESIGN.md §2).
   */
  token: string;
  expiresAt: UnixMs;
  /** the owner this device will act for — bound at mint, not claimed by the phone */
  ownerId: string;
  /** WebAuthn rpId the credential must be created under */
  rpId: string;
  /** human-readable RP name shown by the platform's create() UI */
  rpName: string;
  /**
   * WebAuthn user.id: an opaque CSPRNG handle, stable per owner, never
   * PII — the spec forbids personal data here, and this design forbids
   * reusing the ownerId string
   */
  userId: Base64Url;
  /** COSE algorithm allow-list for create(); pinned to ES256 only */
  pubKeyCredParams: readonly [-7];
  /** the authenticator-selection contract, verbatim for create() */
  authenticatorSelection: {
    authenticatorAttachment: "platform";
    residentKey: "preferred";
    userVerification: "required";
  };
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
   * Exportable SPKI public key of the SECOND WebCrypto keypair (ECDSA
   * P-256) whose PRIVATE key the app creates non-extractable
   * (extractable: false) and submits only after the persistence test —
   * generate, commit, close/reopen, retrieve, sign from the service
   * worker (DESIGN.md §2 step 4). REQUIRED — there is no HMAC fallback
   * and no client-selectable mode: an optional field here would let an
   * origin that is already hostile at enrolment pick its own downgrade
   * (DESIGN.md §2). Precision matters (DESIGN.md §2, §4): the server
   * cannot VERIFY non-extractability — it sees a public key and a
   * proof, nothing more — so this removes the server-side shared secret
   * and prevents byte-level export under honest code; it does not
   * prevent persistent impersonation after a hostile enrolment or
   * origin compromise. Only revocation + re-enrolment severs that.
   */
  cheapLaneKey: Base64Url;
  /**
   * Proof of possession of cheapLaneKey's private half, format pinned by
   * ENROLL_POP_LABEL above: ECDSA P-256 / SHA-256, raw r||s (not DER),
   * base64url, over the length-prefixed transcript. Verified with the
   * submitted key BEFORE the invite is consumed: a key the client cannot
   * sign with is refused and the invite survives — a root-of-trust
   * ceremony must not accept a dead credential (DESIGN.md §2).
   */
  cheapLaneKeyProof: Base64Url;
}

/**
 * Returned exactly once, on successful enrolment. Deliberately carries no
 * secret: both lanes register PUBLIC keys, so nothing on this wire — or
 * in the app's storage, or in the control plane's — is worth stealing
 * (DESIGN.md §2, §4).
 */
export interface EnrollmentResponse {
  deviceId: string;
}

/**
 * What the control plane stores per enrolled device — ONE record holding
 * BOTH credentials: the WebAuthn credential and the cheap-lane key
 * belong to the same identity, governed by the same revocation
 * generation, so revocation severs one device, never half of two
 * (DESIGN.md §2). Everything downstream — ack, veto, approve, GO 2 —
 * reduces to "is there a live record here". Both lanes are asymmetric:
 * the server holds only public keys, so a control-plane compromise can
 * deny and lie but cannot sign (DESIGN.md §4). This record's class is
 * "owner-device"; the physical button's HMAC is a distinct class with
 * strictly narrower authority (DESIGN.md §3).
 */
export interface EnrolledDevice {
  deviceId: string;
  ownerId: string;
  name: string;
  credentialId: Base64Url;
  /** COSE public key — verifies every future assertion */
  publicKey: Base64Url;
  /**
   * Exportable SPKI public key verifying cheap-lane signatures. Always
   * present — enrolment refuses a device without one (proof of
   * possession included; DESIGN.md §2). There is no HMAC-fallback
   * device class.
   */
  cheapLaneKey: Base64Url;
  /**
   * last accepted authenticator signature counter. A regression flags
   * cloning; synced passkeys legitimately report 0 or a frozen counter,
   * so this is a tripwire, not a guarantee.
   */
  signCount: number;
  transports: string[];
  enrolledAt: UnixMs;
  /**
   * bumped atomically by revocation. Sessions, assertion challenges,
   * unspent invites this device issued, cold-push capabilities minted
   * for it, and its ack evidence all record the generation they were
   * minted under and are re-checked against it at use — so revoking a
   * device kills everything it minted at the next decision point, not
   * at token expiry (DESIGN.md §2, §3, §4).
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
/* The alert — an open veto window reaches the phone (DESIGN.md §1, §3) */
/* ------------------------------------------------------------------ */

/**
 * The encrypted push payload. It carries the renderable summary AND a
 * one-time veto capability, because on the iOS cold-start path
 * (WebKit bug 283793) the service worker may wake with indexedDB
 * undefined — the key store unreachable — and must still be able to
 * render and to stop (DESIGN.md §3, "The iOS cold-push path"). The
 * payload is encrypted end-to-end (RFC 8291); what its capture gains an
 * attacker — one window's summary and one single-use, veto-only stop —
 * is analysed and accepted in DESIGN.md §3.
 */
export interface OwnerAlertPush {
  kind: "veto-window";
  windowId: string;
  /** pushes are dispatched only for open windows */
  status: "pending" | "extended";
  /** who is acting and what they asked for — rendered verbatim */
  agentId: string;
  tool: string;
  summary: string;
  /** when silence releases (delivered) or extends/holds (not delivered) */
  deadline: UnixMs;
  /**
   * Single-use, server-minted, VETO-ONLY capability for the cold path.
   * Its server-side record binds {deviceId, revocationGeneration,
   * windowId, allowedOperation: "veto", expiresAt ≤ the window's
   * deadline}; it dies with the window's terminal state or the device's
   * revocation, and it can never ack — the ack is the permissive
   * direction and never rides in a payload (DESIGN.md §3).
   */
  vetoCapability: string;
  capabilityExpiresAt: UnixMs;
}

/**
 * The shared veto wire vocabulary — the five VetoWindow states plus
 * "spent", introduced by #28 (packages/control-plane/src/veto.ts,
 * VetoWireStatus): the status a would-be release reports when the
 * window's recorded kill epoch is no longer current. "spent" is TERMINAL
 * on this surface — not ackable (the ack rule accepts only pending/
 * extended), not a release, not reusable; the app renders "this review
 * expired after a kill" and the action needs a fresh owner review
 * (DESIGN.md §5). This file is deliberately import-free, so the union is
 * mirrored here by name and must stay identical to the canonical export —
 * alias it (and pin with a contract test) once #28 lands on main.
 */
export type VetoWireStatus = "pending" | "vetoed" | "released" | "extended" | "held" | "spent";

/**
 * Device-signed GET /veto/:id — the renderable truth about a veto
 * window, whatever its status. (Renamed from HeldWindowDetail: "held" is
 * a specific TERMINAL state, and this shape covers all of them.) The
 * existing open (unauthenticated) read stays status-only; this shape is
 * for enrolled devices. Rendering rules per status live in DESIGN.md §5:
 * only pending/extended get a countdown and a VETO control; held renders
 * "approval required" with neither.
 */
export interface VetoWindowDetail {
  windowId: string;
  status: VetoWireStatus;
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
 * A "spent" window is past both states — never ackable, and the
 * cold-push capability can never ack (DESIGN.md §3). An accepted ack is
 * stored as EVIDENCE {deviceId, revocationGeneration, receivedAt}, and
 * release-on-silence requires at least one piece of evidence from a
 * device still active at the same generation at the moment of the
 * release decision — an ack does not outlive its device (DESIGN.md §4).
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
 * POST /veto/:id — the one-tap stop. Cheap forever, and IDEMPOTENT:
 * re-vetoing an already-vetoed window succeeds as a no-op, so the
 * service worker can blind-retry a send it cannot prove arrived
 * (DESIGN.md §3). Normally device-signed; on the iOS cold path, where
 * the key store may be unreachable, `capability` carries the payload's
 * single-use veto capability instead — veto only, never any other
 * operation (DESIGN.md §3).
 */
export interface VetoTap {
  windowId: string;
  tappedAt: UnixMs;
  /** cold-path only: the single-use veto capability from OwnerAlertPush */
  capability?: string;
}

/* ------------------------------------------------------------------ */
/* The expensive lane — fresh, bound assertions (DESIGN.md §3)         */
/* ------------------------------------------------------------------ */

/**
 * What a fresh assertion is FOR. The challenge binds to one purpose and
 * one subject; an assertion minted for ceremony A is useless for
 * ceremony B, for an approval, or for tomorrow. "device-invite" and
 * "device-revoke" exist so a stolen bearer session ALONE can never add
 * or remove a device (DESIGN.md §2, §3).
 */
export type AssertionPurpose =
  | "approve"
  | "restore-go2"
  | "session"
  | "device-invite"
  | "device-revoke";

/** POST /assert/challenge — device-signed request for a bound challenge. */
export interface AssertionChallengeRequest {
  purpose: AssertionPurpose;
  /**
   * approvalId for "approve", ceremonyId for "restore-go2", the target
   * deviceId for "device-revoke"; absent for "session" and
   * "device-invite"
   */
  subjectId?: string;
}

/**
 * The minted challenge. Single-use, short TTL; the {purpose, subjectId}
 * binding lives server-side keyed by challengeId — the phone repeating it
 * back is convenience, never trusted. A challenge also records the
 * minting device's revocation generation and dies with it: revoking the
 * device voids its outstanding challenges (DESIGN.md §2). For
 * purpose "approve", the server additionally binds the approval record's
 * canonical action hash into the challenge record, and the record itself
 * is immutable once created — the passkey signs the exact action the
 * owner was shown, and confirm re-verifies record and kill epoch
 * (DESIGN.md §5).
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
 * approval queue exists), passkey-gated session minting, and the
 * device-invite / device-revoke gates. Verification, with each check in
 * its actual location: `type`, `challenge`, and `origin` are verified
 * from clientDataJSON; `rpIdHash` and the required UP+UV flags from
 * authenticatorData; the signature (ES256 on P-256 — the only algorithm
 * enrolment admits) with the stored public key over
 * authenticatorData || SHA-256(clientDataJSON); the challenge matched
 * and burned; the signature counter monotonic where the authenticator
 * provides one.
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
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "delivery ack — the production caller of markDelivered(); accepted only while the window is pending/extended on the SERVER's clock and only from a device enrolled to the window's owner; renderedAt is audit-only; late acks recorded and ignored; stores evidence {deviceId, revocationGeneration, receivedAt} — release requires evidence from a still-active device at the same generation",
  },
  {
    method: "POST",
    path: "/veto/:id",
    auth: "device-signed | owner-session | single-use cold-push veto capability",
    status: "extension",
    purpose:
      "one-tap veto; today owner-session only — the device-signed relay and the cold-path capability are the additions; idempotent (re-veto of a vetoed window is a successful no-op) so the worker can retry blindly",
  },
  {
    method: "GET",
    path: "/veto/:id",
    auth: "device-signed for detail; open read stays status-only",
    status: "extension",
    purpose:
      "deadline + delivered + call summary, for enrolled devices only; status speaks VetoWireStatus (#28) including terminal 'spent'",
  },
  {
    method: "POST",
    path: "/devices/invite",
    auth: "owner-session + fresh UV assertion (purpose: device-invite); bootstrap/no-devices-left recovery via host CLI or permission-protected Unix socket — NEVER an HTTP loopback bypass",
    status: "addition",
    purpose:
      "mint a single-use enrolment invite carrying the full WebAuthn creation contract; records the issuing device's {deviceId, revocationGeneration} (bootstrap: a bootstrap generation); token rides in the URL fragment where a URL form exists, is spent in a POST body, and is never logged",
  },
  {
    method: "POST",
    path: "/devices/enroll",
    auth: "invite-token",
    status: "addition",
    purpose:
      "verify the WebAuthn registration (type/challenge/origin from clientDataJSON; rpIdHash + UP/UV from authenticatorData; ES256 on P-256) AND the pinned cheap-lane proof of possession, re-check the issuer's standing (or bootstrap generation + zero active devices) atomically, then store ONE EnrolledDevice holding both credentials; the invite burns atomically and only on success; a successful bootstrap enrolment invalidates sibling bootstrap invites",
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
    auth: "owner-session + fresh UV assertion (purpose: device-revoke, subject: target deviceId); host CLI / Unix socket can always revoke",
    status: "addition",
    purpose:
      "kill a device's standing: bump its revocation generation and atomically void credentials, push subscription, live sessions, outstanding challenges, unspent invites it issued, and its ack evidence",
  },
  {
    method: "PUT",
    path: "/devices/:id/push-subscription",
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "store / refresh the Web Push subscription; :id derived from the authenticated identity — a mismatched path id is rejected; endpoint validated as an SSRF surface (HTTPS, known push-service shapes, no private/metadata addresses)",
  },
  {
    method: "POST",
    path: "/assert/challenge",
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "mint a single-use challenge bound to {purpose, subjectId} across all five purposes; dies with the minting device's revocation generation",
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
