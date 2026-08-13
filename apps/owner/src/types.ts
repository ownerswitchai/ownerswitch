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

/**
 * Minimum owner-response interval, ms (DESIGN.md §3). An ack is valid
 * delivery evidence only when receivedAt ≤ deadline − this interval: a
 * delivery landing five milliseconds before the deadline must not
 * count as "the owner was reached and chose not to object". 60 s is a
 * decision interval (wake, read, unlock, open — without rushing), small
 * against the 4-minute window, and matches the 60 s skew/replay bound
 * the signature scheme already uses.
 */
export const MIN_VETO_RESPONSE_MS_DEFAULT = 60_000;

/**
 * The enforced FLOOR for minVetoResponseMs, checked AT STARTUP: a
 * control plane configured below this refuses to start (the same
 * stance as the kill-state path guard). The reviewed minimum is the
 * enforced minimum — "configurable" never means "configurable to 1 ms"
 * (DESIGN.md §3).
 */
export const MIN_VETO_RESPONSE_MS_FLOOR = 60_000;

/**
 * RenderableAlertV1 — the bounded canonical alert format (DESIGN.md §3,
 * "Truthful rendering"). The payload hash proves the device rendered
 * the issued bytes; these bounds are what make the rendered bytes mean
 * what the human read (UTR #36: bidi overrides, control characters, and
 * truncation can make true bytes read as a false sentence). Enforced at
 * MINT: fields exceeding the limits, containing any C0/C1 control
 * (incl. CR/LF/TAB — single-line only), or containing explicit bidi
 * embedding/override/isolate controls (LRE RLE LRO RLO PDF LRI RLI FSI
 * PDI) are refused server-side. Clients render each field in its own
 * bidi isolate and never ack a truncated render. Limits are Unicode
 * code points, sized to make lock-screen truncation UNLIKELY — an
 * assumption about platform surfaces, not a guarantee: visible width
 * depends on glyphs, fonts, and accessibility settings, and the
 * Notifications API reports no truncation result. Which is one more
 * reason notifications are alert-only and never ack evidence — the ack
 * comes only from the foreground detail view (DESIGN.md §3, §4).
 */
export const RENDERABLE_ALERT_V1_LIMITS = {
  agentId: 64,
  tool: 64,
  summary: 200,
} as const;

/**
 * The versioned canonical alert envelope. Its SHA-256 over the fixed
 * canonical encoding is the WindowRevision's renderContentHash, so any
 * change to visible content OR to this schema (a new `v`) is by
 * construction a new revision with new deliveries — two different
 * summaries or schema versions can never both be valid under one
 * revision (DESIGN.md §3).
 */
export interface RenderableAlertV1 {
  v: 1;
  agentId: string;
  tool: string;
  summary: string;
}

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
   * single-use bearer capability, ≥128 bits from a CSPRNG — generated
   * ON the inviting device (or the host CLI for bootstrap) and NEVER
   * returned by the server, which stores only its SHA-256 (hash
   * commitment: a captured mint request or raced response yields
   * nothing — DESIGN.md §2). Travels device-to-device only (QR / typed
   * code); where a URL form exists it rides ONLY in the fragment
   * (never query or path — fragments stay out of access logs and the
   * Referer header), is cleared with history.replaceState the moment
   * the app reads it, is spent as a preimage in a POST body, and is
   * never written to a log on either end. Burned atomically and only
   * on a SUCCESSFUL registration — a failed attempt does not consume
   * it (DESIGN.md §2).
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
   * The complete WebAuthn user entity. `id` is an opaque CSPRNG handle,
   * stable per owner, never PII — the spec forbids personal data there,
   * and this design forbids reusing the ownerId string. `name` and
   * `displayName` are display-only labels for the platform's UI.
   */
  user: {
    id: Base64Url;
    name: string;
    displayName: string;
  };
  /** credential parameter descriptors for create(); pinned to ES256 only */
  pubKeyCredParams: ReadonlyArray<{ type: "public-key"; alg: -7 }>;
  /** the authenticator-selection contract, verbatim for create() */
  authenticatorSelection: {
    authenticatorAttachment: "platform";
    residentKey: "preferred";
    userVerification: "required";
  };
  /** creation challenge for navigator.credentials.create() */
  challenge: Base64Url;
  /**
   * The ceremony's SECOND challenge: immediately after create(), the app
   * performs a fresh `navigator.credentials.get()` with the NEW credential
   * over this challenge and submits the assertion in the enrolment request
   * (possessionAssertion). With attestation "none" nothing in the creation
   * output is signed, so THIS assertion is what proves the phone holds the
   * new private key and a human passed user verification. Minted with the
   * invite, single-use with it.
   */
  assertionChallenge: Base64Url;
  /**
   * The mint-committed display label, carried IN the payload because the
   * enrolment request must repeat it EXACTLY (EnrollmentRequest.deviceName
   * — the echo rule, DESIGN.md §2 step 5): the phone confirms it is
   * redeeming the invite it was actually shown.
   */
  deviceName: string;
}

/**
 * POST /devices/invite — the hash-commitment mint (DESIGN.md §2), THE
 * pinned invite model: the inviting device (or the host CLI for
 * bootstrap) generates the ≥128-bit secret locally and submits ONLY its
 * SHA-256; the server's response carries no secret, and the control
 * plane's InviteStore (packages/control-plane/src/invite.ts) stores only
 * this commitment. EnrollmentInvite above is the DEVICE-TO-DEVICE
 * payload (QR / typed code) — its `token` is the locally generated
 * secret in transit between phones, never a server-returned value.
 * Device-signed, plus owner session and a device-invite assertion
 * (DESIGN.md §3).
 */
export interface InviteMintRequest {
  /** SHA-256 of the locally generated ≥128-bit invite secret */
  tokenHash: Base64Url;
  /** human label for the device being invited, e.g. "Adam's new phone" */
  deviceName: string;
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
  /** the invite secret — the preimage of the committed hash (DESIGN.md §2) */
  token: string;
  /**
   * Human label shown in the device list — REQUIRED, and it must repeat
   * the invite's mint-committed label (InviteMintRequest.deviceName)
   * EXACTLY: the inviter chose the label; the enrolling phone repeats it
   * as confirmation it is redeeming the invite it was actually shown. A
   * mismatch refuses with the invite alive (DESIGN.md §2 step 5).
   */
  deviceName: string;
  registration: WebAuthnRegistration;
  /**
   * The fresh webauthn.get assertion with the NEWLY created credential,
   * over the invite's assertionChallenge — the possession-and-UV proof
   * attestation "none" cannot give (see EnrollmentInvite.assertionChallenge).
   * REQUIRED: the control plane's enrolment core refuses to spend an invite
   * without it (performEnrollment, enrollment.ts).
   */
  possessionAssertion: WebAuthnAssertion;
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
  /**
   * THE canonical stored key representation, everywhere: base64url of the
   * CANONICAL SPKI DER the control plane's registration verifier
   * re-exported (never the raw COSE bytes off the wire — one format from
   * RegistrationVerdict through the durable registry to the assertion
   * verifier, converted to PEM only at the verify edge).
   */
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
   * unspent invites this device issued, deliveries minted for it, and
   * its ack evidence all record the generation they were minted under
   * and are re-checked against it at use — so revoking a device kills
   * everything it minted at the next decision point, not at token
   * expiry (DESIGN.md §2, §3, §4).
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
 * caps (DESIGN.md §5, rows 7 and 11). The subscription must be
 * restricted to the configured VAPID public key (`applicationServerKey`,
 * RFC 8292) — an unrestricted subscription is refused at upsert. This
 * record NEVER leaves the server: `auth` in particular is the secret
 * that lets a holder generate push messages the user agent accepts
 * (RFC 8291) — clients see DeviceSummary, not this.
 */
export interface PushSubscriptionRecord {
  endpoint: string;
  keys: {
    p256dh: Base64Url;
    auth: Base64Url;
  };
}

/**
 * What GET /devices actually returns — a REDACTED projection of
 * EnrolledDevice. No push endpoint, no p256dh, no auth secret, no keys:
 * returning the full record to a bearer session would hand out the push
 * `auth` secret (RFC 8291 §8.2 — its holder can mint pushes the user
 * agent accepts) and the subscription endpoint. A boolean is all the UI
 * needs (DESIGN.md §5, row 6).
 */
export interface DeviceSummary {
  deviceId: string;
  name: string;
  enrolledAt: UnixMs;
  revokedAt: UnixMs | null;
  /** whether a push subscription is registered — the fact, never the contents */
  pushRegistered: boolean;
}

/* ------------------------------------------------------------------ */
/* The alert — an open veto window reaches the phone (DESIGN.md §1, §3) */
/* ------------------------------------------------------------------ */

/**
 * A showing of a veto window — the versioned-delivery contract's unit
 * of truth (DESIGN.md §3, "Versioned delivery"). `revision` increments
 * on EVERY status, deadline, visible-content, or render-schema change;
 * `renderContentHash` pins the exact RenderableAlertV1 envelope this
 * revision shows; `immutableActionHash` (the same canonicalization
 * vocabulary as the approval hash, DESIGN.md §5) never changes across
 * revisions — one window, one action, many showings.
 */
export interface WindowRevision {
  windowId: string;
  revision: number;
  status: "pending" | "extended";
  deadline: UnixMs;
  immutableActionHash: Base64Url;
  /** SHA-256 of this revision's canonical RenderableAlertV1 envelope */
  renderContentHash: Base64Url;
}

/**
 * Server-side record minted every time renderable content is handed to
 * a device — a push dispatch or a device-signed detail read.
 * `payloadHash` is the SHA-256 of the exact bytes issued. `renderClass`
 * is decided by the server from how the delivery was minted — never by
 * a client field — and ONLY "foreground-detail" deliveries are
 * ack-eligible: notifications alert, they never produce evidence
 * (DESIGN.md §3). An ack counts only by naming a live, same-window,
 * foreground-detail Delivery and matching its hash — so a forged or
 * replayed push cannot turn the device into an ack-signing oracle.
 * Dies with the window's terminal state, its own expiry, or the
 * device's revocation generation.
 */
export interface Delivery {
  deliveryId: string;
  windowId: string;
  revision: number;
  deviceId: string;
  deviceGeneration: number;
  /** "notification" = alert-only, never ack-eligible; server-decided */
  renderClass: "notification" | "foreground-detail";
  payloadHash: Base64Url;
  expiresAt: UnixMs;
}

/**
 * Server-side record of an ACCEPTED ack — the full coordinates of what
 * was actually shown, never a bare "seen" bit. Validation and insertion
 * run as ONE transaction on the serialization authority (DESIGN.md §5)
 * spanning the window state AND the witnessing device's generation
 * record — a window-only CAS could race a generation bump stored on the
 * device record, so a concurrent revocation necessarily conflicts. An
 * ack validated against revision 1 that races the transition to
 * revision 2 fails and is recorded-and-ignored; so does one racing its
 * device's revocation. Release, revision change, and revocation
 * serialize on the same authority; release for revision N counts only
 * evidence with revision == N from a device still active at
 * deviceGeneration (DESIGN.md §3, §4).
 */
export interface AckEvidence {
  windowId: string;
  revision: number;
  deliveryId: string;
  deviceId: string;
  deviceGeneration: number;
  payloadHash: Base64Url;
  /** server receive time — the only clock that counts */
  receivedAt: UnixMs;
}

/**
 * The encrypted push payload. It carries the renderable summary and the
 * delivery coordinates, because on the iOS cold-start path (WebKit bug
 * 283793) the service worker may wake with indexedDB undefined — the
 * key store unreachable — and must still render something useful
 * without a fetch (DESIGN.md §3, "The iOS cold path"). It deliberately
 * carries NO capability and NO authority of any kind: the v0.3
 * cold-push veto capability was dropped — it had no consumer, since the
 * only iOS gesture is the tap that opens the app where the key is
 * foreground-accessible (DESIGN.md §3). Payload capture gains one
 * window's summary — nothing actionable. agentId/tool/summary conform
 * to RenderableAlertV1 (RENDERABLE_ALERT_V1_LIMITS above) — enforced at
 * mint, so a conforming payload cannot hide or reorder its decisive
 * facts. The dispatcher keeps the whole plaintext under RFC 8291's
 * 3993-byte ceiling or degrades to a generic alert, which never acks.
 */
export interface OwnerAlertPush {
  kind: "veto-window";
  windowId: string;
  /** the WindowRevision this payload shows */
  revision: number;
  /** the server-minted Delivery this payload IS — echoed by the ack */
  deliveryId: string;
  /** pushes are dispatched only for open windows */
  status: "pending" | "extended";
  /** who is acting and what they asked for — rendered as TEXT, never markup */
  agentId: string;
  tool: string;
  summary: string;
  /** when silence releases (delivered) or extends/holds (not delivered) */
  deadline: UnixMs;
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
 * for enrolled devices. The read itself mints a Delivery — the warm
 * path renders THIS and acks the revision and delivery the fetch minted
 * (DESIGN.md §3). Rendering rules per status live in DESIGN.md §5: only
 * pending/extended get a countdown and a VETO control; held renders
 * "approval required" with neither.
 */
export interface VetoWindowDetail {
  windowId: string;
  status: VetoWireStatus;
  /** current revision of this window's showing (open statuses) */
  revision: number;
  /** the Delivery this read minted — echoed by the ack */
  deliveryId: string;
  /** who is acting and what they asked for — rendered as TEXT, never markup */
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
 * Sent device-signed, only after content carrying the CONCRETE action
 * summary rendered (a generic, oversized, or truncated render must not
 * ack — DESIGN.md §4). Proves rendered-on-enrolled-device; nothing more.
 * Sent ONLY from the foreground detail view — the exact window's view
 * selected, document visible AND focused, a paint opportunity
 * completed, visibility re-checked immediately before signing
 * (DESIGN.md §3). Notifications never ack: no service-worker context
 * produces evidence, and a notification-class delivery is refused
 * server-side. Counts ONLY under the full versioned-delivery rule,
 * judged in one transaction on the server's clock and records
 * (DESIGN.md §3): the named Delivery exists, is unexpired, is for THIS
 * window, is "foreground-detail" class, and belongs to the signing
 * device at its current generation; ack revision == delivery revision
 * == the window's current open revision; `renderedPayloadHash` equals
 * the hash the server recorded; the window is still pending/extended;
 * and receivedAt ≤ deadline − minVetoResponseMs (floor 60 s, enforced
 * at startup — a last-second delivery extends or holds, never
 * releases). Anything else is recorded in the audit trail and ignored.
 * An accepted ack is stored as AckEvidence in a transaction spanning
 * the window and the witnessing device's generation record; release
 * for revision N requires revision-N evidence from a device still
 * active at the same generation at the moment of the release decision
 * — an ack does not outlive its device or its revision (DESIGN.md §3,
 * §4).
 */
export interface SeenAck {
  windowId: string;
  /** the WindowRevision the device actually rendered */
  revision: number;
  /** the server-minted foreground-detail Delivery that carried it */
  deliveryId: string;
  /** SHA-256 of the exact payload bytes as received and rendered */
  renderedPayloadHash: Base64Url;
  /**
   * when the view was rendered on this device — AUDIT DATA ONLY. The
   * server's own receive time and records decide whether the ack
   * counts; nothing the phone asserts moves the deadline.
   */
  renderedAt: UnixMs;
  /** the only ack-eligible render class (DESIGN.md §3) */
  surface: "foreground-detail";
}

/**
 * POST /veto/:id — the one-tap stop. Always device-signed (on iOS the
 * tap opens the app, where the key is foreground-accessible and the
 * veto goes out signed — DESIGN.md §3; the v0.3 payload capability was
 * dropped for having no consumer). Cheap forever, and IDEMPOTENT:
 * re-vetoing an already-vetoed window succeeds as a no-op, so the
 * service worker can blind-retry a send it cannot prove arrived
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
 * What a fresh assertion is FOR — a DISCRIMINATED union, so a subject
 * is required exactly where one exists and impossible where none does.
 * The challenge binds to one purpose and one subject; an assertion
 * minted for ceremony A is useless for ceremony B, for an approval, or
 * for tomorrow. "device-invite" and "device-revoke" exist so a stolen
 * bearer session ALONE can never add or remove a device (DESIGN.md §2,
 * §3).
 */
export type AssertionBinding =
  | { purpose: "approve"; subjectId: string }
  | { purpose: "restore-go2"; subjectId: string }
  | { purpose: "device-revoke"; subjectId: string }
  | { purpose: "session"; subjectId?: never }
  | { purpose: "device-invite"; subjectId?: never };

export type AssertionPurpose = AssertionBinding["purpose"];

/** POST /assert/challenge — device-signed request for a bound challenge. */
export type AssertionChallengeRequest = AssertionBinding;

/**
 * The minted challenge. Single-use, short TTL; the binding lives
 * server-side keyed by challengeId — the phone repeating it back is
 * convenience, never trusted. `rpId` and `allowCredentials` name the
 * ISSUING device's paired WebAuthn credential, so the assertion must
 * come from the same EnrolledDevice that requested the challenge — the
 * identity-continuity line for device-invite, device-revoke, and GO 2
 * (DESIGN.md §3); the platform cannot satisfy it with some other
 * synced passkey. A challenge records the minting device's revocation
 * generation and dies with it (DESIGN.md §2). Redemption is atomic:
 * verify, consume the challenge, perform exactly ONE protected
 * mutation — a raced assertion mints one invite, one session, one
 * restore, one execution, never two (DESIGN.md §3). For purpose
 * "approve", the server additionally binds the approval record's
 * canonical action hash into the challenge record; the record itself
 * is immutable once created and carries a TTL (minutes, not hours);
 * confirm re-verifies — inside the atomic commit — record hash, kill
 * epoch, session + device generation, and that the action STILL routes
 * to the approve lane under the CURRENT policy; queued executions
 * re-check the approving device's generation immediately before
 * dispatch (DESIGN.md §3, §5).
 */
export type AssertionChallenge = AssertionBinding & {
  challengeId: string;
  challenge: Base64Url;
  /** rpId the assertion must be made under */
  rpId: string;
  /** the issuing device's paired credential — and only it */
  allowCredentials: ReadonlyArray<{ type: "public-key"; id: Base64Url }>;
  expiresAt: UnixMs;
};

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
 * device-invite / device-revoke gates. A captured-but-unredeemed
 * BoundAssertion is bearer authority for its exact bound mutation, so
 * EVERY redemption request is additionally DEVICE-SIGNED by the same
 * device whose credential produced the assertion — a captured
 * assertion alone redeems nothing, because the device key never
 * travels (DESIGN.md §3). Verification, with each check in its actual
 * location: `type`, `challenge`, and `origin` are verified from
 * clientDataJSON; `rpIdHash` and the required UP+UV flags from
 * authenticatorData; the signature (ES256 on P-256 — the only algorithm
 * enrolment admits) with the stored public key over
 * authenticatorData || SHA-256(clientDataJSON); the challenge matched
 * and burned; the signature counter monotonic where the authenticator
 * provides one. Session validity + device generation, challenge
 * ownership, target state, and kill epoch are re-verified INSIDE the
 * atomic consume-and-commit, never before it (DESIGN.md §3).
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
      "delivery ack — the production caller of markDelivered(); counts only under the versioned-delivery rule, judged in ONE transaction spanning the window and the witnessing device's generation record: named Delivery exists, unexpired, same windowId, foreground-detail render class (notification-class deliveries are refused — notifications never produce evidence), owned by the signing device at its current generation; ack revision == delivery revision == current open revision; matching renderedPayloadHash; window still pending/extended; receivedAt <= deadline - minVetoResponseMs (floor 60 s, enforced at startup); renderedAt audit-only; everything else recorded and ignored; release for revision N requires revision-N evidence from a still-active device at the same generation",
  },
  {
    method: "POST",
    path: "/veto/:id",
    auth: "device-signed | owner-session",
    status: "extension",
    purpose:
      "one-tap veto; today owner-session only — the device-signed relay is the addition; idempotent (re-veto of a vetoed window is a successful no-op) so the worker can retry blindly; the v0.3 cold-push capability is dropped — no consumer",
  },
  {
    method: "GET",
    path: "/veto/:id",
    auth: "device-signed for detail; open read stays status-only",
    status: "extension",
    purpose:
      "deadline + delivered + RenderableAlertV1 content + current revision, for enrolled devices only; the read mints the foreground-detail Delivery the ack must echo — the only ack-eligible render class; status speaks VetoWireStatus (#28) including terminal 'spent'",
  },
  {
    method: "GET",
    path: "/veto",
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "open-window reconciliation — the inbox a root-launched app renders when iOS loses the click handoff; lists open windows with current revisions; listing never acks — rendering ONE window's detail mints the delivery its ack must echo, so an inbox can never bulk-ack",
  },
  {
    method: "POST",
    path: "/devices/invite",
    auth: "owner-session + device-signed + fresh UV assertion (purpose: device-invite) — redemption is device-signed; bootstrap/no-devices-left recovery via host CLI or permission-protected Unix socket — NEVER an HTTP loopback bypass",
    status: "addition",
    purpose:
      "register a client-generated invite by hash commitment (InviteMintRequest): the inviting device generates the secret locally, submits only its SHA-256, and the server stores the hash and RETURNS NO SECRET — a captured signed request or raced response yields nothing; records the WebAuthn creation contract and the issuing device's {deviceId, revocationGeneration} (bootstrap: a bootstrap generation); the secret travels device-to-device only and is spent as a preimage, never logged",
  },
  {
    method: "POST",
    path: "/devices/enroll",
    auth: "invite secret (preimage of the committed hash)",
    status: "addition",
    purpose:
      "verify the WebAuthn registration (type/challenge/origin from clientDataJSON, REJECTING crossOrigin:true or an unexpected topOrigin; rpIdHash + UP/UV from authenticatorData; ES256 on P-256) AND the pinned cheap-lane proof of possession, re-check the issuer's standing (or bootstrap generation + zero active devices) atomically, then store ONE EnrolledDevice holding both credentials; the invite burns atomically and only on success; a successful bootstrap enrolment invalidates sibling bootstrap invites",
  },
  {
    method: "GET",
    path: "/devices",
    auth: "owner-session",
    status: "addition",
    purpose:
      "list enrolled devices as REDACTED DeviceSummary — never EnrolledDevice: the push endpoint, p256dh, and auth secret stay server-side (RFC 8291: the auth secret's holder can mint pushes the user agent accepts)",
  },
  {
    method: "POST",
    path: "/devices/:id/revoke",
    auth: "owner-session + device-signed + fresh UV assertion (purpose: device-revoke, subject: target deviceId) — redemption is device-signed; host CLI / Unix socket can always revoke",
    status: "addition",
    purpose:
      "kill a device's standing: bump its revocation generation and atomically void credentials, push subscription, live sessions, outstanding challenges, unspent invites it issued, its deliveries, and its ack evidence",
  },
  {
    method: "PUT",
    path: "/devices/:id/push-subscription",
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "store / refresh the Web Push subscription; :id derived from the authenticated identity — a mismatched path id is rejected; subscription must be restricted to the configured VAPID public key (RFC 8292) or it is refused; endpoint validated as an SSRF surface (HTTPS, known push-service shapes, no private/metadata addresses)",
  },
  {
    method: "POST",
    path: "/assert/challenge",
    auth: "device-signed (owner-device class only)",
    status: "addition",
    purpose:
      "mint a single-use challenge for a discriminated {purpose, subject} binding; response carries rpId + allowCredentials naming the issuing device's paired credential (identity continuity); dies with the minting device's revocation generation; redemption is atomic — verify, consume, exactly one protected mutation",
  },
  {
    method: "POST",
    path: "/session",
    auth: "device-signed + verified assertion (purpose: session) — redemption is device-signed",
    status: "addition",
    purpose:
      "passkey-gated session minting — closes TODO(passkey) in auth.ts; atomic redemption with all checks inside the commit: one assertion, one session; session binds to deviceId + revocation generation and is re-checked against the device on every use",
  },
  {
    method: "POST",
    path: "/restore",
    auth: "owner-session + device-signed + verified assertion (purpose: restore-go2, subject: ceremonyId) — redemption is device-signed",
    status: "extension",
    purpose:
      "GO 2 stops accepting the bearer token GO 1 already saw; the ceremony stores GO 1 provenance {ownerId, go1SessionDeviceId, go1SessionGeneration, killEpoch}; session + device generation, challenge ownership, ceremony state, and kill epoch are re-verified INSIDE the atomic consume-and-commit — revoking the GO 1 device kills the pending ceremony",
  },
] as const;

export type OwnerAppEndpoint = (typeof OWNER_APP_ENDPOINTS)[number];
