# Owner app — the phone in the loop

**The only surface that can confirm the owner actually saw an alert, and
the only one that can carry a passkey — so it unblocks two things at
once.**

Two of the control plane's promises currently end at a stub:

- The veto lane's reachability rule — *"silence only approves if we KNOW
  the owner saw the notification"* — is enforced by `markDelivered()` in
  `packages/control-plane/src/veto.ts`, and nothing in production ever
  calls it. Today every window nobody manually ticks runs the
  unreachable-owner path: extend once, then `held`. The fail-closed half
  works; the *"owner reached, silence releases"* half has no way to
  happen, so the veto lane silently degrades into a second approval lane.
- The approve lane and the restore ceremony both say "passkey", and no
  passkey exists anywhere. `createOwnerSession()` mints bearer tokens for
  whoever can call it in-process (`TODO(passkey)` in
  `packages/control-plane/src/auth.ts`), and GO 1 and GO 2 of the restore
  ceremony accept the *same* bearer token
  (`packages/control-plane/src/server.ts`) — a stolen session performs
  both GOs, and the 30 s cooldown is the only thing 2GO still adds
  against it.

The owner app is the missing device: an installable PWA on the owner's
phone that (1) renders held veto windows and reports the render, (2)
carries the one-tap VETO, and (3) holds the WebAuthn passkey that the
approve lane and GO 2 will demand. This PR is the design and a static
scaffold — types, shell, service-worker stub. No push infrastructure, no
WebAuthn ceremony code, no control-plane change ships here.

## 1. What it must do

Three jobs, one per lane of the asymmetry:

1. **The stop path.** A web push arrives for a held veto window. The
   service worker renders a notification with the concrete action
   summary — agent, tool, what it's about to do, when silence releases
   it. One tap on VETO stops it. Stopping stays one gesture, no
   biometric, no session dance: the veto is signed by the enrolled
   device (§2), the same cheap HMAC mechanism the physical button
   already uses, because stopping must never acquire friction.
2. **The ack.** The moment the summary is actually rendered on the
   enrolled device, the app reports it: `POST /veto/:id/seen`,
   device-signed. That is the production caller `markDelivered()` has
   been waiting for. From then on the window's silence means what the
   state machine wants it to mean — *the owner was reached and chose not
   to object* — instead of "nobody was listening". §4 states exactly how
   much an ack proves; it is less than it sounds.
3. **The passkey lanes.** At enrolment the app creates a WebAuthn
   credential on the phone's platform authenticator. Approving an
   `approve`-lane action and confirming GO 2 of the restore ceremony
   each demand a *fresh* assertion with user verification, bound to the
   specific approval or ceremony id — not "the app is open", not a
   bearer token that GO 1 already saw. That closes the
   `TODO(passkey)` at session minting and splits GO 1 from GO 2 with a
   proof a stolen session cannot forge.

## 2. Device enrolment — the root of trust

Every claim this app makes reduces to one sentence: *this request came
from a device the owner enrolled.* The ack's meaning, the veto's
attribution, the approve's authority, GO 2 — all of it inherits the
enrolment ceremony's honesty. If enrolment is loose, nothing downstream
tightens it back up. So it is designed first.

### Becoming an enrolled device

1. **Invite.** An enrolment invite is minted server-side:
   `POST /devices/invite`, owner session required. The invite is a
   single-use CSPRNG token (≥128 bits), TTL ~10 minutes, bound to the
   `ownerId` that minted it, carrying a WebAuthn *creation* challenge.
   It is presented out-of-band — a QR code or URL shown where the
   operator stands — and the phone opens it over HTTPS.
2. **Credential creation.** The phone calls
   `navigator.credentials.create()` against the invite's challenge:
   platform authenticator, `userVerification: "required"`,
   `residentKey: "preferred"`, attestation `"none"` (a deliberate
   choice, stated plainly in §4).
3. **Verification and storage.** The control plane burns the invite
   atomically (spent-or-refused, exactly once), checks the challenge,
   origin and rpId in `clientDataJSON`, and stores the
   `EnrolledDevice` record: credential id, COSE public key, signature
   counter, transports, device name, `ownerId`, `enrolledAt`.
4. **Cheap-lane secret.** In the same response the control plane
   provisions a per-device HMAC secret — the credential for the cheap
   direction (ack, veto tap, detail reads), verified by the existing
   `verifyDeviceSignature()` machinery in
   `packages/control-plane/src/auth.ts`. Returned exactly once, stored
   on-device, never re-readable. The passkey's private key never leaves
   the authenticator; the HMAC secret is symmetric and the server keeps
   its copy — an asymmetry inside the asymmetry that §4 accounts for.
5. **Push subscription.** After notification permission is granted, the
   app registers its Web Push subscription
   (`PUT /devices/:id/push-subscription`, device-signed) and re-upserts
   it on `pushsubscriptionchange`.

**What proves it at enrolment time: possession of a live invite.**
Nothing else. The WebAuthn ceremony proves the phone holds the new
private key (and that a human passed user verification); it does not
prove *whose* phone it is. The invite's out-of-band channel — the
operator's screen to the owner's camera, in person — is the actual
security of enrolment. TTL and single-use bound an interception, they do
not prevent it. **A leaked invite is total compromise of the owner
surface:** whoever spends it becomes an enrolled device and inherits
everything — the ability to ack (turning veto-lane silence into
release), veto, approve, mint sessions, and complete both GOs of
restore with their own passkey. There is no cheaper way to say it:
guard invites like the kill-state directory.

### Bootstrap, and where trust actually roots

The first device cannot be enrolled with an owner session that requires
a passkey — no passkey exists yet. The first invite is therefore minted
from the control-plane host itself (in-process or CLI on the box),
which is exactly the trust the system already runs on today: session
minting is in-process, flagged in `auth.ts`. Enrolment doesn't add that
assumption; it makes it explicit and *bounded in time*. After the first
device is enrolled, invite minting demands an owner session, which
demands an enrolled device: host access → first device → everything
else. The control-plane host is, and remains, the recovery root — the
same deployment boundary the threat model already names for kill state.

### Revocation, two devices, the lost phone

- **Revoke:** `POST /devices/:id/revoke`, owner session required. The
  HMAC secret dies immediately, the credential is removed, the push
  subscription is dropped. Revocation applies to future requests; it
  cannot recall an ack or veto already accepted (both are in the safe
  direction — an attestation and a stop).
- **Two devices:** each enrolls independently — own invite, own
  passkey, own secret, own subscription. Alerts fan out to every
  enrolled device; the *first* render acks; any device can veto; any
  single device's passkey satisfies approve and GO 2 (1-of-N in v0 —
  an N-of-M quorum is a visible future change, not an accidental
  default). A second device is the recommended recovery path: lose one
  phone, revoke it from the other.
- **Lost only phone:** the owner cannot mint a session (post-passkey,
  sessions require an enrolled device), so recovery goes through the
  root: on the control-plane host, revoke the lost device and mint a
  fresh invite. Deliberately no remote self-service recovery — a
  recovery path cheaper than enrolment would *be* the attack surface.
- **All devices revoked / none enrolled:** veto windows can never
  confirm delivery, so every one runs extend → `held`; approvals and
  restores have no passkey to satisfy them. The system degrades to
  fully fail-closed, never fail-open. Mass revocation is a de facto
  self-kill of the veto and approve lanes — accepted, and consistent
  with everything else in this repo: reachability problems must add
  friction, not permission.

## 3. The asymmetry, preserved

The switch's rule — stopping cheap, starting expensive — maps onto the
app's two credentials:

| action | credential | user verification | bound to |
| --- | --- | --- | --- |
| ack (`/veto/:id/seen`) | device HMAC | none | window id |
| veto tap | device HMAC | none | window id |
| read window detail | device HMAC | none | window id |
| approve an action | fresh WebAuthn assertion | **required** | that approval id |
| GO 2 of restore | fresh WebAuthn assertion | **required** | that ceremony id |
| mint owner session | fresh WebAuthn assertion | **required** | session mint |

**Cheap lane.** The ack and the veto are HMAC-signed requests the app
can send in one tap — from the service worker's notification action,
without waking WebAuthn UI, without a live session. This is the same
mechanism, the same headers, and the same verification code path as the
physical button, and for the same reason: the stop direction must
survive friction, dead sessions, and a sleepy owner.

**Expensive lane.** Approve and GO 2 each require a fresh
`navigator.credentials.get()` with `userVerification: "required"`
against a challenge the control plane minted *for that specific
subject*: single-use, TTL ~2 minutes, bound server-side to
`{purpose, subjectId}` — the approval id or the ceremony id. The
signature covers the challenge via `clientDataJSON`, so an assertion
for ceremony A is cryptographically useless for ceremony B, for a
different approval, or for tomorrow. Verification checks the stored
public key, the rpId hash, the UP and UV flags, burns the challenge,
and enforces a monotonic signature counter where the authenticator
provides one. "The app is open" authorizes nothing; every yes is a
fresh biometric-or-PIN ceremony naming the exact thing it approves.

**What a stolen, unlocked phone can and cannot do — plainly.** It can
read every pending alert. It can veto everything (a stop: paralysis of
the veto lane at worst, and revocation ends it). It cannot approve, it
cannot complete GO 2, and it cannot mint a session — each demands user
verification the thief's face and finger will fail. What it *does*
break, silently, is the ack's meaning: the phone keeps rendering and
acking alerts in a pocket the owner doesn't control, so veto-lane
silence keeps releasing calls the owner never saw. An ack proves
*rendered on the enrolled device* — §4 — and a stolen phone is the
cleanest demonstration of the gap between that and "seen by the
owner". Two caveats that bound even the good news: user verification
is the platform's claim, not ours — a device passcode the thief
shoulder-surfed typically both satisfies UV and can enroll a new
biometric; and on most platforms the passcode also unlocks the synced
passkey store. Stolen unlocked phone plus known passcode is full
compromise of that device's owner powers; the answer is revocation
from the second device or the host, not anything this app can do.

## 4. Honest limits

In the spirit of `packages/mcp/THREAT-MODEL.md`: what the shipped thing
will actually prove, and what it will not.

- **An ack proves *rendered on the enrolled device*. Nothing more.**
  Not read, not understood, not that the eyes in front of the screen
  were the owner's — a phone face-down in a bag acks exactly like an
  attentive owner. And "rendered" itself means "the OS accepted and
  displayed the notification as far as the API can tell":
  `showNotification()` resolves even when Do-Not-Disturb, focus modes,
  or a notification summary suppress every visible and audible trace.
  The ack is the strongest claim web push can make, and it is a
  strictly weaker claim than the words "the owner saw it". The veto
  state machine is designed for exactly this honesty — the ack only
  flips which *fail-safe* applies (release on silence vs extend→held);
  it never executes anything by itself.
- **The ack only fires on a concrete render.** The service worker acks
  after — and only after — a notification carrying the actual action
  summary is displayed. If the device-signed detail fetch fails and the
  app can only show a generic "an action is being held", it shows it
  *without acking*: the owner saw that something is pending, but since
  they could not judge *what*, silence must not release it. Fail-closed
  on partial delivery.
- **A forged ack fails open; the enrolment boundary is what prevents
  it.** Absence of acks degrades safely (extend → `held`). A *false*
  ack is the dangerous direction — it converts the veto lane's silence
  into release. Only enrolled devices can sign one, which is why §2 is
  the root of trust and why a leaked invite or a compromised device is
  scoped as total compromise of the owner surface, not an
  inconvenience.
- **Push delivery is best-effort, and a third party sits in the path.**
  The OS can throttle, batch, delay, or silence; the user can revoke
  notification permission and no API reliably tells us; battery savers
  and doze add minutes to windows that are only minutes long. Delivery
  rides the platform push services (APNs, FCM, Mozilla's autopush) —
  payloads are encrypted end-to-end (RFC 8291), so they cannot *read*
  an alert, but they can drop or delay it, and they see that this
  deployment alerts, when, and how often. A push-service outage
  silences the fleet's alerts; every window then runs extend → `held`
  and the system gets slower, not weaker. Silence composes with
  fail-closed. That is the entire reason the ack exists.
- **PWA push is platform-dependent, iOS most of all.** On iOS, web push
  requires the PWA to be installed to the home screen (16.4+), and
  permission requires a user gesture inside the installed app. Safari,
  Chrome, and Firefox differ in subscription lifetime and background
  behavior. "Install the app, grant notifications, keep it installed"
  is an operational requirement on the owner, and an uninstalled app
  fails exactly like an unreachable owner — closed.
- **Passkeys sync; "the device" is really "the platform account".**
  Platform authenticators sync credentials through iCloud Keychain and
  Google Password Manager, and WebAuthn gives a relying party no
  reliable, portable way to force a hardware-bound credential.
  The credential enrolled in §2 may therefore turn up on every device
  signed into the owner's platform account — and on an attacker's
  device if that account is compromised, with the attacker's own
  biometrics satisfying UV. The honest description of the expensive
  lane's root: *the owner's platform-account security plus the
  enrolment channel*, not a specific slab of hardware. The signature
  counter is kept as a cloning tripwire, but synced passkeys
  legitimately report zero or non-incrementing counters, so it can
  catch clumsy cloning, never certify its absence.
- **Attestation `"none"` means we don't verify what the authenticator
  is.** Enrolment cannot distinguish a Secure Enclave from a software
  key in a browser extension. Demanding and verifying attestation buys
  little across today's platforms (most attest as anonymized batches or
  not at all) and costs enrolment friction; v0 takes the honest default
  and says so here instead of implying provenance checks that don't
  exist.
- **The app is served code.** A PWA is JavaScript from an origin; who
  controls the origin controls what the owner's screen *says*. WebAuthn
  keeps the private key safe from a hostile origin, and challenge
  binding means the server-side subject is what gets approved — but the
  *rendering* of that subject ("merge PR #7") is app code, and a lying
  app can caption approval A with description B, or show "veto sent"
  and send nothing. The origin server joins the trusted computing base
  the moment the app is trusted with these decisions. WebAuthn signs
  challenges, not human-readable intent — there is no deployable
  transaction confirmation display on today's web platform. Mitigations
  (subresource integrity, a pinned native wrapper) are hardening work,
  listed and not shipped.
- **The cheap lane is symmetric crypto.** The control plane stores each
  device's HMAC secret, so a control-plane compromise can forge acks
  and vetoes — including the ack that flips silence to release. This is
  strictly less new exposure than it sounds: the threat model already
  ranks a compromised control plane as the serious failure (it owns
  kill state and the veto windows themselves — it doesn't need to forge
  an ack to lie about a window). The passkey lane is deliberately
  asymmetric so that same compromise cannot sign approvals or GO 2:
  the server holds only public keys.
- **One owner, 1-of-N devices, no quorum.** Any single enrolled
  device's passkey approves and restores. Multi-owner and N-of-M
  confirmation are future, visible design changes.
- **Nothing in this PR delivers anything.** This is a design and a
  static shell. Until the control-plane additions in §5 and the push
  dispatcher exist, `markDelivered()` still has no production caller
  and the TODO(passkey) still stands. This document is the contract
  they will be built against, not a claim that they work today.

## 5. Control-plane additions this requires

Listed here so each can be scoped and reviewed separately — none are
implemented in this PR. The app's `src/types.ts` carries the request
and response shapes.

| # | addition | route | auth | what it does |
| --- | --- | --- | --- | --- |
| 1 | delivery ack | `POST /veto/:id/seen` | device HMAC | the production caller of `markDelivered()`. Idempotent; records `deviceId`, surface, and rendered-at in the audit trail; 404 on unknown window |
| 2 | device-signed veto relay | `POST /veto/:id` (extended) | device HMAC **or** owner session | one-tap veto without a live session; `vetoedBy` resolves to the enrolled device's `ownerId`, audit records the device |
| 3 | window detail for rendering | `GET /veto/:id` (extended) | device HMAC for detail | adds `deadline`, `delivered`, and the call summary — for device-signed callers only. The existing open read stays status-only: what an alert says is for enrolled devices, not for anyone who can reach the port (same disclosure discipline as the `/status` `epoch` note) |
| 4 | enrolment: invite | `POST /devices/invite` | owner session (host-local for bootstrap and lost-phone recovery) | single-use, short-TTL invite + WebAuthn creation challenge |
| 5 | enrolment: enroll | `POST /devices/enroll` | invite token | verifies registration, stores `EnrolledDevice`, provisions the per-device HMAC secret (returned once) |
| 6 | enrolment: list / revoke | `GET /devices`, `POST /devices/:id/revoke` | owner session (host-local revoke fallback) | inventory and the kill switch for a device's standing |
| 7 | push subscription upsert | `PUT /devices/:id/push-subscription` | device HMAC | stores/refreshes the Web Push subscription |
| 8 | assertion challenge | `POST /assert/challenge` | device HMAC | mints a single-use challenge bound to `{purpose, subjectId}`, TTL ~2 min |
| 9 | passkey-gated sessions | `POST /session` | verified assertion (`purpose: "session"`) | replaces in-process minting — closes `TODO(passkey)` in `auth.ts` |
| 10 | GO 2 hardening | `POST /restore` (extended) | owner session **+** verified assertion (`purpose: "restore-go2"`, `subjectId` = ceremony id) | GO 2 stops accepting the bearer token GO 1 already saw |
| 11 | alert dispatcher | (not a route) | — | the process that actually web-pushes on window register/extend: VAPID key custody, fan-out to enrolled devices, retry/TTL. Needs its own design; send-failure feeds back into nothing, because the window's fail-closed path already covers silence |

The approve lane's confirm endpoint is deliberately absent: the control
plane has no server-side approval queue yet. When it exists, its
confirmation takes the same bound assertion with `purpose: "approve"` —
the shape is already in `src/types.ts` so that design can start from
this contract.

## 6. In this PR / not in this PR

**In:** this document; `src/types.ts` — the wire types for enrolment,
the alert payload, the ack, the veto tap, and the bound assertion,
plus the endpoint contract above as data; a static installable shell
(`public/index.html`, `manifest.webmanifest`) showing the alert /
approve / restore / devices views with placeholder data and every
live control disabled; a service-worker stub (`public/sw.js`) whose
push and notification handlers document the real flow and perform
none of it.

**Not in:** VAPID keys or any push sending or receiving; WebAuthn
ceremony code (no `navigator.credentials` calls); any control-plane
change (every route in §5 lands in its own scoped PR); any network
call from the app at all; icons beyond a placeholder; multi-owner,
quorums, native wrappers, attestation verification.
