# Owner app — the phone in the loop

**The only surface that can report an alert was rendered on a device the
owner enrolled, and the only one that can carry a passkey — so it
unblocks two things at once.**

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
   device (§2), the same cheap signed-request shape the physical
   button already uses, because stopping must never acquire friction.
2. **The ack.** The moment the summary is actually rendered on the
   enrolled device, the app reports it: `POST /veto/:id/seen`,
   device-signed. That is the production caller `markDelivered()` has
   been waiting for. From then on the window's silence carries the most
   meaning web push can give it — *the alert was rendered where the
   owner should have seen it, and no objection came* — instead of
   "nobody was listening". The server accepts an ack only while the
   window is still open on the server's own clock (§4); §4 also states
   exactly how much an accepted ack proves — it is less than it sounds.
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
   operator stands — and the phone opens it over HTTPS. The token rides
   in the URL **fragment**, never the query string or path: fragments
   are not sent to the server, so the secret stays out of access logs —
   and out of the `Referer` header the app's own asset loads (icon,
   manifest, service worker) would otherwise attach. The app reads it,
   immediately clears it with `history.replaceState`, is served with
   `Referrer-Policy: no-referrer` as a second fence, and spends it in a
   POST body. No invite token is ever written to a log on either end.
2. **Credential creation.** The phone calls
   `navigator.credentials.create()` against the invite's challenge:
   platform authenticator, `userVerification: "required"`,
   `residentKey: "preferred"`, attestation `"none"` (a deliberate
   choice, stated plainly in §4).
3. **Verification and storage.** The control plane verifies the
   challenge, origin and rpId in `clientDataJSON`, and only on a fully
   successful registration burns the invite — atomically, exactly once:
   two racing spends of the same token admit at most one device. A
   failed or malformed attempt does not consume the invite, so a
   stranger's garbage cannot burn the capability the owner is holding
   mid-enrolment. (The flip side is accepted: an intercepted invite
   stays spendable until its TTL — one more reason the TTL is short.)
   On success the control plane stores the `EnrolledDevice` record:
   credential id, COSE public key, signature counter, transports,
   device name, `ownerId`, `enrolledAt`, and a **revocation
   generation** starting at 0 — the counter that makes revocation mean
   something (below).
4. **Cheap-lane credential, with proof of possession.** In the same
   ceremony the app generates a *second*, non-exportable WebCrypto
   keypair (ECDSA P-256, `extractable: false`) for the cheap direction
   — ack, veto tap, detail reads — and registers its public key
   alongside the passkey's. The request also carries a **proof of
   possession**: a signature, under the new key, over a
   domain-separated transcript — the protocol label
   (`ownerswitch/enroll-cheap-lane/v1`), the invite id, the owner id,
   the WebAuthn credential id, and the SPKI key bytes themselves, each
   field length-prefixed so the encoding is injective (the same lesson
   as the dot-ambiguity guard in `auth.ts`). The server verifies the
   proof with the submitted key **before the invite is consumed**: a
   key the client cannot sign with is refused, and the invite
   survives. A root-of-trust ceremony must not accept a dead
   credential — an unusable key would quietly turn every future window
   into the unreachable-owner path: denial rather than escalation, but
   a broken enrolment all the same. There is **no HMAC fallback and no
   client-selectable mode** — the next paragraph is why.
5. **Push subscription.** After notification permission is granted, the
   app registers its Web Push subscription
   (`PUT /devices/:id/push-subscription`, device-signed) and re-upserts
   it on `pushsubscriptionchange`. The subscription's `endpoint` is an
   attacker-influenceable URL the dispatcher will later call — it is
   validated as such (§5, rows 7 and 11), never trusted as a plain
   string.

**One key mode, and the server chooses it — by having no mode to
offer.** An earlier draft made the non-exportable key "preferred" with
a per-device HMAC fallback. That handed the attacker the downgrade:
enrolment runs through served code, so an origin already hostile at
enrolment time would simply omit the key, be handed a raw exfiltratable
secret, and keep forging acks forever — even after the origin was
cleaned up. Binding an allowed mode to the invite would fix the
negotiation, but would keep the raw-secret path, the server-side
symmetric storage, and the permanent-theft caveat alive for the sake of
platforms that do not exist: this app's floor is already an installed
PWA with a service worker, Web Push, and a WebAuthn platform
authenticator, and every engine in that intersection also holds
non-exportable WebCrypto keys. So v0 ships the simpler rule:
`cheapLaneKey` is **required**, the server **refuses** any enrolment
without a valid key and its proof of possession, and a platform that
cannot hold one **fails closed at enrolment** — it never becomes an
enrolled device, instead of silently becoming the weakest one. (The
physical button keeps its HMAC: a different device class, provisioned
offline, its secret never exposed to web-served code — the app shares
the button's request shape, not its key type.) One honest cost:
browsers may evict IndexedDB storage under pressure, and an evicted
key is a device that silently stops acking — fail closed, extend →
`held` — until re-enrolment; `navigator.storage.persist()` at install
time is part of the real app's flow.

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
from the control-plane host itself — and **not through any HTTP
route**. Bootstrap and no-devices-left recovery are a local CLI (or a
Unix domain socket protected by filesystem permissions, owner-only
like the kill-state directory). There is deliberately no HTTP loopback
exception: behind a same-host reverse proxy every remote caller
*looks* local — the exact caveat already known on `/kill`'s loopback
fallback — and enrolment, unlike kill, is the expensive direction, so
it gets no such door. Deployment constraint, stated explicitly: if a
reverse proxy or any forwarder runs on the control-plane host,
"host-local" must mean the socket's file permissions or process
identity, never a source address.

The bootstrap lane also **self-closes**: host-local invite minting is
allowed only while *zero* active devices are enrolled — the genuine
first boot, and the lost-every-phone recovery case after a host-local
revoke. The moment one active device exists, every invite demands an
owner session, which demands an enrolled device: host access → first
device → everything else. (The host CLI can always *revoke* — that is
the safe direction, and whoever holds the host already holds the
deployment boundary.) Minting the first invite is the same trust the
system already runs on today — session minting is in-process, flagged
in `auth.ts`; enrolment doesn't add that assumption, it makes it
explicit and *bounded in time*. The control-plane host is, and
remains, the recovery root — the same deployment boundary the threat
model already names for kill state.

### Revocation, two devices, the lost phone

- **Revoke:** `POST /devices/:id/revoke`, owner session required.
  Revocation bumps the device's **revocation generation** and, in the
  same atomic step, invalidates everything minted under it: the
  cheap-lane key verifies nothing, the passkey
  credential is removed, the push subscription is dropped, **every
  owner session the device minted dies, and every outstanding
  assertion challenge it requested is void**. Sessions make this
  checkable: a session records the `deviceId` that minted it and that
  device's generation at mint, and *every* session check re-verifies
  that the device is still enrolled and its generation unchanged —
  a session is never trusted on its own token again. So "dies
  immediately" means precisely this: the next request authenticated by
  *any* artifact of the revoked device — signature, session, or
  challenge — fails. Without the session↔device binding, a stolen
  phone that minted a session five minutes before revocation could
  keep minting invites and starting GO 1 until the token expired; with
  it, revocation cuts that off at the next request. Two honest bounds:
  a request already past its auth check when revocation lands may
  still complete (one process, one event loop — the same single-spend
  honesty as the restore ceremony), and an ack or veto already
  *accepted* is not recalled — a veto is a stop, and an ack on a
  still-open window is answered by vetoing from a surviving device.
- **Two devices:** each enrolls independently — own invite, own
  passkey, own cheap-lane key, own subscription. Alerts fan out to every
  enrolled device; the *first* render acks; any device can veto; any
  single device's passkey satisfies approve and GO 2 (1-of-N in v0 —
  an N-of-M quorum is a visible future change, not an accidental
  default). A second device is the recommended recovery path: lose one
  phone, revoke it from the other.
- **Lost only phone:** the owner cannot mint a session (post-passkey,
  sessions require an enrolled device), so recovery goes through the
  root: at the control-plane host — CLI or permission-protected Unix
  socket, never an HTTP route (see Bootstrap above) — revoke the lost
  device; with zero active devices left, the bootstrap lane reopens
  and mints a fresh invite. Deliberately no remote self-service
  recovery — a recovery path cheaper than enrolment would *be* the
  attack surface.
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
| ack (`/veto/:id/seen`) | device signature | none | window id |
| veto tap | device signature | none | window id |
| read window detail | device signature | none | window id |
| approve an action | fresh WebAuthn assertion | **required** | that approval id |
| GO 2 of restore | fresh WebAuthn assertion | **required** | that ceremony id |
| mint owner session | fresh WebAuthn assertion | **required** | session mint |

**Cheap lane.** The ack and the veto are device-signed requests the app
can send in one tap — from the service worker's notification action,
without waking WebAuthn UI, without a live session. The request shape
is the physical button's — a signature over the exact bytes on the
wire, a single-use nonce, a timestamp — with the signature computed
under the device's non-exportable cheap-lane key (§2); the button
keeps its own HMAC scheme, and the app shares its request shape, not
its key type. Same shape for the same reason the
button is cheap: the stop direction must survive friction, dead
sessions, and a sleepy owner. The veto relay is also **idempotent** —
re-vetoing an already-vetoed window succeeds as a no-op — so a service
worker can blind-retry a send it cannot prove arrived (§5, row 2).

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
from the second device or the host, not anything this app can do —
and revocation now actually severs the phone (§2): every session it
minted and every challenge it requested dies with its generation, so
it cannot go on minting invites or starting GO 1 on a session it
opened before it was taken.

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
  *without acking*: the device rendered that something is pending, but
  since the owner could not judge *what*, silence must not release it.
  Fail-closed on partial delivery.
- **A late ack changes nothing.** The server accepts an ack only while
  the window is still `pending` or `extended` **on the server's own
  clock**, and only from a device enrolled to the window's owner. The
  client-supplied `renderedAt` is audit data, never enforcement — the
  server's receive time and the window's live state decide. After the
  deadline, or in any terminal state, an ack is recorded in the audit
  trail and **ignored**: a delayed or backdated ack must never flip
  `markDelivered()` after the fact and let the next tick read past
  silence as consent. That is the fail-open direction this whole lane
  exists to avoid, so the deadline check belongs to the server, not to
  anything the phone asserts.
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
- **The app is served code — and an origin compromise steals keys, not
  just pixels.** A PWA is JavaScript from an origin; who controls the
  origin controls what the owner's screen *says*. WebAuthn keeps the
  passkey's private key safe from a hostile origin, and challenge
  binding means the server-side subject is what gets approved — but the
  *rendering* of that subject ("merge PR #7") is app code, and a lying
  app can caption approval A with description B, or show "veto sent"
  and send nothing. WebAuthn signs challenges, not human-readable
  intent — there is no deployable transaction confirmation display on
  today's web platform. And the UI lie is the *smaller* half. The
  cheap-lane credential lives where the PWA's JavaScript can use it, so
  an XSS, a compromised third-party script, or a hostile deploy forges
  acks and vetoes *as the device, remotely* — and a forged ack is the
  dangerous direction: it converts silence into release. If that
  credential were a raw secret readable from app storage, the theft
  would be **permanent** — fixing the origin would not un-steal the
  key. That is exactly why §2 ships no such mode: the cheap lane is a
  non-exportable WebCrypto key, full stop — with only public keys on
  the server and no extractable material on the device, hostile code
  is reduced to requesting signatures *while it runs on the owner's
  device* — bad, but bounded, observable, and revocable, not
  permanent.
  Requirements, not suggestions: the owner app lives on a **dedicated
  origin** that serves nothing else, with a strict Content-Security-
  Policy and **zero third-party script**; and an origin compromise is
  treated as compromise of *every* enrolled device — revoke them all,
  rotate every credential, re-enrol. The residual limit, stated
  plainly: no key design stops malicious code from asking a
  non-exportable key to sign while that code is resident on the
  device. Subresource integrity and a pinned native wrapper are
  further hardening, listed and not shipped.
- **No HMAC fallback is a security decision, not an omission.** A
  client-selectable key mode is attacker-negotiated: hostile served
  code would pick the downgrade at enrolment and walk away with a raw
  secret (§2 states the full argument). With one mode, the control
  plane stores only public keys for both lanes, so a control-plane
  compromise can deny and lie — it owns kill state and the veto
  windows themselves, so it never needed to forge an ack to lie about
  a window — but it cannot *sign*: not approvals, not GO 2, not acks.
  The one symmetric secret left in the system is the physical
  button's, provisioned offline and never exposed to web code.
- **One owner, 1-of-N devices, no quorum.** Any single enrolled
  device's passkey approves and restores. Multi-owner and N-of-M
  confirmation are future, visible design changes.
- **Nothing in this PR delivers anything.** This is a design and a
  static design scaffold — not a served, installable app (§6). Until
  the control-plane additions in §5 and the push dispatcher exist,
  `markDelivered()` still has no production caller and the
  TODO(passkey) still stands. This document is the contract they will
  be built against, not a claim that they work today.

## 5. Control-plane additions this requires

Listed here so each can be scoped and reviewed separately — none are
implemented in this PR. The app's `src/types.ts` carries the request
and response shapes.

| # | addition | route | auth | what it does |
| --- | --- | --- | --- | --- |
| 1 | delivery ack | `POST /veto/:id/seen` | device signature | the production caller of `markDelivered()` — accepted only while the window is `pending`/`extended` on the **server's** clock, and only from a device enrolled to the window's owner; `renderedAt` is audit data, never enforcement; a late ack is recorded and ignored. Idempotent; 404 on unknown window |
| 2 | device-signed veto relay | `POST /veto/:id` (extended) | device signature **or** owner session | one-tap veto without a live session; `vetoedBy` resolves to the enrolled device's `ownerId`, audit records the device. Idempotent: re-vetoing an already-vetoed window succeeds as a no-op, so the service worker can retry blindly |
| 3 | window detail for rendering | `GET /veto/:id` (extended) | device signature for detail | adds `deadline`, `delivered`, and the call summary — for device-signed callers only; `status` speaks the shared wire vocabulary (`VetoWireStatus`, #28) including terminal `spent`. The existing open read stays status-only: what an alert says is for enrolled devices, not for anyone who can reach the port (same disclosure discipline as the `/status` `epoch` note) |
| 4 | enrolment: invite | `POST /devices/invite` | owner session — bootstrap and no-devices-left recovery mint via the host CLI / permission-protected Unix socket (§2), **never** an HTTP loopback bypass | single-use, short-TTL invite + WebAuthn creation challenge; token delivered in the URL fragment, spent in a POST body, never logged |
| 5 | enrolment: enroll | `POST /devices/enroll` | invite token | verifies the WebAuthn registration **and** the cheap-lane proof of possession (signature over the domain-separated enrolment transcript, checked with the submitted key *before* the invite is consumed), registers both lanes' public keys, stores `EnrolledDevice`. `cheapLaneKey` is required — no HMAC mode exists to fall back to (§2). The invite burns atomically and **only on success** — a failed attempt, including a failed proof, does not consume it |
| 6 | enrolment: list / revoke | `GET /devices`, `POST /devices/:id/revoke` | owner session (host CLI / Unix socket can always revoke) | inventory, and the kill switch for a device's standing: revoke bumps the revocation generation and atomically voids the device's credentials, push subscription, **live sessions, and outstanding challenges** (§2) |
| 7 | push subscription upsert | `PUT /devices/:id/push-subscription` | device signature | stores/refreshes the Web Push subscription. The `endpoint` is an SSRF surface and is validated at write: HTTPS only, known push-service endpoint shapes, and rejection of localhost, private, link-local, and metadata addresses |
| 8 | assertion challenge | `POST /assert/challenge` | device signature | mints a single-use challenge bound to `{purpose, subjectId}`, TTL ~2 min; challenges record the minting device's revocation generation and die with it (§2) |
| 9 | passkey-gated sessions | `POST /session` | verified assertion (`purpose: "session"`) | replaces in-process minting — closes `TODO(passkey)` in `auth.ts`. The minted session records `deviceId` + revocation generation, and every session check re-verifies the device is still active (§2) |
| 10 | GO 2 hardening | `POST /restore` (extended) | owner session **+** verified assertion (`purpose: "restore-go2"`, `subjectId` = ceremony id) | GO 2 stops accepting the bearer token GO 1 already saw |
| 11 | alert dispatcher | (not a route) | — | the process that actually web-pushes on window register/extend: VAPID key custody, fan-out to enrolled devices, retry/TTL. It re-validates every `endpoint` at send time — the checks from row 7 again, **after DNS resolution as well as before**, plus no redirect following and hard size/timeout caps — because a stored-then-repointed hostname is the classic SSRF. Needs its own design; send-failure feeds back into nothing, because the window's fail-closed path already covers silence |

**Wire-status alignment with #28.** `GET /veto/:id` speaks
`VetoWireStatus`: the state machine's five states plus `spent` — the
status a would-be release reports when the window's recorded kill
epoch is no longer current, because a kill (even one later restored)
happened after registration. `spent` is **terminal on this surface**:
not ackable (the ack rule accepts only `pending`/`extended`, and
`spent` is neither), not a release, not reusable. The app renders it
as *"this review expired after a kill"* — and the action needs a fresh
owner review, a new window or an approval as the gateway decides,
never a resurrection of this window id. A delayed push arriving after
a kill-then-restore therefore lands on a status the app can represent
honestly instead of one it cannot parse.

The approve lane's confirm endpoint is deliberately absent: the control
plane has no server-side approval queue yet. When it exists, its
confirmation takes the same bound assertion with `purpose: "approve"`,
and it must be built against this contract: **an approval record is
immutable once created**, and it carries a canonical action hash —
over connector, operation, `canonicalArgs`, `resourceId`,
`policyVersion`, and `killEpoch`, the `ActionTicket` vocabulary of
`packages/executor/DESIGN.md` — computed at creation. The assertion
challenge for `purpose: "approve"` binds `{purpose, subjectId, that
action hash}` server-side, so the passkey signs the exact action the
owner was shown, not a mutable id that could be repointed between
render and confirm. Confirm re-verifies that the record still matches
its hash and that the kill epoch is still current before anything
executes; a record that changed, or an epoch that moved, gets the same
generic refusal as every other failed check. The shapes are already in
`src/types.ts` so that design can start from this contract.

## 6. In this PR / not in this PR

**In:** this document; `src/types.ts` — the wire types for enrolment,
the alert payload, the ack, the veto tap, and the bound assertion,
plus the endpoint contract above as data; a **static design scaffold**
(`public/index.html`, `public/app.css`, `public/app.js`,
`manifest.webmanifest`) showing the alert / approve / restore /
devices views with placeholder data and every live control disabled —
styles and script live in separate files so the strict CSP §4 requires
(`script-src 'self'; style-src 'self'`, no `unsafe-inline`) is
achievable without rework; a service-worker stub (`public/sw.js`)
whose push and notification handlers document the real flow and
perform none of it. Called a design scaffold on purpose: the
repository provides no supported install path — manually serving
`public/` over HTTPS or localhost may register the no-op service
worker, but what results is not a functional OwnerSwitch app; it is
the views and the contract.

**Not in:** VAPID keys or any push sending or receiving; WebAuthn
ceremony code (no `navigator.credentials` calls); any control-plane
change (every route in §5 lands in its own scoped PR); any network
call from the app at all; a dev server, build step, or any way to
actually install this — real installability needs a served origin and
real PNG icons including the `apple-touch-icon` iOS requires before
home-screen install (and therefore before iOS push); multi-owner,
quorums, native wrappers, attestation verification.
