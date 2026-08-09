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
phone that (1) renders open veto windows and reports the render, (2)
carries the one-tap VETO, and (3) holds the WebAuthn passkey that the
approve lane and GO 2 will demand. This PR is the design and a static
scaffold — types, shell, service-worker stub. No push infrastructure, no
WebAuthn ceremony code, no control-plane change ships here.

## 1. What it must do

Three jobs, one per lane of the asymmetry:

1. **The stop path.** A web push arrives for an open veto window — a
   call being held for the owner. The service worker renders a
   notification with the concrete action summary — agent, tool, what
   it's about to do, when silence releases it. VETO stops it: one
   labelled tap where the platform honours notification actions, tap-
   then-tap where it doesn't (§3). No biometric, no session dance: the
   veto is always device-signed (§2) — on iOS the tap opens the app,
   the key becomes foreground-accessible, and the veto goes out signed
   (§3) — because stopping must never acquire meaningful friction.
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

1. **Install first.** An installed Home Screen PWA gets a **separate
   storage partition** from the browser tab that installed it — a key
   generated in Safari before install is simply absent inside the
   installed app. So the order is fixed: install the app to the Home
   Screen, launch the *installed* app, and do everything below inside
   it. The invite is handed off *into* the installed app — its in-app
   QR scanner or a typed code (the typed form is an *encoding* of the
   full token, grouped for human entry, never a truncation: the full
   ≥128 bits of invite entropy either way) — never by navigating a
   URL, which
   would land the token in the wrong partition (and, on iOS, in a
   browser that cannot receive push at all). An invite URL opened in a
   browser renders install instructions only.
2. **Invite.** An enrolment invite is minted server-side:
   `POST /devices/invite`, requiring an owner session **plus a fresh
   UV assertion** with `purpose: "device-invite"` (§3 — a stolen
   bearer token alone must not be able to add a device). The invite is
   a single-use CSPRNG token (≥128 bits), TTL ~10 minutes, bound to
   the `ownerId` that minted it, and its server-side record stores the
   **issuing device's `{deviceId, revocationGeneration}`** — re-checked
   atomically when the invite is spent, so revoking the issuer voids
   its outstanding invites. The invite carries the full WebAuthn
   creation contract: the RP (`rpId`, `rpName`), a **complete user
   entity** — an opaque CSPRNG `user.id` (stable per owner, never PII)
   plus display-only `name` and `displayName` — `pubKeyCredParams` as
   proper descriptors, pinned to `[{type: "public-key", alg: -7}]`
   (ES256 only), and the authenticator-selection contract
   `{authenticatorAttachment: "platform", residentKey:
   "preferred", userVerification: "required"}`. Where the invite takes
   URL form at all, the token rides in the **fragment** only (never
   query or path — fragments stay out of access logs and `Referer`),
   is cleared with `history.replaceState` on read, is served under
   `Referrer-Policy: no-referrer`, and is spent in a POST body. No
   invite token is ever written to a log on either end.
3. **Credential creation.** Inside the installed app, the phone calls
   `navigator.credentials.create()` against the invite's challenge and
   contract from step 2. Attestation stays `"none"` (a deliberate
   choice, stated plainly in §4).
4. **Cheap-lane key, persistence test, proof of possession.** The app
   generates a *second* WebCrypto keypair (ECDSA P-256) whose private
   key is created **non-extractable** (`extractable: false`) — a
   property §4 prices precisely, because the server cannot verify it.
   Before enrolment is submitted, the app runs a **persistence test**:
   generate → commit the key to IndexedDB (after
   `navigator.storage.persist()`) → close and reopen the context →
   retrieve → produce a test signature **from the service worker**.
   Only when that round-trip succeeds is the enrolment request sent —
   a key that cannot be retrieved where it will actually be used would
   enrol a device that silently never acks. (The test is app-side
   discipline: the server cannot verify where a signature was made;
   what the server verifies is the proof of possession.) The request
   carries the SPKI public key and the **proof of possession**, pinned
   exactly: ECDSA on P-256 with SHA-256, signature in WebCrypto's raw
   IEEE P1363 `r||s` form (64 bytes, two 32-byte big-endian integers —
   **not** DER), transported base64url (RFC 4648 §5, no padding). The
   signed transcript is the concatenation of length-prefixed fields —
   each prefixed by a 4-byte big-endian unsigned byte count — in this
   order: the UTF-8 label `ownerswitch/enroll-cheap-lane/v1`, the
   UTF-8 `inviteId`, the UTF-8 `ownerId`, the **raw bytes** of the
   WebAuthn credential id (base64url-decoded), and the **raw bytes**
   of the SPKI key. Length-prefixing keeps the encoding injective —
   the same lesson as the dot-ambiguity guard in `auth.ts`. There is
   **no HMAC fallback and no client-selectable mode** — the paragraph
   after this list is why.
5. **Verification and storage.** The control plane verifies, in the
   right places: `type`, `challenge`, and `origin` live in
   `clientDataJSON`; `rpIdHash` and the **UP and UV flags** live in the
   authenticator data *inside the attestation object*; the credential's
   algorithm must be ES256 (COSE `-7`) on P-256. It verifies the proof
   of possession with the submitted key, re-checks the invite's issuing
   device is still active at its recorded generation (or, for a
   bootstrap invite, that there are still **zero** active devices and
   the invite's bootstrap generation is current), and only on a fully
   successful registration burns the invite — atomically, exactly once:
   two racing spends admit at most one device, a failed or malformed
   attempt (including a failed proof) consumes nothing, and a
   stranger's garbage cannot burn the capability the owner is holding
   mid-enrolment. (The flip side is accepted: an intercepted invite
   stays spendable until its TTL — one more reason the TTL is short.)
   On success the control plane stores **one** `EnrolledDevice` record
   holding *both* credentials — the WebAuthn credential and the
   cheap-lane public key belong to the same record, governed by the
   same revocation generation, so revocation severs one identity, not
   half of two. The record: credential id, COSE public key, cheap-lane
   SPKI key, signature counter, transports, device name, `ownerId`,
   `enrolledAt`, and a **revocation generation** starting at 0.
6. **Push subscription.** After notification permission is granted, the
   app registers its Web Push subscription
   (`PUT /devices/:id/push-subscription`, device-signed). The `:id` is
   taken from the **authenticated identity** — the signing device — and
   a mismatched path id is rejected; one device can never write another
   device's subscription. Re-upserted on `pushsubscriptionchange`. The
   subscription's `endpoint` is an attacker-influenceable URL the
   dispatcher will later call — it is validated as such (§5, rows 7 and
   11), never trusted as a plain string.

**One key mode, and the server chooses it — by having no mode to
offer.** An earlier draft made the key mode "preferred" with a
per-device HMAC fallback. That handed the attacker the downgrade:
enrolment runs through served code, so an origin already hostile at
enrolment time would simply omit the key, be handed a raw exfiltratable
secret, and keep forging acks forever — even after the origin was
cleaned up. Binding an allowed mode to the invite would fix the
negotiation, but would keep the raw-secret path, the server-side
symmetric storage, and the permanent-theft caveat alive for the sake of
platforms that do not exist: this app's floor is already an installed
PWA with a service worker, Web Push, and a WebAuthn platform
authenticator, and every engine in that intersection also supports
non-extractable WebCrypto private keys. So v0 ships the simpler rule:
`cheapLaneKey` is **required**, the server **refuses** any enrolment
without a valid key and its proof of possession, and a platform that
cannot hold one **fails closed at enrolment** — it never becomes an
enrolled device, instead of silently becoming the weakest one. (The
physical button keeps its HMAC as a **distinct server-side credential
class** — §3; the app shares the button's header discipline, never its
key type or its authority.)

**What public-key mode actually buys — stated precisely, because an
earlier draft overclaimed it.** The vocabulary, used consistently from
here on: *non-extractable private key, exportable SPKI public key*.
The server sees only the public key and a proof of possession; it
**cannot verify non-extractability** — a hostile origin at enrolment
can generate an extractable key, or import the attacker's own, and
still produce a valid proof. And even a genuinely non-extractable
`CryptoKey` is **structured-cloneable**: injected script can
`postMessage` the key object to another context and hand the *signing
capability* away without ever seeing key bytes. So the honest claim is
this: public-key mode removes the server-side shared secret (a
control-plane compromise cannot sign acks), and it prevents byte-level
key export **under honest code**. It does **not** prevent persistent
impersonation after a hostile enrolment or an origin compromise — only
**revocation and re-enrolment** sever that. Two honest costs close
this out: browsers may evict IndexedDB under storage pressure, and an
evicted key is a device that silently stops acking — fail closed,
extend → `held` — until re-enrolment (`navigator.storage.persist()`
and the step-4 persistence test are the mitigations); and no key
design stops code resident on the device from asking the key to sign
while it runs.

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
revoke. Bootstrap invites additionally carry a **bootstrap
generation**: spending one re-verifies *at spend time* that there are
still zero active devices and that the invite's generation is current,
and the first successful bootstrap enrolment bumps the generation —
**invalidating its sibling invites** — so a batch of bootstrap invites
can never admit a second, unnoticed device. The moment one active
device exists, every invite demands an owner session **plus a
device-invite assertion** (step 2), which demands an enrolled device:
host access → first device → everything else. (The host CLI can always
*revoke* — that is the safe direction, and whoever holds the host
already holds the deployment boundary.) Minting the first invite is
the same trust the system already runs on today — session minting is
in-process, flagged in `auth.ts`; enrolment doesn't add that
assumption, it makes it explicit and *bounded in time*. The
control-plane host is, and remains, the recovery root — the same
deployment boundary the threat model already names for kill state.

### Revocation, two devices, the lost phone

- **Revoke:** `POST /devices/:id/revoke` — owner session **plus a
  fresh UV assertion** (`purpose: "device-revoke"`, subject = the
  target device id) for remote revocation; the host CLI / socket can
  always revoke with neither. (A bare stolen session must not be able
  to mass-revoke every device and sever the owner — that fails closed,
  but it is a lockout whose only exit is host recovery, so it costs an
  assertion. The host path keeps revocation's floor: whoever holds the
  host already holds the deployment boundary.) Revocation bumps the
  device's **revocation generation** and, in the same atomic step,
  invalidates everything minted under it: the cheap-lane key verifies
  nothing, the passkey credential is removed, the push subscription is
  dropped, **every owner session the device minted dies, every
  outstanding assertion challenge it requested is void, every
  unspent invite it issued is void, its outstanding deliveries are
  void, and its ack evidence stops counting toward release (§4)**. Sessions make this checkable: a
  session records the `deviceId` that minted it and that device's
  generation at mint, and *every* session check re-verifies that the
  device is still enrolled and its generation unchanged — a session is
  never trusted on its own token again. So "dies immediately" means
  precisely this: the next request authenticated by *any* artifact of
  the revoked device — signature, session, challenge, or invite —
  fails. Without the session↔device binding, a stolen phone that
  minted a session five minutes before revocation could keep acting
  until the token expired; with it, revocation cuts that off at the
  next request. Two honest bounds: a request already past its auth
  check when revocation lands may still complete (one process, one
  event loop — the same single-spend honesty as the restore ceremony),
  and a veto already accepted is not recalled — a veto is a stop, and
  stays irreversible.
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
can send in one tap — without waking WebAuthn UI, without a live
session — under the device's cheap-lane key (non-extractable private
key, §2). The app shares the button's *header discipline* — a
single-use nonce, a timestamp, a signature — but its signed preimage
is deliberately richer, because the button's dot-joined
`deviceId.timestamp.nonce.body` shape does not bind an empty-body
`GET /veto/:id` to that id at all. The app's preimage is the
concatenation of length-prefixed fields (4-byte big-endian byte
counts, injective by construction): the UTF-8 label
`ownerswitch/device-sig/v1`, the `deviceId`, the upper-case HTTP
method, the request path **and query exactly as sent** (byte-exact,
percent-encoding preserved), the **SHA-256 of the exact body bytes**
(the empty body hashes as zero bytes — so a body-less GET is still
bound), the decimal timestamp, and the nonce. Signature: ECDSA P-256
with SHA-256, raw `r||s`, base64url — the same pinning as the
enrolment proof (§2). Cheap for the same reason the button is cheap:
the stop direction must survive friction, dead sessions, and a sleepy
owner. The veto relay is also **idempotent** — re-vetoing an
already-vetoed window succeeds as a no-op — so a service worker can
blind-retry a send it cannot prove arrived (§5, row 2).

**The button is a different credential class, and the server knows
it.** The physical button's HMAC secret remains exactly what it is
today — offline-provisioned, kill-and-alert only. Server-side, every
signing credential belongs to a **server-recorded class** — `button`
or `owner-device` — and the class decides authority: a button-class
credential is **never** accepted for `/veto/:id/seen`, window detail
reads, `/assert/challenge`, or push-subscription writes, whatever the
request claims. The record decides the class; no client field ever
does.

### The iOS cold path

WebKit's cold-start defect (bug 283793) is a product-defining
constraint: in a service worker woken **cold** by a background push,
`indexedDB` can be `undefined` — the key store itself is unreachable,
so the worker cannot device-sign anything. The payload therefore
carries what a keyless worker needs to be *useful*:

- **The renderable summary rides in the encrypted payload.**
  `OwnerAlertPush` carries the agent, tool, summary text, status,
  deadline, and the delivery coordinates (next subsection) — the
  notification renders from the payload alone, no fetch required.
  RFC 8291 encryption means this widens nothing in transit; at rest it
  is exactly what the notification was going to display anyway. The
  dispatcher enforces RFC 8291's **3993-byte plaintext ceiling**: a
  summary that would not fit is sent as a generic alert instead, and a
  generic or truncated render never acks (§4). What payload capture
  gains an attacker is exactly one window's summary — information
  disclosure, identical to the device's own lock screen — and **no
  authority of any kind**.
- **No capability rides beside it — dropped from v0 deliberately.** An
  earlier revision carried a single-use, veto-only capability so a
  keyless cold worker could still stop. The fourth review made the
  decisive observation: it has **no consumer**. On iOS there are no
  notification action buttons, so the only possible gesture is the
  plain tap — which opens the app, where the key is
  foreground-accessible and the veto goes out *signed*. On platforms
  that do honour action buttons, the worker can reach the key anyway.
  A payload-borne authority with no consumer is pure attack surface to
  design, review, and maintain; least authority wins. If a platform
  ever ships an action button that fires while storage is unreachable,
  the capability comes back **with its own design** — its bounds
  argued then, not inherited silently.

**What iOS gets in v0, plainly:** a cold notification showing the
concrete action; a tap that opens the app; a **signed** veto — and, if
the window is still open, a signed ack — from the foreground. No
automatic ack on the cold path: an alert the owner never touches runs
extend → `held`. Friction, not permission — silence releases only when
a warm context or a human actually engaged, which is the reachability
rule doing its job.

**Click handoff carries no secrets and trusts no URL.**
`PushEvent.data` does not survive to `notificationclick`, so the
worker copies `{windowId, revision, deliveryId, expiry}` into
`NotificationOptions.data` — which the standard persists on the
notification — and reads it back in the click handler. Nothing rides
in the navigation URL: launch URLs leak into history and logs, and
anything that can open a URL could forge one. And because some iOS
versions launch only the manifest root or lose the click handoff
entirely, the app never assumes it knows *why* it opened: a
root-launched app calls the device-signed reconciliation read
(`GET /veto`, §5 row 12), shows an **inbox** of open windows, and acks
only the ONE window actually rendered in front of the owner — never
the whole list.

**The veto gesture, per platform.** Notification action buttons
(`Notification.maxActions`, feature-detected) are honoured on Chromium
and not reliably on Safari. Where action buttons exist, VETO is a
labelled button on the notification — one deliberate gesture, signed
with the device key, which is reachable on exactly the platforms that
have the button. Where they don't (iOS), **the notification tap opens
the app on the alert view and the veto is a second, explicit tap** —
chosen over "the whole notification tap IS the veto" because a veto is
irreversible and notification taps are among the least intentional
gestures on a phone: a whole-tap veto would convert pocket taps and
read-attempts into permanent stops, train owners to distrust the
surface, and paralyze the veto lane with accidents. Two seconds of
extra friction on the stop is the price; the stop still needs no
session, no biometric, no typing.

### Versioned delivery — a stale render must never ack

The subtle fail-open is not iOS-specific: a **delayed** push for a
window's `pending` phase can arrive while the key *is* reachable —
after the window has already moved to `extended`. The device renders
an old status and an old deadline and signs an ack the server would
happily accept; silence then releases a review whose current form the
owner never saw. The fix is a versioned delivery contract:

- Every state the owner can be shown is a **`WindowRevision`** —
  `{windowId, revision, status, deadline, immutableActionHash}`. The
  revision increments on every status or deadline change; the action
  hash (the same canonicalization vocabulary as the approval hash, §5)
  never changes across revisions — one window, one action, many
  showings.
- Every time the server hands renderable content to a device — a push
  dispatch, a device-signed detail read, an inbox render — it mints a
  **`Delivery`**: `{deliveryId, windowId, revision, deviceId,
  deviceGeneration, payloadHash, expiresAt}`, where `payloadHash` is
  the SHA-256 of the exact bytes issued.
- An ack carries `{windowId, revision, deliveryId,
  renderedPayloadHash, renderedAt, surface}` and **counts only if all
  of these hold, judged by the server**: the revision is still the
  window's current open revision; the rendered payload hash equals the
  hash the server recorded for that delivery; the delivery belongs to
  the signing device at its current generation; the window is still
  `pending` or `extended`; and server time is before that revision's
  deadline. Anything else is recorded in the audit trail and ignored.
- **The warm path prefers the fetch.** A worker that can device-sign
  fetches the authoritative `VetoWindowDetail`, renders *that*, and
  acks the revision and delivery the fetch minted. A forged or
  replayed push therefore cannot turn the device into an ack-signing
  oracle: a countable ack must name a delivery the server itself
  issued, of content the server itself hashed, to this device at this
  generation.
- **Evidence is revision-scoped and inserted atomically.** An accepted
  ack is stored as evidence `{deviceId, deviceGeneration, revision,
  deliveryId, payloadHash, receivedAt}` — the full coordinates of what
  was actually shown, never a bare "seen" bit. Validation and
  insertion are **one serialized operation**: the insert
  compare-and-sets on the window's *current* revision, so an ack
  validated against revision 1 that races the transition to revision 2
  fails the CAS and is recorded-and-ignored — it can never be stored
  against a revision that was never rendered. Release, revision
  change, and revocation all operate on that same serialized window
  state, and release for revision N counts only evidence whose
  `revision == N` from a device still active at its recorded
  generation (§4).
- **A last-second ack must not release.** `serverNow < deadline` alone
  would let a notification landing five milliseconds before the
  deadline count as "the owner was reached and chose not to object" —
  when the owner had no chance to object at all, which inverts what
  the veto lane means. So valid delivery evidence additionally
  requires `receivedAt ≤ deadline − minVetoResponseMs`. The default is
  **60 seconds**, and here is why: it is enough to wake the screen,
  read a one-line summary, unlock, and tap VETO without rushing — a
  *decision* interval, where 5–15 s would be a reflex test — while
  staying small against the 4-minute window, so an on-time delivery
  still leaves the owner most of it; and it matches the 60 s
  skew/replay bound the device-signature scheme already uses, so the
  deployment reasons about one human-and-network latency budget, not
  two. The knob is server-side policy with a hard floor — never
  configurable to zero. An ack inside the final interval is stored as
  audit, ignored as evidence, and the window runs its fail-closed
  course — extend, then hold — where the extension re-alerts with a
  fresh revision and a fresh delivery, giving the owner a full
  response interval. Late delivery can only ever add friction, never a
  near-immediate release.

### Truthful rendering — the hash proves bytes, not truth

`textContent` stops markup injection (§4), and the payload hash proves
the device rendered the bytes the server issued — neither proves the
*human saw something true*. Agent-controlled text can still lie
typographically: Unicode bidirectional overrides can visually reorder
a summary so it reads as its own opposite, control characters can hide
a decisive suffix, an embedded newline can push the fact that matters
below an OS truncation fold — the class of attack catalogued in
**Unicode Technical Report #36**. So what the owner is shown is a
bounded canonical format, **`RenderableAlertV1`**, enforced where the
text is *minted*:

- **Per-field length limits** — `agentId` ≤ 64, `tool` ≤ 64, `summary`
  ≤ 200 Unicode code points — chosen so a conforming alert fits
  un-truncated inside common lock-screen budgets. If it fits by
  construction, "the OS cut off the decisive part" stops being an
  attack surface.
- **Control characters are rejected, not escaped**: all C0/C1
  controls, including CR, LF, and TAB — every field is a single line —
  and every explicit bidirectional embedding, override, and isolate
  control (LRE, RLE, LRO, RLO, PDF, LRI, RLI, FSI, PDI). The server
  refuses to mint a `WindowRevision` whose fields violate this; the
  client has nothing to sanitize, only to verify.
- **Bidi isolation at display**: the client renders each field in its
  own bidi isolate (CSS `unicode-bidi: isolate`; the scaffold does),
  so legitimate RTL text displays correctly but can never visually
  reorder *across* field boundaries.
- **No ack from a truncated render.** If any critical field was
  truncated or substituted at render time — an over-limit legacy
  value, a platform that cut the body anyway — the surface shows the
  generic alert and does not ack, like every other partial render
  (§4).

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

**Redeeming an assertion is atomic, and identity is one line.** A
verified assertion is a token, not a mood: the server verifies
cryptographically, then **atomically consumes the challenge and
performs exactly one protected mutation** — one invite minted, one
session, one restore, one approval executed. A device-invite assertion
raced on two connections mints one invite, not two; the loser gets the
generic refusal. The same single-spend rule governs session minting,
GO 2, and approval execution. And for the operations that change who
can act — `device-invite`, `device-revoke`, and GO 2 — the identity
line is checked end to end: the session's `deviceId`, the challenge's
issuing device, and the `EnrolledDevice` that owns the asserting
credential must be the **same record at the same generation**, and the
challenge names the paired credential in `allowCredentials`, so the
platform cannot satisfy it with some other synced passkey. GO 1
additionally records its provenance — `{ownerId, go1SessionDeviceId,
go1SessionGeneration, killEpoch}` — and GO 2 re-checks it atomically:
revoking that device moves its generation and kills the pending
ceremony. The veto stays the intentional, irreversible exception to
identity continuity: any enrolled device stops, always.

**And the checks live inside the commit, not before it.** Session
validity and device generation, challenge ownership and binding, the
target's state (ceremony ready; approval record intact), and the kill
epoch are re-verified **inside the atomic consume-and-commit** — never
in a look-before-you-leap prologue that a revocation, a kill, or a
policy change can invalidate mid-flight. For approvals the commit-time
check goes one further: the action must **still route to the
`approve` lane under the current policy** when confirmed — an approval
created while a tool sat in the approve lane must not execute after
the policy moved it to `deny`, hash match or not — and an approval
carries a **TTL** (minutes, not hours: a yes is not a standing grant,
the executor's own rule). If execution is queued rather than
immediate, the dispatcher re-checks the approving device's generation
**immediately before dispatch** — an approval whose approver was
revoked while it sat in the queue dies in the queue.

**A captured, unredeemed assertion is bearer authority — so
redemption is device-signed too.** Between the authenticator ceremony
and the server's consume, a `BoundAssertion` in transit is a bearer
token for its exact bound mutation: whoever holds those bytes can
redeem them once. The two honest options: rest its confidentiality on
HTTPS and origin integrity and say so, or close it. The call:
**every assertion-redemption request is also device-signed** —
`/session`, GO 2, approval confirm, device-invite, device-revoke — by
the same device whose credential produced the assertion. The cost is
one cheap-lane signature on a request the foreground app is already
making: WebAuthn is a foreground ceremony, so wherever an assertion
exists, the key store is reachable — the cold-path constraint (§3)
never applies here. The gain is structural: a captured assertion
alone now redeems nothing, because the device key never travels; and
the identity-continuity line above becomes enforceable at the wire —
transport signer, challenge issuer, and asserting credential are
checked as one device before the commit begins. Honest bound: this
does not defend against a compromised origin, which can request both
the signature and the assertion while its code runs (§4); it defends
the transport, and it removes the one place where a bare bearer blob
was sufficient authority.

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
minted, every challenge it requested, every invite it issued, and its
ack evidence (§4) die with its generation.

**And a stolen session alone — plainly.** With invites and revocation
assertion-gated (§2), a bare bearer token can: start GO 1 (harmless
alone), veto (a stop), and list devices (a read). It cannot enrol a
device, revoke one, mint another session, ack, approve, or complete
GO 2. The earlier design let a stolen 15-minute session mint an
invite and enrol the *attacker's* passkey — inheriting everything and
defeating the promise that a stolen session cannot perform GO 2; the
device-invite assertion closes exactly that.

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
- **The ack only fires on a concrete render, from a reachable key.**
  The service worker acks after — and only after — content carrying
  the actual action summary is displayed, and only when it can
  device-sign the ack. A cold worker that cannot reach its key renders
  without acking — the ack arrives later, from a warm context or from
  the opened app, if the window is still live (§3). The warm path
  prefers to fetch the authoritative detail and render *that*, acking
  the revision and delivery the fetch minted (§3). If the payload is
  unreadable, oversized, or truncated and only a generic "an action is
  waiting for review" can be shown, the app shows it *without acking*:
  the device rendered that something is pending, but since the owner
  could not judge *what*, silence must not release it. Fail-closed on
  partial delivery.
- **A late or stale ack changes nothing.** An ack counts only under
  the full versioned-delivery rule (§3): current open revision,
  matching rendered-payload hash for a server-minted delivery, a
  delivery belonging to the signing device at its current generation,
  window still `pending`/`extended`, and — not merely before the
  deadline — received at least the **minimum owner-response interval**
  before it (`receivedAt ≤ deadline − minVetoResponseMs`, default
  60 s; §3): a last-second delivery extends or holds, never releases.
  All of it judged on the **server's own clock and records**; the
  client-supplied `renderedAt` is audit data, never enforcement.
  Everything else — late, last-second, stale-revision, wrong-hash,
  forged-delivery — is recorded in the audit trail and **ignored**: a
  delayed, backdated, or replayed ack must never flip
  `markDelivered()` after the fact and let the next tick read past
  silence as consent. That is the fail-open direction this whole lane
  exists to avoid, so every one of these checks belongs to the server,
  not to anything the phone asserts.
- **An ack must not outlive its device — and evidence is
  revision-scoped.** Delivery is recorded as **evidence** —
  `{deviceId, deviceGeneration, revision, deliveryId, payloadHash,
  receivedAt}` per accepted ack, inserted atomically under a
  compare-and-set on the window's current revision (§3) — and a
  revision releases on silence only if, *at the moment of the release
  decision*, at least one piece of evidence **for that revision**
  comes from a device still active at the same generation.
  `markDelivered()`'s boolean becomes this evidence list — a contract
  change on the window record, stated here on purpose — and release,
  revision change, and revocation all act on the same serialized
  window state. Chosen over the alternative (revocation eagerly
  sweeping delivered windows to `held`) for three reasons: it is the
  same at-use standing check as every session and challenge in this
  design; it keeps a legitimate release alive when a *second,
  still-active* device also rendered the alert — the eager sweep would
  hold windows the owner genuinely saw; and it needs no
  revocation-time sweep racing in-flight ticks — the check runs
  exactly once, where the release decision is made. The consequences
  fall out correctly: a stolen phone that acked an open window and was
  then revoked contributes nothing at the deadline, so the window
  extends → `held`; an ack that raced a revision change is never
  stored against the revision it did not render; zero active devices
  means zero valid evidence, so *every* open window goes `held`. Two
  things stand regardless: a release already executed is not recalled,
  and a veto stays irreversible.
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
  key. §2 ships no such mode, and §2 also states *precisely* what the
  public-key mode does and does not buy: no server-side shared secret,
  no byte-level export under honest code — but the server cannot
  verify non-extractability, a hostile origin at enrolment can
  register an extractable or attacker-imported key with a valid proof
  of possession, and even a genuinely non-extractable `CryptoKey` is
  structured-cloneable, so injected script can hand the signing
  capability to another context without ever seeing key bytes. The
  honest bottom line: an origin compromise, or a hostile enrolment,
  yields impersonation that **persists until revocation** — cleaning
  the origin does not end it; **revoking and re-enrolling every
  device does**. Requirements, not suggestions: the owner app lives on
  a **dedicated origin** that serves nothing else, with a strict
  Content-Security-Policy and **zero third-party script**; and an
  origin compromise is treated as compromise of *every* enrolled
  device — revoke them all, rotate every credential, re-enrol. The
  residual limit, stated plainly: no key design stops malicious code
  from asking a key to sign while that code is resident on the
  device. Subresource integrity and a pinned native wrapper are
  further hardening, listed and not shipped.
- **Agent-supplied strings render as text, never markup — and text
  alone is not truth.** `agentId`, `tool`, `summary` — every string
  that originates from an agent, a tool call, or the server — is
  assigned via `textContent`, never `innerHTML`, never interpolated
  into markup. The alert surface renders attacker-influenced input *by
  design* (that is its job), and a summary that could smuggle HTML
  into the owner-app origin would be XSS exactly where the device keys
  live — able to request permissive device signatures with the owner
  none the wiser. But `textContent` only stops markup: bidi overrides,
  control characters, and truncation games (UTR #36) can still make
  true bytes read as a false sentence, which is why the fields are
  bound to `RenderableAlertV1` — length-limited, single-line,
  bidi-control-free at mint, bidi-isolated at display, and never acked
  when truncated (§3, "Truthful rendering"). The scaffold demonstrates
  both rules (`public/app.js` assigns sample values with
  `textContent`; `app.css` isolates the fields); the strict CSP is the
  second fence, never the first.
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
| 1 | delivery ack | `POST /veto/:id/seen` | device signature (owner-device class only) | the production caller of `markDelivered()` — an ack counts only under the versioned-delivery rule (§3): current open revision, matching rendered-payload hash for a server-minted `Delivery` belonging to the signing device at its current generation, window still `pending`/`extended`, and `receivedAt ≤ deadline − minVetoResponseMs` (default 60 s — a last-second delivery extends or holds, never releases); `renderedAt` is audit data, never enforcement; everything else recorded and ignored. Stores revision-scoped **evidence** `{deviceId, deviceGeneration, revision, deliveryId, payloadHash, receivedAt}`, inserted atomically via compare-and-set on the current revision; release for revision N requires revision-N evidence from a still-active device at the same generation (§3, §4). Idempotent; 404 on unknown window |
| 2 | device-signed veto relay | `POST /veto/:id` (extended) | device signature **or** owner session | one-tap veto without a live session; `vetoedBy` resolves to the enrolled device's `ownerId`, audit records the device. Idempotent: re-vetoing an already-vetoed window succeeds as a no-op, so the service worker can retry blindly. (The v0.3 cold-push capability is **dropped** — no consumer; §3) |
| 3 | window detail for rendering | `GET /veto/:id` (extended) | device signature for detail | adds `deadline`, `delivered`, the call summary, and the current `revision` — and the read itself mints a `Delivery` whose id and hash the ack must echo (§3); `status` speaks the shared wire vocabulary (`VetoWireStatus`, #28) including terminal `spent`. The existing open read stays status-only: what an alert says is for enrolled devices, not for anyone who can reach the port (same disclosure discipline as the `/status` `epoch` note) |
| 4 | enrolment: invite | `POST /devices/invite` | owner session **+** device signature **+** fresh UV assertion (`purpose: "device-invite"`) — redemption is device-signed, §3; bootstrap / no-devices-left recovery via the host CLI / permission-protected Unix socket (§2), **never** an HTTP loopback bypass | single-use, short-TTL invite + the full WebAuthn creation contract (RP info, complete user entity, ES256-only `pubKeyCredParams`, authenticator selection); records the issuing device's `{deviceId, revocationGeneration}` (bootstrap invites: a bootstrap generation instead); token in the URL fragment where a URL form exists, spent in a POST body, never logged |
| 5 | enrolment: enroll | `POST /devices/enroll` | invite token | verifies the WebAuthn registration in the right places (`type`/`challenge`/`origin` in `clientDataJSON`; `rpIdHash` + UP/UV flags in the authenticator data; ES256 on P-256) **and** the pinned cheap-lane proof of possession (§2) *before* the invite is consumed; re-checks the issuer's standing (or bootstrap generation + zero active devices) atomically at spend; stores **one** `EnrolledDevice` holding both credentials. `cheapLaneKey` is required — no HMAC mode exists to fall back to (§2). The invite burns atomically and **only on success** |
| 6 | enrolment: list / revoke | `GET /devices`, `POST /devices/:id/revoke` | list: owner session; remote revoke: owner session **+** device signature **+** fresh UV assertion (`purpose: "device-revoke"`, subject = target device) — redemption is device-signed, §3; host CLI / Unix socket can always revoke | list returns a **redacted `DeviceSummary`** — never the `EnrolledDevice` record: the push `endpoint`, `p256dh`, and above all the `auth` secret stay server-side (RFC 8291: disclosing `auth` lets anyone generate pushes the user agent accepts). Revoke bumps the revocation generation and atomically voids the device's credentials, push subscription, **live sessions, outstanding challenges, unspent invites it issued, its deliveries, and its ack evidence** (§2, §4) |
| 7 | push subscription upsert | `PUT /devices/:id/push-subscription` | device signature (owner-device class only) | stores/refreshes the Web Push subscription; the `:id` is derived from the authenticated identity — a mismatched path id is rejected. Subscriptions must be **restricted to the configured VAPID public key** (`applicationServerKey`, RFC 8292) — an unrestricted subscription is refused. The `endpoint` is an SSRF surface and is validated at write: HTTPS only, known push-service endpoint shapes, and rejection of localhost, private, link-local, and metadata addresses |
| 8 | assertion challenge | `POST /assert/challenge` | device signature (owner-device class only) | mints a single-use challenge bound to a **discriminated** `{purpose, subject}` (subject required for `approve`/`restore-go2`/`device-revoke`, absent for `session`/`device-invite`), TTL ~2 min; the response carries `rpId` and `allowCredentials` naming the issuing device's paired credential (§3 — identity continuity); challenges record the minting device's revocation generation and die with it (§2). Redemption is atomic: verify, consume, exactly one protected mutation (§3) |
| 9 | passkey-gated sessions | `POST /session` | device signature **+** verified assertion (`purpose: "session"`) — redemption is device-signed, §3 | replaces in-process minting — closes `TODO(passkey)` in `auth.ts`. Atomic redemption: one assertion, one session, all checks inside the commit (§3). The minted session records `deviceId` + revocation generation, and every session check re-verifies the device is still active (§2) |
| 10 | GO 2 hardening | `POST /restore` (extended) | owner session **+** device signature **+** verified assertion (`purpose: "restore-go2"`, `subjectId` = ceremony id) — redemption is device-signed, §3 | GO 2 stops accepting the bearer token GO 1 already saw. The ceremony record stores GO 1 provenance `{ownerId, go1SessionDeviceId, go1SessionGeneration, killEpoch}`; session and device generation, challenge ownership, ceremony state, and kill epoch are re-verified **inside** the atomic consume-and-commit — revoking the GO 1 device kills the pending ceremony (§3) |
| 11 | alert dispatcher | (not a route) | — | the process that actually web-pushes on window register/extend: VAPID key custody, fan-out to enrolled devices, and per (device, revision) minting the `Delivery` the ack must echo (§3). Channel correctness: an RFC 8030 **Topic**, used precisely — the *same* topic replaces an outstanding undelivered push, so one topic token is reused across transport retries of a single revision (retries collapse into one), and the topic is **rotated on pending → extended exactly so the extension does NOT replace a still-undelivered pending alert: both are preserved and delivered**, each able to ack only its own revision (a stale revision's ack is ignored by §3, and the notification `tag` collapses the display best-effort); push **TTL capped at the remaining deadline** (an alert that outlives its window is noise). Enforces the RFC 8291 **3993-byte plaintext ceiling** — an oversized summary degrades to a generic alert, which never acks (§4). It re-validates every `endpoint` at send time — the checks from row 7 again, **after DNS resolution as well as before**, plus no redirect following and hard size/timeout caps — because a stored-then-repointed hostname is the classic SSRF. Needs its own design; send-failure feeds back into nothing, because the window's fail-closed path already covers silence |
| 12 | open-window reconciliation | `GET /veto` (collection read) | device signature (owner-device class only) | lists the owner's open (`pending`/`extended`) windows with their current revisions — the inbox a root-launched app renders when iOS loses the click handoff (§3). Listing never acks; rendering ONE window's detail (row 3) mints the delivery its ack must echo, so an inbox can never bulk-ack |

**Wire-status alignment with #28, and how each status renders.**
`GET /veto/:id` speaks `VetoWireStatus`: the state machine's five
states plus `spent` — the status a would-be release reports when the
window's recorded kill epoch is no longer current, because a kill
(even one later restored) happened after registration. Pushes are
dispatched only for `pending` and `extended` windows — the only states
that render a countdown, a VETO control, and an ack-on-render.
Everything else is **terminal on this surface** and renders without a
countdown, without a veto control, and without ever acking (the ack
rule accepts only `pending`/`extended`): `held` renders **"approval
required"** — the window escalated because delivery was never
confirmed, and the app must not show a release countdown for a state
that will never release; `vetoed` renders as stopped; `released` as
already run; `spent` as *"this review expired after a kill"* — not a
release, not reusable, and the action needs a fresh owner review, a
new window or an approval as the gateway decides, never a resurrection
of this window id. A delayed push arriving after a kill-then-restore
therefore lands on a status the app can represent honestly instead of
one it cannot parse.

The approve lane's confirm endpoint is deliberately absent: the control
plane has no server-side approval queue yet. When it exists, its
confirmation takes the same bound assertion with `purpose: "approve"`,
and it must be built against this contract: **an approval record is
immutable once created**, and it carries a canonical action hash —
**SHA-256**, base64url, over the deep-key-sorted canonical JSON (the
executor's canonicalization: object keys sorted lexicographically at
every depth, no insignificant whitespace, UTF-8) of `{agentId,
canonicalArgs, connector, decision, killEpoch, operation,
policyVersion, resourceId, ruleId, sourceTool}` — the `ActionTicket`
vocabulary of `packages/executor/DESIGN.md` plus the attribution the
owner is actually ruling on: *which agent*, *through which tool
surface*, *under which policy rule and decision*. Computed at
creation, never recomputed from mutable state. The assertion challenge
for `purpose: "approve"` binds `{purpose, subjectId, that action
hash}` server-side, so the passkey signs the exact action the owner
was shown, not a mutable id that could be repointed between render and
confirm. Confirm is device-signed like every redemption (§3), carries
a **TTL** (minutes, not hours), and re-verifies **inside the atomic
consume-and-commit**: the record against its hash, the kill epoch, the
session and device generation, challenge ownership — and the **current
policy**: the action must still route to the `approve` lane at confirm
time, so an approval created under one policy cannot execute after the
policy moved the tool to `deny`, hash match or not. Queued executions
re-check the approving device's generation immediately before
dispatch. A record that changed, an epoch that moved, a policy that
tightened, or an approver since revoked — each gets the same generic
refusal as every other failed check. The shapes are already in
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
