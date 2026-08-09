# Escalation — the ladder that makes "silence releases" true

**A veto window may release on silence only when the system KNOWS the
owner saw the alert. Today nothing can know that. This package is how
the system learns — and it is allowed to learn it only from the owner's
own device.**

The veto lane exists to be the calm middle: the owner is told, can stop
the action with one tap, and does not have to do anything for normal
work to proceed. The state machine for that has shipped since day one
(`packages/control-plane/src/veto.ts`): silence releases a held tool
call *only if* `markDelivered()` was called first; otherwise the window
extends once and then escalates to `held` — a passkey approval, fail
closed. The honest note in `packages/mcp/README.md` says the rest:
delivery confirmation "isn't wired yet", so `markDelivered()` has no
production caller, every untouched window walks
pending → extended → held, and the veto lane is currently just a slower
approval lane. Safe — but not the design.

This package is the delivery arm: an **escalation ladder** that tries
progressively harder to put the alert in front of the owner, reports
honestly what each attempt proved, and feeds exactly two things back
into the state machine it serves — `markDelivered()` and `veto()`. It
adds no states, shortens no deadlines, and releases nothing itself.

## 1. The ladder

Rung offsets are config; the defaults below are drawn against the
window's own defaults (4 min window, one 6 min extension):

```
minute 0     PUSH to the owner app — one-tap VETO action — and EMAIL
minute 2.5   SMS ("reply 1 to stop") — last try before the deadline
minute 4     first deadline: not confirmed → window extends (+6 min)
minute 5     OUTBOUND CALL — a machine reads the alert; press 1 to stop
minute 10    second deadline: still not confirmed → held → 2GO approval
```

Every rung is cancelled the moment the window stops being undecided or
the owner is confirmed reached:

- **owner app confirms** (§3) → remaining rungs cancelled; the window
  releases at its deadline if the owner stays silent — the designed calm
  path. A push acked at 0:30 costs zero SMS and zero calls.
- **veto arrives from any channel** → relayed, window `vetoed`,
  terminal.
- **window leaves `pending`/`extended`** for any other reason (kill,
  gateway gone) → stand down.

The ladder runs as its own process, not inside the control plane — the
control plane stays the one small, framework-free process the threat
model praises. The escalation service holds the provider account and
the webhook surface, and talks to the control plane only through the
same authenticated device surface every other component uses.

## 2. The asymmetry, at channel level

| channel | can it STOP? | can it CONFIRM the owner saw it? | can it APPROVE? |
| --- | --- | --- | --- |
| push → owner app | yes — one tap, authenticated | **yes — the only one** | never |
| email | only via a link into the owner app | no | never |
| SMS reply | yes | no — not even a carrier delivery receipt | never |
| voice keypress | yes — press 1 | no | never |

Every channel can stop. One channel can confirm. **No channel can
approve — and the scaffold types make a channel that claims otherwise
unrepresentable (§7).**

Pressing 1 on a phone call is weak authentication, and the design says
so plainly: caller ID is spoofable in both directions, a SIM swap
redirects the call, call forwarding redirects it invisibly, and anyone
standing near the phone can press the key. An SMS reply is no better —
interceptable, spoofable, and after a SIM swap it comes from the
attacker's handset with the owner's number on it. **This is acceptable
precisely because the only verb these channels carry is deny.** The
worst outcome of a forged keypress is that something the owner wanted
gets stopped and lands in the audit trail with a channel attribution —
the same doctrine as the device HMAC being "scoped to the cheap
direction" (`packages/mcp/THREAT-MODEL.md` §4): stops are cheap and
attributable, starts are expensive and ceremonial. Approval stays where
it is: the owner's passkey, through 2GO. Nothing in this package can
move it.

Email is the odd one out: it gets no direct stop verb at all. A
one-click veto link would hand every mail scanner that prefetches URLs
a way to stop actions at random — fail-closed spam, safe but silly. So
the email only deep-links into the owner app, where both the veto tap
and the ack are authenticated.

One invariant worth teaching the owner, because it defeats the obvious
vishing script: **a real OwnerSwitch call only ever offers to stop.**
It reads the alert and says "press 1 to stop it; do nothing and the
system follows your policy." Any call that asks the owner to press a
key to *approve*, or to read back a code, is fake by definition — this
system has no such flow on any telephone channel, ever.

## 3. Delivery confirmation — what counts, and how the control plane learns it

`markDelivered()` is the *permissive* bit of the veto lane: it is what
lets silence release a held call. So the bar for flipping it is the
strongest evidence a channel can produce, and the path that flips it
must be authenticated end to end. What each channel can actually prove:

| evidence | what it proves | flips `markDelivered()`? |
| --- | --- | --- |
| provider accepted the send (any channel) | we handed it off | no |
| email: SMTP accept / open pixel | approximately nothing | no |
| SMS: carrier delivery receipt (DLR) | *a handset* received the bytes | no |
| voice: call answered | someone — or voicemail — picked up | no |
| voice: DTMF keypress | a human at that number interacted | no (it can veto, though) |
| **owner-app ack**: the enrolled device reports the alert was rendered in front of a human — notification tapped, or the app opened and displayed it | the alert reached a human on the owner's enrolled device | **yes — the only one** |

Why the line sits there and nowhere lower: a delivered push is not a
read push, an answered call is not the owner, and a carrier DLR after a
SIM swap is proof the *attacker's* handset got the message. If a DLR
could flip the bit, an attacker holding the owner's number could make
silence release actions the owner never saw — quietly converting phone
interception from deny-only (§2) into a release enabler. By admitting
only the app ack, **everything that routes through the telephony
provider is deny-or-nothing**, and the one permissive signal travels a
path the provider never touches: owner app → control plane, directly,
authenticated. Weak channels get the strong verb (stop); only the
strong channel gets the permissive one (confirm).

Honest limits, so nobody reads more into the bit than it holds: the app
ack proves *rendered in front of a human on the enrolled device* — not
read, not understood, and not that the human was the owner (a stolen
unlocked phone acks; §5). It is the strongest thing any push pipeline
can prove, and the design names what it does not prove rather than
rounding it up.

Mechanically, four small control-plane additions (deferred to the
wiring PR — this PR touches nothing):

1. **`POST /veto/:id/seen`** — owner-session or enrolled-device signed;
   the missing production caller of `markDelivered()`. Recorded with
   which device acked and when, so a later "released on silence" is
   explainable from the audit trail alone.
2. **Channel vetoes relayed under a device signature.** Provider
   webhooks land at the escalation service (signature-verified there),
   which relays a stop as a device-signed `POST /veto/:id`. Today that
   route demands an owner session; it grows a device-signed variant
   whose attribution is honest about its weakness — `vetoedBy:
   "channel:voice-dtmf"`, flagged like unauthenticated kills are —
   rather than pretending a keypress was a session.
3. **`GET /veto/:id` exposes `deadline` and `delivered`** alongside
   `status`, so the ladder can pace itself off the window's own clock
   instead of guessing.
4. **`GET /veto/pending`** (device-signed) — the listing the ladder
   polls to discover work. Window contents describe held agent actions,
   so the listing is authenticated like registration is.

Clock skew between the two processes is fail-safe by construction: a
ladder that fires rungs late only lowers the chance of confirmation, so
doubt degrades toward `held`, never toward release.

## 4. What happens when nobody answers

Nothing new — and that is the point. The fallback already shipped in
`veto.ts`: miss the first deadline unconfirmed and the window extends
once; miss the second and it goes `held`, which the gateway surfaces as
`-32051 ApprovalRequired` — the action now needs the owner's passkey,
fail closed. The ladder does not replace that ending; it exists to make
it rare. Each rung is one more chance for one of the two good exits —
a confirmation (so silence can release) or a veto (so the question is
answered) — before the fail-closed one:

| outcome | how it ends |
| --- | --- |
| owner acks, stays silent | released at the deadline — the calm path |
| owner acks, taps veto / replies 1 / presses 1 | `vetoed`, terminal |
| nobody reachable through any rung | extended once, then `held` → passkey approval |
| caps hit mid-storm (§6), rungs unspent | same as unreachable: `held`, fail closed |

The ladder holds no lever that could change the ending: its entire
interface to the state machine is `markDelivered()` and `veto()`. It
cannot extend a window, shorten one, or release one.

## 5. The threat model of the ladder itself

Same rules as `packages/mcp/THREAT-MODEL.md`: what the code enforces,
what it cannot, stated plainly.

- **An attacker who can receive the owner's SMS or answer their phone**
  (SIM swap, call forwarding, a lifted handset) **can veto things the
  owner wanted to allow.** Denial, not escalation — and denial is the
  safe direction: nothing runs that would not have run, the forged stop
  is attributed to a channel in the audit log, and a pattern of them is
  a visible incident, not a quiet compromise. The same attacker cannot
  confirm delivery (app-only, §3), cannot approve (passkey), cannot
  restore (2GO). The ladder hands phone-level attackers exactly one
  power: making the system more conservative.
- **An attacker who can BLOCK delivery** — muted push, filtered SMS, a
  dead provider account, an unplugged phone — **prevents releases and
  causes held calls.** Silence never releases unconfirmed, so every
  window walks to `held` and the veto lane degrades into the approval
  lane: an availability attack against the agent's throughput, never an
  authorization gain. The flip side stated honestly: blocking delivery
  also blinds the owner mid-window — but the action they didn't see
  doesn't run on silence either; it waits for their passkey, where they
  will see it.
- **The provider (Twilio or whoever) becomes a dependency and sees
  alert metadata.** It learns the owner's phone number, the timing and
  rate of alerts — a decent proxy for how busy the fleet is — and
  whatever the alert text says. So the alert text stays terse: a tool
  name and a window id at most, never arguments; detail lives in the
  owner app. A compromised provider (or provider account) can suppress
  messages (that is the delivery-block above), forge inbound webhooks
  (forged vetoes — deny direction; webhook signature verification
  raises the bar without changing the direction), and spend the
  account's money. It can never confirm delivery and never approve,
  because those paths do not route through it — that is not luck, it is
  why §3 draws the line where it does.
- **Outbound calls cost money, so a flood is a billing attack.** A
  compromised agent — or an ordinary bug — that opens veto windows in a
  loop is asking the ladder to dial the owner's phone on a meter. The
  caps and coalescing in §6 exist for this, and they fail closed: a cap
  stops spending, never releases anything.
- **The escalation service itself, compromised**, holds a device
  credential and the provider credentials. Worst case: it spams the
  owner, forges channel vetoes, spends the phone budget, or goes silent
  — in which case every window goes `held`. It holds no owner sessions
  and no passkeys; it cannot release, approve, or restore. It is built
  deny-capable on purpose, like every other device credential in the
  system.

## 6. What it costs and what it needs

Being concrete about the external dependency (order-of-magnitude 2026
US list prices — check current rates before budgeting):

- **A telephony provider account.** Twilio is the working assumption;
  the `Channel` interface (§7) is provider-agnostic and nothing else
  may know which provider is behind it.
- **A provisioned phone number**: ~$1–2/month for a US local number,
  shared by SMS and voice.
- **SMS**: ~$0.008 per segment, plus carrier surcharges — and, in the
  US, **A2P 10DLC registration**: brand and campaign vetting that takes
  days-to-weeks and carries a small monthly fee. The SMS rung has real
  onboarding friction; the design treats it as optional per deployment
  rather than pretending it is free.
- **Voice**: ~$0.014 per outbound minute. The alert call is under a
  minute by design — read the alert, offer press-1, hang up — so about
  a cent per call.
- **Push**: APNs/FCM are free, but require the owner app to exist and
  (for iOS) an Apple developer account. The ladder's strongest channel
  is also the one that needs the most product to exist around it.
- **Email**: effectively free (~$0.10 per thousand via SES or any
  SMTP); worth its rung because it costs nothing and survives a dead
  phone.

**Rate limits, so a kill storm doesn't become a thousand phone calls.**
Defaults, all configurable, none removable:

- **One active ladder per owner.** Windows opened while a ladder is
  running join it (the alert becomes "N actions held — open the app"),
  the app lists them all, and a veto from a coalesced alert stops *all*
  of them — bulk stop is safe because stop is the safe direction. A
  1,000-window storm therefore costs one ladder run — a push, an email,
  an SMS or two, one call; pennies — not 1,000 calls.
- **Per-owner ceilings** behind that: at most 2 voice calls per 10
  minutes, at most 6 SMS per hour, and a daily spend ceiling in
  dollars.
- **At a cap: stop spending, log loudly, let the windows go `held`.** A
  rate limit converts unspent rungs into the fail-closed ending; it may
  never convert them into a release. Hitting the budget makes the
  system more conservative and the owner's passkey more necessary —
  never the reverse.

## 7. Scaffold types (what is actually in this PR)

Types only — no provider SDK, no live calls, no webhook server. The
asymmetry of §2 is encoded in the types themselves: `approve` on a
channel is the literal type `false`, so a channel that claims it can
approve does not compile. Confirmation is not a return value of
`send()` — it arrives later, from the provider via `handleCallback()`
(deny-or-nothing evidence) or from the owner app via the control plane
directly (the only permissive path, which is why `Channel` has no verb
for it).

```ts
export type ChannelKind = "push" | "email" | "sms" | "voice";

/** What a channel may do. approve is the literal false — unrepresentable. */
export interface ChannelVerbs {
  stop: boolean;
  confirmSeen: boolean; // true only for the push→owner-app channel
  approve: false;
}

/** Evidence ladder of §3. Only owner-app-ack may flip markDelivered(). */
export type DeliveryEvidence =
  | { level: "provider-accepted"; channel: ChannelKind; at: number; marksDelivered: false }
  | { level: "device-received";   channel: ChannelKind; at: number; marksDelivered: false }
  | { level: "human-interacted";  channel: ChannelKind; at: number; marksDelivered: false }
  | { level: "owner-app-ack";     deviceId: string;     at: number; marksDelivered: true };

export interface Channel {
  readonly kind: ChannelKind;
  readonly verbs: ChannelVerbs;
  /** Hand the alert to the provider. Resolving means accepted, not delivered. */
  send(alert: EscalationAlert): Promise<ChannelAttempt>;
  /** Verify + parse a provider callback. Bad signature → no events. */
  handleCallback(callback: ProviderCallback): ChannelEvent[];
}
```

The `Ladder` sequences channels against an injected clock, in the
repo's house style: `tick()` is pure and returns the actions to
perform; side effects live at the edge.

```ts
export interface LadderRung { afterMs: number; channel: ChannelKind }

export interface Ladder {
  windowOpened(windowId: string, call: ToolCall, deadlineMs: number): void;
  channelEvent(event: ChannelEvent): void;
  /** Advance; returns sends to make, vetoes to relay, stand-downs to record. */
  tick(nowMs: number): LadderAction[];
}
```

And the shape the control plane stores per window — the audit trail
that makes a later "released on silence" explainable after the fact:
every attempt, every piece of evidence with its honest level, and a
`seen` bit that can only have come from an owner-app ack:

```ts
export interface EscalationRecord {
  windowId: string;
  attempts: ChannelAttempt[];
  evidence: DeliveryEvidence[];
  /** mirrors VetoWindow's delivered bit; true only via owner-app-ack */
  seen: boolean;
  vetoRelayed?: { channel: ChannelKind; at: number; attribution: string };
}
```

Full definitions, with the connective types (`EscalationAlert`,
`ChannelAttempt`, `ChannelEvent`, `LadderAction`, `LadderConfig`,
`RateLimits`), are in [`src/types.ts`](./src/types.ts).

## 8. What this does NOT solve

- **The owner app has to exist.** Push is the strongest rung and the
  only confirming one, and today nothing renders these notifications or
  sends the ack. Until it ships, the ladder's confirming path is
  design, not behavior — the same "isn't wired yet" honesty the MCP
  README already carries, one package closer to fixed.
- **Confirmation is not comprehension.** An ack proves the alert was
  rendered in front of a human on the enrolled device. A distracted tap
  is an ack. Alert fatigue makes distracted taps more likely; pacing
  and coalescing are the mitigation, not a cure.
- **A compromised enrolled device beats the ladder.** A stolen unlocked
  phone can ack and veto. Approval and restore still stand behind the
  passkey — the ladder never weakens them — but "the enrolled device is
  the owner's" is an assumption this package inherits, not one it can
  check.
- **Provider trust in the deny direction is bounded, not eliminated.**
  Webhook signatures authenticate that the provider sent the callback,
  not that the carrier's story inside it is true.
- **Timeliness is best-effort.** Providers queue; minute-5 is a target,
  not a bound. The deadline math lives in the control plane, and late
  delivery degrades toward `held` — fail closed — never toward release.
- **A new always-on process with a wallet.** The escalation service is
  one more thing to run, monitor, and fund. If it is down, the veto
  lane quietly becomes the approval lane again — exactly today's
  behavior, which is the right failure mode, but worth alarming on.

## 9. In this PR / not in this PR

**In:** this document; `src/types.ts` — the `Channel` interface, the
evidence ladder, the `Ladder` contract, the `EscalationRecord` stored
shape, all types only; package scaffolding so `pnpm typecheck` covers
it.

**Not in:** any provider SDK or credential; any live push, email, SMS,
or call; the webhook server; the rate limiter; the four control-plane
additions of §3 (`/veto/:id/seen`, device-signed veto relay, `deadline`
+ `delivered` on `GET /veto/:id`, `GET /veto/pending`); the owner app;
any wiring into the gateway or control plane. Nothing existing is
touched.
