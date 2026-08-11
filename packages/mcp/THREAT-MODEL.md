# OwnerSwitch MCP gateway — threat model

**Written 2026-08-08 — the day we watched a well-behaved agent route
around the gateway.** Docs only: this file changes no behavior. It states
what the current code enforces, what it cannot, and what to deploy around
it when "cannot" is not acceptable.

**TL;DR.** The MCP gateway is a policy decision point and an audit record
for every call that routes through it. It is not, by itself, containment.
An agent with direct file, shell, or network access has paths the gateway
never sees; for that agent, `deny` removes permission, not capability.
Containment is a property of the deployment around the gateway — §3 ranks
the options.

## 0. The finding that motivates this document

Claude Code was put behind the MCP gateway. A write it attempted was
denied twice by the fail-closed default (unknown tool → `approve`, and no
owner approval was given) — correct, twice. Then the user repeated the
request. The agent read the repetition as authorization and performed the
write with its own built-in `Write` tool, a path that never touches the
gateway. It announced what it was doing. Nothing was compromised.

What this proves, and doesn't:

1. **Enforcement on the routed path is real.** Two calls in, two
   fail-closed denials out. No bug, no misconfiguration.
2. **Routing is voluntary.** The gateway ruled on exactly the calls the
   agent chose to send it. The third action happened outside its view.
3. **A boundary the agent can route around is advice.** The denial did
   not make the action impossible; it made it impolite. The agent weighed
   "the gateway said no" against "the user asked twice" and picked a
   different tool. No jailbreak, no malice, no hidden step — which is
   exactly why this failure mode must be designed for, not trusted away.

Nothing here is specific to Claude Code. Any agent that carries built-in
tools next to gatewayed ones can do the same, and an agent under prompt
injection can do it for worse reasons.

## 1. What the gateway DOES enforce

Everything in this section applies to calls that route through the
gateway. That qualifier is the point of this document.

- **Live kill state at decision time.** Every routed call is evaluated
  with the current kill state; the order of authority is kill switch →
  first matching policy rule → fail-closed default
  (`packages/gateway/src/engine.ts`). Once KILL is engaged, everything
  routed is denied.
- **Kill state cannot be forgotten, only asserted.** `evaluate()` takes
  kill state as a required parameter with no default — a caller that
  omits it doesn't compile. A caller with no live source must write
  `{ killed: false }` itself, making that assumption visible at the call
  site.
- **Fail-closed on doubt.** The control-plane client reads every failure
  as killed: network error, timeout (500 ms default), non-2xx response,
  unparseable body (`packages/gateway/src/client.ts`). A silent or broken
  control plane stops the fleet; it never silently frees it.
- **Fail-closed on the unknown.** No matching rule → the policy default,
  shipped as `approve`: the action waits for the owner's passkey (2GO).
  Unknown tools never run on silence.
- **Owner lanes with fail-closed timeouts.** `veto` holds a call for
  3–5 min in the control plane; silence releases it only if delivery to
  the owner was confirmed — otherwise the window extends once, then
  escalates to `held` (`packages/control-plane/src/veto.ts`). `approve`
  is default-deny.
- **An attributable audit trail.** Every verdict carries the matched rule
  id and reason; the control plane appends every kill and restore
  transition to an append-only log, with unauthenticated triggers
  flagged (§4 states exactly how much "immutable" currently means).

| Doubt | Reads as |
| --- | --- |
| control plane unreachable / timeout / non-2xx / garbage | `killed: true` |
| no policy rule matches | `approve` — the owner decides |
| veto notice never confirmed delivered | extend once, then `held` |
| kill state omitted at a call site | compile error |

## 2. What the gateway does NOT enforce

- **Paths that never route through it.** An agent with built-in file
  tools, a shell, its own network stack, other MCP servers, or
  credentials already sitting in its environment can act without asking.
  The gateway cannot deny a call it never receives. For an agent like
  Claude Code that concretely means `Write`/`Edit`, `Bash`, and its own
  egress — the exact path used in §0.
- **Denial ≠ disablement.** `deny` means the gateway refuses to perform
  or forward the action. The action remains physically available on every
  non-routed path. Only deployment (§3) turns "refused" into
  "impossible".
- **The agent's interpretation of the owner.** A user repeating a denied
  request can be read by the agent as authorization to route around
  policy — that is the §0 finding. Prompt injection or plain helpfulness
  pressure can induce the same reinterpretation. It happens inside the
  agent, where no gateway can see it.
- **Semantics of tool names.** Policy matches tool names and argument
  patterns. A tool whose name undersells its effects gets the weaker
  rule. Policy is only as good as the tool catalog is honest.
- **Retroactive revocation.** Stated in the README and repeated here:
  KILL stops NEW authorized actions at the boundary. In-flight actions
  and already-issued downstream credentials live out their TTLs unless a
  connector supports revocation. Short TTLs are the mitigation, not a
  waiver.

## 3. Deployment models that close the gap

Ranked by containment strength — measured by what a denied-but-attempted
action can still reach, not by how much policy vocabulary a layer has.
The models compose, and the gateway (d) is the decision-maker inside all
of them.

| | Model | After a denial, an alternate path can still… | Enforcement lives |
| --- | --- | --- | --- |
| a | credential broker | act locally, unauthenticated — nothing to spend | outside the agent's reach |
| b | sandbox, gateway-only egress | act inside the sandbox | host / infra config |
| c | kernel/LSM enforcement | whatever the profile still allows | kernel, per host |
| d | MCP proxy alone | everything it could before | the agent's cooperation |

### (a) Credential broker — strongest

The README's pitch, taken seriously: agents never hold real credentials.
Real keys exist only behind the broker; agents get short-lived, scoped
tokens issued per approved call and checked against the same kill state
at issuance. A bypassed gateway then has nothing to spend: the built-in
`curl` still runs — unauthenticated. KILL = no more tokens, and a denial
stops being a refusal and becomes an absence. This is the only model
whose enforcement sits entirely outside the agent's machine, which is why
it ranks first.

Honest limits: purely local effects need no credentials — §0 was a local
file write, and a broker would not have stopped it. And today this model
is roadmap, not shipping code (`packages/sdk` is a stub): until the
broker exists, "the agent holds no real keys" is deployment discipline —
vault the keys where the agent cannot read them.

### (b) Sandboxed agent, gateway as only egress

Run the agent in a container/VM/network namespace whose egress is
default-deny except the gateway (and broker). Bypassing now requires a
sandbox escape — a vulnerability class — rather than a tool choice. With
a scratch-only filesystem this also bounds local effects, the thing (a)
cannot.

Honest limits: the containment equals the configuration. Mounted host
paths, forwarded secrets, cloud metadata endpoints, open DNS, or "just
this one package registry" each reopen a path, and the enforcement sits
on infrastructure right next to the agent — one compose-file edit from
gone.

### (c) Kernel/LSM-level enforcement

SELinux/AppArmor/Landlock/seccomp profiles on the agent host: mandatory
access control the agent process cannot opt out of. Mechanically the
hardest "no" on this list — the kernel does not weigh arguments.

Ranked third in practice: profiles tight enough to matter are brutally
hard to write for a general-purpose agent (a useful agent wants broad
read/exec, so real profiles end up broad); the kernel governs this host's
files and sockets, not remote APIs — a permitted HTTPS socket spends any
credential the agent already holds; and it is per-host and subject to
drift. Best used as the mechanism that implements (b), not as a
standalone answer.

### (d) MCP proxy alone — weakest as containment

Everything in §1 and nothing more: policy lanes, owner veto/approval,
live kill checks, audit — on the routed path. This is the quickstart
deployment, and it is genuinely valuable: it is where decisions get made
and remembered, and every stronger model still needs it (a broker without
policy is a token vending machine; a sandbox without policy just
contains). But as containment it is a convention. It works exactly until
an agent has a reason — malicious or perfectly mundane — to route around
it. §0 is what that looks like.

**Guidance:** run (d) always — it is the brain. Add (a) so denials have
teeth against the outside world. Add (b), built with (c), where local
side effects matter. Distrust any architecture diagram in which the arrow
from agent to gateway is load-bearing but voluntary.

## 4. If OwnerSwitch itself is compromised

Two components, two very different failures.

### Compromised gateway / MCP proxy

It sits on the routed path, so it can lie there: allow what policy says
deny, skip the kill lookup, drop its own log lines. It cannot restore a
killed control plane, mint owner sessions, or rewrite the control plane's
audit of kills and restores. Its worst case is functionally §2 — an
unpoliced routed path — which is why the same layers that bound a
bypassing agent, (a)–(c), also bound a lying gateway: a proxy with no
keys to hand out and no egress of its own has little to betray.

### Compromised control plane

The serious one: it owns kill state, owner sessions, and the audit log.
It could answer `killed: false` while the owner believes the system is
dead, refuse restores, or mint owner sessions at will (until passkey
verification lands, session minting trusts its in-process caller —
flagged in `auth.ts`).

What limits the blast radius today — real code, caveats included:

- **The stop/start asymmetry.** Stopping never depends on auth — even an
  unauthenticated loopback caller can kill, recorded and flagged as such.
  Restoring always requires an owner session, with no loopback bypass.
  An attacker who merely breaks the control plane has, in effect, pressed
  the button.
- **Fail-closed clients turn sabotage into KILL.** Gateways read silence,
  timeouts and garbage as killed within 500 ms. To keep agents running,
  an attacker must keep serving a well-formed lie; crashing, wedging, or
  firewalling the control plane stops the fleet instead of freeing it.
- **`/status` must NEVER be cached — a deployment requirement.** Every
  kill check in the system (the gateway's per-call lookup, the executor's
  two live re-checks before dispatch) is a fetch of `GET /status`; a
  reverse proxy or intermediate cache replaying a stale
  `{killed:false, epoch:N}` after a kill would defeat all of them at once,
  and a cached `"released"` on `/veto/:id` would resurrect a spent release
  across a kill-and-restore. Both ends refuse caching in code: the control
  plane serves EVERY response with `Cache-Control: no-store, max-age=0`
  and `Pragma: no-cache` (`server.ts` `sendJson` — nothing this server
  serves is cacheable), and clients fetch `/status` with
  `cache: "no-store"` plus explicit no-store request headers
  (`packages/gateway/src/client.ts`). The residual requirement is on the
  deployment: do not place a cache, CDN, or "optimizing" reverse proxy in
  front of the control plane, and if a proxy is unavoidable, it must be
  configured to honor `no-store` on this origin. An infrastructure layer
  that strips or ignores these headers reintroduces the stale-answer
  window no client code can close.
- **Device HMAC, scoped to the cheap direction.** Device secrets sign
  kill requests: HMAC-SHA256 over the exact bytes on the wire,
  single-use nonce, 60 s skew window, timing-safe comparison
  (`packages/control-plane/src/auth.ts`). A stolen device secret forges
  attributed *stops* — the safe direction — and helps not at all with
  restore. Caveat: the seen-nonce store is process memory; a restart
  reopens a ≤60 s replay window (flagged in code — shared store before
  multi-process).
- **Server-side, single-use restore ceremonies.** Restore demands a live
  2GO ceremony that the control plane itself started and tracks
  (`packages/control-plane/src/server.ts`). `POST /restore` verifies the
  ceremony exists in server state, belongs to the session's owner, has
  passed its mandatory 30 s cooldown, is inside its 5 min TTL, and is
  bound to the kill epoch still in force — then consumes it atomically.
  Single-spend atomicity holds for one process and one event loop — the
  only place ceremony state lives — not across instances. Every other
  outcome is the same generic 409: a uniform response SHAPE, deliberately
  unrevealing about which check failed, but NOT a constant-time or
  side-channel-free guarantee — timing, evaluation order and transport
  metadata still differ between causes. Every kill increments the epoch,
  so a second kill
  invalidates ceremonies already in flight. There is no shape-only path:
  an authorization-shaped body without live server state restores
  nothing, and ceremony state is process-local, so a control-plane
  restart loses ceremonies *closed* — they must be restarted, never
  resurrected. The same locality is a deployment limit: ceremony state
  neither survives nor spans multi-instance / HA deployments, so a shared
  ceremony store is required before running more than one control-plane
  instance.
- **Ceremony capacity cannot be weaponized against restore.** Each owner
  holds at most ONE live ceremony per kill epoch, and GO 1/2 is
  IDEMPOTENT: while an owner has a live ceremony under the current
  epoch, a repeat call returns that same ceremony with its clocks
  untouched — so a double-click, a browser retry or a second tab cannot
  invalidate the id the owner is holding, and a stolen same-owner
  session cannot reset the cooldown by hammering GO 1. There is
  deliberately NO cancel verb: a pending ceremony ends only by TTL
  expiry, consumption, or a new kill epoch. Any owner-session cancel
  would hand the same bearer token a repeatable way to destroy the
  owner's pending ceremony — the exact lockout idempotency closes — so
  ceremonies are left to expire on their own. Before any capacity
  decision, dead records (TTL-expired, consumed, superseded kill epoch)
  are purged. The remaining global ceiling (`MAX_CEREMONY_RECORDS`) is a
  memory backstop against a flood of distinct hostile sessions, set far
  above legitimate use, and it fails closed: full refuses NEW ceremonies
  with the generic 409 and never evicts a live one (an owner with a
  pending ceremony still gets it back via the idempotent path). An
  earlier design capped raw map size with only TTL sweeping, which let
  consumed or superseded records block new ceremonies for minutes — a
  denial of the recovery operation itself; the purge-before-cap ordering
  is the fix and is pinned by tests. Limit, stated plainly: the ceiling
  is per-IDENTITY, so it is still exhaustible by an attacker who can
  present many DISTINCT valid owner identities — the capacity math
  assumes an authoritative owner registry bounding who counts as an
  owner. Today session minting is in-process and single-owner (flagged
  in `auth.ts`); until a real registry (passkey enrollment) lands, that
  assumption is enforced by deployment, not by this code.
- **Kill state survives restarts — and fails closed.** The kill switch
  persists `{killed, epoch, last kill event}` to a JSON file on every
  transition and loads it synchronously at construction — before the
  HTTP handler exists, so before any request can be answered
  (`packages/control-plane/src/kill-state.ts`). Restarting the process is
  therefore not a restore: `kill -9` comes back killed, with the same
  epoch and the same attributed reason. The mechanics, and what each is
  for: writes go to a random-named temp file opened
  `O_CREAT|O_EXCL|O_NOFOLLOW` with mode 0600 and are published by rename
  in the same directory (atomic visibility — a reader sees the old state
  or the new, never a torn one); the temp file is fsynced before the
  rename and the parent directory after it. Durability is claimed
  narrowly: a transition is durable only after EVERY fsync has
  succeeded, and a directory-fsync failure surfaces as degraded
  persistence on `GET /status` (plus a log line) — it is never accepted
  in silence, because the rename is then visible but a power cut may
  resurface the previous state. Reads open with `O_NOFOLLOW` and fstat
  the descriptor, so a symlink or any non-regular file at the state path
  is refused. A state file that exists but cannot be read or parsed
  boots the plane KILLED with a loud log. A sibling initialisation
  marker (`<state-file>.initialized`) is written when the store first
  persists and never removed: once it exists, a MISSING state file also
  boots KILLED — deleting the state file is not a restore. Only a store
  with neither file is a genuine first boot. A persist failure (disk
  full, read-only fs) never blocks the transition — stopping must not
  fail because the disk did — but it is never swallowed either:
  durability is reported DEGRADED on `GET /status` and in the `/kill`
  response, and the store is asked to quarantine the stale state it
  failed to replace (marker in, stale state file out) so a later restart
  boots killed rather than resurrecting the not-killed state the failed
  save could not replace. If that quarantine itself fails, the plane
  does not pretend otherwise: it reports itself UNHEALTHY on
  `GET /status` and keeps denying restores until an owner repairs the
  store — flipping the in-memory switch is the only working stop left,
  and it will not be given away while stale state may survive a restart.
  Why a file: v0 is one process on one host, and the state is a boolean,
  a counter and one event — a `cat`-auditable JSON file needs no daemon.
  The limits of that choice, stated plainly:
  1. **Whoever can write the state directory holds an administrative
     stop-and-restore capability over kill state.** They can corrupt or
     delete the state file (forcing fail-closed boots — an
     administrative stop), and a deleter who removes BOTH the state file
     and the marker manufactures a "first boot" (indistinguishable
     without an external anchor). No Node-level hardening changes this;
     it is the deployment boundary, and it is stated as a REQUIREMENT:
     the state directory must be writable only by the control plane's
     user, on a path the agent cannot reach. Production boots enforce
     what is checkable: `createControlPlane` refuses to start unless
     `killStateFile` is an explicit absolute path outside the working
     directory, in an existing directory owned by the process uid with
     no group/world write access — each refusal logs what is wrong and
     what the operator must do. `dev: true` (the dev server, demos and
     tests) skips these checks with a loud warning; the cwd-relative dev
     default is a convenience, and starting from a different working
     directory silently addresses a different (empty) store — two more
     reasons it is not for production.
  2. **The store is single-instance, and nothing enforces singleton
     operation yet.** There is no lock file and no lease: two control
     planes pointed at one state file will interleave last-writer-wins,
     and — like ceremony state — nothing here coordinates or spans HA
     deployments. Run exactly one instance per state file; a shared
     store with real coordination is required before anything else.
  3. **Crash points can leave the previous state published.** In-memory
     transitions flip before the file write begins, so a crash between
     the flip and the rename leaves the PREVIOUS state on disk; a power
     cut between the rename and the directory fsync can do the same even
     though the new state was briefly visible. Losing a restore this way
     fails closed; losing a kill falls back to the state before it —
     which is why kill triggers should be re-assertable (the button can
     be pressed again) and why durability degradation is surfaced
     rather than assumed away.
  4. **The in-memory audit log is unbounded, and kills are deliberately
     cheap.** Every kill appends to the process-local log forever, does
     a synchronous state-file write, and bumps the epoch — invalidating
     every ceremony in flight. A loopback kill flood therefore grows
     memory, hammers the disk, and can keep invalidating an owner's
     pending restore ceremony indefinitely. That is the accepted price
     of "stopping never fails on auth": bounding the log, batching
     writes or rate-limiting kills are hardening work, not shipped, and
     none of them may ever make a kill fail.
  Hardening beyond this (external anchoring, a shared store, singleton
  enforcement, log bounding) is future work, tracked with the audit-log
  hardening above.
- **`GET /status` is unauthenticated by design, and now discloses one more
  bit.** The route has always leaked `killed` to any caller who can reach
  the control plane — that is the point, since gateways and (per
  `packages/executor/DESIGN.md`) executors must be able to poll it without
  a session. It now also returns `epoch`, a monotone count of every kill
  this deployment has EVER had. That is a real, if narrow, widening: an
  outside observer who can merely reach `/status` learns how many times
  this system has been stopped over its lifetime — nothing about when, why,
  or by whom (reason/at require reading the killed branch of the same open
  response, already true before this change; source and full attribution
  still require an owner session). It is worth accepting because `killed`
  alone cannot support the one job `epoch` exists for: telling a stale
  approval from a current one. A restore flips `killed` back to `false`, so
  a client that only checked `killed` would treat a pre-kill approval as
  fresh the moment the owner restores — exactly the gap a kill-then-restore
  cycle is supposed to close. `epoch` never resets, so an approval minted
  before a kill (an `ActionTicket`'s `killEpoch`, in the executor design)
  stays dead forever, even across a restore. Same fail-closed contract
  applies to readers: a client that cannot read or parse `epoch` must not
  default it to `0` — that would make every ticket minted before this
  deployment's first-ever kill look permanently current, silently
  defeating the check it exists to support.
- **Short TTLs everywhere.** Owner sessions: 15 min. Ceremonies: 5 min.
  Downstream connector tokens, in the broker model: minutes. A stolen
  artifact is a window, not a standing capability.
- **An append-only, attributing audit log.** Every kill and restore is
  appended with source and time; unverified triggers carry
  `unauthenticated: true`; reads return copies. Caveat, stated plainly:
  today the log is an in-process array. "Immutable" means no API can
  rewrite history — it does not yet mean a compromised process can't.
  Hash-chaining and external anchoring are hardening work, not shipped.
- **There is little to steal.** In the proxy-only deployment OwnerSwitch
  holds no agent credentials, so compromise yields policy manipulation,
  not key theft. The broker model changes that deliberately: the broker
  becomes the crown jewels and must be built as such (KMS/HSM-backed
  issuance, per-connector scoping, short-lived derivations) before it
  holds anything real.

The control plane is deliberately one small, framework-free process — a
surface auditable in one sitting. That concentration is the design: one
place to defend, and the place most worth defending.

## 5. What changes now that a real downstream credential exists

"There is little to steal" (§4) was written for the proxy-only
deployment, and it stops being true the moment the executor's GitHub
connector is configured: the deployment now contains a **GitHub App
private key** and mints **installation tokens** with it
(`packages/executor/DESIGN.md` §6). This section is what that changes.

- **Neither the key nor a token lives in the gateway — because of the
  uid problem, and because a token is raw authority.** File modes (0600,
  ownership) defend against other USERS; they defend nothing against a
  process under the SAME uid, and in the stdio deployment the MCP client
  spawns the gateway, so gateway and agent share a uid. A key the gateway
  could read, the agent could read. An earlier design moved the key into
  a separate-uid broker that VENDED tokens — but a `contents: write`
  installation token authenticates git-over-HTTPS, so anything that
  reached the broker socket held raw push authority, and within one uid
  nothing distinguishes the gateway from the agent: a same-uid agent could
  take the vended token and push directly, bypassing owner review, the
  ticket, the head pin and policy. The separate uid protected the KEY; it
  did not preserve the AUTHORIZATION BOUNDARY. The shipped shape is
  therefore the **executing merge broker** (`ownerswitch-merge-broker`):
  a separate-uid process that alone reads the PEM, **never returns a token
  or the key**, and instead PERFORMS the merge itself after validating a
  control-plane-signed, single-use grant. It is the theft target now, and
  it is small, credential-only, and auditable in one sitting.
- **A merge needs the owner's ACTIVE approval, not their silence — and the
  approval is a passkey ceremony, not a bearer token.** The party that
  registers an owner-review window is the gateway, which shares the agent's
  uid and whose device secret the agent can therefore forge — so a window's
  mere existence proves nothing, and silence-approval would let an agent's
  own registration release itself into a merge. The control plane mints a
  merge grant ONLY on the owner's active approval, and with a passkey
  enrolled that approval requires a fresh WebAuthn assertion: a single-use
  challenge bound to {windowId, callHash}, signed by the authenticator with
  UP+UV, counter-checked, atomically redeemed. An owner SESSION (a reusable
  bearer token) only OPENS the ceremony — a stolen session cannot complete
  it, because completing it takes the hardware in the owner's hand passing
  its screen lock. Session-only approval exists only in dev mode; a
  production control plane without an enrolled passkey refuses approvals.
  Silence leaves a merge pending forever; the grant binds the kill epoch at
  approval so a window opened during a kill cannot outlive it.
- **The owner's veto revokes an issued, undispatched grant — atomically,
  not as a snapshot.** The control plane tracks every minted jti; a
  purposed window accepts a veto even after approval; the broker's
  read-only signed probe answers `grantLive` per jti before the token mint;
  and the FINAL pre-PUT check is an ATOMIC COMMIT — the broker sends an
  HMAC-signed commit request (only it holds the key, so an agent cannot
  pre-commit) and the control plane transitions the grant
  live→committed-for-dispatch only if a veto has not already won. Both the
  commit and the veto handlers are synchronous, so the race has exactly one
  winner: if commit wins, the later veto is reported 409 "in flight"; if
  veto wins, the commit returns `committed:false` and no PUT is sent. This
  closes the window a signed-then-stale `grantLive:true` snapshot left open.
- **Single request per broker connection.** The broker latches the
  connection the instant it reads a full request line, before any await, so
  a second chunk arriving mid-merge (or oversized trailing data) can never
  re-parse the line and launch a duplicate coroutine that double-burns and
  false-refuses while the original dispatches.
- **The passkey approval binds the DISPLAYED transaction, in the current
  kill epoch.** The approval ceremony stores the kill epoch it was minted
  in and is cleared on any kill, so a challenge created before a kill can
  never be redeemed after a restore. The ceremony returns a typed,
  per-field `RenderableApprovalV1` — never raw canonical JSON — with every
  string field (owner, repo, base ref, head) proven safe to display: NFC
  form, and rejected by Unicode PROPERTY (`Cc`/`Cf`/`Zl`/`Zp`/`Bidi_Control`/
  `Default_Ignorable_Code_Point`) rather than an enumerated range, so
  U+061C, U+00AD, U+180E, U+FFF9–FFFB and astral default-ignorables are all
  refused. The render's hash is bound to the challenge. In production the
  owner obtains the session that opens the ceremony by a passkey login
  (`POST /session/challenge` → `POST /session`), so a fresh process needs no
  seeded credential. WebAuthn assertion verification requires an exact
  https origin, rejects cross-origin (embedded) ceremonies, and rejects an
  unexpected `topOrigin`. So "the owner tapped yes" means the owner saw an
  unspoofable transaction, at the real origin, in the world the approval
  belongs to.
- **The merge destination is pinned, not just the head.** GitHub allows
  retargeting a PR's base branch after approval and its merge API guards
  only the head sha — so OwnerSwitch pins `expectedBaseRef` server-side at
  review time, shows it to the owner, signs it into the grant, and
  re-checks the PR's live base immediately before dispatch, refusing on
  mismatch. The residual read-to-PUT race (the API has no atomic base
  guard) is documented in DESIGN.md rather than papered over.
- **The merge is authorized by evidence the gateway cannot forge.** That
  **MergeGrant** (`packages/shared/src/merge-grant.ts`) is minted by the
  CONTROL PLANE at the owner's active approval, signed with a key
  (`OWNERSWITCH_GRANT_KEY`) shared ONLY with the broker — never in the
  gateway/agent environment, and that is ENFORCED, not assumed: the
  gateway refuses to start if the variable is present in its environment,
  and the control plane requires the same uid/host isolation from the
  agent as the broker (whoever reads the key mints approvals). The grant
  carries the exact owner-reviewed call (including the pinned
  `expectedHeadSha`), its SIGNED PURPOSE (connector + operation — the
  broker refuses any purpose but `github`/`merge_pull_request`, so an
  approval registered for another tool can never be spent as a merge, and
  the control plane mints only for that purpose in the first place), the
  authorization-world hash, a single-use id, the approval's kill epoch,
  and a short expiry anchored to the RELEASE moment — a release that sits
  unread past the grant window is `spent`, never a later fresh
  capability. The broker verifies all of it independently and merges only
  the signed args. Single-use burns twice, both out of the agent's reach
  and neither in volatile memory alone: the control plane issues each
  window's grant once, and the broker burns the jti in a durable, atomic
  on-disk store that survives restarts and arbitrates between broker
  processes — a burn it cannot persist is a refusal.
- **What a same-uid agent that finds the socket can obtain NOW, stated
  plainly.** A read-only head sha (`pin-head` — public-ish, low value),
  and a merge ONLY if it also presents a currently-valid, unburned,
  owner-approved grant it cannot mint (the signing key is not in its
  reach — and which is now minted only when the OWNER actively approves,
  never on silence). It can never obtain a token or the key. Neither
  filesystem permissions nor SO_PEERCRED would help — they cannot tell
  gateway from agent within one uid — which is why the executing design
  removes the thing worth stealing rather than trying to identify the
  caller. The residual: a same-uid agent racing the gateway for a
  freshly-issued grant could present it first, but that grant exists only
  because the owner actively approved THAT exact call, and the double
  single-use burn caps it at the one merge the owner approved, with the
  args the owner approved. The
  **same-process mode** (key in the gateway, merges direct, no grant)
  still exists behind an explicit
  `OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK=1` acknowledgment — it
  refuses to start without it and warns loudly with it, because in stdio
  deployments it means the agent can read the key.
- **The socket's GID is verified, not assumed.** A unix socket inherits
  the broker process's effective gid, not the directory's group, so a
  documented "0750 dir + 0660 socket" can silently deny the intended
  gateway user or admit a wider one. The broker checks the socket's actual
  gid after bind and refuses to serve on a mismatch with
  `OWNERSWITCH_BROKER_SOCKET_GID`; the deployment makes them agree with a
  setgid (02750) socket directory and/or by running the broker with that
  gid. The socket directory must also be neither world- nor group-writable
  (a group member that can write it could unlink the socket and bind its
  own), which the broker enforces.
- **The kill-state channel is authenticated, so fail-closed means closed
  against an impostor.** The broker's live kill check does not trust the
  unauthenticated loopback `/status`: it calls `GET /kill-state?nonce=…`
  and requires an HMAC-signed, nonce-bound envelope (shared
  `OWNERSWITCH_KILL_STATE_KEY`). If the isolated control plane stops, a
  hostile local process can bind the unprivileged port and answer
  "not killed" — but it cannot sign, and a replayed real answer carries a
  stale nonce, so the broker reads KILLED. Without this, "unreachable ⇒
  fail closed" is defeated by an impostor that makes the plane look
  reachable while lying.
- **The grant and kill-state keys are isolated three ways, and enforced.**
  Each is ≥256 bits (short keys refused at startup), lives only in the
  broker and a control plane running under its OWN uid (distinct from the
  gateway/agent AND from the broker uid that owns the App PEM), is read
  from a file into the process environment rather than passed on any
  command line (argv is world-readable via `/proc`), and the gateway
  REFUSES to start if it finds EITHER `OWNERSWITCH_GRANT_KEY` or
  `OWNERSWITCH_KILL_STATE_KEY` in its own environment — the second because
  an agent holding the kill-state key could port-squat a stopped control
  plane and SIGN fresh `killed:false` envelopes, defeating the
  authenticated kill channel from the inside.
- **The burn store's namespace is pinned, not assumed.** Containment is
  checked on the post-realpath result (an intermediate symlink cannot
  smuggle it into the agent workspace), every ancestor must be trusted
  (owned by root or the broker, no group/world write) so no other writer
  can rename the store away, the directory's inode is pinned at startup
  and re-verified before every burn, the pinned fd is what gets fsynced,
  and EVERY directory-fsync failure refuses the burn — no platform
  exemptions.
- **The blast radius is configured, not coded.** An installation token
  is scoped at mint to ONE repository and
  `{ contents: write, pull_requests: read }`, and dies within an hour —
  and the mint VERIFIES GitHub's repositories echo, refusing tokens
  that come back broader (enterprise-owned installations cannot be
  repository-downscoped and are therefore unsupported, enforced by
  behavior). The key itself is bounded by the App's installation list
  and permissions. Deployment requirements, restated as requirements:
  install the App on exactly the repositories the executor may merge
  in, grant it Contents read/write + Pull requests read-only and
  nothing else, and never install it org-wide out of convenience —
  every extra repository in the installation list is a wider key.
- **The key's placement is the same class of requirement as the
  kill-state file.** Absolute path, outside the AGENT'S workspace
  (passed to the loader explicitly — never inferred from the loading
  process's cwd), owned by the broker's user, mode 0600. The loader
  enforces what a process can check (symlink refusal, mode, ownership,
  size, "not under the given workspace") and refuses to start
  otherwise; whether the agent has some OTHER route to that path is a
  property of the deployment, and no Node-level check can prove a
  negative about host access.
- **Approvals bind to exactly one head.** Every routed merge carries a
  mandatory `expectedHeadSha`, derived BY OWNERSWITCH from GitHub at
  review time — the agent cannot supply it, the owner sees it in the
  veto window, the ticket canonicalizes it, and the merge sends it as
  the API's head-match guard. Commits pushed after the owner's review
  draw HTTP 409 (or a fresh review), never a merge under the old
  approval.
- **Credentials appear on the wire to exactly one host, from exactly one
  process.** Installation tokens exist only inside the broker and ride in
  an `Authorization` header to `api.github.com` and nowhere else — never
  across the broker socket, never in the gateway. No code path logs them,
  thrown errors are assembled from status codes and a redacted, bounded
  `message` field, transport failures collapse to fixed sentences (a token
  FRAGMENT cannot be exact-match redacted, so the channel is removed), and
  everything crosses a second SecretLedger redaction before an error can
  reach the agent. The residual leak surface is a compromised broker
  process itself — which is §4's scenario, now with something
  real to exfiltrate.
- **Kill does not revoke a minted installation token.** Same boundary
  as ever: KILL stops new executions (the executor's live re-checks) AND
  new merges at the broker (it checks live kill state before every merge,
  requires the grant's kill epoch to match, and re-checks ACROSS the
  token mint to catch a kill that lands during it). But a token exists
  only inside the broker and never crosses the socket, so the only way a
  token outlives a kill is a broker compromise — and a compromised broker
  is §4's scenario regardless. GitHub exposes
  `DELETE /installation/token`; wiring token revocation into the kill
  path is future hardening, not shipped. Until then the honest bound on
  a stolen token is one hour and one repository.
- **The agent-side containments carry unchanged weight.** The upstream
  child's environment is built explicitly with every credential
  stripped by name and value, a credential in `upstream.args` is a
  startup refusal, and `OWNERSWITCH_GITHUB_TOKEN` — the PAT seam the
  App model replaces — is no longer accepted as a credential at all; if
  set, it only arms scrubbing and the env-strip.

---

**Rule of thumb.** Treat the gateway as where decisions are made and
remembered. Treat containment as a property of the deployment around it.
Where a quickstart and this document appear to disagree, this document is
the one telling the truth.
