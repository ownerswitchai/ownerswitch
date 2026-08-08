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
  bound to the kill epoch still in force — then consumes it atomically,
  so exactly one restore can spend it and every other outcome is the
  same generic 409. Every kill increments the epoch, so a second kill
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
  session cannot reset the cooldown by hammering GO 1. Abandoning a
  pending ceremony requires the explicit cancel
  (`DELETE /restore/ceremony/:id`), which only ever deletes server state
  — it can make restore harder, never easier. Before any capacity
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
  rename and the parent directory after it (durability — rename alone
  orders visibility, not survival of a power cut; a platform where the
  directory fsync is unavailable gets a loud log line instead of a false
  promise); reads open with `O_NOFOLLOW` and fstat the descriptor, so a
  symlink or any non-regular file at the state path is refused. A state
  file that exists but cannot be read or parsed boots the plane KILLED
  with a loud log. A sibling initialisation marker
  (`<state-file>.initialized`) is written when the store first persists
  and never removed: once it exists, a MISSING state file also boots
  KILLED — deleting the state file is not a restore. Only a store with
  neither file is a genuine first boot. A persist failure (disk full,
  read-only fs) never blocks the transition — stopping must not fail
  because the disk did — but it is never swallowed either: durability is
  reported DEGRADED on `GET /status` and in the `/kill` response, and the
  store is degraded best-effort (marker in, stale state file out) so a
  later restart boots killed rather than resurrecting the not-killed
  state the failed save could not replace. Why a file: v0 is one process
  on one host, and the state is a boolean, a counter and one event — a
  `cat`-auditable JSON file needs no daemon. The limits of that choice,
  stated plainly:
  1. **The state file must live on a path the agent cannot write to.**
     Everything above assumes the attacker does not own the directory: a
     writer there can replace state wholesale, and a deleter who removes
     BOTH the state file and the marker manufactures a "first boot"
     (indistinguishable without an external anchor). The cwd-relative
     default (`ownerswitch-kill-state.json`) is a development
     convenience, nothing more; production deployments must set
     `killStateFile` (or `OWNERSWITCH_KILL_STATE_FILE`) to an explicit
     absolute path in a directory writable only by the control plane's
     user — and note that starting the process from a different working
     directory silently addresses a different (empty) store, which is
     another reason the default is not for production.
  2. **The store is single-instance, and nothing enforces singleton
     operation yet.** There is no lock file and no lease: two control
     planes pointed at one state file will interleave last-writer-wins,
     and — like ceremony state — nothing here coordinates or spans HA
     deployments. Run exactly one instance per state file; a shared
     store with real coordination is required before anything else.
  3. A power cut in the narrow window between a transition and its
     fsyncs can still lose that newest transition — losing a restore
     fails closed, losing a kill falls back to the state before it.
  Hardening beyond this (external anchoring, a shared store, singleton
  enforcement) is future work, tracked with the audit-log hardening
  above.
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

---

**Rule of thumb.** Treat the gateway as where decisions are made and
remembered. Treat containment as a property of the deployment around it.
Where a quickstart and this document appear to disagree, this document is
the one telling the truth.
