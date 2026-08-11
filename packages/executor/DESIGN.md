# Executor — from authorize() to authorizeAndExecute()

**The agent asks for the action. OwnerSwitch performs it. The agent never
sees a credential.**

Today the decision path is real end to end: the MCP proxy fronts the
agent, the gateway's `evaluate()` answers allow / veto / approve / deny
against live kill state, and on yes the proxy *forwards the call to the
upstream MCP server* — tooling that acts with a credential the agent's
side holds. The credential on the agent's side of the boundary is exactly
the thing OwnerSwitch exists to eliminate: a token handed out survives the
moment of the decision. It can be exfiltrated, replayed after a kill, or
used for a different action than the one that was approved — which is why
the kill switch's own docs are careful to say kill stops *new* actions and
does not revoke credentials already issued downstream.

This package inverts the last step. When the answer is yes, OwnerSwitch
calls the connector API **itself, with its own credential**, and returns
the *result* of the action to the agent — never a token. There is nothing
for the agent to leak, because the agent was never given anything. For
executor-routed actions, the "credentials already issued downstream"
residue disappears entirely: nothing is issued downstream.

One connector to start: **GitHub PR merge** (`merge_pull_request`). It is a
single, well-bounded, irreversible-ish action with a clean approve/deny
shape — the right proof before generalizing. It is also already in the
gateway's test policy (`github.merge_pr`, veto lane), so the whole path
exists on paper today.

## 1. The canonical action ticket

A yes-decision produces an `ActionTicket` — the one data structure that
crosses from "decided" to "executed". Everything the executor needs to
refuse a stale, replayed, or tampered request is *in* the ticket; the
executor never reaches back into the gateway's memory.

| field           | type      | why it exists |
| --------------- | --------- | ------------- |
| `agentId`       | `string`  | who the action was authorized *for* — same id as `ToolCall.agentId`; lands in the audit trail |
| `sourceTool`    | `string`  | the MCP tool name the agent actually called. Several MCP surfaces may front one operation, and the audit trail must say which one the owner's decision was about |
| `decision`      | `Decision` | the verdict that authorized the ticket — `"allow"`, or `"veto"` after release |
| `ruleId`        | `string \| null` | the policy rule that produced the verdict (`null` for the default decision) — what was approved, *under which rule* |
| `connector`     | `string`  | which backend performs it, e.g. `"github"` |
| `operation`     | `string`  | which action within the connector, e.g. `"merge_pull_request"` |
| `canonicalArgs` | `string`  | the arguments, canonicalized (below). The executor runs *these bytes* — not a re-supplied copy — so what runs is exactly what was evaluated and approved |
| `resourceId`    | `string`  | stable id of the object acted on, e.g. `github:pr:ownerswitchai/ownerswitch#7` — audit and future per-resource rules key on this, independent of args shape. **Deliberately sha-free:** it identifies the pull request, not the approved head; the pinned `expectedHeadSha` lives in `canonicalArgs` (and thus the grant and the action hash), never here |
| `policyVersion` | `string`  | content hash of the **whole authorization semantics** the verdict came from: the policy *and* the executor-route mapping, as canonical JSON. Routes decide which real operation a tool name reaches, so a hash of the policy alone would identify only half of what was authorized — the same policy with a re-pointed route is a different authorization world |
| `killEpoch`     | `number`  | `KillSwitch.epoch` at mint time (§3). Must still match at execution time |
| `expiresAt`     | `number`  | unix ms. Tickets are short-lived (minutes, not hours) — a yes is not a standing grant |
| `nonce`         | `string`  | unique per ticket; burned on first execution attempt |
| `singleUse`     | `true`    | always `true` in v0. The field exists so a future batch/recurring grant is an explicit, visible design change — not an accidental default |

**Canonicalization.** `canonicalArgs` is JSON with object keys sorted
lexicographically at every depth, no insignificant whitespace, arrays in
original order. Same arguments in, same bytes out — so a ticket authorizes
exactly one action shape, and the executor's parse of those bytes cannot
diverge from what the owner saw in the approval prompt. (Full RFC 8785 JCS
is deliberately deferred; deep key-sort covers every argument shape the
connectors use today.)

**Naming.** The MCP-visible tool id (`github.merge_pr` in today's policy)
maps to `(connector: "github", operation: "merge_pull_request")` at mint
time. The ticket stores the connector/operation pair *and* the source tool
name, so several MCP surfaces can front the same executor operation without
the executor caring — while the audit trail still says which surface the
owner's decision was about.

**Alias coherence is enforced.** Policy judges the agent-chosen tool NAME;
routes map names to real operations afterwards. Two aliases of one
operation sitting in different policy lanes would therefore be a policy
bypass — the agent simply calls the looser alias. The gateway refuses such
a configuration at startup (config load AND proxy construction), naming
both tools: aliases of one `(connector, operation)` must have provably
identical verdicts — the same ordered candidate-rule list (id, decision,
argsPattern) and the same default — e.g. one glob rule covering all of
them.

## 2. The flow

```
agent ──MCP──▶ proxy ── evaluate() ──▶ allow ──────────────────────┐
                             ├───────▶ veto   ── released ────────┤
                             ├───────▶ approve ── 2GO confirmed ──┤
                             └───────▶ deny ──────────────────────┼──▶ refused
                                                                  │   (result to agent)
                                                     mint ActionTicket
                                                                  │
                                                     executor.run(ticket)
                                                       1. fetch LIVE kill state   ◀── control plane, never cached
                                                       2. killed? epoch moved? expired?
                                                          nonce burned?  ──▶ refuse
                                                       3. burn the nonce
                                                       4. re-fetch LIVE state, re-check
                                                          right before dispatch ──▶ refuse
                                                          (narrows the race; cannot close it)
                                                       5. backend.execute(ticket) ──▶ GitHub API,
                                                                  │                   OwnerSwitch's OWN credential
agent ◀────────── result: { merged: true, sha } ──────────────────┘
                  (data, never a token)
```

Where today the proxy's yes-path is `forward(call)` — hand the call to the
upstream MCP server and pass its result through — an executor-routed
operation's yes-path is `executor.run(ticket)`. Same lanes, same refusals,
different last step.

The agent's MCP call *is* the request; the result of the merge is the
response. From the agent's point of view `merge_pull_request` is just a
tool that either worked, was refused, or is pending the owner — it has no
idea a credential was involved, because for the agent, none was.

`authorize()` becomes `authorizeAndExecute()`: the same call that used to
end with "yes, here's a token" now ends with "yes — and it's done".

## 3. Kill re-check at execution time

A verdict is a fact about the past. Execution needs a fact about the
present. Veto windows are minutes long and a 2GO approval can sit in a
queue — plenty of room for the world to change between yes and run. The
dangerous ticket is the one minted *before* a kill and executed *after* it.

So the executor re-checks, **immediately before executing, against the live
control plane** — never a cached answer:

1. `killed` must be `false` — an engaged kill refuses everything,
   including already-approved tickets;
2. `ticket.killEpoch` must equal the current kill epoch;
3. `now < ticket.expiresAt`;
4. the nonce must not already be burned.

**The guarantee, stated precisely: a ticket is refused if the final
pre-dispatch live-state check observes a kill or an epoch change. A kill
landing after that check may race with dispatch; once the connector call is
dispatched it cannot be recalled.** The check is not the same instant as
dispatch — there is a small, irreducible gap between the check resolving and
the connector call going out, and a kill landing in that gap, or while the
call is on the wire, is not caught. Against an external API with no fencing
no mechanism can close that gap; anything claiming otherwise would be
theater. This is the same boundary the kill switch itself documents for
in-flight actions (`packages/mcp/THREAT-MODEL.md`, `gateway/src/engine.ts`):
kill stops *new* actions, it does not recall dispatched ones. What the
executor does is run a **second live re-check immediately before
dispatch**, after the nonce burn — it *narrows* the window in which a kill
can land undetected; it does not and cannot close it.

**A veto release binds to its window's kill epoch — server-side.** The
epoch rule would be worthless if it only covered the ticket: a veto window
opened under epoch N, released, then killed-and-restored would otherwise be
retried and minted with the *retry's* epoch — a pre-kill approval executing
in the post-kill world. So the control plane records the kill epoch in
force when a window is **created**, in the window record itself (not in any
gateway's memory — the binding survives gateway restarts and holds across
multiple gateways). A would-be `released` status from a window whose epoch
is no longer current is served as `spent`: the release authorizes nothing,
the proxy refuses the call, and only a fresh window — a fresh owner
decision — can let it run. An owner's `vetoed` is never downgraded: "no"
survives everything.

**The kill epoch is the control plane's, not ours.** `KillSwitch` already
maintains it: `epochCounter`, bumped on every `engage()`, exposed as
`KillSwitch.epoch`, persisted across process restarts by the
`KillStateStore` (and fail-closed at boot if that state can't be trusted).
Restore never resets it. The control plane already uses it for exactly the
pattern this design needs: a restore ceremony binds to the epoch in force
when it started, and a later kill bumps the counter and invalidates every
ceremony in flight. The `ActionTicket` applies the same rule to actions —
a ticket binds to the epoch at mint time, and a later kill invalidates
every ticket in flight. This package invents no kill state of its own.

**Done:** `GET /status` now exposes `epoch` alongside `killed`, the
attributing kill's `reason`/`at`, and the persistence-degradation fields —
acknowledged in the endpoint's own docs and in
`packages/mcp/THREAT-MODEL.md` as the deliberate widening it is. The
gateway's kill-state client (`packages/gateway/src/client.ts`) reads it and
fails the whole lookup closed if `epoch` is missing or unparseable, rather
than defaulting it to `0`. The executor's own kill-state reader is wired to
that same client: `liveKillStateFromControlPlane`
(`packages/executor/src/live-kill-state.ts`) backs the injected
`fetchLiveKillState`, so the re-check before execution reads `killed` and
`epoch` off `/status` under the same fail-closed contract as every other
lookup — including refusing a "not killed" answer that carries no epoch,
which could not support the ticket-epoch check.

**Why an epoch and not just `killed === false`:** kill-then-restore. The
owner kills at 12:00, cleans up, completes 2GO and restores at 12:10. At
12:11 `killed` is `false` again — but an approval minted at 11:59 belongs
to the world *before* the incident and must not execute in the world after
it. The kill bumped the epoch, the ticket's epoch no longer matches, the
ticket is dead forever. Approvals do not survive a kill, even one that was
later restored.

**Fail-closed, like everything else.** If the live kill state cannot be
read — network error, timeout, garbage response — the executor treats it as
killed and refuses, exactly as the gateway's `fetchKillState` already does.

**The nonce burns before the connector call, not after.** For
irreversible actions, at-most-once beats at-least-once: if the process
dies mid-call, the ticket is dead and the owner re-approves. A duplicate
merge is not a retry, it's an incident.

## 4. How this composes with what already exists

The gateway's engine remains the only authority on yes/no. `evaluate()`
does not change, the decision vocabulary does not change, veto windows and
2GO do not change, and the MCP proxy keeps deciding every call the way it
does today. This package is purely the *"then what"* for yes — it runs the
action instead of forwarding the call to tooling that holds a credential
on the agent's side.

| piece | before | now |
| --- | --- | --- |
| `@ownerswitchai/shared` | `Decision`, `ToolCall`, `Policy`, `Verdict` | unchanged |
| gateway `evaluate()` / `evaluateRemote()` | the decision, live kill state required | unchanged — still the sole authority |
| control plane | `KillSwitch` with `killed` + persisted `epoch`; ceremonies bound to the epoch; `GET /status` returns `epoch` too (§3) | veto windows now record the kill epoch at registration, server-side in the window record; a would-be release from a dead epoch is served `spent` (§3) |
| mcp proxy, on yes | `forward(call)` — hand the call to the upstream MCP server, pass the result through | **wired**: for operations declared in the gateway config's `executorRoutes` (MCP tool name → connector/operation, alias-coherence enforced at startup, §1), a yes — allow, or veto after release with the window's epoch still current — mints an `ActionTicket` (`packages/mcp/src/executor-route.ts`) and calls `executor.run()`; the result is relayed to the agent. Every unrouted tool keeps forwarding exactly as before |
| **this package** | — | ticket type, refusal core with a second pre-dispatch re-check (§3), `ExecutorBackend`, `liveKillStateFromControlPlane` (§3), GitHub merge backend that scrubs its own credential from results and errors, HTTP call still stubbed |

The wiring is deliberately thin: the proxy's decision path did not change —
same lanes, same refusals, same honeytoken scan immediately before anything
crosses the boundary. Routing only replaces the *last step* of yes. The
ticket binds to the kill epoch the decision itself observed (the same
`/status` answer `evaluateRemote` fetched for the call), and the executor
re-checks live state through the same fail-closed client before running.

## 5. What this does NOT solve

Honesty about the boundary, in the same spirit as the threat model:

- **An agent with its own GitHub token is unaffected.** If the agent holds
  a PAT, an SSH key, or a browser session through any path that doesn't go
  through OwnerSwitch, it can merge whatever that credential allows and
  this package never hears about it. The executor closes the gap *for
  actions routed through OwnerSwitch* — routing everything through
  OwnerSwitch is a deployment property, not something this code can force.
- **Kill stops new executions, not in-flight ones.** Precisely (§3): a
  ticket is refused if the final pre-dispatch live-state check observes a
  kill or an epoch change; a kill landing after that check may race with
  dispatch, and once the connector call is on the wire it cannot be
  recalled. This is the same enforcement boundary the kill switch itself
  documents — kill guarantees no *new* authorized action crosses the
  boundary, nothing more. What the executor removes is the other half of
  that caveat: for actions routed through it, there are no credentials
  issued downstream to outlive the kill.
- **OwnerSwitch's credential is now the prize — and it lives in the
  broker, not the gateway.** Whoever holds the GitHub App private key can
  merge without any ticket, so the key does not sit in the gateway (which
  shares the agent's uid in stdio deployments). It lives in the executing
  merge broker, under its own uid; the broker never returns the key or a
  token, only the outcome of a merge it performed after validating a
  control-plane-signed grant. Least privilege is shipped, not aspirational:
  a GitHub App whose installation tokens live at most an hour and are
  scoped, per mint, to one named repository and two permissions — §6 has
  the full model, including where the key must live, why the broker
  executes rather than vends, and what a stolen artifact of each kind is
  worth.
  Two containments ship with the wiring. First, the upstream child process —
  the agent's side of the boundary — gets an EXPLICITLY built environment
  with every gateway/executor/connector credential stripped: by name
  (`OWNERSWITCH_*` always, plus known alias names like `GITHUB_TOKEN` and
  `DEVICE_SECRET` regardless of their current value) and by value (any
  entry containing a known secret, so a credential can't ride in composed
  into an unrelated variable). `upstream.args` gets the harder stance: a
  credential value found there is not filtered, it is a startup refusal
  naming which argument is at fault — command-line arguments are visible to
  any process on the host that can read this process's argv, a worse leak
  surface than an environment variable (`packages/mcp/src/upstream-env.ts`).
  Together this means the premise "the agent's side holds no credential"
  cannot be silently falsified by environment inheritance or a
  misconfigured launch command. Second, the backend scrubs its own token
  from results and errors. The scrubbing is a SECOND line of defence, not
  the design: the real connector client must be written so a credential
  never enters a log or an error in the first place —
  redaction only catches what should never have been emitted at all.
- **Tickets are structs, not cryptography.** Gateway and executor are the
  same trust domain in v0 — a compromised process can mint its own
  tickets or skip the checks. Signed tickets and a separated executor are
  later hardening, not a v0 property. What v0 *does* prove is the shape:
  the agent's side of the interface carries no credential at all.
- **The owner can approve a bad merge.** Approval fatigue and social
  engineering of the human are untouched. The veto window's pacing helps;
  it does not make the owner infallible.
- **GitHub-side paths remain.** Other collaborators, other bots, and
  branch-protection gaps are GitHub's access model, not ours.
- **The nonce store is per-process — this is a deployment constraint, not
  a footnote.** The store lives in one `Executor` instance inside one
  gateway process, so a ticket is single-use *within that process* and
  nothing more: a gateway restart forgets every burned nonce, a second
  gateway process has its own empty store, and a future remote executor
  would share nothing. The wiring is defensible TODAY because of two facts
  that must both stay true: the agent never holds a ticket (mint and run
  happen inside one proxy call), and there is no executor endpoint to
  replay one against. **Deployment constraint: run exactly one gateway
  process per deployment, and do not stand up a remote executor, until a
  shared nonce store exists.** A shared atomic consume would require, at
  minimum: a unique-constraint insert (or Redis `SET NX`) so exactly one
  consumer wins; keys namespaced by deployment so environments cannot burn
  each other's nonces; entry TTL ≥ the maximum ticket lifetime plus clock
  skew, so a nonce cannot be forgotten while its ticket could still be
  presented; fail closed on any storage error (an unreachable store refuses
  the ticket, never assumes it fresh); and the burn still ordered before
  dispatch, exactly as in-process.

## 6. The GitHub connector, live

The seam described above is now filled: `createGitHubMergeClient`
(`src/github-client.ts`) is the real HTTP client behind
`GitHubMergePrExecutor`, and OwnerSwitch performs approved merges itself.
This section is the credential model and the honesty section for the one
call that crosses to GitHub.

### The credential is a GitHub App, not a PAT

A personal access token is a standing, human-scoped credential: it lives
until someone rotates it, it acts as its owner across every repo that
owner touches, and revoking it is a manual act. The connector refuses that
model. It authenticates as a **GitHub App** (`src/github-app-auth.ts`):

1. The App's **RSA private key** signs a short-lived JWT — RS256, `iat`
   backdated 60 s against clock drift, `exp` 9 minutes out (GitHub's cap
   is 10). The JWT can do exactly one thing: mint installation tokens.
2. The JWT calls
   `POST /app/installations/{installation_id}/access_tokens` with an
   explicit down-scoping body:
   `repositories: [<the one repo in the ticket>]` and
   `permissions: { contents: "write", pull_requests: "read" }`.
   `contents: write` is the documented requirement of the merge endpoint;
   `pull_requests: read` covers the review-time head pin and the
   post-ambiguity verification read below. Nothing else is ever requested.
3. The response's `repositories` echo is **verified**: GitHub documents
   that **enterprise-owned installations cannot be repository-downscoped**,
   so a token that comes back covering anything other than exactly the one
   requested repository is refused and never used or cached. **OwnerSwitch
   supports repository-scoped installations only** — the support boundary
   is enforced by behavior, not stated and hoped for.
4. **Installation tokens expire one hour after minting** (GitHub's
   lifetime, not configurable). The source caches one token per
   repository and re-mints when a cached token is within 5 minutes of
   expiry, so a token is never knowingly presented near its deadline.

What a stolen artifact is worth: a leaked *installation token* is ≤ 1 hour
of merge capability on one repository; a leaked *App private key* is the
standing credential (rotate it in the App's settings; every outstanding
JWT and token dies with its own short TTL). GitHub also exposes
`DELETE /installation/token` to revoke a live installation token —
wiring that into the kill path is future hardening, not shipped; today
the bound on a leaked token is its ≤ 1 h expiry and one-repo scope.

### Where the key lives: the token broker, and the uid problem

File modes defend against other USERS. They do nothing against a process
under the **same uid** — and in the stdio MCP deployment the client spawns
the gateway, so gateway and agent share a uid. A key file the gateway can
read is a key file the AGENT can read; 0600 does not change that, and a
same-uid agent that discovers the path could mint its own tokens forever.
So the key does not live in the gateway.

The shape is the **executing merge broker**
(`src/merge-broker.ts`, `ownerswitch-merge-broker`): a separate small
process **under its own uid** that alone reads the PEM and mints
installation tokens — and **never returns a token**. It performs the merge
itself and returns only the outcome. The gateway
(`OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET`) never holds the key, and never
holds a token either.

**Why the broker executes, instead of vending tokens.** An earlier design
had the broker return a `contents: write` installation token. That was the
wrong boundary: a `contents: write` token authenticates git-over-HTTPS, so
anything that could reach the socket held raw push authority — and within
one uid *nothing distinguishes the gateway from the agent*. A same-uid
agent could take the token and push directly, bypassing owner review, the
ticket, the nonce, the head pin and policy entirely. The separate uid
protected the standing KEY; it did not preserve the AUTHORIZATION BOUNDARY,
and the boundary is the whole product. So the broker never hands out raw
authority. It hands out a *result*.

**What crosses the socket** (`{op}` → response):
- `pin-head` → the PR's current head sha (read-only, for the review-time
  pin). Data, not authority.
- `merge {grant, args}` → the outcome of the merge. Never a token.

**How a merge is authorized — the broker validates independently, trusting
nothing the gateway says.** The evidence is a **MergeGrant**
(`packages/shared/src/merge-grant.ts`):
- **Who mints it:** the CONTROL PLANE, at the moment the owner ACTIVELY
  APPROVES the exact call — never a quiet timeout (`server.ts` `getVeto`):
  a merge is grant-eligible only through a positive owner "yes", because
  the party that REGISTERS a window is untrusted under the same-uid model
  (it can forge the gateway's device secret), so silence-approval would let
  the agent's own registration release itself. And the "yes" is not a
  bearer token: with a passkey enrolled (`ownerPasskey`), approval demands
  a FRESH WebAuthn ASSERTION (`webauthn.ts`) — a server-minted, single-use,
  short-lived challenge bound to {windowId, callHash}, signed by the
  owner's authenticator with user presence AND user verification, counter
  checked against cloning, redeemed atomically (spent by its first
  presentation, valid or not). A stolen owner SESSION therefore cannot
  approve anything: the session only opens the ceremony; the authenticator
  in the owner's hand completes it. Session-only approval survives solely
  in dev mode; a non-dev control plane without an enrolled passkey refuses
  approvals outright. Not the gateway: within one uid the gateway can hold
  no secret the agent cannot read, so nothing the gateway knows can
  authorize a merge. The grant is signed with a key
  (`OWNERSWITCH_GRANT_KEY`) the control plane shares ONLY with the broker —
  never in the gateway/agent environment, and its `killEpoch` is the epoch
  AT APPROVAL, so a window registered during a kill cannot become authority
  that outlives the kill.
- **The owner's "no" outranks an issued grant.** A grant in flight is
  revocable until dispatch: the control plane remembers every jti it
  minted, a purposed window accepts a VETO even after approval, and the
  broker's signed kill-state probe (`/kill-state?nonce=…&jti=…`) answers
  `grantLive` — false the moment the window is vetoed, unknown, or the
  control plane restarted. The broker requires `grantLive === true` both
  before the token mint and again immediately before the PUT, so
  approve → grant fetched → owner vetoes → the merge still refuses. The
  liveness answer rides inside the same HMAC-signed, nonce-bound envelope
  as the kill state, so an impostor cannot vouch for a grant any more than
  it can fake "not killed".
- **Both pins, head AND base.** The review-time pin records the PR's head
  sha and its DESTINATION (`expectedBaseRef`), both server-derived, both in
  the owner-reviewed canonical args, both signed. GitHub enforces the head
  atomically at merge time (`sha`); it offers NO base guard and allows
  retargeting a PR after approval — so the executor re-reads the PR's base
  immediately before the PUT and refuses on mismatch. Stated honestly: that
  read-then-PUT pair is not atomic, so a retarget landing in the
  milliseconds between them can still slip through; the pin shrinks the
  window from "any time since approval" to that gap, and the veto/kill
  paths remain the owner's recourse. (GitHub's API docs describe both
  behaviors; there is nothing stronger to build on.)
- **What is inside it:** the exact tool call the owner reviewed (tool,
  agentId, canonical args), the SIGNED PURPOSE the window was registered
  under (`connector` + `operation`, plus the gateway's authorization-world
  hash `policyVersion`), the content hash of the canonical args, the kill
  epoch at approval, a single-use id (`jti`), and a short expiry —
  **anchored to the release moment**, not to whichever read finally
  fetched the grant: a release that sits unread past the grant window is
  served `spent`, never a later fresh capability.
- **Who verifies it:** the BROKER, independently — signature under the
  shared key, version, expiry, hash↔args, **and purpose**: the broker
  serves exactly one purpose (`github`/`merge_pull_request`) and refuses
  any other before even burning the jti. An owner approval registered for
  some other tool can never be spent as a merge, however merge-shaped its
  arguments — and the control plane will not mint a grant for such a
  window in the first place (`grantEligibleArgs`). The gateway relays the
  grant but cannot forge one.
- **Where single-use burns — twice, both agent-inaccessible, neither in
  volatile memory alone:** the control plane issues each window's grant at
  most once (a second read is served `spent`), and the broker burns the
  `jti` in a DURABLE, atomic store (`burn-store.ts` — an O_CREAT|O_EXCL
  record create, fsynced, that survives broker restarts and arbitrates
  between broker processes sharing the directory; a burn the store cannot
  persist is a refusal, never a memory-only pass). The gateway's own
  in-process nonce store is now only defense in depth, not the boundary.
- **Args must match:** the broker merges the SIGNED args — parsed under
  the CLOSED merge schema, unknown fields refused — and refuses any wire
  args that do not re-canonicalize to them.
- **The broker's answers stay honest under pathology:** its
  per-connection timeout is PHASE-AWARE — before dispatch it refuses
  (nothing was sent); once the PUT is in flight it answers
  `connector`/`unknown`, never "refused", because the merge may still
  land after the response and the caller must not hear "safe to retry"
  while GitHub is executing. Each burned grant's outcome is recorded in
  its burn record, and `{op:"outcome", jti}` (read-only, grants nothing,
  deliberately not kill-gated) resolves an in-doubt dispatch after the
  fact. The gateway-side client mirrors the same stance: any transport
  failure after the request was written to the socket maps to `unknown`,
  never `not-performed`.

**Peer verification of the socket, honestly.** Pure Node exposes no
`SO_PEERCRED`, so the kernel-enforced part of the allow-list is the socket
inode's connect(2) permission: the broker refuses to listen unless the
socket directory is broker-owned with **no world access** (deploy it
**setgid `02750`** — see the GID note below), and chmods the socket 0660
after listen. **A unix socket inherits the broker process's effective GID,
not the directory's group**, so the broker also reads the socket's actual
gid after bind and — when `OWNERSWITCH_BROKER_SOCKET_GID` is set — refuses
to serve if it is not the intended group. The deployment makes the two
agree with a setgid socket directory (so new inodes inherit the dir's
group) and/or by running the broker with that gid (`sg <group>`). Without
that, a directory whose group is the allow-list does *not* by itself make
the socket connectable by that group.

**What a same-uid agent that finds the socket can obtain NOW.** It can read
a head sha (`pin-head` — public-ish, low value), and it can obtain a merge
ONLY by also presenting a currently-valid, unburned, owner-approved grant —
which it cannot mint, because the signing key is not in its reach. It can
never obtain a token or the key. `SO_PEERCRED` would not improve this,
because it cannot tell gateway from agent within one uid; the executing
design removes the thing worth stealing instead. Residual risk, stated: a
same-uid agent that races the gateway for a freshly-issued grant before the
gateway consumes it could present it — but the control plane issues each
grant once and the broker burns the jti, so at most one merge results from
one owner approval, and it is exactly the merge the owner approved. Detail
in THREAT-MODEL.md §5.

**The broker and kill state.** The broker checks live kill state — same
fail-closed contract as every other check — **before every pin and every
merge**, and for a merge it additionally requires the grant's kill epoch to
equal the live epoch AND re-checks across the token mint (the TOCTOU close:
the mint can take seconds, so a kill landing during it aborts before
anything is sent). Killed, or control plane unreachable, means nothing acts.
What a kill does NOT do is revoke a token already on GitHub's side of a
dispatched call (there is none held anywhere else) — the in-flight boundary
is unchanged.

That kill check is only as trustworthy as the channel it runs over, so the
channel is AUTHENTICATED (`signed-kill-state.ts`). The broker does not poll
the unauthenticated `/status`; it calls `GET /kill-state?nonce=<fresh>` and
requires an HMAC-signed envelope (shared `OWNERSWITCH_KILL_STATE_KEY`) over
{killed, epoch, nonce, expiresAt}. This closes an impersonation hole: if
the isolated control plane stops, a hostile local process can bind the
unprivileged loopback port and answer `{killed:false}` — but it cannot
sign, and a replayed real answer carries a stale nonce, so every unforged
or stale answer reads as KILLED. Fail-closed means "closed against an
impostor," not merely "closed when the socket refuses."

A **single-process mode** exists for deployments that genuinely separate
the gateway's uid from the agent's by other means (or accept the risk):
the `OWNERSWITCH_GITHUB_APP_*` triple loads the key into the gateway
process — and **refuses to start** unless
`OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK=1` is set, then starts
with a loud warning naming exactly the isolation it does not have. It
never silently claims what it cannot deliver: in a stdio deployment this
mode means the agent can read the key, full stop.

### Provisioning (once, by the operator)

1. Create a GitHub App on the org (or user) that owns the target repos.
   Repository permissions: **Contents: Read & write** and **Pull
   requests: Read-only**. No webhooks, no other permissions.
2. Install the App on **exactly the repositories** the executor may merge
   in (repository-scoped — "All repositories" and enterprise-owned
   installations are unsupported, see above). The installation is itself
   a scope: a token minted here cannot reach an uninstalled repo no
   matter what a ticket says.
3. Generate a private key in the App's settings; a `.pem` downloads.
4. Create the broker's user (e.g. `oswitch-broker`) and a shared group
   for the socket (e.g. `oswitch`) with the gateway's user in it. Put the
   key at an absolute path owned by the BROKER's user, mode `0600`,
   **outside the agent's workspace** (e.g. `/etc/ownerswitch/github-app.pem`)
   — the same placement rule as the kill-state file. The loader
   (`src/github-app-key.ts`) enforces what is checkable — absolute path,
   not under the AGENT WORKSPACE it is given explicitly (never implied
   from `process.cwd()`), regular file behind no symlink, ≤ 64 KiB, no
   group/world access, owned by the loading process's uid, parses as an
   RSA key — and refuses to start otherwise. The placement rule itself (a
   host path the agent has no route to) remains a deployment requirement
   no process can self-verify.
5. Generate a strong random **grant key** and give it to the control plane
   (`ControlPlaneOptions.grantKey` / its `OWNERSWITCH_GRANT_KEY`) AND the
   broker (`OWNERSWITCH_GRANT_KEY`) — and NOWHERE else. This is the key the
   broker verifies MergeGrants with; the gateway must never see it.
6. Create the socket directory **setgid** so inodes inherit the shared
   group: `install -d -o oswitch-broker -g oswitch -m 02750
   /run/ownerswitch`. Run the broker under its own uid with the shared
   group as its effective gid (e.g. `sg oswitch -c '…'`):
   `OWNERSWITCH_GITHUB_APP_ID`, `OWNERSWITCH_GITHUB_APP_INSTALLATION_ID`,
   `OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE`,
   `OWNERSWITCH_AGENT_WORKSPACE` (the agent's workspace, explicitly),
   `OWNERSWITCH_GRANT_KEY`,
   `OWNERSWITCH_BROKER_SOCKET` (e.g. `/run/ownerswitch/broker.sock`),
   `OWNERSWITCH_BROKER_SOCKET_GID` (the shared group's gid — the broker
   refuses to serve if the socket does not end up owned by it),
   `OWNERSWITCH_CONTROL_PLANE_URL`, and ideally
   `OWNERSWITCH_BROKER_ALLOWED_REPOS`.
7. Point the gateway at it by environment (never argv, never the config
   file): `OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET=/run/ownerswitch/broker.sock`.
   The gateway needs NO GitHub credential and NO grant key. Setting both
   the broker socket AND the `OWNERSWITCH_GITHUB_APP_*` triple is refused —
   the credential lives in exactly one place. A partial triple is refused
   naming what is missing (`packages/mcp/src/github-app-env.ts`).
   `OWNERSWITCH_GITHUB_TOKEN` is NOT an accepted credential; if set anyway
   it only arms scrubbing and the upstream env-strip.
8. **Route the merge tool through an owner-gated lane** (veto or approve),
   not `allow`: in broker mode a routed merge requires an owner-approval
   grant, so an `allow`-lane routed merge is refused (`owner-grant-required`)
   — an action that spends OwnerSwitch's own credential should never run
   with no human in the loop.

### The connector never logs or returns the credential — structurally

The scrubbing in `GitHubMergePrExecutor` is the second line of defence.
The client itself is written so a credential cannot enter a log line, an
error, a thrown object or a rejection in the first place:

- the private key, every App JWT and every installation token are
  registered with a **SecretLedger** (`src/secret-ledger.ts`) the moment
  they exist — the ledger accumulates forever, so an expired token is
  still redacted from an error produced later;
- no code path in `github-app-auth.ts` / `github-client.ts` logs, and no
  thrown error is built from a request, a header, or a raw response body.
  The ONLY thing lifted out of a response is its JSON `message` string —
  **redacted first, then truncated** (the order is load-bearing: truncate
  first and a long echoed credential is cut mid-way, leaving a fragment
  exact-match redaction can no longer recognize; a unit test pinned
  exactly that failure with an echoed App JWT), bounded to 300 chars;
- **transport failures surface as FIXED sentences** ("the request timed
  out" / "a network-level failure occurred") — a transport stack is free
  to serialize half an Authorization header into its error text, and
  exact full-secret replacement cannot redact a token FRAGMENT, so the
  channel is removed entirely instead of filtered (pinned by a unit test
  that plants a token fragment in the transport error);
- **response bodies are capped while streaming** (`boundedRequest`) — a
  hostile or broken peer cannot make the process buffer an unbounded body
  just to truncate it later, and one timeout covers the connection AND
  the body read;
- **every request refuses redirects** (`redirect: "error"`): an
  authenticated request following a redirect hands its Bearer token to
  whoever controls the Location header;
- every error message passes through the ledger's redaction at
  construction, because GitHub's own auth errors quote credentials back
  ("Bad credentials: ghs_…") — simulated in the unit tests with responses
  that echo the live token and the App JWT;
- the executor's scrub then runs over everything the backend emits —
  results AND errors — with the same ledger, so even a path that somehow
  escaped the client's own discipline crosses a second redaction before
  an `ExecutionFailed` refusal can carry it to the agent.

### The head pin: every approval binds to the exact head the owner saw

`expectedHeadSha` is **mandatory and server-derived**. Before the owner
sees a routed merge — before a veto window opens, before a ticket mints —
the proxy reads the PR's CURRENT head from GitHub with OwnerSwitch's own
credential (`getPullRequestHead`, `pull_requests: read`) and writes it
into the call's arguments (`packages/mcp/src/proxy.ts`,
`pinIfRoutedMerge`). From there the pinned sha is in the canonical
arguments, therefore in the ticket, the veto window the owner reviews,
the audit trail, and the merge call's `sha` parameter — "SHA that pull
request head must match to allow merge". One value, one origin, end to
end.

- **A branch that moved after review draws HTTP 409 — that is the
  point.** Commits pushed after the owner's review never merge under the
  old approval; the operator re-approves against the new head. The veto
  window's call identity includes the pinned sha, so a head that moves
  between release and retry doesn't even burn a ticket on the 409 — a
  FRESH owner review opens for the new head.
- **Agent-supplied shas are refused, not ignored.** An agent that sends
  `expectedHeadSha` gets a refusal naming why (the pin is derived at
  review time), before any owner review opens. The tool schema agents see
  says so too: for routed merge tools, `tools/list` advertises
  OwnerSwitch's OWN input schema (owner, repo, pullNumber, mergeMethod —
  `additionalProperties: false`) IN PLACE of whatever the upstream
  declares under that name, with a description stating the pin. A routed
  tool the upstream doesn't advertise stays unadvertised; the call-time
  refusal is the enforcement either way.
- A ticket without `expectedHeadSha` does not even parse
  (`parseMergePrArgs`) — defense in depth beneath the proxy.
- The pin read refusing (PR already merged, unusable head, GitHub down)
  fails CLOSED: the call is refused before anything opens or burns.

### Ambiguous dispatch: what GitHub offers, and what stays ambiguous

The nonce burns before the connector call (§3), so a dispatch that fails
after GitHub may have accepted it is never retried. Checked against the
API documentation rather than assumed: **GitHub offers no idempotency key
for `merge_pull_request`.** It offers the conditional head-match guard
(the mandatory pin above) and one adjacent property the connector uses:

**Verification after the fact.** Merges are readable ground truth:
`merged` and `merge_commit_sha` on `GET /repos/{owner}/{repo}/pulls/{n}`
(and the dedicated 204/404 merged-check endpoint). After an ambiguous
dispatch — the PUT died on the wire, timed out, drew a 5xx, drew a status
the merge endpoint does not document, or answered 200 without confirming
the merge — the client performs **one verification read**. Precision
about what that read proves, everywhere the answer travels (result
fields, the audit trail, this document): **the read proves the pull
request IS merged; it cannot prove THIS dispatch performed the merge.**

- the read shows **merged** → reported as success, with the
  `merge_commit_sha`, and a `message` that states exactly the above —
  merged state confirmed, attribution undeterminable;
- the read shows **not merged** → reported failed with outcome UNKNOWN,
  and the error says why plainly: a request that died on the wire can
  still complete after the read, so the answer is a snapshot, not proof;
- the read itself fails → outcome UNKNOWN, with the same instruction.

**Failure classification is a whitelist, not a guess.** Only the statuses
GitHub documents for the merge endpoint — 403, 404, 405, 409, 422 — plus
401 (auth) and 429 (rate limiting) are trusted to mean "GitHub received
and refused this; the merge did not happen", reported as "not-performed"
(`ConnectorCallError`) so the agent hears "did NOT run"
(`packages/mcp/src/errors.ts`). **Any unrecognized status — including an
intermediary-generated 408 — is treated as UNKNOWN and takes the
verification path**, never a false "did NOT run": an intermediary's
status line says nothing about what reached GitHub behind it.

What the operator sees in the residual case: an `ExecutionFailed`
(`-32057`) whose message names the double failure and instructs "check
`owner/repo#n` directly before re-approving — a re-approved merge could
run the action twice."

### What the test suite proves, and what only a live run can

Unit tests (`src/github-client.test.ts`, `src/github-app-auth.test.ts`,
`src/merge-broker.test.ts`, and `packages/shared/src/merge-grant.test.ts`)
run against scripted responses only — success, 404, 403, 405, 409, 422,
primary and secondary rate limits, an unrecognized 408 taking the
verification path, a 200 that fails to confirm the merge,
credential-echoing errors, token FRAGMENTS in transport errors,
stream-cap enforcement, redirect refusal, dot-segment and length
rejection, the enterprise down-scoping refusal, grant signing/verify
(bad signature, expiry, replay, args mismatch), the broker's kill/epoch
gate and TOCTOU recheck, socket gid verification, and the mandatory
pin end to end, and the broker over a real UNIX socket (directory
hardening, socket mode, kill gate, allow-list, protocol bounds, error
redaction). **Nothing in the test suite performs a live merge.** The one
live run is a documented manual procedure against a throwaway repository
— `MANUAL-VERIFICATION.md` states the steps, what the run proves, and
what it deliberately does not.

## 7. Wired / still stubbed

**Wired:** this document; `ActionTicket` (including source tool, verdict
decision and rule id for the audit trail); the pure refusal core (kill /
epoch / expiry / nonce) plus the second pre-dispatch re-check (§3);
`ExecutorBackend` with `execute(ticket)`; the control-plane `/status` epoch
field and its fail-closed client; veto windows epoch-bound server-side,
with `spent` served for a release from a dead epoch (§3);
`liveKillStateFromControlPlane` backing the executor's live re-checks
(§3); the proxy wiring — config-declared `executorRoutes` with the
alias-coherence gate (§1), the authorization hash covering policy AND
routes, ticket minting on yes, `executor.run()` instead of `forward()` for
routed operations, result relayed to the agent
(`packages/mcp/src/executor-route.ts`, `proxy.ts`, `config.ts`);
end-to-end tests over a fake backend proving the claim as stated in §3 — a
kill observed by the pre-dispatch check refuses the ticket and the backend
is never called (engaged, kill-then-restore epoch mismatch, and a spent
veto release), expired ticket refused, replayed nonce refused, unreachable
control plane refused, a happy path where the backend runs exactly once
and the agent receives the result, never a token — and a leak test where
the backend genuinely holds the credential and an upstream error that
echoes it reaches the agent scrubbed.

**And now wired: the live GitHub call, behind the executing broker.**
`merge_pull_request` is **shipped**: `createGitHubMergeClient` performs the
merge with a GitHub App installation token minted per repository (§6); the
**executing merge broker** (`ownerswitch-merge-broker`) holds the private
key under its own uid, **never returns a token**, validates a
control-plane-signed single-use **MergeGrant** independently, and performs
the merge itself — the gateway (`OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET`)
holds neither the key nor a token. Signed grants (the shared
`OWNERSWITCH_GRANT_KEY`) are minted by the control plane at owner-approval
time and burned single-use on both the control-plane and broker sides —
**ticket signing for this path has moved from future work to shipped**.
Every merge carries a **mandatory, server-derived `expectedHeadSha`** pinned
at review time (a moved branch draws 409 or a fresh review); the closed
agent schema is ENFORCED, not just advertised (an unknown field or invalid
`mergeMethod` refuses before any head read), and the canonical action is
built from the normalized object, never spread from raw input; kill state
is re-checked before the mint AND across it (TOCTOU); ambiguous dispatches
get one verification read worded for what it proves; rejection
classification is a documented-status whitelist; and the SecretLedger's
redaction backs the client (fixed transport sentences, stream-capped
bodies, redirect refusal) and the executor's scrub. The same-process triple
survives only behind an explicit same-uid risk acknowledgment. The
injectable `GitHubMergeClient` seam remains — tests never hit GitHub.

**Still stubbed / not yet:** a shared nonce store — until one exists the
single-gateway constraint in §5 stands; a general signed-ticket scheme for
connectors beyond this path (the MergeGrant covers the merge path today);
revoking live installation tokens on kill (`DELETE /installation/token`,
§6); `SO_PEERCRED`-grade peer identification on the broker socket (needs a
native module or a socket-activation supervisor; today the kernel-enforced
checks are the socket directory's ownership/mode and the verified socket
gid, §6); any connector beyond `merge_pull_request`.
