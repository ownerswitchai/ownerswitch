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
| `resourceId`    | `string`  | stable id of the object acted on, e.g. `github:pr:ownerswitchai/ownerswitch#7` — audit and future per-resource rules key on this, independent of args shape |
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
- **OwnerSwitch's credential is now the prize.** The executor holds a
  standing GitHub credential; whoever compromises the executor process
  merges without any ticket. Least privilege shrinks the blast radius; it
  does not eliminate it. That least privilege is now shipped, not
  aspirational: the connector authenticates as a GitHub App whose private
  key mints installation tokens that live at most an hour and are scoped,
  per mint, to one named repository and two permissions — §6 has the full
  model, including where the key must live and what a stolen artifact of
  each kind is worth.
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
   `pull_requests: read` exists solely for the post-ambiguity verification
   read below. Nothing else is ever requested.
3. **Installation tokens expire one hour after minting** (GitHub's
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

### Provisioning (once, by the operator)

1. Create a GitHub App on the org (or user) that owns the target repos.
   Repository permissions: **Contents: Read & write** and **Pull
   requests: Read-only**. No webhooks, no other permissions.
2. Install the App on **exactly the repositories** the executor may merge
   in. The installation is itself a scope: a token minted here cannot
   reach an uninstalled repo no matter what a ticket says.
3. Generate a private key in the App's settings; a `.pem` downloads.
4. Put the key where the **agent's side cannot read it — the same rule as
   the kill-state file**: an absolute path outside the agent's workspace,
   owned by the gateway's user, mode `0600`
   (e.g. `/etc/ownerswitch/github-app.pem`). The loader
   (`src/github-app-key.ts`) enforces what is checkable — absolute path,
   not under the gateway's working directory, regular file behind no
   symlink, ≤ 64 KiB, no group/world access, owned by the process's uid,
   parses as an RSA key — and refuses to start otherwise. The placement
   rule itself (a host path the agent has no route to) remains a
   deployment requirement no process can self-verify.
5. Configure the gateway by environment (never argv, never the config
   file): `OWNERSWITCH_GITHUB_APP_ID`,
   `OWNERSWITCH_GITHUB_APP_INSTALLATION_ID`,
   `OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE`. All three or none —
   a partial set is refused at startup, naming what is missing
   (`packages/mcp/src/github-app-env.ts`). `OWNERSWITCH_GITHUB_TOKEN` is
   NOT an accepted credential; if set anyway it only arms scrubbing and
   the upstream env-strip.

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
- every error message passes through the ledger's redaction at
  construction, because GitHub's own auth errors quote credentials back
  ("Bad credentials: ghs_…") — simulated in the unit tests with responses
  that echo the live token and the App JWT;
- the executor's scrub then runs over everything the backend emits —
  results AND errors — with the same ledger, so even a path that somehow
  escaped the client's own discipline crosses a second redaction before
  an `ExecutionFailed` refusal can carry it to the agent.

### Ambiguous dispatch: what GitHub offers, and what stays ambiguous

The nonce burns before the connector call (§3), so a dispatch that fails
after GitHub may have accepted it is never retried. Checked against the
API documentation rather than assumed: **GitHub offers no idempotency key
for `merge_pull_request`.** It offers two adjacent mechanisms, and the
connector uses both:

- **A conditional guard.** The merge endpoint's `sha` parameter — "SHA
  that pull request head must match to allow merge" (HTTP 409 on
  mismatch). Tickets may carry `expectedHeadSha` (full 40- or 64-hex
  commit id, validated at parse), and the owner's approval then binds to
  the exact head they reviewed: a branch that gains commits after
  approval draws a refusal, not a merge of unreviewed code. This does not
  make the operation idempotent — it makes it precise.
- **Verification after the fact.** Merges are readable ground truth:
  `merged` and `merge_commit_sha` on `GET /repos/{owner}/{repo}/pulls/{n}`
  (and the dedicated 204/404 merged-check endpoint). After an ambiguous
  dispatch — the PUT died on the wire, timed out, or drew a 5xx — the
  client performs **one verification read**:
  - the read shows **merged** → the operation succeeded; the agent gets
    a normal result whose `message` says it was confirmed by a
    post-dispatch verification read, with the real `merge_commit_sha`;
  - the read shows **not merged** → still reported as failed with
    outcome UNKNOWN, and the error says why plainly: a request that died
    on the wire can still complete after the read, so the answer is a
    snapshot, not proof;
  - the read itself fails → outcome UNKNOWN, with the same instruction.

What the operator sees in the residual case: an `ExecutionFailed`
(`-32057`) whose message names the double failure and instructs "check
`owner/repo#n` directly before re-approving — a re-approved merge could
run the action twice." Failures the API definitively rejected (any 4xx:
404, 403/rate limit, 405 not-mergeable, 409 head-moved, 422) are NOT
ambiguous: the connector classifies them "not-performed"
(`ConnectorCallError`), and the agent-facing error says the action did
NOT run instead of the blanket "may or may not have completed"
(`packages/mcp/src/errors.ts`).

### What the test suite proves, and what only a live run can

Unit tests (`src/github-client.test.ts`, `src/github-app-auth.test.ts`)
run against scripted responses only — success, 404, 403, 405, 409, 422,
primary and secondary rate limits, credential-echoing errors, wire
deaths, and every verification branch. **Nothing in the test suite
performs a live merge.** The one live run is a documented manual
procedure against a throwaway repository — `MANUAL-VERIFICATION.md`
states the steps, what the run proves, and what it deliberately does not.

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

**And now wired (this PR): the live GitHub call.** `merge_pull_request`
moves from "stubbed" to **shipped**: `createGitHubMergeClient` performs
the merge with a GitHub App installation token minted per repository
(§6), the CLI wires it from the `OWNERSWITCH_GITHUB_APP_*` environment,
tickets may pin `expectedHeadSha`, ambiguous dispatches get one
verification read, definitive rejections reach the agent as "did NOT
run", and the SecretLedger's redaction backs both the client (first line)
and the executor's scrub (second line). The injectable
`GitHubMergeClient` seam remains — tests never hit GitHub.

**Still stubbed / not yet:** ticket signing; a shared nonce store — until
one exists the deployment constraint in §5 stands (one gateway process,
no remote executor); revoking live installation tokens on kill
(`DELETE /installation/token`, §6); any connector beyond
`merge_pull_request`.
