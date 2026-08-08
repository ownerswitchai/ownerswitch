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
| `connector`     | `string`  | which backend performs it, e.g. `"github"` |
| `operation`     | `string`  | which action within the connector, e.g. `"merge_pull_request"` |
| `canonicalArgs` | `string`  | the arguments, canonicalized (below). The executor runs *these bytes* — not a re-supplied copy — so what runs is exactly what was evaluated and approved |
| `resourceId`    | `string`  | stable id of the object acted on, e.g. `github:pr:ownerswitchai/ownerswitch#7` — audit and future per-resource rules key on this, independent of args shape |
| `policyVersion` | `string`  | content hash of the policy the verdict came from. `Policy` has no version field today, so the version *is* the hash of its canonical JSON; if the policy changed between decision and execution, the audit trail shows which policy said yes |
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
time. The ticket stores the connector/operation pair, not the MCP name, so
several MCP surfaces can front the same executor operation without the
executor caring.

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
                                                       4. backend.execute(ticket) ──▶ GitHub API,
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
| control plane | `KillSwitch` with `killed` + persisted `epoch`; ceremonies bound to the epoch; `GET /status` returns `epoch` too (§3) | unchanged |
| mcp proxy, on yes | `forward(call)` — hand the call to the upstream MCP server, pass the result through | **wired**: for operations declared in the gateway config's `executorRoutes` (MCP tool name → connector/operation), a yes — allow, or veto after release — mints an `ActionTicket` (`packages/mcp/src/executor-route.ts`) and calls `executor.run()`; the result is relayed to the agent. Every unrouted tool keeps forwarding exactly as before |
| **this package** | — | ticket type, refusal core, `ExecutorBackend`, `liveKillStateFromControlPlane` (§3), GitHub merge backend with the HTTP call still stubbed |

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
- **Kill stops new executions, not in-flight ones.** The re-check in §3
  runs immediately before `backend.execute()`; once the connector call is
  on the wire, a kill cannot recall it. This is the same enforcement
  boundary the kill switch itself documents — kill guarantees no *new*
  authorized action crosses the boundary, nothing more. What the executor
  removes is the other half of that caveat: for actions routed through it,
  there are no credentials issued downstream to outlive the kill.
- **OwnerSwitch's credential is now the prize.** The executor holds a
  standing GitHub credential; whoever compromises the executor process
  merges without any ticket. Least privilege (a GitHub App with
  short-lived installation tokens scoped to exactly the repos and the
  one permission needed) shrinks the blast radius; it does not eliminate it.
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
- **The nonce store is per-process.** In-memory in v0; two executor
  instances behind a balancer could each burn the same nonce once. A
  shared store is part of productionizing, not of this proof.

## 6. Wired / still stubbed

**Wired:** this document; `ActionTicket`; the pure refusal core (kill /
epoch / expiry / nonce); `ExecutorBackend` with `execute(ticket)`; the
control-plane `/status` epoch field and its fail-closed client;
`liveKillStateFromControlPlane` backing the executor's live re-check (§3);
the proxy wiring — config-declared `executorRoutes`, ticket minting on yes,
`executor.run()` instead of `forward()` for routed operations, result
relayed to the agent (`packages/mcp/src/executor-route.ts`, `proxy.ts`,
`config.ts`); end-to-end tests over a fake backend proving the central
claim — kill between mint and execution refuses before the backend is ever
called (engaged, and kill-then-restore epoch mismatch), expired ticket
refused, replayed nonce refused, unreachable control plane refused, and a
happy path where the backend runs exactly once and the agent receives the
result, never a token.

**Still stubbed / not yet:** the live GitHub call —
`GitHubMergePrExecutor`'s HTTP call stays behind its injectable
`GitHubMergeClient`, and the CLI wires the backend with no client, so a
routed call that clears every check fails with an explicit "not
implemented" (`ExecutionFailed`, `-32057`) rather than silently
forwarding. Also not yet: ticket signing; a persistent/shared nonce store;
any connector beyond `merge_pull_request`.
