# 🔴 OwnerSwitch

**The kill switch your AI agents can't talk their way around.**

Owner-controlled, fail-closed control layer for AI agents. Every tool
call routed through the gateway is checked against live policy and kill
state before it runs. The architecture we're building toward: agents
never hold real credentials at all — they get short-lived, scoped
tokens issued by an OwnerSwitch broker, so kill means no more tokens.
That broker is roadmap, not shipping code (`packages/sdk` is a stub);
until it lands, "no real keys in the agent's hands" is deployment
discipline on your side, not a guarantee OwnerSwitch enforces.

*One press to stop. Two GOs to start.*

**New here? [First Kill in 10 minutes](FIRST-KILL.md)** — install, put a
demo agent behind the gateway, veto it, kill it, prove the kill survives a
restart, and restore with the 2GO ceremony. Every command pre-run on a
fresh clone; no AI client or API key needed.

## How a tool call is decided

| Decision | Meaning |
| --- | --- |
| `allow` | runs immediately, logged |
| `veto` | held 3–5 min; one tap from the owner stops it |
| `approve` | default-deny; runs only after passkey approval (2GO) |
| `deny` | never runs — also the state of *everything* once the kill switch is engaged |

Unknown tools hit the fail-closed default (`approve`): if OwnerSwitch
doesn't know an action, the owner decides.

## What KILL guarantees (and what it doesn't)

**The guarantee:** no NEW authorized action crosses the OwnerSwitch
enforcement boundary after KILL. Every tool call routed through the
gateway is checked against live kill state at decision time; once KILL
is engaged, every one of them is denied.

**Measured, not "fast":** kill-to-deny latency — from `POST /kill`
returning to the next gateway evaluation denying a previously-allowed
call — benchmarked at **p50 0.75 ms / p99 2.3 ms** (300 runs, localhost
loopback, a real fsync'd kill-state write included in every run; network
between your gateway and control plane adds its own round trip on top).
Reproduce it yourself: `pnpm bench:kill-latency`
([examples/kill-latency-benchmark.ts](examples/kill-latency-benchmark.ts)).

**The limit:** in-flight actions aren't interrupted — today. A call the
gateway already forwarded upstream runs to completion; KILL stops the
next one. Aborting outstanding upstream calls at the moment the kill
lands is designed and tracked in
[#53 (in-flight abort on KILL)](https://github.com/ownerswitchai/ownerswitch/issues/53),
with the residual it cannot remove stated up front: a request that
already reached the upstream may have taken effect — abort cancels our
side of the wire, it is not a rollback. And the guarantee covers calls
that route through the gateway, nothing an agent reaches by other means
(see [Enforcement boundary](#enforcement-boundary)).

**Scoped kill — stop one agent, not the fleet.** `POST /kill` with an
`agentId` stops that agent only: every call carrying its id is denied at
the gateway, and the control plane refuses to open review windows for
it, approve its pending calls, or commit its grants. Stopping an agent
is as cheap as stopping everything; restoring one takes the same 2GO
ceremony, scoped. A scoped kill bumps the global kill epoch on purpose —
every in-flight approval needs a fresh owner decision afterwards — and
if more than 64 agents pile up scope-killed, the next one escalates to
the global kill rather than being refused: stopping never fails on a
capacity ceiling.

**Cumulative limits — declared budgets with teeth.** The community
`KILLSWITCH.md` convention declares agent boundaries in prose — spending
thresholds, error budgets, call-rate ceilings — that an agent is free to
ignore. OwnerSwitch enforces the same boundaries as configuration:
`limits` rules in the gateway config count across calls (`calls`,
`errors`, or an `amount` read off the call's own arguments, over a
sliding window or the process lifetime), and a tripped `kill`-action
rule refuses the crossing call and fires the same signed, scoped kill a
honeytoken does — the agent that blew its budget stops, the fleet keeps
running, and restoring it is the owner's 2GO ceremony. `alert`-action
rules only flag — they never block, whatever tripped them. When a metric
counts decides what its kill can promise: `calls` and `amount` meter
**before** dispatch, so the crossing call is refused and never runs;
`errors` meters **after** dispatch — the failing call already happened,
and the kill stops the next one. An error budget is a circuit breaker on
a failing agent, not a promise that the failure which crossed it was
prevented.

The durable record of a tripped kill is the control plane's persisted scoped kill —
delivered synchronously on the crossing refusal, with the response
validated (the agent echoed back, its commit epoch carried, no degraded
persistence, redirects refused) before the latch reads it as confirmed.
That commit epoch matters because the epoch line is shared: without it a
neighbouring agent's kill epoch could pass for this kill's world and a
stale snapshot could look like the owner's restore. The record goes to
the one store the
agent cannot reach (a gateway-side file would be the agent's own file
under the stdio deployment's shared uid, so none is kept). Stated
honestly: the counters themselves are gateway-process state (one budget
per gateway — two gateways under one agentId count separately), and an
agent that can kill the gateway process can reset them by crashing it
before a threshold. Arming a `kill`-action budget therefore requires
`OWNERSWITCH_LIMITS_ACCEPT_PROCESS_LOCAL_BUDGET_RISK=1` — an explicit
acknowledgment that either the deployment removes that capability (the
restricted-runtime profile: no shell, no subagents) or accepts the
bound; control-plane-side budgets are the tracked follow-up. Budgets
meter ATTEMPTED dispatches; while the control plane is unreachable
every call is already denied fail-closed. On a `kill`-action rule an
unreadable amount trips rather than passing unmetered, amounts count in
integer atomic units (a rounding budget is no budget), and the latch
releases only when the owner's 2GO restore is observed on `/status` —
never by a restart.

```jsonc
// gateway config
"limits": [
  { "id": "spend",  "tool": "stripe.*", "metric": "amount", "amountPath": "cents",
    "max": 10000, "windowMs": 3600000, "action": "kill" },
  { "id": "errors", "tool": "*", "metric": "errors", "max": 20, "action": "kill" },
  { "id": "rate",   "tool": "*", "metric": "calls",  "max": 300, "windowMs": 60000, "action": "alert" }
]
```

**Where this is headed:** once the credential broker above ships, KILL
also means no more tokens — the shorter the TTL, the smaller the window
between KILL and everything downstream going dark. That's the
highest-ranked deployment model in the
[threat model](packages/mcp/THREAT-MODEL.md); it isn't built yet.

## Enforcement boundary

The gateway enforces policy on calls that **route through it**: checked
against live kill state, fail-closed on doubt. It does not confine an
agent that also has direct file, shell, or network access — for that
agent a denial removes permission, not capability, and a repeated user
request can be read as authorization to use a non-routed path (we have
watched it happen). Containment comes from what you deploy around the
gateway — credential broker, sandboxed egress, OS-level enforcement —
ranked honestly in the [threat model](packages/mcp/THREAT-MODEL.md).
Don't read the quickstart as a containment promise.

## FAQ — the skeptic's questions, answered with links

**What exactly does the button stop?**
Every tool call routed through the gateway, at decision time, against
live kill state — measured kill-to-deny at p50 0.75 ms on loopback. See
[What KILL guarantees](#what-kill-guarantees-and-what-it-doesnt).

**Does it interrupt an operation already in progress?**
Not today — an already-forwarded call runs to completion; KILL denies
the next one. In-flight abort is designed in
[#53](https://github.com/ownerswitchai/ownerswitch/issues/53), and even
then one residual stays: what already reached the upstream may have
taken effect. We say so instead of pretending otherwise. See
[What KILL guarantees](#what-kill-guarantees-and-what-it-doesnt).

**How does OwnerSwitch know what the agent is doing?**
It doesn't watch the agent — it sits on the agent's tool-call path. The
gateway IS the agent's MCP server, so every call the agent makes through
it is inspected before it runs; nothing is inferred from logs after the
fact. See [How a tool call is decided](#how-a-tool-call-is-decided).

**And if the agent acts outside the gateway?**
Then OwnerSwitch never saw it — a denial removes permission, not
capability, and we've watched an agent route around a correct denial
with its own built-in tool. Containment is a deployment property
(credential broker, sandbox, OS enforcement), not a library feature; the
honest ranking is in
[Enforcement boundary](#enforcement-boundary) and
[packages/mcp/THREAT-MODEL.md](packages/mcp/THREAT-MODEL.md).

## Layout

```
apps/web              — ownerswitch.ai landing (static)
apps/owner            — the owner's phone app: veto, delivery ack, device enrollment
packages/shared       — policy model types + wire contracts
packages/gateway      — the decision engine + limit budgets (start here)
packages/mcp          — MCP gateway: OwnerSwitch in front of any MCP server (+ doctor/verify)
packages/sdk          — agent-side client (stub)
packages/button       — physical kill button daemon (keyboard, HTTP, or serial e-stop)
packages/honeytoken   — decoy credentials that trip an automatic kill on touch
packages/control-plane— kill state, veto windows, 2GO restore, device standing, audit
packages/escalation   — the alert ladder: push, SMS, voice, email — until the owner answers
packages/executor     — the executing merge broker (grant-gated GitHub merges)
packages/restricted-runtime — locked-down launch profile for the gateway process
```

## Dev

```bash
pnpm install       # installs AND builds the workspace (root `prepare`)
pnpm typecheck
pnpm test
```

The packages import each other's build output, so an installed-but-unbuilt
tree fails with `ERR_MODULE_NOT_FOUND … /dist/index.js`. `pnpm install`
builds; if you ever see that error anyway, `pnpm build` is the fix.

## Status

Pre-launch, building in public — [@ownerswitchai](https://x.com/ownerswitchai) · [ownerswitch.ai](https://ownerswitch.ai)

License: [FSL-1.1-ALv2](LICENSE.md) — Functional Source License. Free to
use, read, modify, and self-host for anything except building a competing
product or service; each version automatically becomes Apache-2.0 two years
after release.
