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

**The limit:** in-flight actions aren't interrupted. And today that's
the whole guarantee — it covers calls that route through the gateway,
nothing an agent reaches by other means (see
[Enforcement boundary](#enforcement-boundary)).

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

## Layout

```
apps/web              — ownerswitch.ai landing (static)
packages/shared       — policy model types
packages/gateway      — the decision engine (start here)
packages/mcp          — MCP gateway: OwnerSwitch in front of any MCP server
packages/sdk          — agent-side client (stub)
packages/button       — physical kill button daemon (keyboard, HTTP, or serial e-stop)
packages/honeytoken   — decoy credentials that trip an automatic kill on touch
packages/control-plane— policies, kill state, audit (stub)
```

## Dev

```bash
pnpm install
pnpm typecheck
pnpm test
```

## Status

Pre-launch, building in public — [@ownerswitchai](https://x.com/ownerswitchai) · [ownerswitch.ai](https://ownerswitch.ai)

License: [FSL-1.1-ALv2](LICENSE.md) — Functional Source License. Free to
use, read, modify, and self-host for anything except building a competing
product or service; each version automatically becomes Apache-2.0 two years
after release.
