# 🔴 OwnerSwitch

**The kill switch your AI agents can't talk their way around.**

Owner-controlled, fail-closed control layer for AI agents. Agents never
hold real credentials — they get short-lived, scoped tokens through the
OwnerSwitch gateway. Kill = no more tokens.

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

## Layout

```
apps/web              — ownerswitch.ai landing (static)
packages/shared       — policy model types
packages/gateway      — the decision engine (start here)
packages/sdk          — agent-side client (stub)
packages/button       — physical kill button daemon (V0: keyboard-mode USB buttons)
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

License: TBD before the repo goes public (Apache-2.0 vs FSL — open question).
