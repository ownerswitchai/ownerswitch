# @ownerswitchai/control-plane — kill state, veto windows, 2GO restore

The one small, framework-free process every other component answers to.
Stops are cheap and attributable; starts are expensive and ceremonial.

## Surface (see `src/server.ts` for the full contract)

| route | auth | direction |
| --- | --- | --- |
| `POST /kill` | device-signed or loopback | stop — free forever |
| `POST /kill` `{agentId}` | device-signed or loopback | stop ONE agent (scoped kill) — same cheapness |
| `POST /veto/:id` | owner session, or device-signed (deny-only relay) | stop |
| `POST /veto/:id/seen` | device-signed only | delivery ack (the permissive bit; 60 s response floor) |
| `GET /veto/pending`, `GET /veto/:id` | device-signed for pacing fields | read |
| `POST /veto/:id` `decision:approve` | owner session + passkey assertion | start (merge grant) |
| `POST /restore/ceremony` → `POST /restore` | owner session + passkey; 2GO cooldown | start — **the licensed act** |
| `POST /restore/ceremony` `{agentId}` → `POST /restore` | owner session + passkey; 2GO cooldown | start ONE scope-killed agent — same ceremony, scoped |

Scoped kills ride the same rails as the global switch: `GET /status`
always serves `killedAgents` (gateways fail closed on its absence, like
`epoch`), a scoped kill bumps the global kill epoch so pre-kill
approvals die with it, the state file persists scope-killed agents
across restarts, and at 64 scope-killed agents the next distinct scoped
kill escalates to the global kill instead of failing — stopping has no
capacity ceiling. Rollout order matters and fails in the safe
direction: a NEW gateway polling an OLD control plane reads the missing
`killedAgents` as an untrustworthy answer and denies everything —
upgrade the control plane first, then its gateways.

## 2GO licensing (`src/license.ts`)

One press to stop is free, forever, for everyone — no stop path consults a
license, by construction (the only enforcement point in the codebase is
the restore-ceremony start, which answers **402** unlicensed). Two GOs to
start is the product, and **production is protected by default**: the
production launcher (`packages/mcp/src/control-plane.ts`) arms the gate
against the pinned official vendor key
(`OWNERSWITCH_VENDOR_LICENSE_PUBLIC_KEY_PEM`) with zero configuration —
a fresh production plane stops perfectly and answers 402 on restore until
its token arrives. A TEAM/ENTERPRISE deployment provisions just

```
OWNERSWITCH_LICENSE=osl1.<payload>.<signature>
```

(`OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE` overrides the pinned key for
self-hosted forks; dev/quickstart instances stay ungated.)

Tokens are Ed25519-signed, verified offline — no phone-home, no
telemetry, air-gap friendly. An expired license keeps restoring for a
**72 h grace** (`RESTORE_GRACE_MS`): the paywall must never become a
ransom note over a killed fleet. Past the grace the fleet stays safely
stopped until renewal — fail closed, like everything else here.

**Theft containment:** a license is not an authorization credential —
restoring a fleet still demands that fleet's owner session, passkey and
the 2GO ceremony, so a stolen token can never restore *your* systems; at
worst it runs a stranger's deployment under your name. Mint with
`--deployment <id>` to close even that: a bound token verifies only on
the control plane whose `OWNERSWITCH_DEPLOYMENT_ID` matches, and dies
anywhere else. The `jti` on every token is the hook for a revocation
list if one is ever needed.

Vendor tooling: `ownerswitch-license keygen | mint | inspect`
(`src/license-cli.ts`); key material travels by file path, never argv.
Dev/quickstart instances (no licensing option) are ungated.
