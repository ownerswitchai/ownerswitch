# First Kill in 10 minutes

Install OwnerSwitch, put a demo agent behind the gateway, watch policy hold
and deny it, hit the kill switch, prove the kill survives a restart, and
bring the system back with the owner's 2GO ceremony. Every command below was
run, in this order, on a fresh clone before it was written down. No AI
client, no API key, and no package downloads beyond `pnpm install` — the
demo agent and its tool server live in this repo.

You need: **node 22+** and **pnpm 9** (`corepack enable`), and two
terminals.

## [0:00] Install

```bash
git clone https://github.com/ownerswitchai/ownerswitch && cd ownerswitch
pnpm install     # warnings about bins it could not create are expected here —
pnpm build       # they point at dist/ files this build step creates
```

## [2:00] Terminal 1 — the control plane

```bash
pnpm --filter @ownerswitchai/mcp dev:control-plane
```

Leave it running. It prints three things you will use: the **owner token**
(you are the owner; it is your "one tap"), the device secret the demo
config already matches, and where the **kill state** persists. Export the
token in terminal 2 so the commands below can use it:

```bash
export OWNERSWITCH_OWNER_TOKEN=<the printed owner token>
```

## [2:30] Terminal 2 — preflight, then the demo agent

```bash
cd ownerswitch/packages/mcp
npx tsx src/cli.ts doctor --config examples/first-kill.config.json
```

Every line must be `✔` — each failing line says exactly what to fix.
(You'll also see a warning that the example config is world-readable; for
this dev-secret demo that is fine, for a real config run the `chmod 600` it
suggests.) Then run the agent:

```bash
npx tsx examples/first-kill-agent.ts
```

This is a real MCP client. It spawns the **gateway**, which spawns the demo
**tool server**, and then it tries to do a day's work:

```
  RAN     list_files({})                       ← policy: allow
  RAN     read_file({"name":"welcome.txt"})    ← policy: allow
  HELD    write_file({"name":"hello.txt", …})  ← policy: veto — a window is open
          -> … A veto window (id "veto_ab12cd34ef56") is now open …
  DENIED  move_file({"from":"welcome.txt", …}) ← policy: deny — never runs
```

The policy that decided all of that is
`examples/first-kill.config.json` — five lines of rules, fail-closed
default.

## [4:00] Be the owner: veto the held write

Copy the `veto_…` id from the agent's output:

```bash
curl -X POST http://127.0.0.1:4600/veto/veto_ab12cd34ef56 \
  -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN"
# → {"status":"vetoed"}
```

Run the agent again: the write now comes back **VETOED** — held is a
decision point, and the owner just decided.

## [5:00] The kill switch

```bash
curl -X POST http://127.0.0.1:4600/kill -d '{"reason":"first kill tutorial"}'
# → {"killed":true,"epoch":1}
```

Run the agent again. **Everything** — even the reads that were allowed —
now returns:

```
  KILLED  list_files({})
          -> MCP error -32054: … Every tool call is denied until the owner
             restores OwnerSwitch …
```

That is your first kill: one HTTP call, and the agent can do nothing, with
an honest explanation instead of a mystery timeout.

## [6:00] Prove it survives a restart

In terminal 1: `Ctrl-C` the control plane and start it again:

```bash
pnpm --filter @ownerswitchai/mcp dev:control-plane
```

It boots and prints `kill state : KILLED (restore takes the 2GO ceremony)`.
Sessions and veto windows reset on restart — **the kill does not**. It
persisted to the kill-state file, and a restart is not a restore. (The
restart also printed a fresh owner token — re-export it in terminal 2.)

```bash
export OWNERSWITCH_OWNER_TOKEN=<the NEW printed owner token>
```

## [7:00] The 2GO restore ceremony

Restoring is deliberately not one call. GO 1/2 opens a ceremony and starts
a mandatory 30-second cooldown — the anti-panic, anti-social-engineering
pause:

```bash
curl -X POST http://127.0.0.1:4600/restore/ceremony \
  -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN"
# → {"id":"cer_…","state":"go1","cooldownRemainingMs":30000,…}
```

Wait out the cooldown (check progress with
`curl http://127.0.0.1:4600/restore/ceremony/cer_… -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN"`),
then GO 2/2, quoting the ceremony id:

```bash
curl -X POST http://127.0.0.1:4600/restore \
  -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"ceremonyId":"cer_…"}'
# → {"killed":false}
```

Run the agent one last time: `RAN … RAN … HELD … DENIED` — back to work,
under the same policy. Kill → restart-proof → deliberate two-step restore:
that is the whole product in one loop.

> In production GO 2/2 additionally requires the owner's **passkey**
> (WebAuthn) — a stolen session alone cannot restore. The dev control plane
> runs session-only so this tutorial fits in ten minutes; the production
> launcher and its checklist are `packages/mcp/src/control-plane.ts` and
> `packages/control-plane/STANDING-DEPLOYMENT.md`.

## Where to go next

- **Guard a real MCP server with a real agent** — the
  [`packages/mcp` README](packages/mcp/README.md) quickstart connects
  Claude Code (or any MCP client) to the same gateway, guarding the
  official filesystem server; `doctor` and `verify` catch a broken setup
  before an agent burns quota on it.
- **Budgets that trip the kill** — `limits` rules (spend / error / call
  ceilings) fire a scoped kill automatically; see the config reference in
  the same README.
- **Honeytokens** — decoy credentials that kill on first touch
  (`packages/honeytoken`).
- **What this does and does not contain** — read
  [`packages/mcp/THREAT-MODEL.md`](packages/mcp/THREAT-MODEL.md) before
  trusting any of it in production: the gateway decides the calls routed
  through it, and containment is a deployment property, not a library
  feature.
