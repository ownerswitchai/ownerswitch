# Your first kill, in 10 minutes

A hands-on walkthrough on a machine that has never seen OwnerSwitch. By the
end you will have watched a policy allow, hold, and deny a real agent's
calls, vetoed one yourself, stopped everything with one press, seen that a
restart does **not** undo it, and brought it back with the two-GO ceremony.

No AI client, no API key, and no downloads beyond `pnpm install`: the demo
agent and the tool server it works against live in this repo. That is
deliberate — the fastest way to trust a stop button is to press it yourself
before anything valuable is behind it.

**What you need:** Node 22+, pnpm 9 (`corepack enable`), a Unix-like OS
(Linux or macOS — the demo sandbox requires `O_NOFOLLOW` and refuses to
run without it, deliberately), and two terminals.
`jq` is used in a couple of commands for readability; skip it and read the
JSON yourself if you would rather. The `curl` calls use `-fsS` so an HTTP
error fails the step loudly instead of printing an error body that scrolls
past looking like success — the one place that is dropped is called out.

---

## 1. Install (≈2 min)

```bash
git clone https://github.com/ownerswitchai/ownerswitch && cd ownerswitch
pnpm install
```

`pnpm install` also **builds the workspace** (the root `prepare` script) —
about 15 seconds after the dependency install. Every command below assumes
it: the packages import each other's build output, so a workspace that was
installed but not built fails with `ERR_MODULE_NOT_FOUND … /dist/index.js`,
which reads like a broken repo and is really just a missing build. If you
ever see that, run `pnpm build`.

You will also see a batch of `WARN Failed to create bin … ENOENT` lines
*during* the install, before the build has run. They are noise from that
same ordering, and they are gone on the next install.

## 2. Start the control plane (≈30 s)

This is the thing that holds kill state. Leave it running in its own
terminal — **terminal 1** for the rest of this document.

```bash
pnpm --filter @ownerswitchai/mcp dev:control-plane
```

It prints a **device secret** (the gateway authenticates with it) and an
**owner token** (that is you, the human with the stop button — 15-minute
TTL, restart to mint a fresh one). Keep the terminal visible.

If it answers `port 4600 is already in use`, you have one running already
from an earlier attempt — keep that one, or start this one on another port
with `OWNERSWITCH_CONTROL_PLANE_PORT=4601` **and** its own
`OWNERSWITCH_KILL_STATE_FILE`.

## 3. Preflight (≈1 min)

In **terminal 2**. The demo's config ships in the repo —
`packages/mcp/examples/first-kill.config.json`: reads and listings run,
writes are held for your review, renames never run, and anything the policy
has not heard of needs you (fail closed). Its upstream is the in-repo demo
tool server, so nothing downloads.

```bash
cd packages/mcp
npx tsx src/cli.ts doctor --config examples/first-kill.config.json
```

Six lines, every one either `✔` or an instruction. Do not continue past a
non-`✔` line — that is the whole point of the command. (You will also see a
warning that the example config is world-readable; it holds only the dev
secret, but for a config of your own run the `chmod 600` it suggests.)
`doctor` checks the things that otherwise fail *inside* an MCP client,
where the only symptom is a dead connection:

| check | what it catches |
| --- | --- |
| node version | too old to run the gateway |
| config | unparseable, or missing a required field |
| **startup gates** | a config that parses but the gateway **refuses to start on** — an unacknowledged kill-action budget, a half-configured honeytoken registry, a credential passed through argv |
| control plane | unreachable, or reachable **and already killed** |
| device credentials | secret mismatch between gateway and control plane |
| upstream command | not on PATH, not executable, or not actually an MCP server |

**If you later guard a real MCP server and the upstream check times out**,
read its fix line before changing anything. The most common cause is not
the command: the upstream child is spawned with a **stripped environment**
— roughly `HOME/LOGNAME/PATH/SHELL/TERM/USER` and nothing else. Behind a
proxy or a custom CA, the exact command that works when you type it hangs
when the gateway spawns it, because `HTTPS_PROXY` and
`NODE_EXTRA_CA_CERTS` did not come along. `doctor` names the variables you
have set that the child will not inherit — declare what it needs in
`upstream.env`. A cold `npx -y` download can also outlast the 15-second
budget on a slow link; `--upstream-timeout 60000` raises it.

## 4. Prove enforcement, before an agent is anywhere near it (≈1 min)

```bash
export OWNERSWITCH_OWNER_TOKEN=<the owner token from terminal 1>
npx tsx src/cli.ts verify --config examples/first-kill.config.json
```

This runs the veto lane end to end against your real control plane: an
allowed call passes, an unknown tool lands on the fail-closed default, a
real review window opens, your token vetoes it, and it reads back vetoed.
It never touches the kill switch, so it is safe to run whenever you have
changed a policy.

The token is deliberately **not** a CLI flag — flags land in shell history
and in `ps` output. (Keep it exported; the next step uses it too.)

## 5. Run the demo agent — and veto it live (≈2 min)

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

After the HELD line the agent **pauses and waits for you** — a veto window
lives in the gateway process that opened it, so the held → vetoed
transition plays out on this same, still-open session. It prints the exact
command; run it in another terminal:

```bash
curl -fsS -X POST http://127.0.0.1:4600/veto/veto_ab12cd34ef56 \
  -H "Authorization: Bearer $OWNERSWITCH_OWNER_TOKEN" \
  -H 'content-type: application/json' -d '{"decision":"veto"}'
# → {"status":"vetoed"}
```

Press Enter back in the agent's terminal: it retries the exact same write
and gets **VETOED** — held is a decision point, and the owner just decided.

Want a real AI agent behind the same gateway instead? The
[`packages/mcp` README](packages/mcp/README.md) quickstart connects Claude
Code (or any MCP client) to it in two commands.

## 6. Be the owner: stop it (≈30 s)

The single most important command in this document:

```bash
curl -fsS -X POST http://127.0.0.1:4600/kill \
  -H 'content-type: application/json' -d '{"reason":"first kill"}'
```

Run the demo agent again — **everything**, even the reads that were
allowed, now comes back `-32054`: the kill switch is engaged. Not "this
tool is blocked" — stopped.

Two things worth doing while it is down, because they are the properties
people assume and rarely check:

```bash
# 1. it is not a mood: kill state persists to disk
#    stop the control plane in terminal 1 (Ctrl-C), start it again
pnpm --filter @ownerswitchai/mcp dev:control-plane
curl -fsS http://127.0.0.1:4600/status    # still {"killed":true,…}

# 2. no control plane, no tool calls: stop it entirely and run the agent
#    again — every call is refused, because unreachable reads as killed
```

Restarting is not a restore. There is exactly one way back. (The restart
printed a fresh owner token — re-export it before the next step.)

## 7. Be the owner: the two GOs (≈2 min)

Restoring is meant to be the expensive direction: an owner session, a
mandatory cooldown, and a single-use ceremony that expires.

```bash
OWNER=$OWNERSWITCH_OWNER_TOKEN   # the FRESH token from the restart

# GO 1/2 — open the ceremony
CER=$(curl -fsS -X POST http://127.0.0.1:4600/restore/ceremony \
  -H "Authorization: Bearer $OWNER" | jq -r .id)

# the cooldown is real; watch it drain
curl -fsS "http://127.0.0.1:4600/restore/ceremony/$CER" -H "Authorization: Bearer $OWNER"
# {"state":"go1","cooldownRemainingMs":28417,…}

# GO 2/2 — after it reaches 0
curl -fsS -X POST http://127.0.0.1:4600/restore -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' -d "{\"ceremonyId\":\"$CER\"}"
# {"killed":false}
```

Try GO 2/2 early on purpose — this one wants the status code, so drop the
`-f` that makes the others fail loudly:

```bash
curl -sS -X POST http://127.0.0.1:4600/restore -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' -d "{\"ceremonyId\":\"$CER\"}" \
  -w '\nHTTP %{http_code}\n'
# {"error":"restore rejected"}
# HTTP 409
```

That is all you get, whatever went wrong. The body never says which check
failed (wrong owner, wrong epoch, too early, replayed), because that answer
would be a map for someone who is not you. `cooldownRemainingMs` above is
the number to read; it is yours to ask for, and asking requires your token.

Run the demo agent one last time: `RAN … RAN … HELD … DENIED` — back to
work, under the same policy (just press Enter through the veto pause this
time). You have completed the loop the whole product is about — **one press
to stop, two GOs to start.**

> In production GO 2/2 additionally requires the owner's **passkey**
> (WebAuthn) — a stolen session alone cannot restore. The dev control plane
> runs session-only so this walkthrough fits in ten minutes; the production
> launcher and its checklist are `packages/mcp/src/control-plane.ts` and
> `packages/control-plane/STANDING-DEPLOYMENT.md`.

## 8. Stop one agent instead of everything (optional, ≈1 min)

A fleet does not need a fleet-wide stop for one misbehaving member:

```bash
curl -fsS -X POST http://127.0.0.1:4600/kill \
  -H 'content-type: application/json' -d '{"agentId":"mcp-gateway","reason":"just this one"}'
curl -fsS http://127.0.0.1:4600/status  # {"killed":false,"killedAgents":["mcp-gateway"],…}
```

Everything carrying that agent id is denied; every other agent keeps
running. Restoring is the same ceremony, scoped: pass `{"agentId":
"mcp-gateway"}` when opening it.

---

## What you just proved (and what you did not)

**Proved:** every call routed through the gateway is checked against live
kill state before it runs; a kill denies all of them; kill state survives a
restart of the control plane; an unreachable control plane denies rather
than allows; coming back takes an owner, a cooldown, and a single-use
ceremony.

**Not proved, and not claimed:** that the agent *cannot act*. The gateway
decides the calls that route **through it**. An agent with its own file,
shell, or network access can act without asking, and a denial removes
permission, not capability — we have watched exactly that happen.
Containment is what you build around the gateway; it is ranked honestly in
[THREAT-MODEL.md](packages/mcp/THREAT-MODEL.md). Read that next if you are
deciding whether to put this in front of something that matters.

## Where to go next

- [`packages/mcp/README.md`](packages/mcp/README.md) — the full
  configuration reference: every policy field, error code, and the veto
  lane's behaviour — plus connecting a real MCP client (Claude Code) to the
  same gateway.
- **Budgets with teeth** — `limits` rules stop an agent that spends, fails,
  or calls too much, without you watching. Kill-action budgets require
  `OWNERSWITCH_LIMITS_ACCEPT_PROCESS_LOCAL_BUDGET_RISK=1`; `doctor`'s
  startup-gates check tells you so before an MCP client turns it into a
  silent failure.
- **Honeytokens** — decoy credentials that fire a kill the moment anything
  touches them (`packages/honeytoken`).
- **A physical button** — `packages/button`, for when the stop should not
  depend on a terminal being open.
