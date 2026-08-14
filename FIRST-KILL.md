# Your first kill, in 10 minutes

A hands-on walkthrough on a machine that has never seen OwnerSwitch. By the
end you will have stopped a real agent mid-task, seen that a restart does
**not** undo it, and brought it back with the two-GO ceremony.

No agent is required for the first eight minutes: everything up to step 6 is
you, a terminal, and `curl`. That is deliberate — the fastest way to trust a
stop button is to press it yourself before anything valuable is behind it.

**What you need:** Node 22+, pnpm 9 (`corepack enable`), and a terminal.
`jq` is used in a couple of commands for readability; skip it and read the
JSON yourself if you would rather.

**Timings below are real**, measured on a warm machine with a fast link.
The two things that move them most are npm downloads and how long you spend
reading. Nothing here needs a network after step 1 except the upstream MCP
server the demo guards.

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

## 3. Write one config file (≈1 min)

In **terminal 2**. This guards the official filesystem MCP server: reads and
listings run, writes are held for your review, renames never run, and
anything the policy has not heard of needs you (fail closed).

```bash
mkdir -p /tmp/ownerswitch-demo
cat > ~/ownerswitch.mcp.json <<'JSON'
{
  "controlPlaneUrl": "http://127.0.0.1:4600",
  "device": { "id": "mcp-gateway", "secret": "dev-device-secret" },
  "upstream": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/ownerswitch-demo"]
  },
  "policy": {
    "rules": [
      { "id": "reads",  "tool": "read_*",     "decision": "allow", "description": "reading is safe" },
      { "id": "lists",  "tool": "list_*",     "decision": "allow", "description": "listing is safe" },
      { "id": "writes", "tool": "write_file", "decision": "veto",  "description": "the owner can veto writes" },
      { "id": "moves",  "tool": "move_file",  "decision": "deny",  "description": "renames never run" }
    ],
    "defaultDecision": "approve"
  }
}
JSON
chmod 600 ~/ownerswitch.mcp.json
```

The `chmod` is not ceremony: the file holds `device.secret` in plaintext, and
the gateway warns on every start until the mode is `0600`.

## 4. Preflight (≈1 min)

```bash
cd packages/mcp
npx tsx src/cli.ts doctor --config ~/ownerswitch.mcp.json
```

Six lines, every one either `✔` or an instruction. Do not continue past a
non-`✔` line — that is the whole point of the command. `doctor` checks the
things that otherwise fail *inside* an MCP client, where the only symptom is
a dead connection:

| check | what it catches |
| --- | --- |
| node version | too old to run the gateway |
| config | unparseable, or missing a required field |
| **startup gates** | a config that parses but the gateway **refuses to start on** — an unacknowledged kill-action budget, a half-configured honeytoken registry, a credential passed through argv |
| control plane | unreachable, or reachable **and already killed** |
| device credentials | secret mismatch between gateway and control plane |
| upstream command | not on PATH, not executable, or not actually an MCP server |

**If the upstream check times out**, read its fix line before changing
anything. The most common cause by far is not the command: the upstream
child is spawned with a **stripped environment** — roughly
`HOME/LOGNAME/PATH/SHELL/TERM/USER` and nothing else. Behind a proxy or a
custom CA, the exact command that works when you type it hangs when the
gateway spawns it, because `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` did not
come along. `doctor` names the variables you have set that the child will
not inherit; declare what it needs:

```jsonc
"upstream": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/ownerswitch-demo"],
  "env": { "HTTPS_PROXY": "…", "NODE_EXTRA_CA_CERTS": "…" }
}
```

A cold `npx -y` download can also outlast the 15-second budget on a slow
link — `--upstream-timeout 60000` raises it.

## 5. Prove enforcement, before an agent is anywhere near it (≈1 min)

```bash
export OWNERSWITCH_OWNER_TOKEN=<the owner token from terminal 1>
npx tsx src/cli.ts verify --config ~/ownerswitch.mcp.json
unset OWNERSWITCH_OWNER_TOKEN
```

This runs the veto lane end to end against your real control plane: an
allowed call passes, an unknown tool lands on the fail-closed default, a real
review window opens, your token vetoes it, and it reads back vetoed. It never
touches the kill switch, so it is safe to run whenever you have changed a
policy.

The token is deliberately **not** a CLI flag — flags land in shell history
and in `ps` output.

## 6. Point an agent at it (≈2 min)

For Claude Code, from this same `packages/mcp` directory:

```bash
claude mcp add ownerswitch -- npx tsx src/cli.ts --config ~/ownerswitch.mcp.json
claude mcp list     # expect: ownerswitch  ✔ Connected
```

Any other MCP client takes the same shape — `command: "npx"`, `args: ["tsx",
"src/cli.ts", "--config", "/ABS/PATH/ownerswitch.mcp.json"]`, `cwd:
"/ABS/PATH/ownerswitch/packages/mcp"`.

> Do **not** launch it with `pnpm -C <path> exec tsx …`. It works when you
> type it and fails under an MCP client — the extra process layers outlast
> the client's startup timeout, and the orphaned chain survives the client
> giving up. `packages/mcp/README.md` has the full post-mortem.

Now ask the agent for something the policy holds:

> create a file /tmp/ownerswitch-demo/hello.txt containing "hi"

It comes back as MCP error `-32052`: held for owner review, **has not run**,
with the id of the window you now own.

## 7. Be the owner: stop it (≈30 s)

The single most important command in this document:

```bash
curl -sX POST http://127.0.0.1:4600/kill -d '{"reason":"first kill"}'
```

Ask the agent to do *anything* now — even a read. Every call comes back
`-32054`: the kill switch is engaged. Not "this tool is blocked" — stopped.

Two things worth doing while it is down, because they are the properties
people assume and rarely check:

```bash
# 1. it is not a mood: kill state persists to disk
#    stop the control plane in terminal 1 (Ctrl-C), start it again
pnpm --filter @ownerswitchai/mcp dev:control-plane
curl -s http://127.0.0.1:4600/status      # still {"killed":true,…}

# 2. no control plane, no tool calls: stop it entirely and ask the agent
#    again — every call is refused, because unreachable reads as killed
```

Restarting is not a restore. There is exactly one way back.

## 8. Be the owner: the two GOs (≈2 min)

Restoring is meant to be the expensive direction: an owner session, a
mandatory cooldown, and a single-use ceremony that expires.

```bash
OWNER=<the owner token from terminal 1>   # a fresh one if 15 min have passed

# GO 1/2 — open the ceremony
CER=$(curl -sX POST http://127.0.0.1:4600/restore/ceremony \
  -H "Authorization: Bearer $OWNER" | jq -r .id)

# the cooldown is real; watch it drain
curl -s "http://127.0.0.1:4600/restore/ceremony/$CER" -H "Authorization: Bearer $OWNER"
# {"state":"go1","cooldownRemainingMs":28417,…}

# GO 2/2 — after it reaches 0
curl -sX POST http://127.0.0.1:4600/restore -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' -d "{\"ceremonyId\":\"$CER\"}"
# {"killed":false}
```

Try GO 2/2 early on purpose. You get `409 {"error":"restore rejected"}` — and
that is all you get, whatever went wrong. The body never says which check
failed (wrong owner, wrong epoch, too early, replayed), because that answer
would be a map for someone who is not you. `cooldownRemainingMs` above is the
number to read; it is yours to ask for, and asking requires your token.

Ask the agent again: it works. You have completed the loop the whole product
is about — **one press to stop, two GOs to start.**

## 9. Stop one agent instead of everything (optional, ≈1 min)

A fleet does not need a fleet-wide stop for one misbehaving member:

```bash
curl -sX POST http://127.0.0.1:4600/kill \
  -H 'content-type: application/json' -d '{"agentId":"mcp-gateway","reason":"just this one"}'
curl -s http://127.0.0.1:4600/status   # {"killed":false,"killedAgents":["mcp-gateway"],…}
```

Everything carrying that agent id is denied; every other agent keeps
running. Restoring is the same ceremony, scoped: pass `{"agentId":
"mcp-gateway"}` when opening it.

---

## What you just proved (and what you did not)

**Proved:** every call routed through the gateway is checked against live
kill state before it runs; a kill denies all of them; kill state survives a
restart of the control plane; an unreachable control plane denies rather than
allows; coming back takes an owner, a cooldown, and a single-use ceremony.

**Not proved, and not claimed:** that the agent *cannot act*. The gateway
decides the calls that route **through it**. An agent with its own file,
shell, or network access can act without asking, and a denial removes
permission, not capability — we have watched exactly that happen. Containment
is what you build around the gateway; it is ranked honestly in
[THREAT-MODEL.md](packages/mcp/THREAT-MODEL.md). Read that next if you are
deciding whether to put this in front of something that matters.

## Where to go next

- [`packages/mcp/README.md`](packages/mcp/README.md) — the full configuration
  reference: every policy field, error code, and the veto lane's behaviour.
- **Budgets with teeth** — `limits` rules stop an agent that spends, fails, or
  calls too much, without you watching. Kill-action budgets require
  `OWNERSWITCH_LIMITS_ACCEPT_PROCESS_LOCAL_BUDGET_RISK=1`; `doctor`'s startup-gates
  check tells you so before an MCP client turns it into a silent failure.
- **Honeytokens** — decoy credentials that fire a kill the moment anything
  touches them (`packages/honeytoken`).
- **A physical button** — `packages/button`, for when the stop should not
  depend on a terminal being open.
