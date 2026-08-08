# @ownerswitchai/mcp — the OwnerSwitch MCP gateway

Put OwnerSwitch between your agent and any MCP server. The gateway is itself
an MCP server (stdio): it launches the real server as a child, presents its
tool list **unchanged**, and checks every `tools/call` against your policy and
the control plane's live kill state before forwarding it.

| decision | what happens | what the agent is told |
| --- | --- | --- |
| `allow` | call forwarded, upstream result passed through untouched | nothing — it just works |
| `veto` | call **held**, a VetoWindow is registered with the control plane | error `-32052`: pending owner review, retry later |
| `approve` | call refused | error `-32051`: needs the owner's explicit approval (2GO) |
| `deny` | call refused | error `-32050`: blocked by policy, don't retry |
| kill switch / control plane down | **every** call refused — fail closed | error `-32054`: says exactly why |

Agents are never left hanging or guessing: every refusal is a distinct MCP
error whose message says what was blocked, why, whether it ran (it didn't),
and what to do next — written to be relayed to the human.

## The 5-minute quickstart

Goal: your first *blocked* tool call in under 5 minutes.

**[0:00] Install** (node 22+, pnpm 9)

```bash
git clone https://github.com/ownerswitchai/ownerswitch && cd ownerswitch
pnpm install
```

**[1:30] Start the dev control plane** (terminal 1 — leave it running)

```bash
pnpm --filter @ownerswitchai/mcp dev:control-plane
```

It prints the device secret and an **owner token** — that token is your
"one tap from the owner" for the rest of the quickstart.

**[2:00] Write one config file** — `~/ownerswitch.mcp.json`. This example
guards the official filesystem MCP server: reads run, writes get a veto
window, renames never run, anything unknown needs the owner (fail closed).

```json
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
      { "id": "edits",  "tool": "edit_file",  "decision": "veto",  "description": "the owner can veto edits" },
      { "id": "moves",  "tool": "move_file",  "decision": "deny",  "description": "renames never run" }
    ],
    "defaultDecision": "approve"
  }
}
```

```bash
mkdir -p /tmp/ownerswitch-demo
```

**[2:30] Point your MCP client at the gateway.** For Claude Code:

```bash
claude mcp add ownerswitch -- pnpm -C /ABS/PATH/ownerswitch/packages/mcp exec tsx src/cli.ts --config ~/ownerswitch.mcp.json
```

Any other MCP client, same shape:

```json
{
  "mcpServers": {
    "ownerswitch": {
      "command": "pnpm",
      "args": ["-C", "/ABS/PATH/ownerswitch/packages/mcp", "exec", "tsx",
               "src/cli.ts", "--config", "/ABS/PATH/ownerswitch.mcp.json"]
    }
  }
}
```

**[3:00] See the first blocked call.** Ask the agent:

> create a file /tmp/ownerswitch-demo/hello.txt containing "hi"

Reads and listings just work. The `write_file` call comes back with:

```
MCP error -32052: OwnerSwitch held "write_file" for owner review: the owner can
veto writes. The call has NOT run. A veto window (id "veto_ab12cd34ef56") is now
open — the owner has a few minutes to stop it. …
```

**[4:00] Be the owner.** Terminal 1 printed the exact commands, e.g.:

```bash
# one tap: stop it
curl -X POST http://127.0.0.1:4600/veto/veto_ab12cd34ef56 \
  -H 'Authorization: Bearer <owner token>'
```

Ask the agent to try again → `MCP error -32053: … the owner vetoed this
action … Do not retry — tell the user the owner stopped it.`

And the big red button:

```bash
curl -X POST http://127.0.0.1:4600/kill -d '{"reason":"owner pressed stop"}'
```

Now *everything* — even reads — comes back `-32054` until you restart the
dev control plane. Stop the control plane entirely and it's the same story:
**no control plane, no tool calls.** Fail closed is not a mode; it's the
default.

## Configuration

One JSON file (`--config <file>`, or `OWNERSWITCH_MCP_CONFIG=<file>`):

| field | required | meaning |
| --- | --- | --- |
| `controlPlaneUrl` | yes | base URL of the OwnerSwitch control plane |
| `device.id`, `device.secret` | yes | this gateway's provisioned device credentials; registrations of veto windows are HMAC-signed with them |
| `upstream.command`, `upstream.args`, `upstream.env`, `upstream.cwd` | command | the MCP server to guard (spawned over stdio) |
| `policy.rules[]` | yes | `{ id, tool, decision, argsPattern?, description? }` — glob on tool name, first match wins |
| `policy.defaultDecision` | yes | decision when no rule matches — ship `"approve"` so unknown tools need the owner |
| `agentId` | no | name attached to calls in windows/audit (default `ownerswitch-mcp`) |
| `timeoutMs` | no | per control-plane call, default 1500 — on timeout the gateway fails closed |

No file? The same config can come from env vars: `OWNERSWITCH_CONTROL_PLANE_URL`,
`OWNERSWITCH_DEVICE_ID`, `OWNERSWITCH_DEVICE_SECRET`, `OWNERSWITCH_UPSTREAM_COMMAND`,
`OWNERSWITCH_UPSTREAM_ARGS` (JSON array), `OWNERSWITCH_POLICY` (JSON),
`OWNERSWITCH_AGENT_ID`, `OWNERSWITCH_TIMEOUT_MS`.

## What the agent sees (error codes)

| code | meaning | retry? |
| --- | --- | --- |
| `-32050` `PolicyDenied` | a rule says this never runs | no |
| `-32051` `ApprovalRequired` | needs the owner's explicit approval (2GO); also a veto window whose owner was unreachable (escalated, fail closed) | after approval |
| `-32052` `VetoPending` | held in an open veto window | yes, in a few minutes |
| `-32053` `OwnerVetoed` | the owner stopped this exact action | no |
| `-32054` `Lockdown` | kill switch engaged, or control plane unreachable | once restored |

Each error's `data` carries the machine-readable detail:
`{ decision, tool, reason, ruleId, vetoWindowId?, vetoStatus? }`.

## How the veto lane behaves

A `veto` decision never forwards the call on the attempt that triggers it.
The gateway registers a VetoWindow with the control plane (device-signed
`POST /veto`) and remembers it by call identity (tool + args), so retries of
the *same* call track the *same* window instead of spamming the owner:

- window **pending/extended** → still refused (`-32052`)
- owner tapped **veto** → refused (`-32053`), and it stays refused
- window **released** (owner saw it, stayed silent) → the next retry runs, once
- window **held** (owner unreachable at deadline) → escalates to approval (`-32051`), fail closed
- control plane lost the window (restart) → a fresh window is registered

V0 honesty: release-on-silence requires delivery confirmation (the owner app's
push pipeline), which isn't wired yet — so an untouched window walks
pending → extended → held and ends as an approval. Silence only approves when
the system *knows* the owner saw the notification. The veto tap works today,
as the quickstart shows.

## Design notes

- **Tool list is forwarded unchanged.** Agents see everything and learn what
  they may *run* per call — a clear refusal at call time beats a confusing
  absence at plan time. `tools/list_changed` notifications pass through too.
- **Every call re-checks live state.** `evaluateRemote()` fetches kill state
  per call; an unreachable control plane reads as killed (the gateway
  client's fail-closed contract), so there is no cached "still fine".
- **Refusals are protocol errors, not tool results** — the upstream server
  never sees a refused call, and the agent can't mistake a refusal for output.
- V0 proxies **tools only** (no resources/prompts passthrough yet), and the
  gateway holds its window bookkeeping in memory — a gateway restart opens
  fresh windows on retry.
