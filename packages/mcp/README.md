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

## Enforcement boundary

This gateway decides and audits **the calls that route through it** —
only those. An agent that also has built-in tools or direct
file/shell/network access can act without asking, and a denial removes
permission, not capability. We have watched exactly that (2026-08-08):
two correct fail-closed denials, then — after the user repeated the
request — the agent did the write with its own built-in tool, announcing
it as it went. The gateway held; the effect happened anyway.

If you need containment, build the deployment around the gateway for it:
credential broker, sandboxed egress, OS-level enforcement — honestly
ranked in **[THREAT-MODEL.md](./THREAT-MODEL.md)**. The quickstart alone
is policy and audit, not a cage.

## The quickstart

Goal: your first *blocked* tool call, with the connection and the policy
both verified *before* you ever prompt an agent.

> Prefer a guided walkthrough that ends with you pressing the stop button?
> **[FIRST-KILL.md](../../FIRST-KILL.md)** — kill, persistence across a
> restart, and the 2GO restore, in about 10 minutes. This section is the
> same path in reference form.

**Honest timing.** We clocked a first, unassisted run of this quickstart
with a stopwatch at **~20 minutes**, not 5. Almost all of it was two
infrastructure surprises — the `claude` CLI wasn't installed, and the
documented launch command didn't work when an MCP client (as opposed to a
human) ran it — plus six minutes of an agent debugging its own connection
because nothing told anyone to check first. This revision fixes all three:
the CLI install is now an explicit step, the launch command below is the
one that actually works under an MCP client, and `doctor` / `verify` (see
the next section) catch what's broken *before* you spend an agent's quota
finding out. We haven't re-timed a from-scratch run to put a new number
here — 5 minutes is the target these tools exist to get you back to, not a
claim we're making about this walkthrough.

**[0:00] Install** (node 22+, pnpm 9, and an MCP client)

```bash
git clone https://github.com/ownerswitchai/ownerswitch && cd ownerswitch
pnpm install

# an MCP client — for Claude Code:
npm install -g @anthropic-ai/claude-code
```

**[1:30] Start the dev control plane** (terminal 1 — leave it running)

```bash
pnpm --filter @ownerswitchai/mcp dev:control-plane
```

It prints the device secret and an **owner token** — that token is your
"one tap from the owner" for the rest of the quickstart, and what you'll
pass to `verify` below.

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

**[2:30] Preflight, before touching any MCP client:**

```bash
cd packages/mcp
npx tsx src/cli.ts doctor --config ~/ownerswitch.mcp.json
```

Every line should be `✔`. If one isn't, its line says exactly what to fix
— fix it here, not by asking an agent to guess.

**[3:00] Point your MCP client at the gateway.** For Claude Code, from
`packages/mcp` (same directory as the `doctor` run above):

```bash
claude mcp add ownerswitch -- npx tsx src/cli.ts --config ~/ownerswitch.mcp.json
```

Any other MCP client, same shape:

```json
{
  "mcpServers": {
    "ownerswitch": {
      "command": "npx",
      "args": ["tsx", "src/cli.ts", "--config", "/ABS/PATH/ownerswitch.mcp.json"],
      "cwd": "/ABS/PATH/ownerswitch/packages/mcp"
    }
  }
}
```

> **Don't use `pnpm -C <path> exec tsx ...` to launch this.** It's the
> command you'd reach for by analogy with the rest of this repo, it runs
> fine when *you* type it by hand, and it still fails under an MCP client —
> we hit exactly this. Reproducing it end to end (`claude mcp add` with the
> `pnpm exec` form, then `claude mcp list`) reliably reproduced the failure:
> `Failed to connect — connection timed out`, the same failure family as
> `-32000: Connection closed`. Inspecting the process tree while it hung
> showed why: `pnpm -C <path> exec <cmd>` doesn't run your command directly.
> On a machine where `pnpm` is a version-manager shim (common — e.g. Corepack
> or a pnpm-version-manager install), invoking it re-execs the pinned pnpm
> binary, which then spawns `tsx`, which then spawns your code — four
> Node.js processes deep before `cli.ts` ever runs, versus `npx tsx`'s more
> direct path. An MCP client's startup timeout doesn't leave much room for
> that. It gets worse: when the client gave up and tore down the connection
> attempt, that `pnpm → pnpm → tsx → node` chain was still alive —
> **orphaned** — minutes later. Killing the one process pnpm handed back to
> the client never reached the leaf process actually speaking MCP. `npx tsx`
> has one fewer layer of indirection and, in every run we tested, connected
> and shut down cleanly.

**[3:30] Verify the connection — before you prompt the agent:**

```bash
claude mcp list
```

Confirm `ownerswitch` shows `✔ Connected`. If it doesn't, don't hand the
problem to the agent — that's the six minutes we lost. Re-run `doctor`
instead; if `doctor` is all green but the client still won't connect, the
client itself (not this gateway) is the thing to debug.

**[4:00] Verify enforcement — also before you prompt the agent:**

```bash
npx tsx src/cli.ts verify --config ~/ownerswitch.mcp.json
```

It prompts for the owner token from terminal 1 — paste it there (or
`export OWNERSWITCH_OWNER_TOKEN=...` first and `unset` it after; it is
deliberately **not** a CLI flag, which would leak it into shell history and
`ps` output). This proves the policy is actually being enforced — allow
passes, an unmatched tool hits the fail-closed default, and the veto lane
runs end to end: a real window is registered, your owner token vetoes it,
and it stays vetoed — without spending an agent's turn finding out, and
without touching the kill switch. See the next section for what it checks
and what to do if it fails.

**[4:30] See the first blocked call.** Ask the agent:

> create a file /tmp/ownerswitch-demo/hello.txt containing "hi"

Reads and listings just work. The `write_file` call comes back with:

```
MCP error -32052: OwnerSwitch held "write_file" for owner review: the owner can
veto writes. The call has NOT run. A veto window (id "veto_ab12cd34ef56") is now
open — the owner has a few minutes to stop it. …
```

**[5:00] Be the owner.** Terminal 1 printed the exact commands, e.g.:

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

Now *everything* — even reads — comes back `-32054`. Restarting the control
plane does NOT undo it: kill state persists to a file
(`ownerswitch-kill-state.json` by default) and a restart comes back killed —
only the 2GO restore ceremony clears it. To hard-reset a dev instance
instead, stop it and delete the kill-state file. Stop the control plane
entirely and it's the same story: **no control plane, no tool calls.** Fail
closed is not a mode; it's the default.

## Preflight: `doctor` and `verify`

Two commands exist so a broken setup gets caught by you, in seconds, instead
of by an agent burning its quota on it. Both take the same `--config <file>`
(or `OWNERSWITCH_MCP_CONFIG`) as the gateway itself.

### `ownerswitch-mcp doctor`

```bash
npx tsx src/cli.ts doctor --config ~/ownerswitch.mcp.json
```

Six one-line checks, printed as `✔` (pass), `⚠` (action required), or `✘`
(failed) — every non-`✔` line names what to do about it:

| check | what it does |
| --- | --- |
| node version | `process.version` is 22 or newer |
| config | the file parses and every field validates (same loader the gateway uses) |
| startup gates | the gateway's **pure configuration gates** — every pre-serve check that depends only on config and environment — run here instead: an unacknowledged kill-action budget, a half-configured or unreadable honeytoken registry, a partial GitHub connector triple, incoherent executor routes, a gateway credential passed through argv. These parse fine and then refuse to start — and a gateway that refuses to start is invisible to an MCP client, which reports only a closed connection. Both paths call the same `startup-gates.ts`, so a new gate cannot be added to one and forgotten in the other. A gate failure **stops the run**: nothing downstream is probed, and in particular the upstream is never spawned — one of these gates fires precisely because `upstream.args` carries a credential, and spawning anyway would perform the `/proc`-and-`ps` leak it just diagnosed |
| control plane | `GET /status` responds within `timeoutMs` — and if it responds `killed:true`, that is a `⚠`, **not** a pass: the plane is reachable but every call will be refused (`-32054`) until an owner runs the 2GO restore ceremony. The fix line prints the ceremony commands themselves, because a premature restore answers a deliberately uniform `409 {"error":"restore rejected"}` that never says which check failed |
| device credentials | a signed, deliberately-malformed `POST /veto` gets `400` (signature accepted) rather than `401` (rejected) — this proves `device.id`/`device.secret` are right *without* opening a real veto window |
| upstream command | launches your `upstream.command` exactly as the gateway will — the same `upstreamLaunchSpec`, so the child's environment is the gateway's, credential strip included; a preflight must never hand the untrusted child more than the gateway would — and completes a **real MCP initialize handshake**, then shuts it down through the SDK's close path (stdin end → wait for the child to exit, escalating only if it lingers) — a binary that starts but crashes on boot, or was never an MCP server, fails here instead of surfacing later as the client's opaque connection timeout |

A failing check skips whatever depends on it (a bad config skips
startup-gates/control-plane/device/upstream; an unreachable control plane
skips the device-credentials check) rather than printing a confusing
cascade. Exits 0 only when every line is `✔` — a `⚠` exits 1 too, because
you must not connect an agent over it.

**When the upstream check times out, suspect the environment first.** The
upstream child does not inherit your shell: the MCP SDK spawns it with an
allowlist of roughly `HOME/LOGNAME/PATH/SHELL/TERM/USER`, and the gateway
does the same (plus stripping every OwnerSwitch credential by name and
value). Behind a proxy or a custom CA, the exact command that works when you
type it hangs when the gateway spawns it, because `HTTPS_PROXY` and
`NODE_EXTRA_CA_CERTS` did not come along — a failure whose evidence points
the wrong way, since running it by hand "proves" the config is fine. The fix
line names which of those variables you have set but have not declared in
`upstream.env`. A cold `npx -y <package>` download can also outlast the
15-second handshake budget; `--upstream-timeout <ms>` (or
`OWNERSWITCH_UPSTREAM_TIMEOUT_MS`) raises it.

### `ownerswitch-mcp verify`

```bash
npx tsx src/cli.ts verify --config ~/ownerswitch.mcp.json
```

Proves the policy is actually enforced, against the real control plane, by
exercising the same decision path the gateway uses at runtime — without
forwarding anything to the real upstream tool, and **without touching the
global kill switch**:

1. a call matching your policy's first `allow` rule → **allowed**
2. a call matching no rule → hits `defaultDecision`, and **fails loudly** if
   that default is itself `"allow"` (that's not fail-closed, and `verify`
   won't pass a policy that can't back up the claim)
3. the **veto lane, end to end**: registers a real window (device-signed,
   exactly as the gateway would for a held call), vetoes it with your owner
   token — the owner's one tap — and confirms it reads back `vetoed` and
   stays that way. The only residue is that one terminally-vetoed demo
   window in the control plane's in-memory map.

The owner token is **required** (it plays the owner's veto tap) and comes
from `OWNERSWITCH_OWNER_TOKEN` or an interactive prompt — never a CLI flag,
which would leak it into shell history and process listings. Typing it at
the prompt never echoes to the terminal (raw-mode input, nothing written
back but the prompt itself and a trailing newline), so it never lands in
scrollback or a screen recording either. It is validated up front by a
harmless probe (`POST /restore` with a ceremony id the server can never
have minted: the uniform `409` proves the token is accepted, `401` proves
it isn't, and neither mutates anything).

If a lane genuinely can't be exercised — e.g. the policy has no `"allow"`
rule to build a demonstration call from, or every tool name matches an
explicit rule so the fail-closed default can never fire — that is a
**failure** for that check, naming exactly what's missing. `verify` proves
three specific things; if it can't prove one, the run fails, full stop —
nothing is silently skipped into an overall `PASS`.

`verify` deliberately does not engage the real kill switch. A live
kill/restore cycle from a CLI preflight has real edges — an ambiguous
`/kill` response on a network blip, a lost connection mid-ceremony, a
Ctrl-C at the wrong moment — that a DX check has no business improvising
answers to, and kill state persisting across restarts makes getting it
wrong expensive. That coverage already exists at the layer that owns it —
`control-plane/src/integration.test.ts` (kill → 2GO → restore, end to end)
and the ceremony's own HTTP-level tests in `control-plane/src/server.test.ts`
— so `verify` stays a fast, low-side-effect preflight instead of repeating
it.

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
| `executorRoutes` | no | MCP tool name → `{ connector, operation }`, e.g. `"github.merge_pr": { "connector": "github", "operation": "merge_pull_request" }`. A yes on a routed tool mints an ActionTicket and the executor performs the action with OwnerSwitch's own credential — never forwarded upstream, and the agent gets the result, never a token (see `packages/executor/DESIGN.md`). Unlisted tools forward exactly as before. Aliases of one operation must have identical policy outcomes — routes that let an agent reach a guarded operation through a looser alias are refused at startup, naming both tools |

No file? The same config can come from env vars: `OWNERSWITCH_CONTROL_PLANE_URL`,
`OWNERSWITCH_DEVICE_ID`, `OWNERSWITCH_DEVICE_SECRET`, `OWNERSWITCH_UPSTREAM_COMMAND`,
`OWNERSWITCH_UPSTREAM_ARGS` (JSON array), `OWNERSWITCH_POLICY` (JSON),
`OWNERSWITCH_AGENT_ID`, `OWNERSWITCH_TIMEOUT_MS`, `OWNERSWITCH_EXECUTOR_ROUTES` (JSON).

The GitHub connector's credential is environment-only (never the config
file, never argv), a GitHub App — not a personal access token — minting
hour-long installation tokens scoped per merge to one repository. Two
mutually exclusive modes (`packages/executor/DESIGN.md` §6 for the model
and provisioning):

- **`OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET`** (recommended): the UNIX
  socket of `ownerswitch-merge-broker`, a separate process under its own
  uid that alone holds the App private key and **never returns a token** —
  it validates a control-plane-signed, single-use grant and PERFORMS the
  merge itself, returning only the outcome. The gateway holds neither the
  key nor a token. This is the only shape that keeps the authorization
  boundary an agent cannot cross, since in stdio deployments the gateway
  shares a uid with the agent (a vended `contents: write` token would be
  raw push authority). Requires an owner-gated lane (see below).
- **`OWNERSWITCH_GITHUB_APP_ID` + `OWNERSWITCH_GITHUB_APP_INSTALLATION_ID`
  + `OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE`** (degraded): loads the key
  into the gateway process and merges directly. Refused at startup unless
  `OWNERSWITCH_GITHUB_APP_ACCEPT_SAME_UID_KEY_RISK=1` explicitly accepts
  that a same-uid agent can read it; starts with a loud warning. A
  partial triple refuses naming what's missing.

Neither configured runs the gateway with routed merges refusing cleanly
as not-configured — at the review-time pin, before any owner window
opens. Routed merges always carry a **mandatory, server-derived
`expectedHeadSha`**: OwnerSwitch pins the PR's head at review time, the
owner approves exactly that head, and an agent-supplied sha is refused
(`-32056`, `refusalCode: "invalid-args"`). In broker mode a routed merge
also requires an **owner-gated lane** — an `allow`-lane routed merge is
refused (`-32056`, `refusalCode: "owner-grant-required"`), because the
merge is authorized by a control-plane grant minted only on the owner's
**active approval** of that exact pinned call (an owner-session
`decision=approve`), never on a silent timeout — the gateway that
registers a window shares the agent's uid, so the agent could open its own
window, and only a real owner "yes" the agent cannot forge may release a
merge. The control plane and broker share an `OWNERSWITCH_GRANT_KEY` (and a
separate `OWNERSWITCH_KILL_STATE_KEY` that authenticates the broker's kill
check) the gateway never sees — enforced at startup: a gateway that finds
`OWNERSWITCH_GRANT_KEY` in its environment refuses to run, because in stdio
deployments anything the gateway can read, the agent can read, and with
that key grants could be forged.

## What the agent sees (error codes)

| code | meaning | retry? |
| --- | --- | --- |
| `-32050` `PolicyDenied` | a rule says this never runs | no |
| `-32051` `ApprovalRequired` | needs the owner's explicit approval (2GO); also a veto window whose owner was unreachable (escalated, fail closed) | after approval |
| `-32052` `VetoPending` | held in an open veto window | yes, in a few minutes |
| `-32053` `OwnerVetoed` | the owner stopped this exact action | no |
| `-32054` `Lockdown` | kill switch engaged, or control plane unreachable | once restored |
| `-32055` `HoneytokenTripped` | a decoy credential surfaced in the call — the kill is already firing | no |
| `-32056` `TicketRefused` | an executor-routed action was approved, but refused at execution time: expired, replayed, a kill happened since the approval, or its veto release predates a kill (release "spent") — it did NOT run. The precise guarantee: a ticket is refused if the final pre-dispatch live-state check observes a kill or an epoch change; a kill landing after that check may race with dispatch, and once dispatched it cannot be recalled | a retry starts a fresh owner decision |
| `-32057` `ExecutionFailed` | the executor's backend call failed after the single-use ticket was consumed. The error's `data.connectorOutcome` says which kind: `"not-performed"` (the backend received and refused the request — the action definitively did NOT run) or `"unknown"` (it died on the wire and a post-dispatch verification read could not settle it — the action MAY OR MAY NOT have completed) | `not-performed`: a retry is safe but will likely refuse again until the cause is fixed. `unknown`: check the resource first; a retry could duplicate the action |

Each error's `data` carries the machine-readable detail:
`{ decision, tool, reason, ruleId, vetoWindowId?, vetoStatus?, refusalCode? }`.

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

Honesty, updated: release-on-silence requires delivery confirmation, and the
control plane now has the production path for it — the enrolled owner app's
`POST /veto/:id/seen`, signed with the owner app's OWN secret
(`OWNERSWITCH_OWNER_APP_SECRET`, distinct from the fleet device secret so no
fleet component or same-uid agent can forge the "I saw it"; refused inside the
60 s response floor before the deadline), with `GET /veto/pending` and a
device-signed veto relay for the escalation ladder (`packages/escalation`)
that pushes, texts and calls until the owner is reached. Without an owner-app
secret enrolled, `/veto/:id/seen` is 501 and windows walk to held → approval,
fail closed. A deployment WITHOUT the owner app or the
escalation service still walks pending → extended → held and ends as an
approval: silence only approves when the system *knows* the owner saw the
notification. The veto tap works today, as the quickstart shows.

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
