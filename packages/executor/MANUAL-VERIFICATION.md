# Manual verification: one live merge through the executor

The test suite never performs a live merge — every GitHub interaction in
CI runs against scripted responses. This procedure is the **one deliberate
live run**, performed by a human against a throwaway repository. Run it
once per deployment change that touches the connector, the credential
model, or the proxy's executor lane.

At the end of this document: exactly what a green run proves, and what it
does not.

## Prerequisites

- A **throwaway repository** you own, e.g. `<you>/ownerswitch-live-test`.
  Nothing in it matters; it will receive one real merge.
- A machine with the repo checked out, `pnpm install && pnpm -r build`
  done, and the ability to create local users (the broker's uid, and a
  third throwaway uid for the peer-boundary negative check).

## 1. Create and install the GitHub App (once)

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
   - Name: anything (`ownerswitch-live-test-app`).
   - Webhook: **disabled**.
   - Repository permissions: **Contents: Read and write**,
     **Pull requests: Read-only**. Nothing else.
2. Note the **App ID** from the App's About page.
3. **Install** the App: Install App → your account → **"Only select
   repositories"** → exactly the throwaway repo. Note the numeric
   **installation id** — the trailing number in the installation's
   settings URL (`…/settings/installations/<id>`). (An enterprise-owned
   installation is unsupported and the broker will refuse its
   un-downscoped tokens — use a personal or ordinary org account.)
4. Generate a **private key**; a `.pem` file downloads.

## 2. Provision the executing broker like production

The point of doing this properly in a test run is that the run rehearses
the deployment rule: the key belongs to a uid the gateway and agent do
NOT share, and the broker performs the merge — it never hands out a token.

Create the broker user and the shared socket group (the GATEWAY's user
joins the group so it can connect; the broker runs WITH that group as its
effective gid so the socket inherits it):

```sh
sudo useradd --system --shell /usr/sbin/nologin oswitch-broker
sudo groupadd oswitch && sudo usermod -aG oswitch "$(id -un)"   # gateway's user in the socket group
sudo usermod -aG oswitch oswitch-broker                          # broker in it too, for its egid
sudo mkdir -p /etc/ownerswitch
sudo mv ~/Downloads/<app-name>.*.private-key.pem /etc/ownerswitch/github-app.pem
sudo chown oswitch-broker /etc/ownerswitch/github-app.pem
sudo chmod 600 /etc/ownerswitch/github-app.pem
# setgid (02750) socket dir so the socket inode inherits the oswitch group:
sudo install -d -o oswitch-broker -g oswitch -m 02750 /run/ownerswitch
OSWITCH_GID=$(getent group oswitch | cut -d: -f3)
```

Pick a strong random **grant key** — the control plane and the broker
share it, and NOTHING else may: `GRANT_KEY=$(openssl rand -hex 32)`.
Handle it accordingly: never `export` it in a shell that will also start
the gateway (the gateway REFUSES to start when it sees
`OWNERSWITCH_GRANT_KEY` — that refusal is one of the checks below), and
give the control-plane process the SAME uid/host isolation from the agent
as the broker — a control plane the agent's uid can read defeats the key.

Create the broker's durable single-use burn directory (burns must survive
a broker restart, so they live on disk, broker-owned, mode 0700):

```sh
sudo install -d -o oswitch-broker -g oswitch-broker -m 0700 /var/lib/ownerswitch/burns
```

Start the broker under its own uid, with the shared group as its egid
(`sg oswitch`), so the socket ends up gid `oswitch`:

```sh
sudo -u oswitch-broker sg oswitch -c '
  OWNERSWITCH_GITHUB_APP_ID=<app id> \
  OWNERSWITCH_GITHUB_APP_INSTALLATION_ID=<installation id> \
  OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE=/etc/ownerswitch/github-app.pem \
  OWNERSWITCH_AGENT_WORKSPACE=<the agent'"'"'s workspace dir> \
  OWNERSWITCH_GRANT_KEY='"$GRANT_KEY"' \
  OWNERSWITCH_BROKER_SOCKET=/run/ownerswitch/broker.sock \
  OWNERSWITCH_BROKER_SOCKET_GID='"$OSWITCH_GID"' \
  OWNERSWITCH_BROKER_BURN_DIR=/var/lib/ownerswitch/burns \
  OWNERSWITCH_BROKER_ALLOWED_REPOS=ownerswitch-live-test \
  OWNERSWITCH_CONTROL_PLANE_URL=http://127.0.0.1:8787 \
  ownerswitch-merge-broker'
```

The loader refuses a relative key path, a path under the given agent
workspace, a symlink, group/world-readable modes, another user's file,
and non-RSA content; the broker refuses a world-accessible socket
directory AND refuses to serve if the socket's gid is not
`OWNERSWITCH_BROKER_SOCKET_GID`. If it won't start, the error names the
failing check.

Sanity-check the isolation while you're here (BOTH must hold):
- `sudo -u "$(id -un)" cat /etc/ownerswitch/github-app.pem` must FAIL
  (permission denied) — the gateway's uid cannot read the key.
- `stat -c '%G %a' /run/ownerswitch/broker.sock` should show `oswitch
  660` — the gateway's user reaches it via the group, no wider.

## 3. Open a PR in the throwaway repo

```sh
git clone https://github.com/<you>/ownerswitch-live-test && cd ownerswitch-live-test
git checkout -b live-test && echo "executor live test $(date -u +%FT%TZ)" > witness.txt
git add witness.txt && git commit -m "executor live-run witness" && git push -u origin live-test
# open the PR and note its number, e.g. #1
```

Note the PR's **head SHA** (`git rev-parse HEAD`) — you will verify the
owner-facing window shows exactly it. You will NOT pass it anywhere:
OwnerSwitch pins it server-side.

## 4. Run the control plane and the gateway

Start the dev control plane **with the same grant key** the broker has,
passed inline to THAT process only
(`OWNERSWITCH_GRANT_KEY="$GRANT_KEY" pnpm --filter @ownerswitchai/mcp
dev:control-plane`), so it mints signed grants the broker will accept. In
this live run the control plane MUST get the same isolation as the
broker: run it under a uid the gateway/agent does not share (e.g. `sudo
-u oswitch-broker …` or a fourth dedicated user) — the grant key is
exactly as sensitive as the App private key, because whoever reads it can
mint approvals. Then launch the gateway with a config whose policy puts
`github.merge_pr` in the **`veto` lane** (an owner-gated lane is required
in broker mode) and whose `executorRoutes` maps it to
`{ "connector": "github", "operation": "merge_pull_request" }`
(see `packages/mcp/README.md`), plus:

```sh
export OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET=/run/ownerswitch/broker.sock
```

The gateway needs NO GitHub credential and NO grant key. Its startup line
must say
`github connector: live via EXECUTING merge broker at /run/ownerswitch/broker.sock` —
`not configured` means the variable didn't resolve.

## 5. The live merge

From the MCP client (agent side), call the routed tool — note there is
NO sha argument; the pin is OwnerSwitch's job:

```json
{ "name": "github.merge_pr", "arguments": {
    "owner": "<you>", "repo": "ownerswitch-live-test", "pullNumber": 1,
    "mergeMethod": "squash" } }
```

1. First call → refused `-32052` (veto window open). **Inspect the
   window the owner sees**: its arguments must carry `expectedHeadSha`
   equal to the head SHA you noted — server-derived, agent-untouched.
2. Release the window the way the owner would.
3. Call again → the merge runs. Expect a result like
   `{ "resourceId": "github:pr:<you>/ownerswitch-live-test#1",
      "detail": { "merged": true, "sha": "<merge commit>", "message": "…" } }`.
4. Confirm on github.com: the PR is merged, by the App's bot identity.

## 6. Negative checks (same session, no second merge)

- **A raw socket client with no valid evidence gets a refusal — never a
  token, never a merge.** As the gateway's user, hit the broker socket
  directly and confirm neither op yields authority:
  ```sh
  # asking for a token: there is no such op
  printf '{"op":"token","repo":"ownerswitch-live-test"}\n' | nc -U /run/ownerswitch/broker.sock
  #   → {"ok":false,...}  and NO ghs_ token anywhere in the reply
  # asking to merge with a forged grant:
  printf '{"op":"merge","grant":{"v":1,"sig":"00"},"args":{}}\n' | nc -U /run/ownerswitch/broker.sock
  #   → {"ok":false,"kind":"refused",...}  and the PR is NOT merged
  ```
  Grep both replies for `ghs_` — nothing. This is the core property: the
  socket hands out results, never authority.
- **A distinct, non-group uid cannot even connect.** As a third user who
  is NOT in the `oswitch` group:
  `sudo -u nobody sh -c 'printf "{}\n" | nc -U /run/ownerswitch/broker.sock'`
  must FAIL with a permission error — connect(2) is denied by the socket's
  0660/group. (This is the peer boundary the kernel actually enforces.)
- **Agent-supplied sha refused:** call the tool with an added
  `"expectedHeadSha": "<any 40-hex>"` → refused `-32056` with
  `refusalCode: "invalid-args"`, no veto window opened, GitHub never
  contacted.
- **Unknown field refused:** call with `"dryRun": true` → refused
  `-32056` `invalid-args` ("unknown argument"), before any head read —
  proof the closed schema is enforced, not just advertised.
- **Replay:** call the tool again with the original arguments — the pin
  read now finds the PR already merged and refuses
  (`head-pin-failed`, "already merged — nothing to pin") before any
  owner review opens. Nothing merges twice.
- **Moved head:** open a second PR, let its window open, note the pinned
  sha, then push another commit to its branch. Release the window and
  call again → a FRESH veto window opens for the new head (the released
  approval never merges the moved branch). Veto the fresh window to
  finish without merging.
- **Allow lane refused:** temporarily move `github.merge_pr` to the
  `allow` lane and call it → refused `-32056`
  `refusalCode: "owner-grant-required"`, nothing runs. Put it back in the
  veto lane.
- **Kill gate at the broker:** engage the kill switch, then call the
  tool → the pin read fails closed (`head-pin-failed` — the broker
  refuses: "kill switch engaged"). Restore afterwards.
- **The gateway refuses a leaked grant key:** start the gateway once from
  a shell with `OWNERSWITCH_GRANT_KEY=anything` exported → it must refuse
  to start, naming the variable and why (the agent shares its uid; a key
  it can see is a key that forges grants). Unset and restart normally.
- **The burn survives a broker restart:** after the successful merge,
  restart the broker (same `OWNERSWITCH_BROKER_BURN_DIR`) and replay the
  same grant bytes at the socket by hand → refused
  ("grant already used"), and `{op:"outcome","args":{"jti":"<jti>"}}`
  reports the recorded `performed` outcome. One approval, one merge, even
  across a restart.
- **No leak:** grep everything the agent-side client printed (its logs
  and the tool results) for `ghs_`, and for the first 20 characters of
  the key file's base64 body. Both greps must come back empty.

Then delete the throwaway repo, or leave it for the next run.

## What a green run proves

- The end-to-end path is real: agent call → policy lane → review-time
  head pin → owner decision over the pinned args → control-plane-signed
  grant → broker validates it independently and PERFORMS the merge with a
  token that never crossed the socket.
- The uid isolation holds as deployed: the gateway's uid cannot read the
  key file (step 2's sanity check), yet merges work — the key never
  entered the gateway, and neither did a token.
- The socket hands out results, never authority: a direct client asking
  for a token gets nothing, a forged grant is refused, and a non-group
  uid cannot even connect.
- The provisioning recipe works as written: broker user, setgid socket
  directory, verified socket gid, key placement checks, repo allow-list,
  the agent-workspace placement argument, the shared grant key.
- The pin is server-derived end to end and the schema is enforced: the
  owner-facing window carried the real head sha, an agent-supplied sha
  and an unknown field were both refused, and a moved head re-opened
  review instead of merging.
- The agent-visible surface (results, refusals, logs) carried no
  credential during a real run with real errors.

## What it does NOT prove

- **Failure classification under real network failure.** The wire-death,
  timeout, 5xx, unrecognized-status and verification branches ran only
  against scripted responses; a live run exercising them would require
  injecting faults into a TLS connection to GitHub. The unit tests are
  the evidence there. Remember what the verification read proves when it
  does fire: the PR's merged STATE — never that a particular dispatch
  performed the merge.
- **The kill/epoch race guarantees, and the TOCTOU recheck across the
  mint.** §3's refusal ordering and the broker's before/after-mint kill
  recheck are pinned by unit tests; one live merge says nothing about
  races.
- **Scope enforcement against a hostile ticket.** That the App cannot
  reach other repos is GitHub's enforcement of the installation list —
  this run demonstrates the happy case (plus the broker's own
  allow-list), it does not adversarially probe GitHub's side.
- **The grant-forgery boundary beyond this smoke test.** The negative
  check shows a bad-signature grant is refused; the cryptographic
  argument (the gateway lacks the signing key) is in the unit tests and
  THREAT-MODEL.md §5, not something one run establishes.
- **The same-uid grant-race residual.** A same-uid agent racing the
  gateway for a freshly-issued grant is bounded by the double single-use
  burn, not eliminated; documented in THREAT-MODEL.md §5, unchanged by
  this run.
- **Multi-gateway / restart nonce semantics.** The single-process nonce
  constraint (DESIGN.md §5) is unchanged and untested by this run.
- **Rate-limit behavior.** One merge cannot trip primary or secondary
  limits.
