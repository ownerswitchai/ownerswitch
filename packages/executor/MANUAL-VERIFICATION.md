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
- A machine with the repo checked out, `pnpm install` done, and the
  ability to create a second local user (the broker's uid).

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

## 2. Provision the broker like production

The point of doing this properly in a test run is that the run also
rehearses the deployment rule: the key belongs to a uid the gateway and
agent do not share.

```sh
sudo useradd --system --shell /usr/sbin/nologin oswitch-broker
sudo groupadd oswitch && sudo usermod -aG oswitch "$(id -un)"  # gateway's user joins the socket group
sudo mkdir -p /etc/ownerswitch /run/ownerswitch
sudo mv ~/Downloads/<app-name>.*.private-key.pem /etc/ownerswitch/github-app.pem
sudo chown oswitch-broker /etc/ownerswitch/github-app.pem
sudo chmod 600 /etc/ownerswitch/github-app.pem
sudo chown oswitch-broker:oswitch /run/ownerswitch && sudo chmod 750 /run/ownerswitch
```

Start the broker under its own uid (`sudo -u oswitch-broker …`):

```sh
sudo -u oswitch-broker \
  OWNERSWITCH_GITHUB_APP_ID=<app id> \
  OWNERSWITCH_GITHUB_APP_INSTALLATION_ID=<installation id> \
  OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE=/etc/ownerswitch/github-app.pem \
  OWNERSWITCH_AGENT_WORKSPACE=<the agent's workspace dir> \
  OWNERSWITCH_BROKER_SOCKET=/run/ownerswitch/broker.sock \
  OWNERSWITCH_BROKER_ALLOWED_REPOS=ownerswitch-live-test \
  OWNERSWITCH_CONTROL_PLANE_URL=http://127.0.0.1:8787 \
  pnpm --filter @ownerswitchai/executor exec tsx src/broker-cli.ts
```

The loader refuses a relative key path, a path under the given agent
workspace, a symlink, group/world-readable modes, another user's file,
and non-RSA content; the broker refuses a world-accessible socket
directory. If it won't start, the error names the failing check.

Sanity check the isolation while you're here:
`sudo -u "$(id -un)" cat /etc/ownerswitch/github-app.pem` must fail
(permission denied) — the gateway's uid cannot read the key.

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

## 4. Run the gateway with the executor routed

Start the dev control plane, then launch the gateway with a config whose
policy puts `github.merge_pr` in the `veto` lane and whose
`executorRoutes` maps it to
`{ "connector": "github", "operation": "merge_pull_request" }`
(see `packages/mcp/README.md`), plus:

```sh
export OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET=/run/ownerswitch/broker.sock
```

The startup line must say
`github connector: live via token broker at /run/ownerswitch/broker.sock` —
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

- **Agent-supplied sha refused:** call the tool with an added
  `"expectedHeadSha": "<any 40-hex>"` → refused `-32056` with
  `refusalCode: "invalid-args"`, no veto window opened.
- **Replay:** call the tool again with the original arguments — the pin
  read now finds the PR already merged and refuses
  (`head-pin-failed`, "already merged — nothing to pin") before any
  owner review opens. Nothing merges twice.
- **Moved head:** open a second PR, let its window open, note the pinned
  sha, then push another commit to its branch. Release the window and
  call again → a FRESH veto window opens for the new head (the released
  approval never merges the moved branch). Veto the fresh window to
  finish without merging.
- **Kill gate at the broker:** engage the kill switch, then call the
  tool → the pin read fails closed (`head-pin-failed` — the broker
  refuses: "kill switch engaged"). Restore afterwards.
- **No leak:** grep everything the agent-side client printed (its logs
  and the tool results) for `ghs_`, and for the first 20 characters of
  the key file's base64 body. Both greps must come back empty.

Then delete the throwaway repo, or leave it for the next run.

## What a green run proves

- The end-to-end path is real: agent call → policy lane → review-time
  head pin → owner decision over the pinned args → ActionTicket →
  executor re-checks → a genuine merge on GitHub, performed with an
  installation token the broker minted.
- The uid isolation holds as deployed: the gateway's uid cannot read the
  key file (step 2's sanity check), yet merges work — the key never
  entered the gateway.
- The provisioning recipe works as written: broker user, socket
  directory permissions, key placement checks, the repo allow-list, the
  agent-workspace placement argument.
- The pin is server-derived end to end: the owner-facing window carried
  the real head sha, an agent-supplied sha was refused, and a moved head
  re-opened review instead of merging.
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
- **The kill/epoch race guarantees.** §3's refusal ordering is pinned by
  the executor's own tests; one live merge says nothing about races.
- **Scope enforcement against a hostile ticket.** That the App cannot
  reach other repos is GitHub's enforcement of the installation list —
  this run demonstrates the happy case (plus the broker's own
  allow-list), it does not adversarially probe GitHub's side.
- **Peer identity on the broker socket beyond the kernel's file
  permissions.** A same-uid-as-gateway process that finds the socket can
  request scoped tokens; that residual is documented in
  THREAT-MODEL.md §5 and no run of this procedure changes it.
- **Multi-gateway / restart nonce semantics.** The single-process nonce
  constraint (DESIGN.md §5) is unchanged and untested by this run.
- **Rate-limit behavior.** One merge cannot trip primary or secondary
  limits.
