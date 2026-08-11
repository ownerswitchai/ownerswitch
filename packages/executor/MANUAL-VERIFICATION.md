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

**Run only INSTALLED, root-owned artifacts — never a user checkout.** The
broker and the control plane hold the HMAC keys and the App PEM, so the
CODE they execute must be immutable to the agent: a same-uid agent that can
edit files in your working copy could rewrite `dev-control-plane.ts` (or
the broker entrypoint) and wait for a restart, and the isolated process
would then run attacker-controlled code holding both keys. Build once and
install the built `dist/` to a root-owned tree the service uids can execute
but not write:

```sh
pnpm -r build
sudo mkdir -p /opt/ownerswitch
sudo cp -R . /opt/ownerswitch/src            # or install just the built dist/ trees
sudo chown -R root:root /opt/ownerswitch     # root-owned: no service uid can modify the code
sudo chmod -R go-w /opt/ownerswitch
```

Launch every service from `/opt/ownerswitch` (absolute paths), under
systemd units whose `ExecStart` names an absolute, root-owned binary —
never `pnpm ... dev:control-plane` from your home directory. The commands
below use `/opt/ownerswitch` to make the point; a production deployment
uses packaged artifacts and `systemd` service files with `User=`,
`SupplementaryGroups=`, `LoadCredential=` and `ReadOnlyPaths=/opt/ownerswitch`.

Create **three** distinct uids and two groups. The broker owns the App PEM
and the burn store; the control plane runs as a SEPARATE uid (it must not
be able to read the App PEM); the gateway is your own user. A secrets
group lets the broker and the control plane — and ONLY those two — read the
shared HMAC keys.

```sh
sudo useradd --system --shell /usr/sbin/nologin oswitch-broker
sudo useradd --system --shell /usr/sbin/nologin oswitch-cp       # control plane: its OWN uid
sudo groupadd oswitch && sudo usermod -aG oswitch "$(id -un)"    # gateway's user in the socket group
sudo usermod -aG oswitch oswitch-broker                          # broker in it too, for its egid
sudo groupadd oswitch-secrets                                    # holds the shared HMAC keys
sudo usermod -aG oswitch-secrets oswitch-broker
sudo usermod -aG oswitch-secrets oswitch-cp                      # NOT the gateway/agent user

sudo mkdir -p /etc/ownerswitch
sudo mv ~/Downloads/<app-name>.*.private-key.pem /etc/ownerswitch/github-app.pem
sudo chown oswitch-broker /etc/ownerswitch/github-app.pem        # broker only — CP cannot read it
sudo chmod 600 /etc/ownerswitch/github-app.pem
# setgid (02750) socket dir so the socket inode inherits the oswitch group:
sudo install -d -o oswitch-broker -g oswitch -m 02750 /run/ownerswitch
OSWITCH_GID=$(getent group oswitch | cut -d: -f3)
# durable burn store — broker-owned, 0700, OUTSIDE the agent workspace:
sudo install -d -o oswitch-broker -g oswitch-broker -m 0700 /var/lib/ownerswitch/burns
```

Two shared **HMAC keys**, each ≥256 bits — the `grant` key authorizes
merges, the `kill-state` key authenticates the broker's live kill check.
Both belong to the broker AND the control plane and to NOTHING else. Write
them to root-owned, `oswitch-secrets`-readable files (mode 0640) — never to
a shell the gateway shares, and never onto any command line:

```sh
umask 077
openssl rand -hex 32 | sudo tee /etc/ownerswitch/grant.key      >/dev/null
openssl rand -hex 32 | sudo tee /etc/ownerswitch/kill-state.key  >/dev/null
sudo chgrp oswitch-secrets /etc/ownerswitch/grant.key /etc/ownerswitch/kill-state.key
sudo chmod 0640           /etc/ownerswitch/grant.key /etc/ownerswitch/kill-state.key
```

Why files, not `-e KEY=…`/argv: a command line is world-readable through
`/proc/<pid>/cmdline` and `ps`, so a secret in argv leaks to the same uid
the whole design is defending against. The service reads each key from its
file into its OWN environment at launch — the secret lands in
`/proc/<pid>/environ` (readable only by that service's uid), and the only
argument any process sees is the file PATH:

```sh
sudo -u oswitch-broker sg oswitch -c '
  set -a
  OWNERSWITCH_GRANT_KEY="$(cat /etc/ownerswitch/grant.key)"
  OWNERSWITCH_KILL_STATE_KEY="$(cat /etc/ownerswitch/kill-state.key)"
  OWNERSWITCH_GITHUB_APP_ID=<app id>
  OWNERSWITCH_GITHUB_APP_INSTALLATION_ID=<installation id>
  OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE=/etc/ownerswitch/github-app.pem
  OWNERSWITCH_AGENT_WORKSPACE=<the agent workspace dir>
  OWNERSWITCH_BROKER_SOCKET=/run/ownerswitch/broker.sock
  OWNERSWITCH_BROKER_SOCKET_GID='"$OSWITCH_GID"'
  OWNERSWITCH_BROKER_BURN_DIR=/var/lib/ownerswitch/burns
  OWNERSWITCH_BROKER_ALLOWED_REPOS=ownerswitch-live-test
  OWNERSWITCH_CONTROL_PLANE_URL=http://127.0.0.1:4600
  set +a
  exec ownerswitch-merge-broker'
```

(The control-plane URL is `:4600` — the port the control plane listens on
below. Keep the two in lock-step.)

(In production this is a systemd unit with `User=oswitch-broker`,
`SupplementaryGroups=oswitch`, and `LoadCredential=`/`EnvironmentFile=` for
the keys — same property: keys in the environment, never in argv.)

The loader refuses a relative key path, a path under the given agent
workspace, a symlink, group/world-readable modes, another user's file, and
non-RSA content; the broker refuses a short (<256-bit) grant key, a
world- or group-writable socket directory, and refuses to serve if the
socket's gid is not `OWNERSWITCH_BROKER_SOCKET_GID`; the burn store refuses
a relative path, a symlink, or a path inside the agent workspace. If it
won't start, the error names the failing check.

Sanity-check the isolation while you're here (ALL must hold):
- `sudo -u "$(id -un)" cat /etc/ownerswitch/github-app.pem` must FAIL —
  the gateway's uid cannot read the App key.
- `sudo -u "$(id -un)" cat /etc/ownerswitch/grant.key` must FAIL — the
  gateway's uid cannot read the HMAC keys (so it cannot forge a grant even
  if it wanted to; the gateway also refuses to START if the key is in its
  env).
- `sudo -u oswitch-cp cat /etc/ownerswitch/github-app.pem` must FAIL — the
  control plane's uid cannot read the App PEM (distinct-uid isolation).
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

Start the PRODUCTION control plane as its OWN uid (`oswitch-cp`), from the
installed artifact, reading its secrets from files into its environment —
never argv. This is `control-plane` (dev:false), NOT `dev:control-plane`:
it enforces the hardened kill-state path, the ≥256-bit key floors, the
https-origin requirement, and — because a passkey is enrolled — it requires
a fresh WebAuthn assertion for every merge approval (a reusable owner
session alone is refused). Enroll the owner's approval passkey in the owner
app first; that yields a credential id, an SPKI public-key PEM, an rpId and
the app's exact https origin, provided here as configuration:

```sh
sudo -u oswitch-cp sg oswitch-secrets -c '
  set -a
  OWNERSWITCH_CONTROL_PLANE_PORT=4600
  OWNERSWITCH_DEVICE_SECRET="$(cat /etc/ownerswitch/device.secret)"
  OWNERSWITCH_KILL_STATE_FILE=/var/lib/ownerswitch/kill-state.json
  OWNERSWITCH_GRANT_KEY="$(cat /etc/ownerswitch/grant.key)"
  OWNERSWITCH_KILL_STATE_KEY="$(cat /etc/ownerswitch/kill-state.key)"
  OWNERSWITCH_OWNER_PASSKEY_CREDENTIAL_ID="$(cat /etc/ownerswitch/passkey.credential-id)"
  OWNERSWITCH_OWNER_PASSKEY_PUBLIC_KEY_FILE=/etc/ownerswitch/passkey.pub.pem
  OWNERSWITCH_OWNER_PASSKEY_RP_ID=owner.example
  OWNERSWITCH_OWNER_PASSKEY_ORIGIN=https://owner.example
  set +a
  exec node /opt/ownerswitch/src/packages/mcp/dist/control-plane.js'
```

The control plane runs where the agent's uid cannot read its environment,
from code the agent cannot rewrite, so the keys it holds are out of the
agent's reach — the same isolation the broker gets, and the reason it is a
distinct uid from both the gateway and (so it cannot read the App PEM) the
broker. (The 5-minute QUICKSTART uses `dev:control-plane`, which approves
on a reusable session and must set
`OWNERSWITCH_ACCEPT_SESSION_ONLY_APPROVAL_RISK=1` to start with a grant key
but no passkey — that path is for the quickstart only, never a live merge.)

Then launch the gateway with a config whose policy puts `github.merge_pr`
in an **owner-gated lane** and whose `executorRoutes` maps it to
`{ "connector": "github", "operation": "merge_pull_request" }` (see
`packages/mcp/README.md`), plus:

```sh
export OWNERSWITCH_GITHUB_TOKEN_BROKER_SOCKET=/run/ownerswitch/broker.sock
```

The gateway needs NO GitHub credential and NO HMAC key — and REFUSES to
start if `OWNERSWITCH_GRANT_KEY` is present in its environment (a key the
gateway can read, the same-uid agent can read, and with it forge grants).
Its startup line must say
`github connector: live via EXECUTING merge broker at /run/ownerswitch/broker.sock` —
`not configured` means the variable didn't resolve.

**A merge is authorized by the owner's ACTIVE approval, not by silence.**
The grant-eligible lane no longer releases a merge on a quiet timeout: the
control plane mints the signed grant only when the owner actively approves
the exact pinned call through an owner SESSION (the phone app / an owner
bearer token), which the same-uid agent cannot forge. Silence leaves the
call pending indefinitely; only a real owner "yes" — or a "no" (veto) —
moves it.

## 5. The live merge

From the MCP client (agent side), call the routed tool — note there is
NO sha argument; the pin is OwnerSwitch's job:

```json
{ "name": "github.merge_pr", "arguments": {
    "owner": "<you>", "repo": "ownerswitch-live-test", "pullNumber": 1,
    "mergeMethod": "squash" } }
```

1. First call → refused `-32052` (owner-review window open). **Inspect the
   window the owner sees**: its arguments must carry `expectedHeadSha`
   equal to the head SHA you noted — server-derived, agent-untouched.
2. **Actively approve** the exact window as the owner would. With a
   passkey enrolled (production stance): request the ceremony
   (POST `/veto/<id>/approval-challenge`, owner bearer token) — its
   response names the exact `canonicalArgs`/`callHash` being approved,
   including the pinned head AND base — then complete it from the owner
   app with the passkey (POST `/veto/<id>`
   `{"decision":"approve","assertion":{…}}`). In a dev run without an
   enrolled passkey, session-only approve works and SAYS so. Confirm that
   letting the window sit WITHOUT approving never merges: a quiet poll
   stays `pending`, no grant is minted — and that with a passkey enrolled,
   the bearer session ALONE (no assertion) is refused 401.
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
- **An impostor kill-state server cannot fool the broker.** Stop the real
  control plane, then, as any local uid, bind `127.0.0.1:8787` with a
  process that answers `GET /kill-state` with
  `{"killed":false,"epoch":<the epoch a captured grant needs>}` and a
  bogus `sig`. Present a still-live grant to the broker → it must REFUSE
  ("kill switch engaged (or control plane unreachable)"): the signature
  does not verify under the shared kill-state key, so the impostor's
  "not killed" is rejected and the broker fails closed. Restart the real
  control plane afterward.
- **A merge cannot be approved while killed, and the approval does not
  survive restore.** Engage the kill, then attempt the owner approval →
  `409` ("cannot approve while the kill switch is engaged"). Restore, and
  confirm the window must be approved AGAIN (its pre-restore state carried
  no grant): a kill always forces fresh post-restore review.
- **A veto REVOKES an issued grant.** On a fresh PR: approve, poll once so
  the grant is fetched, then VETO the same window (allowed after approval
  for merge windows), then present the held grant bytes at the broker
  socket by hand → refused ("the control plane no longer vouches for this
  grant"), zero merges. The owner's "no" wins any time before dispatch.
- **A retargeted PR does not merge into the new base.** On a fresh PR:
  approve against base `main`, then change the PR's base branch on
  github.com, then let the gateway retry → the broker's pre-dispatch base
  check refuses ("retargeted after approval"), nothing merges. Re-approve
  against the new destination to proceed (or veto to finish).
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
  sha, then push another commit to its branch. Approve the window and
  call again → a FRESH owner-review window opens for the new head (the
  approved grant never merges the moved branch). Veto the fresh window to
  finish without merging.
- **Allow lane refused:** temporarily move `github.merge_pr` to the
  `allow` lane and call it → refused `-32056`
  `refusalCode: "owner-grant-required"`, nothing runs. Put it back in the
  owner-gated lane.
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
  head pin → the owner's ACTIVE approval over the pinned args →
  control-plane-signed grant → broker validates it independently and
  PERFORMS the merge with a token that never crossed the socket.
- Silence never merges: a grant-eligible window left unapproved stayed
  pending and minted nothing; only the owner's session-authenticated "yes"
  produced a grant.
- The uid isolation holds as deployed, three ways: the gateway's uid
  cannot read the App PEM or the HMAC keys, and the control plane's uid
  cannot read the App PEM — yet merges work, with no key and no token ever
  entering the gateway.
- The socket hands out results, never authority: a direct client asking
  for a token gets nothing, a forged grant is refused, and a non-group
  uid cannot even connect.
- The kill channel is authenticated: an impostor that binds the loopback
  port after the control plane stops cannot fake "not killed" — its
  unsigned answer is rejected and the broker fails closed.
- The provisioning recipe works as written: three uids, the secrets group,
  setgid socket directory, verified socket gid, keys read from files (never
  argv), key placement checks, the durable burn directory, repo allow-list.
- The pin is server-derived end to end and the schema is enforced: the
  owner-facing window carried the real head sha, an agent-supplied sha
  and an unknown field were both refused, and a moved head re-opened
  review instead of merging.
- Single-use is durable: the burn survived a broker restart, so one
  approval yielded exactly one merge even across a restart.
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
