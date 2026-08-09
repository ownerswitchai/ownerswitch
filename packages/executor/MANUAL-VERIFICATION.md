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
- A machine with the repo checked out, `pnpm install` done, and a shell
  the agent does not share.

## 1. Create and install the GitHub App (once)

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
   - Name: anything (`ownerswitch-live-test-app`).
   - Webhook: **disabled**.
   - Repository permissions: **Contents: Read and write**,
     **Pull requests: Read-only**. Nothing else.
2. Note the **App ID** from the App's About page.
3. **Install** the App: Install App → your account → **"Only select
   repositories"** → exactly the throwaway repo. Note the numeric
   **installation id** — it is the trailing number in the installation's
   settings URL (`…/settings/installations/<id>`).
4. Generate a **private key**; a `.pem` file downloads.

## 2. Provision the key like a production credential

The point of doing this properly in a test run is that the run also
rehearses the deployment rule. As root (or your own user — just NOT a
path inside the agent's workspace or the gateway's working directory):

```sh
sudo mkdir -p /etc/ownerswitch
sudo mv ~/Downloads/<app-name>.*.private-key.pem /etc/ownerswitch/github-app.pem
sudo chown "$(id -u)" /etc/ownerswitch/github-app.pem
sudo chmod 600 /etc/ownerswitch/github-app.pem
```

The loader refuses a relative path, a path under the gateway's cwd, a
symlink, group/world-readable modes, another user's file, and non-RSA
content — if the gateway won't start, the error names the failing check.

## 3. Open a PR in the throwaway repo

```sh
git clone https://github.com/<you>/ownerswitch-live-test && cd ownerswitch-live-test
git checkout -b live-test && echo "executor live test $(date -u +%FT%TZ)" > witness.txt
git add witness.txt && git commit -m "executor live-run witness" && git push -u origin live-test
# open the PR and note its number, e.g. #1
```

Record the PR's **head SHA** (`git rev-parse HEAD`) — the run will pin the
approval to it via `expectedHeadSha`.

## 4. Run the gateway with the executor routed

Start the dev control plane (`pnpm --filter @ownerswitchai/mcp exec tsx
src/dev-control-plane.ts`, or your real one), then launch the gateway
with a config whose policy puts `github.merge_pr` in the `veto` lane and
whose `executorRoutes` maps it to
`{ "connector": "github", "operation": "merge_pull_request" }`
(see `packages/mcp/README.md` for the full config shape), and the App
environment set:

```sh
export OWNERSWITCH_GITHUB_APP_ID=<app id>
export OWNERSWITCH_GITHUB_APP_INSTALLATION_ID=<installation id>
export OWNERSWITCH_GITHUB_APP_PRIVATE_KEY_FILE=/etc/ownerswitch/github-app.pem
```

The startup line must say
`github connector: live (App <id>)` — `not configured` means the
environment triple didn't resolve.

## 5. The live merge

From the MCP client (agent side), call the routed tool:

```json
{ "name": "github.merge_pr", "arguments": {
    "owner": "<you>", "repo": "ownerswitch-live-test", "pullNumber": 1,
    "mergeMethod": "squash", "expectedHeadSha": "<the 40-hex head sha>" } }
```

1. First call → refused `-32052` (veto window open). Release it the way
   the owner would (or wait out the window per your control plane).
2. Call again → the merge runs. Expect a result like
   `{ "resourceId": "github:pr:<you>/ownerswitch-live-test#1",
      "detail": { "merged": true, "sha": "<merge commit>", "message": "…" } }`.
3. Confirm on github.com: the PR is merged, and the merge was performed
   by the App (the merge commit is attributed to the App's bot identity).

## 6. Negative checks (same session, no second merge)

- **Replay:** call the tool a third time with the same arguments — the
  veto lane opens a fresh window; after release it must fail with HTTP
  405 semantics ("not mergeable — … or already merged"), classified
  `not-performed`. Nothing merges twice.
- **Head pinning:** for a second PR, pass an `expectedHeadSha` that is a
  full-length but WRONG sha — expect the 409 refusal naming the moved
  head, and the PR untouched.
- **No leak:** grep everything the agent-side client printed (its logs
  and the tool results) for `ghs_`, and for the first 20 characters of
  the key file's base64 body. Both greps must come back empty.

Then delete the throwaway repo, or leave it for the next run.

## What a green run proves

- The end-to-end path is real: agent call → policy lane → owner decision
  → ActionTicket → executor re-checks → a genuine merge on GitHub,
  performed with OwnerSwitch's own App credential.
- The provisioning recipe works as written: key placement checks, the
  all-or-nothing environment triple, installation-scoped access.
- The App's scoping is honored by GitHub for this installation: the token
  minted for the throwaway repo merged in it.
- The agent-visible surface (results, refusals, logs) carried no
  credential during a real run with real errors.

## What it does NOT prove

- **Any of the failure classifications under real network failure.** The
  wire-death and 5xx verification branches ran only against scripted
  responses; a live run exercising them would require injecting faults
  into a TLS connection to GitHub. The unit tests are the evidence there.
- **The kill/epoch race guarantees.** §3's refusal ordering is pinned by
  the executor's own tests; one live merge says nothing about races.
- **Scope enforcement against a hostile ticket.** That the App cannot
  reach other repos is GitHub's enforcement of the installation list —
  this run demonstrates the happy case, it does not adversarially probe
  it (try a ticket naming a repo the App is not installed on if you want
  that check: expect the 422/404 mint-or-merge refusal).
- **Multi-gateway / restart nonce semantics.** The single-process nonce
  constraint (DESIGN.md §5) is unchanged and untested by this run.
- **Rate-limit behavior.** One merge cannot trip primary or secondary
  limits.
