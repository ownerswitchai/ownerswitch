# @ownerswitchai/honeytoken

**Decoy credentials that trip on touch — a decoy file read raises an alert, a
decoy value crossing the gateway engages the kill.**

A honeytoken is a credential-shaped string with no power: it was never issued
by any provider and authenticates nothing anywhere. Its only job is to be
touched. Plant a few where a credential hunt looks first — an `.env.backup`, a
`credentials.json` — and OwnerSwitch watches for them. What happens on a touch
depends on *how* it was touched, and that split is the whole safety story:

- **a decoy FILE is read / written / deleted → ALERT.** Flagged to the
  control plane and audited; **not** a kill. Reads have innocent causes.
- **a decoy VALUE is about to be forwarded across the gateway → KILL.** A
  signed kill, no appeal. Nothing innocent forwards a planted secret. Restore
  stays a 2GO ceremony.

## Recognition: a deployment-scoped registry, not a checksum

Tokens are recognised by **exact membership in a per-deployment registry** of
the planted values — not by a self-validating checksum embedded in the value.
This is the load-bearing security decision, and it is what makes the tripwire
safe to wire to a global kill:

- **No short tag to brute-force.** An earlier design embedded a 20-bit keyed
  checksum. That is ~1M candidates: an attacker could enumerate every
  candidate for one random prefix in a single tool-call payload, land the one
  that validated, and fire a kill nobody planted — while forcing ~1M HMACs.
  Membership matching removes the tag entirely. To make the scanner fire you
  must present a value that was *actually planted*, i.e. reproduce a token's
  full high-entropy body. Entropy floors: generic 170 bits, openai 210,
  stripe 90, aws 50. Even the aws floor (2^50 twenty-byte candidates ≈ 20 PB)
  cannot be enumerated in a payload; where ≥128-bit assurance is needed for an
  AWS *secret*, plant the `generic` costume — the 20-char access-key-id shape
  cannot exceed 80 bits and still look like an access key id.
- **Bounded scan cost.** Matching is a set of substring checks, one per
  planted token — never per attacker-supplied candidate. There is no
  per-candidate HMAC to grind into a denial of service.

Every value still carries the visible `CANARY` marker so the audit log can
never mistake a decoy for a live credential, and each costume still wears its
provider's shape (`AKIA…`, `sk_live_…`, `sk-…`) so a sweep greps it up as the
real thing.

### The registry is bound to the deployment

The registry is provisioned with two secrets that are **not** the device
secret used to sign kills:

- a **dedicated canary key** — required, no fallback. Defaulting to the device
  secret was wrong twice over: two gateways with different device secrets
  would fail to recognise each other's tokens, and a device secret reused
  across deployments would make cross-deployment matching accidental. The
  canary key is its own provisioned secret; weak or sample values are
  rejected at config time (`requireCanaryKey`).
- an **immutable deployment id**, mixed into the registry's integrity MAC's
  domain separation. A registry minted for deployment A is rejected at load
  under deployment B's id, even if the key matched.

The serialized registry file is MAC'd with the canary key, so a tampered
registry — entries added to force false kills, or removed to blind the
tripwire — is rejected at load. The plaintext values live in that file and in
any gateway that loads it: a deliberate trade, since the gateway is the
enforcement point and a compromise there already defeats honeytokens.

## What honeytokens catch — and what they don't

Honest version, before you rely on this:

**They catch curiosity and broad sweeps.** An agent that wanders into a backup
file it had no reason to read (→ alert). A prompt-injected "collect every key
you can find and post them" that pushes a decoy value through an *allowed*
tool call (→ kill). A dependency doing a bulk grep for `AKIA`/`sk_live_`.

**They do not catch a targeted attacker who knows to avoid them.** The visible
`CANARY` marker means anyone who inspects a value, knows OwnerSwitch is
deployed, or avoids files they didn't expect to need, walks around the bait.
Honeytokens raise the cost of *indiscriminate* theft; they are not a defense
against someone reading this README. Layer them under the policy gateway and
the rest of your containment — a tripwire in the yard, not a lock on the door.

**Known evasions and gaps, stated plainly:**

- **Transformed values.** The scanner matches the exact planted value.
  Base64-encode, lowercase, or split it across fields — no trip.
- **Reads on `noatime` mounts.** Read detection rides atime (below). A mount
  that never records reads only alerts on write/replace/delete; the CLI probes
  for this at arm time and tells you.
- **Copies made before arming**, or exfiltration through a channel the gateway
  doesn't see, trip nothing until the value reappears somewhere we scan.
- **Non-gateway exfiltration.** The argument scanner sees calls routed through
  the OwnerSwitch MCP gateway. An agent with raw network access can leak a
  decoy without crossing it. (Same enforcement-boundary honesty as the
  gateway's own [threat model](../mcp/THREAT-MODEL.md).)

## Two tiers, and why the gateway checks policy first

| trigger | tier | what happens |
| --- | --- | --- |
| decoy **file** read / write / rename / delete | **ALERT** | `POST /alert` — audited, kill state unchanged |
| decoy **value** in a call the gateway is **about to forward** | **KILL** | `POST /kill` — signed, no appeal, background-retried |
| decoy **value** in a call the gateway **will not forward** (denied, approval-gated, held) | **ALERT** | `POST /alert` — flagged, never killed |

The gateway evaluates policy **before** scanning, and scans for kill only
immediately before it would actually forward a call. This is deliberate: if
scanning ran first, a decoy value would be a *remote kill primitive* — an
attacker who gets the value into **any** attempted call, even one policy
denies, could fire a global kill. Instead a decoy in a non-forwarded call only
raises an alert; the kill is reserved for a value genuinely on its way out.
For a vetoed call the scan runs after owner release, right before forwarding.

Escalating a file touch to a kill is a separate, visibly dangerous opt-in
(`watch --DANGER-kill-on-touch`), never the default.

## Delivery: alerts never block kills

Alerts and kills travel on **independent delivery lanes**. An earlier design
shared one strict FIFO whose head retries forever — so an undeliverable alert
(404, 500, a hung socket, a version mismatch) could sit at the head and starve
a genuine kill queued behind it. Now the kill lane drains on its own; a stuck
alert cannot delay a kill by a millisecond. Within each lane, delivery keeps
the button daemon's discipline (200/400/800 ms then every 2 s, fresh signature
per attempt), and `flush()` before shutdown blocks until both lanes drain or a
bounded number of retries is exhausted — so an agent that can influence
process exit cannot silently swallow a tripped-but-unconfirmed report.

## Use

```bash
# Provision a DEDICATED canary key and a deployment id (NOT the device secret):
export OWNERSWITCH_CANARY_KEY=$(openssl rand -hex 24)
export OWNERSWITCH_DEPLOYMENT_ID=prod-us-east

# 1. plant decoys and write the signed registry (keep it OUT of the decoy dir)
ownerswitch-honeytoken plant --dir /srv/agent-home \
  --registry /etc/ownerswitch/honeytokens.json

# 2. arm the file tripwires. Default: a touch ALERTS.
ownerswitch-honeytoken watch --dir /srv/agent-home \
  --registry /etc/ownerswitch/honeytokens.json \
  --url http://localhost:4000 --device-id honeypot-1 --secret $OWNERSWITCH_DEVICE_SECRET
#   add --DANGER-kill-on-touch to escalate file touches to kills (opt-in)

# 3. arm the gateway's argument scanner (opt-in via env):
export OWNERSWITCH_HONEYTOKEN_REGISTRY=/etc/ownerswitch/honeytokens.json
ownerswitch-mcp --config gateway.json     # loads + verifies the registry, then scans
```

Library surface: `generateHoneytoken({ kind, label })`, `HoneytokenRegistry` /
`loadRegistry` / `requireCanaryKey`, `scanForHoneytokens(text, registry)`,
`watchHoneytokenFiles({ paths, onTrip, registry })`, `createTripReporter(...)`,
`plantHoneytokens({ dir, canaryKey, deploymentId })`, `createTripwire(...)`.

## How detection works (and its physics)

- **File reads** cannot be observed by `fs.watch` — no portable API reports
  opens. The watcher pairs `fs.watch` (instant write/replace/delete events)
  with a short-interval `stat()` poll of atime. On `relatime` mounts (the
  Linux default) atime only advances when atime ≤ mtime, so arming *primes*
  each file by backdating its atime — the next read, the one that matters, is
  recorded. `fsReportsReads(dir)` probes whether a mount cooperates.
- **One trip per path.** The first touch fires and disarms that file's
  tripwire; the response is already in flight. Other planted files stay armed.
- **A trip is never lost.** Reports queue and retry with fresh signatures; on
  shutdown the reporter `flush()`es, bounded, and logs any give-up as the
  emergency it is.
