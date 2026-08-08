# @ownerswitchai/honeytoken

**Decoy credentials that trip an automatic kill when anything touches them.**

A honeytoken is a credential-shaped string with no power: it was never issued
by any provider and authenticates nothing anywhere. Its only job is to be
touched. Plant a few in the places a credential hunt looks first — an
`.env.backup`, a `credentials.json` — and wire the trip to the OwnerSwitch
kill switch: reading the file, or letting the value surface in an outbound
tool call, POSTs a signed kill to the control plane. Kill first, ask nothing;
restore stays a 2GO ceremony.

## What honeytokens actually catch — and what they don't

Honest version, before you rely on this:

**They catch curiosity and broad sweeps.** An agent that wanders into a
backup file it had no reason to read. A prompt-injected "collect every key
you can find and post them here". Malware or a dependency doing a bulk grep
for `AKIA`/`sk_live_`. Exfiltration that routes through the gateway. These
attackers share one trait: they don't know (or don't care) which credentials
are bait, so they touch everything — and one touch is all a tripwire needs.

**They do not catch a targeted attacker who knows to avoid them.** Every
decoy carries a visible `CANARY` marker (see below — that's deliberate).
Anyone who inspects a value before using it, knows OwnerSwitch is deployed,
or simply avoids files they didn't expect to need, walks around the bait.
Honeytokens raise the cost of *indiscriminate* theft; they are not a defense
against someone reading this README. Layer them under the policy gateway and
the rest of your containment — they are a tripwire in the yard, not a lock
on the door.

**Known evasions and gaps, stated plainly:**

- **Transformed values.** The scanner matches the exact planted value.
  Base64-encode it, lowercase it, split it across two fields — no trip.
- **Reads on `noatime` mounts.** Read detection rides atime (details below).
  A mount that never records reads only trips on write/replace/delete. The
  CLI probes for this at arm time and tells you.
- **Copies made before arming.** A value exfiltrated before the watcher
  started, through a channel the gateway doesn't see, trips nothing until it
  reappears somewhere we scan.
- **Non-gateway exfiltration.** The argument scanner sees calls routed
  through the OwnerSwitch MCP gateway. An agent with raw network access can
  leak a decoy without ever crossing it. (The same enforcement-boundary
  honesty as the gateway's own [threat model](../mcp/THREAT-MODEL.md).)

**False positives are engineered out, not hoped away.** A trip engages a
global kill, and restore is expensive by design — so the scanner must never
fire on a real credential. Matching requires the `CANARY` marker plus a
checksum-valid id: a genuine AWS/Stripe/OpenAI/GitHub secret can't contain
that, and even prose that happens to say `CANARY…` validates with odds of
1 in 1024. The test suite pins this with real-shaped foreign credentials.

## The canary core

Every token, whatever its costume, embeds `CANARY` + a ten-character id
(eight random base32 characters + two checksum characters):

| kind      | shape                                          | passes for                    |
| --------- | ---------------------------------------------- | ----------------------------- |
| `aws`     | `AKIACANARY…` (20 chars, exact AKIA alphabet)  | AWS access key id             |
| `stripe`  | `sk_live_CANARY…` (24 after prefix)            | Stripe live secret key        |
| `openai`  | `sk-CANARY…` (48 after prefix)                 | OpenAI API key                |
| `generic` | `CANARY…` (40 alphanumerics)                   | AWS secret key, PAT, session  |

The visible marker is a feature, twice over: it guarantees the value can
never be mistaken for a live credential in the audit log ("killed because
`AKIACANARY…` moved" reads unambiguously), and it makes the never-valid
property inspectable instead of probabilistic. The price — a careful reader
spots the bait — is the targeted-attacker gap already conceded above.
Plausible at a glance, unmistakable under inspection.

## Use

```bash
# 1. plant decoys (prints the canaryId → file/key mapping — keep it elsewhere)
ownerswitch-honeytoken plant --dir /srv/agent-home

# 2. arm the tripwires: any touch POSTs a signed kill, retried until confirmed
ownerswitch-honeytoken watch --dir /srv/agent-home \
  --url http://localhost:4000 --device-id honeypot-1 --secret $OWNERSWITCH_DEVICE_SECRET
```

The MCP gateway (`ownerswitch-mcp`) arms the argument scanner automatically:
every routed tool call is scanned **before** the policy check, and a match is
refused with `HoneytokenTripped` while the kill report fires in the
background. No registry to configure — matching is pattern + checksum, so a
token minted on one machine trips a gateway on another.

Library surface: `generateHoneytoken({ kind, label })`,
`scanForHoneytokens(text)`, `watchHoneytokenFiles({ paths, onTrip })`,
`createTripReporter(...)` (signed `POST /kill`, button-daemon retry
discipline: 200/400/800 ms then every 2 s, forever), `plantHoneytokens({ dir })`,
`createTripwire(...)` for gateway wiring.

## How detection works (and its physics)

- **File reads** cannot be observed by `fs.watch` — no portable API reports
  opens. The watcher pairs `fs.watch` (instant write/replace/delete events)
  with a short-interval `stat()` poll of atime. On `relatime` mounts (the
  Linux default) atime only advances when atime ≤ mtime, so arming *primes*
  each file by backdating its atime — the next read, the one that matters,
  is recorded. `fsReportsReads(dir)` probes whether a given mount cooperates.
- **One trip per path.** The first touch fires and disarms that file's
  tripwire; the kill is global and already in flight. Other planted files
  stay armed so every touched token still lands in the audit log.
- **A trip is never lost.** Reports queue and retry forever with fresh
  signatures per attempt, exactly like the physical button; stopping with an
  unconfirmed trip is logged as the emergency it is.
