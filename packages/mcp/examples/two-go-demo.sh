#!/usr/bin/env bash
# The First Kill walkthrough's 2GO restore demonstration (FIRST-KILL.md §7).
#
# A script, not a paste block, so it can PROVE what a paste block only
# implies (three review rounds):
#  - the control-plane URL passes a REAL URL parser: http only, no
#    userinfo/path/query/fragment, hostname a numeric 127/8 or ::1 literal
#    (a shell glob would bless http://127.evil.example and userinfo tricks);
#    only the normalized origin is ever dialed;
#  - the deliberate EARLY GO 2/2 lands inside the 30 s cooldown, and the
#    ceremony id is validated against the canonical cer_<UUIDv4> grammar
#    (version and variant bits included) before anything is posted at it;
#  - every step asserts its EXACT HTTP status (curl -f calls a 3xx a
#    success); every curl carries a clamped 1-15 s max-time (an
#    environment override cannot switch the timeout OFF), -q and
#    --noproxy '*' (the bearer must not transit a configured proxy);
#  - ANY restore answer that is not exactly HTTP 200 + killed:false —
#    transport death, truncated body, unexpected status — reconciles
#    against a fresh, STRICTLY validated /status read before a verdict is
#    spoken: the control plane may have committed and lost the response,
#    and "FAILED" over an ARMED system is the worst kind of wrong. The
#    /status read itself trusts only an exact 200 with a well-formed body
#    and no degraded-persistence flags; anything else is OUTCOME UNKNOWN.
# The repo's test suite (two-go-demo.test.ts) drives this script through
# the failure matrix against a scripted control plane.
#
# Runs under bash on purpose — FIRST-KILL.md invokes it as `bash …`, so the
# user's interactive shell (zsh included) never interprets its insides.
set -euo pipefail

fail() {
  echo "two-go-demo: FAILED — $1" >&2
  exit 1
}

RAW_CP="${OWNERSWITCH_CONTROL_PLANE_URL:-http://127.0.0.1:4600}"
OWNER="${OWNERSWITCH_OWNER_TOKEN:-}"

# clamp the per-request timeout to [1, 15] seconds — a 0 would tell curl
# "no timeout at all" and an override must not be able to unbound the demo
MAX_TIME="${OWNERSWITCH_TWO_GO_MAX_TIME_S:-15}"
case "$MAX_TIME" in
  [1-9]|1[0-5]) ;;
  *) MAX_TIME=15 ;;
esac

CP=$(printf '%s' "$RAW_CP" | node -e '
  let d = "";
  process.stdin.on("data", (c) => (d += c)).on("end", () => {
    let u;
    try { u = new URL(d); } catch { process.exit(1); }
    if (u.protocol !== "http:") process.exit(1);
    if (u.username !== "" || u.password !== "") process.exit(1);
    if ((u.pathname !== "" && u.pathname !== "/") || u.search !== "" || u.hash !== "") process.exit(1);
    const h = u.hostname.startsWith("[") && u.hostname.endsWith("]") ? u.hostname.slice(1, -1) : u.hostname;
    const ip4 = require("node:net").isIP(h) === 4 && h.startsWith("127.");
    if (h !== "::1" && !ip4) process.exit(1);
    process.stdout.write(u.origin);
  });
') || fail "control-plane URL must be a literal-loopback http origin (127.0.0.0/8 or [::1]; no userinfo/path/query) — got: $RAW_CP"

if [ -z "$OWNER" ]; then
  echo "two-go-demo: OWNERSWITCH_OWNER_TOKEN is not exported in this terminal —" >&2
  echo "  the control-plane terminal prints the ready-to-paste export line" >&2
  exit 1
fi

BODY_FILE=$(mktemp)
trap 'rm -f "$BODY_FILE"' EXIT HUP INT TERM

# one exchange: SEND <method> <url> [json-body] -> sets HTTP_STATUS and HTTP_BODY
SEND() {
  local method="$1" url="$2" body="${3-}"
  local -a args=(-q -sS --noproxy '*' --connect-timeout 5 --max-time "$MAX_TIME"
    -X "$method" "$url" -H "Authorization: Bearer $OWNER" -o "$BODY_FILE" -w '%{http_code}')
  if [ -n "$body" ]; then
    args+=(-H 'content-type: application/json' -d "$body")
  fi
  if ! HTTP_STATUS=$(curl "${args[@]}"); then
    HTTP_STATUS=""
    HTTP_BODY=""
    return 1
  fi
  HTTP_BODY=$(cat "$BODY_FILE")
}

# The truth of last resort: a fresh /status read, trusted ONLY when it is
# an exact HTTP 200 whose body parses with a boolean killed, a safe epoch,
# a WELL-FORMED killedAgents list (every element a bounded string), and no
# degraded-persistence field PRESENT at all — the flag's existence, not
# its value, is the signal that durable state cannot be trusted. Prints:
#   ARMED   — killed:false AND no scoped kills remain
#   SCOPED  — killed:false but killedAgents is non-empty (a global restore
#             deliberately leaves scoped kills in force)
#   KILLED  — killed:true
#   UNKNOWN — anything else
status_reading() {
  local status body
  if ! status=$(curl -q -sS --noproxy '*' --connect-timeout 5 --max-time "$MAX_TIME" \
    -o "$BODY_FILE" -w '%{http_code}' "$CP/status" 2>/dev/null); then
    printf 'UNKNOWN'
    return
  fi
  body=$(cat "$BODY_FILE")
  if [ "$status" != "200" ]; then
    printf 'UNKNOWN'
    return
  fi
  printf '%s' "$body" | node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c)).on("end", () => {
      let s;
      try { s = JSON.parse(d); } catch { process.stdout.write("UNKNOWN"); return; }
      if (typeof s !== "object" || s === null) { process.stdout.write("UNKNOWN"); return; }
      if ("persistenceDegraded" in s || "unhealthy" in s) { process.stdout.write("UNKNOWN"); return; }
      if (typeof s.epoch !== "number" || !Number.isSafeInteger(s.epoch) || s.epoch < 0) {
        process.stdout.write("UNKNOWN");
        return;
      }
      const agents = s.killedAgents;
      // drift-pinned to @ownerswitchai/shared isValidAgentId: printable
      // ASCII, 1-128, no leading/trailing whitespace
      const AGENT_ID = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;
      if (!Array.isArray(agents) || !agents.every((a) => typeof a === "string" && a.length <= 128 && AGENT_ID.test(a))) {
        process.stdout.write("UNKNOWN");
        return;
      }
      if (s.killed === true) { process.stdout.write("KILLED"); return; }
      if (s.killed !== false) { process.stdout.write("UNKNOWN"); return; }
      process.stdout.write(agents.length === 0 ? "ARMED" : "SCOPED");
    });
  '
}

echo "GO 1/2 — opening the restore ceremony (POST /restore/ceremony)..."
SEND POST "$CP/restore/ceremony" || fail "GO 1/2 could not be sent (network/timeout)"
if [ "$HTTP_STATUS" != "201" ] && [ "$HTTP_STATUS" != "200" ]; then
  fail "GO 1/2 answered HTTP $HTTP_STATUS instead of 201 (created) or 200 (idempotent repeat); is the token the FRESH one from the restarted control plane?"
fi
CER=$(printf '%s' "$HTTP_BODY" | node -e '
  let d = "";
  process.stdin.on("data", (c) => (d += c)).on("end", () => {
    let id;
    try { id = JSON.parse(d).id; } catch { process.exit(1); }
    const CANON = /^cer_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    if (typeof id !== "string" || !CANON.test(id)) process.exit(1);
    process.stdout.write(id);
  });
') || fail "GO 1/2 answered without a canonical ceremony id — nothing was posted at a guessed one"
echo "    ceremony $CER is open"

echo "GO 2/2 EARLY, on purpose — the cooldown must refuse this (POST /restore):"
if ! SEND POST "$CP/restore" "{\"ceremonyId\":\"$CER\"}"; then
  echo "    the early GO 2/2's answer was lost mid-flight; reconciling with /status..."
  case "$(status_reading)" in
    ARMED|SCOPED) fail "the EARLY restore appears to have LANDED — the cooldown did not refuse; report this" ;;
    KILLED) fail "the early GO 2/2 could not be sent (network/timeout); still killed — retry the script" ;;
    *) echo "two-go-demo: RESTORE OUTCOME UNKNOWN — do not assume killed; read /status yourself" >&2; exit 1 ;;
  esac
fi
echo "    HTTP $HTTP_STATUS $HTTP_BODY"
if [ "$HTTP_STATUS" != "409" ]; then
  case "$(status_reading)" in
    ARMED|SCOPED)
      fail "the early GO 2/2 answered HTTP $HTTP_STATUS and the restore LANDED — the cooldown did not refuse; report this"
      ;;
  esac
  fail "the early GO 2/2 answered HTTP $HTTP_STATUS instead of 409 — the cooldown did not refuse; report this"
fi
echo "    (the body never says WHICH check failed — that answer would be a map"
echo "     for someone who is not you; and the failed try spent nothing)"

echo "the cooldown is real — watching it drain (GET /restore/ceremony/<id>):"
DEADLINE=$(( $(date +%s) + 90 ))
while :; do
  SEND GET "$CP/restore/ceremony/$CER" || fail "the ceremony read could not be sent"
  [ "$HTTP_STATUS" = "200" ] || fail "the ceremony read answered HTTP $HTTP_STATUS instead of 200"
  REM=$(printf '%s' "$HTTP_BODY" | node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c)).on("end", () => {
      let rem;
      try { rem = JSON.parse(d).cooldownRemainingMs; } catch { process.exit(1); }
      if (typeof rem !== "number" || !Number.isFinite(rem) || rem < 0) process.exit(1);
      process.stdout.write(String(rem));
    });
  ') || fail "the ceremony read answered without a usable cooldownRemainingMs"
  echo "    cooldownRemainingMs: $REM"
  if [ "$REM" = "0" ]; then break; fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then fail "the cooldown never drained"; fi
  sleep 2
done

echo "GO 2/2 — the SAME ceremony restores (POST /restore):"
FINAL_CLEAN=0
if SEND POST "$CP/restore" "{\"ceremonyId\":\"$CER\"}"; then
  echo "    HTTP $HTTP_STATUS $HTTP_BODY"
  if [ "$HTTP_STATUS" = "200" ] && printf '%s' "$HTTP_BODY" | node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c)).on("end", () => {
      let killed;
      try { killed = JSON.parse(d).killed; } catch { process.exit(1); }
      if (killed !== false) process.exit(1);
    });
  '; then
    FINAL_CLEAN=1
  fi
else
  echo "    the real GO 2/2's answer was lost mid-flight"
fi
# THE POSTCONDITION IS ALWAYS THE ARBITER. A clean 200 killed:false only
# proves the RESPONSE arrived — the restore may have flipped the in-memory
# switch and then failed to persist, and only the next /status says so
# (persistenceDegraded/unhealthy). An unclear answer additionally means
# the commit itself is in question. Either way: one fresh, strictly
# validated /status read decides what may be claimed. Never a blind retry.
if [ "$FINAL_CLEAN" = "1" ]; then
  echo "    confirming with a fresh /status read (durability and scope)..."
else
  echo "    not a clean killed:false answer; reconciling with /status..."
fi
case "$(status_reading)" in
  ARMED)
    if [ "$FINAL_CLEAN" != "1" ]; then
      echo "    /status says the system is ARMED — the restore LANDED and its response was lost."
    fi
    echo "restored — one press to stop, two GOs to start."
    ;;
  SCOPED)
    # exit 3, not 0: automation must not read "fully restored" out of a
    # state that still denies scope-killed agents (review non-blocking)
    echo "    the GLOBAL restore landed, but scoped kills remain (killedAgents is not"
    echo "    empty) — those agents stay denied until their own scoped ceremony."
    echo "global restore complete — scoped kills remain."
    exit 3
    ;;
  KILLED)
    fail "the restore did not take — /status confirms the system is still killed"
    ;;
  *)
    echo "two-go-demo: RESTORE OUTCOME UNKNOWN — the restore may have landed, but /status cannot certify a healthy durable state; do not assume killed OR restored" >&2
    exit 1
    ;;
esac
