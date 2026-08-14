#!/usr/bin/env bash
# The First Kill walkthrough's 2GO restore demonstration (FIRST-KILL.md §7).
#
# A script, not a paste block, so it can PROVE what a paste block only
# implies (review-driven, two rounds):
#  - the deliberate EARLY GO 2/2 lands inside the 30 s cooldown, with no
#    human reading time between GO 1/2 and it;
#  - the ceremony id is validated (string, canonical cer_<uuid> grammar)
#    BEFORE anything is posted at it;
#  - every step asserts its EXACT HTTP status — `curl -f` calls a 3xx a
#    success, so no step here relies on -f for its verdict;
#  - every curl carries connect/max timeouts (nothing hangs forever), runs
#    with -q (no ~/.curlrc surprises) and --noproxy '*' (the owner bearer
#    must never transit a configured proxy);
#  - the control-plane URL must be literal-loopback http — the bearer does
#    not ride to anything routable from here;
#  - a restore POST whose outcome is UNKNOWN (transport died, garbled
#    answer) is reconciled against a fresh /status read: the control plane
#    may have committed the restore and lost the response, and reporting
#    "refused" while the system is ARMED would be the worst kind of wrong.
# The repo's test suite (two-go-demo.test.ts) drives this script through
# the failure matrix against a scripted control plane, counting requests
# and checking the exact wire contract.
#
# Runs under bash on purpose — FIRST-KILL.md invokes it as `bash …`, so the
# user's interactive shell (zsh included) never interprets its insides.
set -euo pipefail

CP="${OWNERSWITCH_CONTROL_PLANE_URL:-http://127.0.0.1:4600}"
OWNER="${OWNERSWITCH_OWNER_TOKEN:-}"
MAX_TIME="${OWNERSWITCH_TWO_GO_MAX_TIME_S:-15}"

case "$CP" in
  http://127.*|http://\[::1\]*) ;;
  *)
    echo "two-go-demo: control-plane URL must be literal-loopback http (127.0.0.0/8 or [::1]) — got: $CP" >&2
    exit 1
    ;;
esac
if [ -z "$OWNER" ]; then
  echo "two-go-demo: OWNERSWITCH_OWNER_TOKEN is not exported in this terminal —" >&2
  echo "  the control-plane terminal prints the ready-to-paste export line" >&2
  exit 1
fi

fail() {
  echo "two-go-demo: FAILED — $1" >&2
  exit 1
}

# one exchange: SEND <method> <url> [json-body] -> sets HTTP_STATUS and HTTP_BODY
SEND() {
  local method="$1" url="$2" body="${3-}"
  local body_file
  body_file=$(mktemp)
  local -a args=(-q -sS --noproxy '*' --connect-timeout 5 --max-time "$MAX_TIME"
    -X "$method" "$url" -H "Authorization: Bearer $OWNER" -o "$body_file" -w '%{http_code}')
  if [ -n "$body" ]; then
    args+=(-H 'content-type: application/json' -d "$body")
  fi
  if ! HTTP_STATUS=$(curl "${args[@]}"); then
    rm -f "$body_file"
    HTTP_STATUS=""
    HTTP_BODY=""
    return 1
  fi
  HTTP_BODY=$(cat "$body_file")
  rm -f "$body_file"
}

# the truth of last resort: a fresh /status read. Prints ARMED / KILLED /
# UNKNOWN on stdout; used to reconcile any restore whose outcome is unclear.
status_reading() {
  local out
  if out=$(curl -q -sS --noproxy '*' --connect-timeout 5 --max-time "$MAX_TIME" "$CP/status" 2>/dev/null); then
    printf '%s' "$out" | node -e '
      let d = "";
      process.stdin.on("data", (c) => (d += c)).on("end", () => {
        let killed;
        try { killed = JSON.parse(d).killed; } catch { process.stdout.write("UNKNOWN"); return; }
        process.stdout.write(killed === true ? "KILLED" : killed === false ? "ARMED" : "UNKNOWN");
      });
    '
  else
    printf 'UNKNOWN'
  fi
}

# a restore POST went out but its answer is unusable — reconcile honestly
reconcile_restore() {
  local context="$1"
  case "$(status_reading)" in
    ARMED)
      echo "    /status says the system is ARMED — the restore LANDED and its response was lost."
      return 0
      ;;
    KILLED)
      fail "$context — /status confirms the system is still killed"
      ;;
    *)
      echo "two-go-demo: RESTORE OUTCOME UNKNOWN — do not assume killed; read /status yourself" >&2
      exit 1
      ;;
  esac
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
    const CANON = /^cer_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (typeof id !== "string" || !CANON.test(id)) process.exit(1);
    process.stdout.write(id);
  });
') || fail "GO 1/2 answered without a canonical ceremony id — nothing was posted at a guessed one"
echo "    ceremony $CER is open"

echo "GO 2/2 EARLY, on purpose — the cooldown must refuse this (POST /restore):"
if ! SEND POST "$CP/restore" "{\"ceremonyId\":\"$CER\"}"; then
  echo "    the early GO 2/2's answer was lost mid-flight; reconciling with /status..."
  case "$(status_reading)" in
    ARMED) fail "the EARLY restore appears to have LANDED (system is ARMED) — the cooldown did not refuse; report this" ;;
    KILLED) fail "the early GO 2/2 could not be sent (network/timeout); still killed — retry the script" ;;
    *) echo "two-go-demo: RESTORE OUTCOME UNKNOWN — do not assume killed; read /status yourself" >&2; exit 1 ;;
  esac
fi
echo "    HTTP $HTTP_STATUS $HTTP_BODY"
if [ "$HTTP_STATUS" != "409" ]; then
  if [ "$(status_reading)" = "ARMED" ]; then
    fail "the early GO 2/2 answered HTTP $HTTP_STATUS and the system is now ARMED — the cooldown did not refuse; report this"
  fi
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
if ! SEND POST "$CP/restore" "{\"ceremonyId\":\"$CER\"}"; then
  echo "    the real GO 2/2's answer was lost mid-flight; reconciling with /status..."
  reconcile_restore "the real GO 2/2 could not complete"
else
  echo "    HTTP $HTTP_STATUS $HTTP_BODY"
  if [ "$HTTP_STATUS" != "200" ]; then
    fail "the real GO 2/2 answered HTTP $HTTP_STATUS after the cooldown"
  fi
  printf '%s' "$HTTP_BODY" | node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c)).on("end", () => {
      let killed;
      try { killed = JSON.parse(d).killed; } catch { process.exit(1); }
      if (killed !== false) process.exit(1);
    });
  ' || fail "the restore answer did not say killed:false"
fi

echo "restored — one press to stop, two GOs to start."
