#!/usr/bin/env bash
# The First Kill walkthrough's 2GO restore demonstration (FIRST-KILL.md §7).
#
# A script, not a paste block, for three review-driven reasons:
#  - the deliberate EARLY GO 2/2 must land inside the 30 s cooldown, with no
#    human reading time between GO 1/2 and it;
#  - the ceremony id must be validated (string, canonical cer_<uuid> grammar)
#    BEFORE anything is posted at it — `node -p` happily prints "undefined";
#  - the early answer must REALLY be the 409: -w prints a status, it does
#    not assert one, and a cooldown regression would otherwise walk through
#    this demonstration silently.
# Every assertion here stops the walkthrough loudly instead. The repo's test
# suite (two-go-demo.test.ts) drives this script through the failure matrix
# against a scripted control plane, counting that a failed GO 1/2 issues
# ZERO restore POSTs.
#
# Runs under bash on purpose — FIRST-KILL.md invokes it as `bash …`, so the
# user's interactive shell (zsh included) never interprets its insides.
set -euo pipefail

CP="${OWNERSWITCH_CONTROL_PLANE_URL:-http://127.0.0.1:4600}"
OWNER="${OWNERSWITCH_OWNER_TOKEN:-}"
if [ -z "$OWNER" ]; then
  echo "two-go-demo: OWNERSWITCH_OWNER_TOKEN is not exported in this terminal —" >&2
  echo "  the control-plane terminal prints the ready-to-paste export line" >&2
  exit 1
fi

fail() {
  echo "two-go-demo: FAILED — $1" >&2
  exit 1
}

echo "GO 1/2 — opening the restore ceremony (POST /restore/ceremony)..."
GO1_BODY=$(curl -fsS -X POST "$CP/restore/ceremony" -H "Authorization: Bearer $OWNER") ||
  fail "GO 1/2 was refused; is the token the FRESH one from the restarted control plane?"
CER=$(printf '%s' "$GO1_BODY" | node -e '
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
EARLY_BODY_FILE=$(mktemp)
EARLY_STATUS=$(curl -sS -o "$EARLY_BODY_FILE" -w '%{http_code}' -X POST "$CP/restore" \
  -H "Authorization: Bearer $OWNER" -H 'content-type: application/json' \
  -d "{\"ceremonyId\":\"$CER\"}") || { rm -f "$EARLY_BODY_FILE"; fail "the early GO 2/2 could not be sent"; }
EARLY_BODY=$(cat "$EARLY_BODY_FILE")
rm -f "$EARLY_BODY_FILE"
echo "    HTTP $EARLY_STATUS $EARLY_BODY"
if [ "$EARLY_STATUS" != "409" ]; then
  fail "the early GO 2/2 answered HTTP $EARLY_STATUS instead of 409 — the cooldown did not refuse; report this"
fi
echo "    (the body never says WHICH check failed — that answer would be a map"
echo "     for someone who is not you; and the failed try spent nothing)"

echo "the cooldown is real — watching it drain (GET /restore/ceremony/<id>):"
DEADLINE=$(( $(date +%s) + 90 ))
while :; do
  REM=$(curl -fsS "$CP/restore/ceremony/$CER" -H "Authorization: Bearer $OWNER" | node -e '
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
FINAL=$(curl -fsS -X POST "$CP/restore" -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' -d "{\"ceremonyId\":\"$CER\"}") ||
  fail "the real GO 2/2 was refused after the cooldown"
echo "    $FINAL"
printf '%s' "$FINAL" | node -e '
  let d = "";
  process.stdin.on("data", (c) => (d += c)).on("end", () => {
    let killed;
    try { killed = JSON.parse(d).killed; } catch { process.exit(1); }
    if (killed !== false) process.exit(1);
  });
' || fail "the restore answer did not say killed:false"

echo "restored — one press to stop, two GOs to start."
