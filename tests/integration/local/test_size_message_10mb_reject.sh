#!/bin/bash
# Large payload: 10 MiB inline message must be rejected at input.
#
# `pilotctl send-message` carries data inline (unlike send-file). It is
# expected to have a much smaller cap (typically ≤ 64 KiB or ≤ 1 MiB). A
# 10 MiB inline message must be rejected at input validation — we assert a
# non-zero exit and either no frame on the wire or a small clear error.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Large payload: 10 MiB send-message must reject"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "create 10 MiB random text blob on agent-a"
$DC exec -T agent-a bash -c 'head -c $((10*1024*1024)) /dev/urandom | base64 | head -c $((10*1024*1024)) >/tmp/bigmsg.txt'
SZ=$($DC exec -T agent-a bash -c 'wc -c </tmp/bigmsg.txt' | tr -d ' \r\n')
log_pass "size=$SZ"

log_test "send as inline message (expect rejection or clear error)"
OUT=$($DC exec -T agent-a bash -c 'timeout 30 pilotctl --json send-message agent-b --data "$(cat /tmp/bigmsg.txt)" --type text 2>&1' 2>&1)
RC=$?
OK=$(echo "$OUT" | jq -r ".status // empty" 2>/dev/null)
ERR=$(echo "$OUT" | jq -r '.error // ""' 2>/dev/null)

if [ "$OK" = "ok" ]; then
    log_fail "inline 10 MiB message unexpectedly accepted (no size cap enforced?)"
elif [ -n "$ERR" ] && [ "$ERR" != "null" ] && [ "$ERR" != "" ]; then
    log_pass "rejected with error: '$(echo "$ERR" | head -c 200)'"
elif [ $RC -ne 0 ]; then
    log_pass "non-zero exit ($RC), rejection path taken"
else
    log_fail "ambiguous: rc=$RC ok=$OK err='$ERR' raw=$(echo "$OUT" | head -c 300)"
fi

log_test "daemon still responsive after rejection"
OK_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
OK_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$OK_A" ] && [ "$OK_A" != "0" ] && [ -n "$OK_B" ] && [ "$OK_B" != "0" ]; then
    log_pass "both daemons alive (a=$OK_A b=$OK_B)"
else
    log_fail "daemon died: a='$OK_A' b='$OK_B'"
fi

log_test "no panics/OOM"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|OOM|out of memory" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
