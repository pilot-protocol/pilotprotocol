#!/bin/bash
# Duration: 1 msg/s for 60 s.
# Lightweight periodic sanity check; no slow-CI tag.

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
DUR=60

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: 1 msg/s x ${DUR}s"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "1 msg/s for ${DUR}s"
SENT=0
OK=0
end=$(( $(date +%s) + DUR ))
while [ $(date +%s) -lt $end ]; do
    OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send-message agent-b --data "p" --type text' 2>&1)
    SENT=$((SENT+1))
    STATUS=$(echo "$OUT" | jq -r '.status // ""' 2>/dev/null)
    [ "$STATUS" = "ok" ] && OK=$((OK+1))
    sleep 1
done
echo "    sent=$SENT ok=$OK"
MIN=$((SENT * 95 / 100))
if [ "$OK" -ge "$MIN" ]; then
    log_pass "$OK/$SENT successful (>=95%)"
else
    log_fail "only $OK/$SENT successful"
fi

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
