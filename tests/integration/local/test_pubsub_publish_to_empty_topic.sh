#!/bin/bash
# Matrix 2 F-series: publish to a topic that has zero subscribers.
# Spec: publish must not error, must not wedge, and must not leak
# resources. The event is simply delivered to nobody. A later
# subscriber does NOT receive the historical event (unless the
# broker implements backlog replay, which Pilot does not today).

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
echo "Pubsub: publish to empty topic"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "agents up"

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

TOPIC="empty-$(date +%s)"
PAYLOAD="orphan-$(date +%s%N)"

log_test "publish to empty topic must succeed quickly"
T0=$(date +%s)
$DC exec -T agent-a bash -c "timeout 10 pilotctl --json publish agent-b $TOPIC --data '$PAYLOAD'" \
    >/tmp/empty_pub.log 2>&1
RC=$?
T1=$(date +%s)
DELTA=$((T1 - T0))
if [ "$RC" -eq 0 ] && [ "$DELTA" -le 10 ]; then
    log_pass "publish ok in ${DELTA}s"
else
    log_fail "publish rc=$RC delta=${DELTA}s"
fi

# A subscriber joining AFTER the publish must receive NO historical event.
# 5s timeout is enough to confirm silence.
log_test "subscriber joining after the fact gets no backlog"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 5s > /tmp/late_sub.log 2>&1"
sleep 7
LATE=$($DC exec -T agent-b cat /tmp/late_sub.log 2>/dev/null)
if echo "$LATE" | grep -q "$PAYLOAD"; then
    log_fail "late subscriber unexpectedly got historical payload (backlog replay)"
else
    log_pass "no backlog replay (correct)"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
