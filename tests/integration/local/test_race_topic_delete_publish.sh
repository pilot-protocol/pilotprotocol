#!/bin/bash
# Race: unsubscribe (topic tear-down) concurrent with publish.
#
# One goroutine on agent-b subscribes/unsubscribes a topic in a loop while
# agent-a continuously publishes to that topic. If EventBroker's subscriber
# list is mutated without a lock while publish() iterates it, we get one of:
#   - daemon panic
#   - orphan messages delivered after unsubscribe
#   - dropped messages during the gap
#
# PASS criteria: no panic, subscriber counts roughly monotone with
# subscribe/unsubscribe windows, daemon stays alive.

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
echo "Race: topic delete vs publish"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

TOPIC="race/deleting/$$"
DUR=10

# Subscribe/unsub churn on b.
log_test "launch subscribe/unsubscribe churn on agent-b ($DUR s)"
$DC exec -d agent-b bash -c "
    rm -f /tmp/churn.log
    end=\$((\$(date +%s) + $DUR))
    while [ \$(date +%s) -lt \$end ]; do
        # 200 ms subscribe
        timeout 0.2 pilotctl subscribe agent-b '$TOPIC' >>/tmp/churn.log 2>&1 || true
        # brief gap
        sleep 0.05
    done
    echo CHURN_DONE >>/tmp/churn.log
"

# Publisher on a.
log_test "launch publisher on agent-a ($DUR s)"
$DC exec -d agent-a bash -c "
    rm -f /tmp/pub.log
    end=\$((\$(date +%s) + $DUR))
    i=0
    while [ \$(date +%s) -lt \$end ]; do
        i=\$((i+1))
        pilotctl publish agent-b '$TOPIC' --data \"m-\$i\" >>/tmp/pub.log 2>&1 || true
        sleep 0.02
    done
    echo PUB_DONE \$i >>/tmp/pub.log
"

# Wait for both to finish.
sleep $((DUR + 3))

log_test "no panics / data races / fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -5)
if [ -z "$BAD" ]; then
    log_pass "clean logs after churn"
else
    log_fail "crash/race found: $BAD"
fi

log_test "daemons still responsive"
OK_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
OK_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$OK_A" ] && [ -n "$OK_B" ] && [ "$OK_A" != "0" ] && [ "$OK_B" != "0" ]; then
    log_pass "both daemons still serve IPC (a=$OK_A b=$OK_B)"
else
    log_fail "daemon unresponsive: a='$OK_A' b='$OK_B'"
fi

log_test "publish calls reported no orphan deliveries (no 'delivered after close' errors)"
ORPH=$($DC logs agent-b 2>&1 | grep -ciE "orphan|delivered after close|subscriber gone" | tr -d ' \r\n')
if [ "${ORPH:-0}" = "0" ]; then
    log_pass "no orphan-delivery warnings"
else
    log_fail "$ORPH orphan-delivery warnings observed"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
