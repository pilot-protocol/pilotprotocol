#!/bin/bash
# Matrix 2 F-series: subscriber joins an empty topic before the publisher
# exists / publishes. When the publisher later shows up, the event must
# land at the existing subscriber. Tests subscription durability while
# the topic is cold.

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
echo "Pubsub: subscribe before publisher publishes"
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

TOPIC="cold-topic-$(date +%s)"
PAYLOAD="delayed-payload-$(date +%s%N)"

log_test "subscribe on b BEFORE any publish happens"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 30s > /tmp/cold_sub.log 2>&1"
# Give the subscription time to register on the broker (agent-b).
sleep 3

# No publisher has yet emitted — topic is empty. Now publish.
log_test "publisher a emits after sub is already waiting"
$DC exec -T agent-a pilotctl --json publish agent-b "$TOPIC" --data "$PAYLOAD" >/dev/null 2>&1
sleep 5

GOT=""
for _ in $(seq 1 25); do
    out=$($DC exec -T agent-b cat /tmp/cold_sub.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "$PAYLOAD" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        GOT="yes"; break
    fi
    sleep 1
done
if [ "$GOT" = "yes" ]; then
    log_pass "subscriber received event from later-arriving publish"
else
    log_fail "subscriber missed event that was published while it was waiting"
    $DC exec -T agent-b cat /tmp/cold_sub.log 2>/dev/null | head -c 400 | sed 's/^/    /'
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
