#!/bin/bash
# Pub/sub topic filter: subscriber on topic A must NOT receive events
# published to topic B. Tests that topic selection is applied correctly
# at the broker so that messages are not broadcast to wrong subscribers.
#
# Setup:
#   - agent-a subscribes to topic "filter-alpha-<ts>" for 3 events
#   - agent-b publishes 3 events on topic "filter-beta-<ts>"  (wrong topic)
#   - Then publishes 3 events on topic "filter-alpha-<ts>"    (correct topic)
#
# The subscriber must receive exactly the 3 correct events, nothing from beta.

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
echo "Pub/sub topic filter (no cross-topic bleed)"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

ALPHA="filter-alpha-$(date +%s)"
BETA="filter-beta-$(date +%s)"

# ----- 1. Subscribe to alpha only -----
log_test "a subscribes to topic: $ALPHA (count=3)"
$DC exec -d agent-a bash -c "pilotctl --json subscribe agent-a $ALPHA --count 3 --timeout 20s > /tmp/filter_alpha.log 2>&1"
sleep 1
log_pass "subscriber running"

# ----- 2. Publish to WRONG topic (beta) -----
log_test "b publishes 3 events to WRONG topic: $BETA"
for i in 1 2 3; do
    $DC exec -T agent-b pilotctl --json publish agent-a "$BETA" --data "beta:$i" >/dev/null 2>&1
    sleep 0.1
done
log_pass "beta events published"
sleep 2

# ----- 3. Publish to CORRECT topic (alpha) -----
log_test "b publishes 3 events to correct topic: $ALPHA"
for i in 1 2 3; do
    $DC exec -T agent-b pilotctl --json publish agent-a "$ALPHA" --data "alpha:$i" >/dev/null 2>&1
    sleep 0.1
done
log_pass "alpha events published"

# ----- 4. Wait for subscriber to collect events -----
log_test "subscriber collects exactly 3 events within 15s"
for _ in $(seq 1 30); do
    LOG=$($DC exec -T agent-a cat /tmp/filter_alpha.log 2>/dev/null)
    NEVT=$(echo "$LOG" | jq -r '.data.events | length' 2>/dev/null)
    [ "$NEVT" = "3" ] && break
    sleep 0.5
done
LOG=$($DC exec -T agent-a cat /tmp/filter_alpha.log 2>/dev/null)
NEVT=$(echo "$LOG" | jq -r '.data.events | length' 2>/dev/null)
if [ "$NEVT" = "3" ]; then
    log_pass "subscriber got exactly 3 events"
else
    log_fail "expected 3 events, got $NEVT"
    echo "$LOG" | head -c 300
fi

# ----- 5. All 3 events are from alpha topic -----
log_test "all received events are from topic $ALPHA"
WRONG=$(echo "$LOG" | jq -r --arg t "$ALPHA" '[.data.events[]? | select(.topic != $t)] | length' 2>/dev/null)
[ "$WRONG" = "0" ] && log_pass "no cross-topic bleed" || log_fail "$WRONG events have wrong topic"

# ----- 6. No beta:N payloads in alpha subscriber log -----
log_test "no beta:* payloads in alpha subscriber output"
BETA_BLEED=$(echo "$LOG" | jq -r '[.data.events[]? | select(.data | startswith("beta:"))] | length' 2>/dev/null)
[ "$BETA_BLEED" = "0" ] && log_pass "no beta events bled through" || log_fail "$BETA_BLEED beta events received by alpha subscriber"

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Pub/sub topic filter summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
