#!/bin/bash
# Multi-publisher fan-in with per-publisher ordering.
#
# Subscriber runs on agent-a, listening on topic T with --count 10.
# Two publishers fan events INTO the same subscription:
#   - Remote publisher (agent-b): pushes b-1..b-5
#   - Local publisher  (agent-a): pushes a-1..a-5 (publish-to-self)
#
# Asserts:
#   - subscriber receives exactly 10 events
#   - both publishers' streams arrive (5 of each)
#   - per-publisher FIFO preserved (a-1..a-5 in order; b-1..b-5 in order)
#   - no duplicates or bleed from other topics
#
# Covers a pattern not in test_pubsub_fanout.sh (one publisher,
# many subscribers) or test_pubsub_topic_fifo.sh (one publisher,
# interleaved topics): multiple concurrent PUBLISHERS converging on
# a single topic/subscription. Catches bugs where:
#   - the broker deduplicates or reorders events based on publisher id
#   - self-publish (loopback) races with remote delivery
#   - event ids collide across publishers

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
echo "Multi-publisher fan-in test"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

TOPIC="fanin-$(date +%s)"

# ----- 1. Start subscriber on agent-a (expects 10 events) -----
log_test "start subscriber on agent-a topic=$TOPIC (--count 10 --timeout 30s)"
$DC exec -d agent-a bash -c "pilotctl --json subscribe agent-a $TOPIC --count 10 --timeout 30s > /tmp/sub.log 2>&1"
sleep 2
log_pass "subscriber running"

# ----- 2. Fan-in: agent-b and agent-a publish 5 events each -----
log_test "agent-b and agent-a each publish 5 events to $TOPIC (interleaved)"
for i in 1 2 3 4 5; do
    $DC exec -T agent-b pilotctl --json publish agent-a "$TOPIC" --data "b-$i" >/dev/null &
    $DC exec -T agent-a pilotctl --json publish agent-a "$TOPIC" --data "a-$i" >/dev/null &
    wait
    sleep 0.1
done
log_pass "10 events published (5 from each side)"

# ----- 3. Wait for subscriber to collect all 10 -----
log_test "subscriber gathers 10 events within timeout"
for _ in $(seq 1 30); do
    OUT=$($DC exec -T agent-a cat /tmp/sub.log 2>/dev/null)
    N=$(echo "$OUT" | jq -r '.data.events | length' 2>/dev/null)
    if [ "$N" = "10" ]; then break; fi
    sleep 1
done
OUT=$($DC exec -T agent-a cat /tmp/sub.log 2>/dev/null)
N=$(echo "$OUT" | jq -r '.data.events | length' 2>/dev/null)
if [ "$N" = "10" ]; then
    log_pass "subscriber received 10 events"
else
    log_fail "subscriber received $N/10"
    echo "$OUT" | head -c 600
    echo
fi

# ----- 4. Both publishers represented (5 each, no drops) -----
log_test "both publishers contributed 5 events each"
A_CNT=$(echo "$OUT" | jq -r '[.data.events[]? | select(.data | startswith("a-"))] | length' 2>/dev/null)
B_CNT=$(echo "$OUT" | jq -r '[.data.events[]? | select(.data | startswith("b-"))] | length' 2>/dev/null)
if [ "$A_CNT" = "5" ] && [ "$B_CNT" = "5" ]; then
    log_pass "a=5 b=5"
else
    log_fail "a=$A_CNT b=$B_CNT (want 5/5)"
fi

# ----- 5. Per-publisher ordering preserved -----
log_test "a-1..a-5 arrive in order"
A_SEQ=$(echo "$OUT" | jq -r '.data.events[]?.data' 2>/dev/null | grep '^a-' | paste -sd, -)
EXP_A="a-1,a-2,a-3,a-4,a-5"
if [ "$A_SEQ" = "$EXP_A" ]; then
    log_pass "a order preserved: $A_SEQ"
else
    log_fail "a order broken: got '$A_SEQ' expected '$EXP_A'"
fi

log_test "b-1..b-5 arrive in order"
B_SEQ=$(echo "$OUT" | jq -r '.data.events[]?.data' 2>/dev/null | grep '^b-' | paste -sd, -)
EXP_B="b-1,b-2,b-3,b-4,b-5"
if [ "$B_SEQ" = "$EXP_B" ]; then
    log_pass "b order preserved: $B_SEQ"
else
    log_fail "b order broken: got '$B_SEQ' expected '$EXP_B'"
fi

# ----- 6. No duplicates: exactly 10 distinct data values -----
log_test "no duplicate events"
UNIQ=$(echo "$OUT" | jq -r '[.data.events[]?.data] | unique | length' 2>/dev/null)
if [ "$UNIQ" = "10" ]; then
    log_pass "10 unique payloads"
else
    log_fail "duplicates present: unique=$UNIQ/10"
    echo "$OUT" | jq -r '.data.events[]?.data' 2>/dev/null | sort | uniq -c | sed 's/^/    /'
fi

# ----- 7. All events labeled with correct topic -----
log_test "every event is labeled with the correct topic"
WRONG=$(echo "$OUT" | jq -r --arg t "$TOPIC" '[.data.events[]? | select(.topic != $t)] | length' 2>/dev/null)
if [ "$WRONG" = "0" ]; then
    log_pass "all events carry topic=$TOPIC"
else
    log_fail "$WRONG events had the wrong topic"
fi

# ----- 8. No panic/fatal in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Multi-publisher fan-in summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
