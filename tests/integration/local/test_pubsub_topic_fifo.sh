#!/bin/bash
# Per-topic FIFO under interleaved publishes.
#
# One publisher (agent-b) pushes 10 events alternating between two topics:
#   alpha:1, beta:1, alpha:2, beta:2, ... alpha:5, beta:5
#
# Two subscribers on agent-a, one per topic, each with --count 5, must
# each observe exactly their 5 events in publication order (alpha:1..5
# for the alpha subscriber, beta:1..5 for the beta subscriber). No
# cross-topic contamination.
#
# This is a different angle than test_pubsub_fanout.sh (single topic,
# multiple subscribers). Here we stress the broker's per-topic queueing:
#   - does a slow/backed-up topic stall deliveries on an unrelated topic
#     (head-of-line blocking)?
#   - are events delivered in the publisher's original per-topic order
#     (FIFO preservation)?
#   - can a single subscriber connection bleed events from another topic
#     (selector leak)?

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
echo "Per-topic FIFO under interleaved publishes"
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

T_ALPHA="alpha-$(date +%s)"
T_BETA="beta-$(date +%s)"

# ----- 1. Start two bounded subscribers on agent-a, one per topic -----
log_test "start 2 subscribers on agent-a (alpha=$T_ALPHA, beta=$T_BETA)"
$DC exec -d agent-a bash -c "pilotctl --json subscribe agent-a $T_ALPHA --count 5 --timeout 30s > /tmp/alpha.log 2>&1"
$DC exec -d agent-a bash -c "pilotctl --json subscribe agent-a $T_BETA  --count 5 --timeout 30s > /tmp/beta.log 2>&1"
sleep 2
log_pass "subscribers running"

# ----- 2. Publish 5 interleaved pairs from agent-b -----
log_test "agent-b publishes 10 events, alternating topics alpha/beta"
for i in 1 2 3 4 5; do
    $DC exec -T agent-b pilotctl --json publish agent-a "$T_ALPHA" --data "alpha:$i" >/dev/null
    $DC exec -T agent-b pilotctl --json publish agent-a "$T_BETA"  --data "beta:$i"  >/dev/null
    sleep 0.15
done
log_pass "10 events published"

# ----- 3. Collect both subscriber logs -----
log_test "each subscriber collects 5 events within timeout"
for _ in $(seq 1 30); do
    A=$($DC exec -T agent-a cat /tmp/alpha.log 2>/dev/null)
    B=$($DC exec -T agent-a cat /tmp/beta.log  2>/dev/null)
    AN=$(echo "$A" | jq -r '.data.events | length' 2>/dev/null)
    BN=$(echo "$B" | jq -r '.data.events | length' 2>/dev/null)
    if [ "$AN" = "5" ] && [ "$BN" = "5" ]; then break; fi
    sleep 1
done
A=$($DC exec -T agent-a cat /tmp/alpha.log 2>/dev/null)
B=$($DC exec -T agent-a cat /tmp/beta.log  2>/dev/null)
AN=$(echo "$A" | jq -r '.data.events | length' 2>/dev/null)
BN=$(echo "$B" | jq -r '.data.events | length' 2>/dev/null)
if [ "$AN" = "5" ] && [ "$BN" = "5" ]; then
    log_pass "both subscribers got 5 events"
else
    log_fail "alpha=$AN/5 beta=$BN/5"
    echo "  alpha log:"; echo "$A" | head -c 300; echo
    echo "  beta log:";  echo "$B" | head -c 300; echo
fi

# ----- 4. alpha subscriber observed alpha:1..alpha:5 IN ORDER -----
log_test "alpha subscriber events are alpha:1..alpha:5 in submission order"
ALPHA_SEQ=$(echo "$A" | jq -r '.data.events[]?.data' 2>/dev/null | paste -sd, -)
EXPECTED_A="alpha:1,alpha:2,alpha:3,alpha:4,alpha:5"
if [ "$ALPHA_SEQ" = "$EXPECTED_A" ]; then
    log_pass "alpha order: $ALPHA_SEQ"
else
    log_fail "alpha order: got '$ALPHA_SEQ' expected '$EXPECTED_A'"
fi

# ----- 5. beta subscriber observed beta:1..beta:5 IN ORDER -----
log_test "beta subscriber events are beta:1..beta:5 in submission order"
BETA_SEQ=$(echo "$B" | jq -r '.data.events[]?.data' 2>/dev/null | paste -sd, -)
EXPECTED_B="beta:1,beta:2,beta:3,beta:4,beta:5"
if [ "$BETA_SEQ" = "$EXPECTED_B" ]; then
    log_pass "beta order: $BETA_SEQ"
else
    log_fail "beta order: got '$BETA_SEQ' expected '$EXPECTED_B'"
fi

# ----- 6. No cross-topic contamination: alpha log has no beta:*, beta log has no alpha:* -----
log_test "no cross-topic contamination"
CROSS_IN_ALPHA=$(echo "$A" | jq -r '[.data.events[]? | select(.data | startswith("beta:"))] | length' 2>/dev/null)
CROSS_IN_BETA=$(echo "$B"  | jq -r '[.data.events[]? | select(.data | startswith("alpha:"))] | length' 2>/dev/null)
if [ "$CROSS_IN_ALPHA" = "0" ] && [ "$CROSS_IN_BETA" = "0" ]; then
    log_pass "topic isolation held (no cross-events)"
else
    log_fail "contamination: alpha_has_beta=$CROSS_IN_ALPHA beta_has_alpha=$CROSS_IN_BETA"
fi

# ----- 7. Topics reported by the subscriber payloads match subscription -----
log_test "each event's topic field matches its subscription"
ALPHA_WRONG=$(echo "$A" | jq -r --arg t "$T_ALPHA" '[.data.events[]? | select(.topic != $t)] | length' 2>/dev/null)
BETA_WRONG=$(echo "$B"  | jq -r --arg t "$T_BETA"  '[.data.events[]? | select(.topic != $t)] | length' 2>/dev/null)
if [ "$ALPHA_WRONG" = "0" ] && [ "$BETA_WRONG" = "0" ]; then
    log_pass "all events carry the correct topic label"
else
    log_fail "mismatched topics: alpha_wrong=$ALPHA_WRONG beta_wrong=$BETA_WRONG"
fi

# ----- 8. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Per-topic FIFO test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
