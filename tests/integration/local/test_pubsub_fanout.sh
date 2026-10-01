#!/bin/bash
# Pub/sub fan-out and topic isolation tests executed from the host.
# Requires the p2p compose stack (rendezvous, agent-a, agent-b) running.

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
echo "Pub/Sub fan-out integration tests"
echo "=========================================="

log_test "Starting p2p stack"
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "Both agents registered"
else
    log_fail "Agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# ---- 1. Fan-out: three subscribers, one publisher ----
log_test "3 subscribers on agent-b receive one publish from agent-a"
TOPIC="fanout-$(date +%s)"
PAYLOAD="fanout-payload-$(date +%s%N)"

for i in 1 2 3; do
    $DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 20s > /tmp/pubsub_sub$i.log 2>&1"
done
sleep 2
$DC exec -T agent-a pilotctl --json publish agent-b "$TOPIC" --data "$PAYLOAD" >/dev/null
sleep 5

MATCHED=0
for i in 1 2 3; do
    out=$($DC exec -T agent-b cat /tmp/pubsub_sub$i.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "$PAYLOAD" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        MATCHED=$((MATCHED+1))
    fi
done
if [ "$MATCHED" -eq 3 ]; then
    log_pass "all 3 subscribers received publish"
else
    log_fail "only $MATCHED/3 subscribers got the event"
fi

# ---- 2. Topic isolation: subscriber on unrelated topic sees nothing ----
log_test "subscriber on unrelated topic does not receive publish"
T_ALPHA="alpha-$(date +%s)"
T_BETA="beta-$(date +%s)"

$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $T_ALPHA --count 1 --timeout 15s > /tmp/pubsub_alpha.log 2>&1"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $T_BETA --count 1 --timeout 15s > /tmp/pubsub_beta.log 2>&1"
sleep 2
$DC exec -T agent-a pilotctl --json publish agent-b "$T_ALPHA" --data "alpha-only" >/dev/null
sleep 16

ALPHA=$($DC exec -T agent-b cat /tmp/pubsub_alpha.log 2>/dev/null)
BETA=$($DC exec -T agent-b cat /tmp/pubsub_beta.log 2>/dev/null)

alpha_hit=$(echo "$ALPHA" | jq -r '.data.events[0].data // empty' 2>/dev/null)
beta_hit=$(echo "$BETA"   | jq -r '.data.events[0].data // empty' 2>/dev/null)
beta_timeout=$(echo "$BETA" | jq -r '.data.timeout // false' 2>/dev/null)

if [ "$alpha_hit" = "alpha-only" ] && [ -z "$beta_hit" ] && [ "$beta_timeout" = "true" ]; then
    log_pass "topic isolation holds (alpha got event, beta timed out empty)"
else
    log_fail "isolation broken: alpha_hit=$alpha_hit beta_hit=$beta_hit beta_timeout=$beta_timeout"
fi

# ---- 3. Late subscriber does not see previously-published events ----
log_test "late subscriber does not see historical publishes"
T_HIST="hist-$(date +%s)"
$DC exec -T agent-a pilotctl --json publish agent-b "$T_HIST" --data "pre-subscribe-event" >/dev/null
sleep 2
HIST_OUT=$($DC exec -T agent-b bash -c "pilotctl --json subscribe agent-b $T_HIST --count 1 --timeout 3s" 2>&1)
hist_timeout=$(echo "$HIST_OUT" | jq -r '.data.timeout // false' 2>/dev/null)
hist_events=$(echo "$HIST_OUT" | jq -r '.data.events // "null"' 2>/dev/null)
if [ "$hist_timeout" = "true" ] && [ "$hist_events" = "null" ]; then
    log_pass "late subscriber correctly missed pre-subscribe event"
else
    log_fail "late subscriber unexpectedly saw history (timeout=$hist_timeout events=$hist_events)"
fi

# ---- 4. Publish to non-existent hostname returns clear error ----
log_test "publish to unknown hostname rejected cleanly"
OUT=$($DC exec -T agent-a pilotctl --json publish ghost-agent-xyz "$TOPIC" --data "x" 2>&1)
code=$(echo "$OUT" | jq -r '.code // empty' 2>/dev/null)
if [ "$code" = "not_found" ] || [ "$code" = "connection_failed" ]; then
    log_pass "unknown publish target rejected (code=$code)"
else
    log_fail "expected not_found/connection_failed, got: $OUT"
fi

echo
echo "=========================================="
echo "Pub/Sub Fan-out Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
