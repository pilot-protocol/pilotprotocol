#!/bin/bash
# Split-brain divergence: two rendezvous services run in the same docker
# network. agent-a/b register with rendezvous-1; agent-c/d register with
# rendezvous-2. Each rendezvous should see only its own side; lookups
# across the partition must fail.

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

DC="docker compose -f docker-compose.splitbrain.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Split-brain divergence (2 rendezvous)"
echo "=========================================="

log_test "Starting splitbrain stack"
$DC down -v >/dev/null 2>&1
# Clean up any orphaned healed-agent containers from test_splitbrain_heal runs
docker rm -f "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" \
             "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" \
             >/dev/null 2>&1 || true
sweep_pilot_p2p_network
$DC up -d rendezvous-1 rendezvous-2 agent-a agent-b agent-c agent-d >/dev/null 2>&1

log_test "rendezvous-1 sees 2 agents"
C1=""
for _ in $(seq 1 60); do
    C1=$($DC exec -T rendezvous-1 curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "$C1" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$C1" = "2" ]; then
    log_pass "rendezvous-1 has exactly 2 nodes (agent-a,b)"
elif [ "$C1" -gt 2 ]; then
    log_fail "rendezvous-1 sees $C1 nodes — expected 2 (partition leaked)"
else
    log_fail "rendezvous-1 only sees $C1 nodes after 60s"
fi

log_test "rendezvous-2 sees 2 agents"
C2=""
for _ in $(seq 1 60); do
    C2=$($DC exec -T rendezvous-2 curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "$C2" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$C2" = "2" ]; then
    log_pass "rendezvous-2 has exactly 2 nodes (agent-c,d)"
elif [ "$C2" -gt 2 ]; then
    log_fail "rendezvous-2 sees $C2 nodes — expected 2"
else
    log_fail "rendezvous-2 only sees $C2 nodes after 60s"
fi

log_test "agent-a cannot lookup agent-c (cross-partition)"
LK=$($DC exec -T agent-a pilotctl --json find agent-c 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -z "$ADDR" ] || [ "$ADDR" = "null" ]; then
    log_pass "agent-a cannot resolve agent-c (partition holds)"
else
    log_fail "agent-a RESOLVED agent-c to $ADDR — partition leaked"
fi

log_test "agent-c cannot lookup agent-a (cross-partition)"
LK=$($DC exec -T agent-c pilotctl --json find agent-a 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -z "$ADDR" ] || [ "$ADDR" = "null" ]; then
    log_pass "agent-c cannot resolve agent-a (partition holds)"
else
    log_fail "agent-c RESOLVED agent-a to $ADDR — partition leaked"
fi

log_test "agent-a can lookup agent-b (same side)"
LK=$($DC exec -T agent-a pilotctl --json find agent-b 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -n "$ADDR" ] && [ "$ADDR" != "null" ]; then
    log_pass "same-side lookup works (agent-b=$ADDR)"
else
    log_fail "same-side lookup broken: $LK"
fi

log_test "agent-c can lookup agent-d (same side)"
LK=$($DC exec -T agent-c pilotctl --json find agent-d 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -n "$ADDR" ] && [ "$ADDR" != "null" ]; then
    log_pass "same-side lookup works (agent-d=$ADDR)"
else
    log_fail "same-side lookup broken: $LK"
fi

log_test "no panic/fatal in any daemon log"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Split-brain divergence summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
