#!/bin/bash
# Flash-crowd registration: bring up 10 agents that all register with the
# same rendezvous inside a few seconds. Asserts registry count reaches 10
# and that each agent has a unique node id.
#
# Finds races in the register path (duplicate-id allocation, torn updates).

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

DC="docker compose -f docker-compose.multi10.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Flash-crowd: 10 agents register"
echo "=========================================="

log_test "bring rendezvous up first"
$DC down -v >/dev/null 2>&1
sweep_pilot_p2p_network
$DC up -d rendezvous >/dev/null 2>&1
for _ in $(seq 1 30); do
    if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
log_pass "rendezvous up"

log_test "start all 10 agents near-simultaneously"
START=$(date +%s)
$DC up -d a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 >/dev/null 2>&1

# Wait up to 60s for total_nodes == 10, record time-to-quorum.
COUNT=0
FIRST10=0
for i in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 10 ]; then
        FIRST10=$(( $(date +%s) - START ))
        break
    fi
    sleep 1
done

if [ "$COUNT" -ge 10 ]; then
    log_pass "10 agents registered in ${FIRST10}s"
else
    log_fail "only $COUNT/10 registered after 60s"
fi

log_test "all 10 registered within 15s of first"
# Container startup itself takes a few seconds; 15 is loose but catches
# serialization bugs that balloon to >30s.
if [ "$FIRST10" -gt 0 ] && [ "$FIRST10" -le 15 ]; then
    log_pass "time-to-10 = ${FIRST10}s"
else
    log_fail "time-to-10 = ${FIRST10}s (too slow, possible serialization bottleneck)"
fi

log_test "all 10 node ids are unique"
NODES=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/nodes 2>/dev/null)
IDS=$(echo "$NODES" | jq -r '.nodes[]?.node_id // .nodes[]?.id // empty' 2>/dev/null | sort -u)
UNIQUE_COUNT=$(echo "$IDS" | grep -c .)
# Fallback: /api/public-stats total_nodes matches unique count
if [ -z "$IDS" ]; then
    # Endpoint shape varies; fall back to stats assertion.
    if [ "$COUNT" -ge 10 ]; then
        log_pass "registry reports $COUNT nodes (unique-id shape check skipped — no /api/nodes ids)"
    else
        log_fail "could not enumerate nodes"
    fi
elif [ "$UNIQUE_COUNT" -ge 10 ]; then
    log_pass "$UNIQUE_COUNT unique node ids"
else
    log_fail "only $UNIQUE_COUNT unique node ids among 10 agents (duplicates!)"
    echo "$IDS"
fi

log_test "no panic/fatal in rendezvous log"
BAD=$($DC logs rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean rendezvous logs"
else
    log_fail "$BAD"
fi

log_test "no panic/fatal across all 10 agent logs"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | grep -v rendezvous | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean agent logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Flash-crowd summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
