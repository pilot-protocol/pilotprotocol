#!/bin/bash
# Observability: "peer rekeyed" log line exactly once per rekey per tunnel.
# Force a rekey by restarting agent-b (which rotates its tunnel key on
# startup). After agent-a first sends to agent-b post-restart, its
# tunnel.go should log "peer rekeyed" exactly once for that peer.
#
# EXPECTED: at least one "peer rekeyed" log on agent-a with the matching
# peer_node_id; never more than one per completed rekey cycle.

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
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

# Establish initial tunnel.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1
sleep 2

# Snapshot agent-a's log line count for "peer rekeyed" before the event.
BEFORE=$($DC logs agent-a 2>&1 | grep -c 'peer rekeyed' || true)
log_test "before: agent-a has $BEFORE 'peer rekeyed' log lines"

# Force rekey via agent-b restart (fresh identity session -> new key).
log_test "restart agent-b to force rekey on next frame"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    C=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$C" -ge 2 ] && break
    sleep 1
done

# Trigger re-establishment from agent-a.
$DC exec -T agent-a pilotctl ping agent-b --count 3 --timeout 15s >/dev/null 2>&1 || true
sleep 5

AFTER=$($DC logs agent-a 2>&1 | grep -c 'peer rekeyed' || true)
DELTA=$((AFTER - BEFORE))
log_test "after: agent-a has $AFTER 'peer rekeyed' lines (delta=$DELTA)"

if [ "$DELTA" -eq 1 ]; then
    log_pass "exactly one 'peer rekeyed' log emitted"
elif [ "$DELTA" -gt 1 ]; then
    log_fail "more than one 'peer rekeyed' per rekey cycle: delta=$DELTA"
else
    log_fail "no 'peer rekeyed' log emitted (delta=0)"
fi

# Sanity: matches peer_node_id on agent-b
B_NID=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$B_NID" ]; then
    MATCH=$($DC logs agent-a 2>&1 | grep 'peer rekeyed' | grep -c "peer_node_id=$B_NID" || true)
    log_test "'peer rekeyed' log names peer_node_id=$B_NID"
    if [ "$MATCH" -ge 1 ]; then log_pass "peer id present in log"; else log_fail "no matching peer_node_id in log"; fi
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
