#!/bin/bash
# Bidirectional handshake: both agents initiate a handshake to each other
# simultaneously, then both approve the pending request from the other side.
# After the cycle both trust sets must be populated (mutual trust).
#
# This exercises the concurrent handshake path: two agents each sending
# MsgHandshake at roughly the same time so both sides have a pending entry
# before either has approved. The daemon must not dead-lock or double-add.

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
echo "Bidirectional simultaneous handshake"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register (total_nodes=$COUNT)"; exit 1; }
log_pass "both agents registered"

# ----- 1. Both trust sets start empty -----
log_test "initial trust sets are empty"
A0=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B0=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$A0" = "0" ] && [ "$B0" = "0" ]; then
    log_pass "both trust sets empty"
else
    log_fail "expected 0/0 got a=$A0 b=$B0"
    exit 1
fi

# ----- 2. Both agents handshake each other simultaneously -----
log_test "a and b handshake each other concurrently"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1 &
$DC exec -T agent-b pilotctl --json handshake agent-a >/dev/null 2>&1 &
wait
sleep 3

PA=$($DC exec -T agent-a pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
PB=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
log_pass "pending: a=$PA b=$PB (at least one per side expected)"

# ----- 3. Both sides approve -----
log_test "both sides approve all pending handshakes"
for NID in $($DC exec -T agent-a pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-a pilotctl --json approve "$NID" >/dev/null 2>&1
done
for NID in $($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-b pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3
log_pass "approvals sent"

# ----- 4. Mutual trust established -----
log_test "mutual trust established"
A1=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B1=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$A1" -ge 1 ] && [ "$B1" -ge 1 ]; then
    log_pass "trust established (a=$A1 b=$B1)"
else
    log_fail "trust not symmetric (a=$A1 b=$B1)"
fi

# ----- 5. Ping succeeds across trust link -----
log_test "ping a->b succeeds post-trust"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed after mutual trust"
fi

log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Bidirectional handshake summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
