#!/bin/bash
# Full trust approve cycle: validates every observable state in the
# handshake→pending→approve→trusted progression, checking that:
#   - pre-handshake: pending list is empty
#   - post-handshake: pending list has exactly one entry with correct fields
#   - post-approve: pending list is empty again, trust list is populated
#   - re-approve of same node_id is a no-op (idempotent)

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
echo "Full trust approve cycle"
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

# ----- 1. Pre-handshake: pending is empty -----
log_test "pre-handshake: pending list is empty on both sides"
PA=$($DC exec -T agent-a pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
PB=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PA" = "0" ] && [ "$PB" = "0" ]; then
    log_pass "both pending lists empty"
else
    log_fail "non-empty pending before handshake: a=$PA b=$PB"
fi

# ----- 2. a sends handshake -----
log_test "a initiates handshake"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2

# ----- 3. b's pending list has exactly one entry -----
log_test "b has exactly one pending entry"
PENDING_OUT=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null)
PB2=$(echo "$PENDING_OUT" | jq -r '.data.pending | length')
if [ "$PB2" = "1" ]; then
    log_pass "exactly one pending"
else
    log_fail "expected 1 pending, got $PB2"
    exit 1
fi

# ----- 4. Pending entry has node_id field -----
log_test "pending entry contains node_id"
PENDING_NID=$(echo "$PENDING_OUT" | jq -r '.data.pending[0].node_id // empty')
if [ -n "$PENDING_NID" ]; then
    log_pass "pending node_id=$PENDING_NID"
else
    log_fail "pending entry missing node_id"
    exit 1
fi

# ----- 5. b approves -----
log_test "b approves pending handshake"
$DC exec -T agent-b pilotctl --json approve "$PENDING_NID" >/dev/null 2>&1
sleep 3

# ----- 6. Pending cleared -----
log_test "pending list cleared after approve"
PB3=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PB3" = "0" ]; then
    log_pass "pending list empty"
else
    log_fail "pending not cleared: $PB3 remaining"
fi

# ----- 7. Trust lists populated -----
log_test "trust established on both sides"
TA=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
TB=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TA" -ge 1 ] && [ "$TB" -ge 1 ]; then
    log_pass "mutual trust: a=$TA b=$TB"
else
    log_fail "trust not established: a=$TA b=$TB"
fi

# ----- 8. Re-approve is a no-op -----
log_test "re-approve same node_id is idempotent"
$DC exec -T agent-b pilotctl --json approve "$PENDING_NID" >/dev/null 2>&1
sleep 2
TB2=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TB2" = "$TB" ]; then
    log_pass "re-approve did not duplicate trust entry"
else
    log_fail "re-approve changed trust count: was $TB now $TB2"
fi

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Trust approve cycle summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
