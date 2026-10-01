#!/bin/bash
# Invalid handshake rejection: attempt to handshake with a node name that is
# not registered on the rendezvous. The daemon must return an error and NOT
# create any pending entry. Also tests that a second valid handshake to a
# registered peer still works after a failed attempt (no stuck state).

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
echo "Invalid handshake rejection"
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

# ----- 1. Handshake with non-existent peer -----
log_test "handshake to ghost-node-xyz fails"
ERR_OUT=$($DC exec -T agent-a pilotctl --json handshake ghost-node-xyz 2>&1)
EXIT_CODE=$?
if [ "$EXIT_CODE" -ne 0 ] || echo "$ERR_OUT" | grep -qiE '"error"|"not found"|"unknown"'; then
    log_pass "handshake to ghost peer returned error: $(echo "$ERR_OUT" | head -c 100)"
else
    log_fail "expected failure but got: $(echo "$ERR_OUT" | head -c 200)"
fi

# ----- 2. No pending entries created by the failed attempt -----
log_test "no pending entries left after failed handshake"
PA=$($DC exec -T agent-a pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
PB=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PA" = "0" ] && [ "$PB" = "0" ]; then
    log_pass "no stale pending entries"
else
    log_fail "stale pending: a=$PA b=$PB"
fi

# ----- 3. Valid handshake still works after the failed attempt -----
log_test "valid handshake to agent-b works after failed attempt"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
PB2=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PB2" -ge 1 ]; then
    log_pass "agent-b has pending handshake from valid attempt"
else
    log_fail "valid handshake did not arrive at agent-b"
fi

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Invalid handshake rejection summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
