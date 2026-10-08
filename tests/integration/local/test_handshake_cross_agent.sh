#!/bin/bash
# Cross-agent handshake: agent-a initiates trust with agent-b (and vice-versa)
# where both are registered on the same rendezvous server. Validates that the
# registry lookup resolves the peer correctly and that the handshake frames are
# routed through the rendezvous, not just on a direct link.
#
# This differs from test_handshake_bidirectional.sh (which tests simultaneous
# concurrent initiation). Here we test the sequential one-shot path:
#   a handshakes b → b gets pending → b approves → mutual trust.

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
echo "Cross-agent handshake (same rendezvous)"
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

# ----- 1. agent-b is reachable from agent-a (rendezvous registration works) -----
log_test "agent-b reachable from agent-a (ping via rendezvous)"
if $DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 10s >/dev/null 2>&1; then
    log_pass "ping agent-b ok"
else
    log_fail "cannot ping agent-b — rendezvous registration may have failed"
    exit 1
fi

# ----- 2. a handshakes b -----
log_test "agent-a initiates handshake to agent-b"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2

PENDING_B=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PENDING_B" -ge 1 ]; then
    log_pass "agent-b has $PENDING_B pending handshake"
else
    log_fail "agent-b shows no pending handshake"
    exit 1
fi

# ----- 3. b approves -----
log_test "agent-b approves the handshake"
for NID in $($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-b pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3

# ----- 4. Both trust sets populated -----
log_test "trust is symmetric after approve"
TA=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
TB=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TA" -ge 1 ] && [ "$TB" -ge 1 ]; then
    log_pass "mutual trust: a=$TA b=$TB"
else
    log_fail "trust not symmetric: a=$TA b=$TB"
fi

# ----- 5. Ping succeeds -----
log_test "ping b->a succeeds post-trust"
if $DC exec -T agent-b pilotctl ping agent-a --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed"
fi

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Cross-agent handshake summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
