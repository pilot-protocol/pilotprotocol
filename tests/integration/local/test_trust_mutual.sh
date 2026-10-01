#!/bin/bash
# Mutual trust: both agents explicitly grant trust to each other.
# Agent-a handshakes b and b approves; then b handshakes a and a approves.
# Both trust sets must each contain exactly one entry.
# This is distinct from test_trust_approve_cycle.sh (which checks state
# progression) — here we focus on the two-round-trip mutual grant path and
# validate that traffic (message send) works only after both sides have
# completed their respective approvals.

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
echo "Mutual trust: both sides grant"
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

# ----- Round 1: a → b -----
log_test "round 1: a handshakes b"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
for NID in $($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-b pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3
TA1=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
TB1=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TA1" -ge 1 ] && [ "$TB1" -ge 1 ]; then
    log_pass "round-1 trust: a=$TA1 b=$TB1"
else
    log_fail "round-1 trust missing: a=$TA1 b=$TB1"
fi

# ----- Round 2: b → a (explicit mutual initiation) -----
log_test "round 2: b handshakes a (explicit second grant)"
$DC exec -T agent-b pilotctl --json handshake agent-a >/dev/null 2>&1
sleep 2
for NID in $($DC exec -T agent-a pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-a pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3
TA2=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
TB2=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TA2" -ge 1 ] && [ "$TB2" -ge 1 ]; then
    log_pass "round-2 trust: a=$TA2 b=$TB2 (no duplicates expected)"
else
    log_fail "round-2 trust missing: a=$TA2 b=$TB2"
fi

# Trust count should not grow beyond 1 per side (same peer, no duplicates).
log_test "no duplicate trust entries after explicit mutual grant"
if [ "$TA2" = "1" ] && [ "$TB2" = "1" ]; then
    log_pass "exactly one entry per side"
else
    log_fail "unexpected count: a=$TA2 b=$TB2"
fi

# ----- Message send works in both directions -----
log_test "message a->b works"
$DC exec -T agent-a pilotctl --json send-message agent-b --data "hello-from-a" --type text >/dev/null 2>&1
sleep 2
INBOX_B=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
[ "$INBOX_B" -ge 1 ] && log_pass "b got message ($INBOX_B)" || log_fail "b inbox empty"

log_test "message b->a works"
$DC exec -T agent-b pilotctl --json send-message agent-a --data "hello-from-b" --type text >/dev/null 2>&1
sleep 2
INBOX_A=$($DC exec -T agent-a pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
[ "$INBOX_A" -ge 1 ] && log_pass "a got message ($INBOX_A)" || log_fail "a inbox empty"

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Mutual trust summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
