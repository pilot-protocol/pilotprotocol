#!/bin/bash
# Matrix 2 F-series: grant trust from scratch.
#
# test_trust_revoke.sh only exercises handshake+approve+untrust.
# This test proves the GRANT half of the matrix as a first-class
# case: two agents with empty trust sets, end with mutual trust.
#
# Pilot has no `trust grant` CLI command — the grant path is
# handshake (outbound) + approve (inbound). Both sides must end
# up trusting each other.

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
echo "Trust grant from scratch"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "agents up"

# ----- 0. Initial state: both trust sets empty -----
log_test "initial trust sets are empty"
A0=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B0=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$A0" = "0" ] && [ "$B0" = "0" ]; then
    log_pass "both empty"
else
    log_fail "expected 0/0 got a=$A0 b=$B0"
    exit 1
fi

# ----- 1. Handshake (outbound grant intent) -----
log_test "a handshakes b"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
PENDING=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending | length')
if [ "$PENDING" -ge 1 ]; then
    log_pass "b has $PENDING pending handshake"
else
    log_fail "b has no pending handshake"
    exit 1
fi

# ----- 2. Approve -> grant is complete -----
log_test "b approves the grant"
PID=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[0].node_id')
$DC exec -T agent-b pilotctl --json approve "$PID" >/dev/null 2>&1
sleep 3
A1=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B1=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$A1" = "1" ] && [ "$B1" = "1" ]; then
    log_pass "mutual trust established (a=$A1 b=$B1)"
else
    log_fail "grant did not produce symmetric trust (a=$A1 b=$B1)"
fi

# ----- 3. Trust grant has side-effect: traffic now works through trust-gated services -----
log_test "trust-gated ping round-trip works after grant"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-grant ping ok"
else
    log_fail "post-grant ping failed"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
