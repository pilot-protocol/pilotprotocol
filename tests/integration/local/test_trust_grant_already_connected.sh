#!/bin/bash
# Matrix 2 F-series: issue a trust grant to a peer we're already
# connected to and already mutually trust.
#
# Spec: this must be idempotent. No duplicate entries in either
# trust set; no error; a subsequent handshake must either
# (a) short-circuit with "already trusted" or
# (b) produce exactly one new pending (still resolvable to the same
#     trust relationship).

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
echo "Trust grant on already-trusted peer (idempotency)"
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

# Warm tunnel
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# Round 1: establish mutual trust first (setup).
log_test "establish mutual trust (round 1)"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
PID=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[0].node_id // empty')
[ -n "$PID" ] || { log_fail "no pending after round-1 handshake"; exit 1; }
$DC exec -T agent-b pilotctl --json approve "$PID" >/dev/null 2>&1
sleep 3
A1=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B1=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
[ "$A1" = "1" ] && [ "$B1" = "1" ] || { log_fail "round-1 failed (a=$A1 b=$B1)"; exit 1; }
log_pass "mutual trust set up"

# Round 2: re-handshake (redundant grant attempt).
log_test "repeat handshake a->b — must not create duplicate trust entries"
$DC exec -T agent-a pilotctl --json handshake agent-b >/tmp/round2.log 2>&1
RC=$?
sleep 3

# Either the daemon silently accepts (pending possibly created,
# then auto-resolves) or it returns already-trusted. Both are fine.
A2=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B2=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$A2" = "1" ] && [ "$B2" = "1" ]; then
    log_pass "trust sets stayed at 1/1 — no duplicates (rc=$RC)"
else
    log_fail "trust sets mutated: a=$A2 b=$B2"
fi

# If approval needed a second time, run it so test is self-healing.
PID2=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[0].node_id // empty')
if [ -n "$PID2" ]; then
    $DC exec -T agent-b pilotctl --json approve "$PID2" >/dev/null 2>&1
    sleep 2
    A3=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
    B3=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
    if [ "$A3" = "1" ] && [ "$B3" = "1" ]; then
        log_pass "even with approve replay, still 1/1 (idempotent)"
    else
        log_fail "approve replay caused duplicates (a=$A3 b=$B3)"
    fi
fi

log_test "traffic still works after redundant grant"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed after redundant grant"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
