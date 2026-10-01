#!/bin/bash
# Race: concurrent trust grant and trust revoke.
#
# From agent-b, fire `pilotctl approve <A>` and `pilotctl revoke <A>` in
# tight parallel (same ms) and repeat 20 iterations. After all iterations
# settle, the final trust state must be deterministic — either trusted
# or not — with no split-brain (half of `pilotctl trust` shows trusted
# while the other half shows revoked) and no daemon panic.

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
echo "Race: trust grant vs revoke (concurrent)"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

# Get agent-a's node id.
A_NID=$($DC exec -T agent-a pilotctl --json info | jq -r '.data.node_id')
if [ -z "$A_NID" ] || [ "$A_NID" = "0" ] || [ "$A_NID" = "null" ]; then
    log_fail "could not read agent-a node_id"
    exit 1
fi
log_pass "agent-a node_id=$A_NID"

# Create a handshake so b has a pending for a (prerequisite for approve).
$DC exec -T agent-a bash -c "pilotctl handshake agent-b 'race-init'" >/dev/null 2>&1
sleep 1

log_test "20 iterations of concurrent approve+revoke on agent-b"
for i in $(seq 1 20); do
    $DC exec -T agent-b bash -c "
        pilotctl approve $A_NID >/dev/null 2>&1 &
        pilotctl untrust $A_NID >/dev/null 2>&1 &
        wait
    " >/dev/null 2>&1 || true
done
log_pass "iterations finished"

# Give state a moment to settle.
sleep 1

log_test "trust state is readable and deterministic"
OUT1=$($DC exec -T agent-b pilotctl --json trust 2>&1)
OUT2=$($DC exec -T agent-b pilotctl --json trust 2>&1)
T1=$(echo "$OUT1" | jq -r --argjson n "$A_NID" '.data.trusted[]? | select(.node_id==$n) | .node_id' 2>/dev/null)
T2=$(echo "$OUT2" | jq -r --argjson n "$A_NID" '.data.trusted[]? | select(.node_id==$n) | .node_id' 2>/dev/null)
if [ "$T1" = "$T2" ]; then
    if [ -n "$T1" ]; then
        log_pass "deterministic final state: TRUSTED"
    else
        log_pass "deterministic final state: NOT TRUSTED"
    fi
else
    log_fail "non-deterministic: T1='$T1' T2='$T2' (two reads disagree)"
fi

log_test "no panics / races in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

log_test "daemons still responsive"
OK_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$OK_B" ] && [ "$OK_B" != "0" ]; then
    log_pass "agent-b still serves IPC"
else
    log_fail "agent-b unresponsive after race"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
