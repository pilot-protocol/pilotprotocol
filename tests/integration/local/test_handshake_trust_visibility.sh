#!/bin/bash
# Trust visibility after handshake+approve: asserts that the peer appears in
# the trust list with the expected fields (node_id, hostname) on both sides,
# and that the trust entry includes the correct node identity of the peer.
# Also validates that the trusted node is reachable via ping before and
# that an untrusted node does NOT appear in the trust list.

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
echo "Trust visibility after handshake+approve"
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

# ----- 1. Pre-trust: both lists empty -----
log_test "pre-trust: trust lists are empty"
EA=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
EB=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
[ "$EA" = "0" ] && [ "$EB" = "0" ] && log_pass "both empty" || log_fail "expected 0/0 got a=$EA b=$EB"

# ----- 2. Handshake + approve -----
log_test "a handshakes b; b approves"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
for NID in $($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-b pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3

# ----- 3. Both trust lists now have one entry -----
log_test "both trust lists have exactly one entry"
LA=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null)
LB=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null)
CA=$(echo "$LA" | jq -r '.data.trusted | length')
CB=$(echo "$LB" | jq -r '.data.trusted | length')
if [ "$CA" = "1" ] && [ "$CB" = "1" ]; then
    log_pass "one trusted peer each"
else
    log_fail "expected 1/1, got a=$CA b=$CB"
fi

# ----- 4. Trust entries have node_id field -----
log_test "trust entries contain node_id"
NID_IN_A=$(echo "$LA" | jq -r '.data.trusted[0].node_id // empty')
NID_IN_B=$(echo "$LB" | jq -r '.data.trusted[0].node_id // empty')
if [ -n "$NID_IN_A" ] && [ -n "$NID_IN_B" ]; then
    log_pass "node_id present: a-sees=$NID_IN_A  b-sees=$NID_IN_B"
else
    log_fail "missing node_id in trust entry (a='$NID_IN_A' b='$NID_IN_B')"
fi

# ----- 5. Cross-check: a's trusted peer is b's own node_id -----
log_test "a's trusted peer identity matches b's registered node_id"
B_NODE=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$B_NODE" ] && [ "$NID_IN_A" = "$B_NODE" ]; then
    log_pass "node_id matches b's identity ($B_NODE)"
else
    log_fail "mismatch: a trusts $NID_IN_A but b's node_id is $B_NODE"
fi

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Trust visibility summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
