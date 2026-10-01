#!/bin/bash
# Untrust visibility: after establishing mutual trust and then revoking it,
# the peer must disappear from the trust list on both sides within 10s.
# Also verifies that the `pilotctl trust` output before untrust shows the
# peer and after untrust shows an empty list (zero entries).
#
# This focuses on the list-visibility dimension of revocation, complementing
# test_trust_revoke.sh which validates log messages and re-handshake.

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
echo "Untrust visibility"
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

# ----- Setup: establish mutual trust -----
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
for NID in $($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[].node_id'); do
    $DC exec -T agent-b pilotctl --json approve "$NID" >/dev/null 2>&1
done
sleep 3

log_test "setup: mutual trust established"
TA=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
TB=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "$TA" -ge 1 ] && [ "$TB" -ge 1 ]; then
    log_pass "trust in place: a=$TA b=$TB"
else
    log_fail "setup failed: a=$TA b=$TB"
    exit 1
fi

# ----- 1. Pre-untrust: peer appears in trust list -----
# Get B_NODE from a's trust list (avoids info/trust JSON type mismatch).
log_test "pre-untrust: agent-b appears in agent-a trust list"
TRUST_LIST=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null)
B_NODE=$(echo "$TRUST_LIST" | jq -r '.data.trusted[0].node_id // empty')
CA=$(echo "$TRUST_LIST" | jq -r '.data.trusted | length')
if [ "$CA" = "1" ] && [ -n "$B_NODE" ]; then
    log_pass "b (node_id=$B_NODE) found in a's trust list"
else
    log_fail "b not in a's trust list (count=$CA node_id='$B_NODE')"
fi

# ----- 2. Revoke trust from a -----
log_test "a untrusts b"
PEER_NID=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted[0].node_id')
$DC exec -T agent-a pilotctl --json untrust "$PEER_NID" >/dev/null 2>&1

# ----- 3. a's trust list is empty within 5s -----
log_test "a's trust list is empty after untrust"
for _ in $(seq 1 10); do
    TA2=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
    [ "$TA2" = "0" ] && break
    sleep 1
done
[ "$TA2" = "0" ] && log_pass "a's trust list empty" || log_fail "a's trust list still has $TA2 entries"

# ----- 4. b's trust list is empty within 10s (propagation) -----
log_test "b's trust list is empty after revocation propagates"
for _ in $(seq 1 10); do
    TB2=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
    [ "$TB2" = "0" ] && break
    sleep 1
done
[ "$TB2" = "0" ] && log_pass "b's trust list empty" || log_fail "b's trust list still has $TB2 entries"

# ----- 5. b is no longer in a's trust list -----
log_test "b not reachable via trust lookup after untrust"
TRUST_AFTER=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null)
CA_AFTER=$(echo "$TRUST_AFTER" | jq -r '.data.trusted | length')
[ "$CA_AFTER" = "0" ] && log_pass "b absent from a's trust list (empty)" \
    || log_fail "b still listed ($CA_AFTER entries remain)"

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Untrust visibility summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
