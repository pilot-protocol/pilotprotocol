#!/bin/bash
# Trust revocation propagation tests.
# Requires the p2p compose stack (rendezvous, agent-a, agent-b) running.

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

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Trust revocation integration tests"
echo "=========================================="

log_test "Starting p2p stack"
docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1
docker compose -f docker-compose.multi.yml up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# ---- 1. Handshake + approve establishes mutual trust ----
log_test "handshake + approve creates mutual trust"
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json handshake agent-b >/dev/null
sleep 2
PENDING=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json pending | jq -r '.data.pending[0].node_id // empty')
if [ -z "$PENDING" ]; then
    log_fail "agent-b saw no pending handshake"
    exit 1
fi
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json approve "$PENDING" >/dev/null
sleep 3
A_TRUSTED=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json trust | jq -r '.data.trusted | length')
B_TRUSTED=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json trust | jq -r '.data.trusted | length')
if [ "$A_TRUSTED" = "1" ] && [ "$B_TRUSTED" = "1" ]; then
    log_pass "both trust sets populated"
else
    log_fail "trust not symmetric (a=$A_TRUSTED b=$B_TRUSTED)"
fi

# ---- 2. Revoke propagates: both sides end empty ----
log_test "revoke propagates to remote peer"
PEER_FROM_A=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json trust | jq -r '.data.trusted[0].node_id')
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json untrust "$PEER_FROM_A" >/dev/null
sleep 5
A_AFTER=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json trust | jq -r '.data.trusted | length')
B_AFTER=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json trust | jq -r '.data.trusted | length')
if [ "$A_AFTER" = "0" ] && [ "$B_AFTER" = "0" ]; then
    log_pass "both trust sets empty after revoke"
else
    log_fail "revoke did not propagate (a=$A_AFTER b=$B_AFTER)"
fi

# ---- 3. Peer logs "trust revoked by peer" ----
log_test "remote peer logs revocation"
if docker compose -f docker-compose.multi.yml logs --tail=100 agent-b 2>&1 | grep -q "trust revoked by peer"; then
    log_pass "agent-b logged 'trust revoked by peer'"
else
    log_fail "agent-b did not log the revocation"
fi

# ---- 4. Relayed stale approval doesn't resurrect trust ----
# Simulated by waiting past the poll cycle — if a stale relayed approval were
# going to re-add trust, it would do so within a few seconds.
log_test "stale relayed approval does not resurrect trust"
sleep 8
A_LATE=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json trust | jq -r '.data.trusted | length')
B_LATE=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json trust | jq -r '.data.trusted | length')
if [ "$A_LATE" = "0" ] && [ "$B_LATE" = "0" ]; then
    log_pass "trust stayed empty after poll cycle"
else
    log_fail "trust resurrected by stale relay (a=$A_LATE b=$B_LATE)"
fi

# ---- 5. Re-handshake is rejected during cooldown (optional: explicit behavior check) ----
log_test "new handshake after revoke still works (cooldown blocks relayed approval only)"
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json handshake agent-b >/dev/null
sleep 2
PENDING2=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json pending | jq -r '.data.pending | length')
if [ "$PENDING2" = "1" ]; then
    log_pass "fresh handshake request arrives at peer"
else
    log_fail "fresh handshake not received (pending=$PENDING2)"
fi

echo
echo "=========================================="
echo "Trust revocation test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
