#!/bin/bash
# Craft a PILS (encrypted) frame whose embedded sender-node-id does NOT
# match any peer agent-b has crypto state for. The AAD in tunnel.go
# handleEncrypted is bound to the advertised peerNodeID (see H3 fix in
# pkg/daemon/tunnel.go: `binary.BigEndian.PutUint32(aad, peerNodeID)`),
# so the daemon MUST drop the frame before it reaches application code.
#
# EXPECTED: log line "encrypted packet from node but no key" with the
# spoofed peer_node_id. No packet delivered to the application (bytes_recv
# may tick for UDP framing but pkts_recv for decrypted traffic does not).

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
# shellcheck source=sec_helpers.sh
source ./sec_helpers.sh

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if ! wait_for 60 bash -c '
    c=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r ".total_nodes // 0")
    [ "$c" -ge 2 ]
'; then
    log_fail "agents did not register"
    exit 1
fi

IP_B=$(ip_of agent-b)
log_test "craft PILS with a bogus peerNodeID (0xDEADBEEF)"
SPOOF_NID=$((0xDEADBEEF))
NONCE=$(hex_rand 12)
CT=$(hex_rand 64) # gibberish ciphertext; will fail even if key were present
FRAME=$(craft_encrypted_frame "$SPOOF_NID" "$NONCE" "$CT")

log_test "send spoofed frame to agent-b:4000 several times"
for _ in 1 2 3 4 5; do
    send_raw_udp agent-a "$IP_B" 4000 "$FRAME" >/dev/null 2>&1 || true
done
sleep 2

log_test "agent-b logs show drop for spoofed node_id"
LOG=$($DC logs --tail=300 agent-b 2>/dev/null)
# Either "no key" (most common — attacker id has no crypto context) or an
# explicit decrypt error / replay detection. Any of these is acceptable;
# the critical property is that NO successful decrypt happened.
if echo "$LOG" | grep -qE 'encrypted packet from node but no key|tunnel decrypt error'; then
    log_pass "spoofed frame rejected"
else
    log_fail "expected defensive log not found"
    echo "--- tail agent-b ---"
    echo "$LOG" | tail -30
fi

log_test "agent-a can still talk to agent-b (tunnel not poisoned)"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
    log_pass "live tunnel still works after spoof attempt"
else
    log_fail "spoof attempt degraded the legitimate tunnel"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
