#!/bin/bash
# P1-010 desync recovery test.
#
# Scenario:
#   1. agent-a and agent-b establish an encrypted tunnel.
#   2. agent-b is `compose restart`ed — identity preserved on disk, all
#      in-memory crypto state lost.
#   3. agent-a still has the OLD key for agent-b cached in its tunnel
#      manager. Its next encrypted send to agent-b uses the stale key;
#      agent-b drops the ciphertext (no matching key) and replies with
#      a fresh key_exchange.
#   4. agent-a's handleAuthKeyExchange installs the new key (keyChanged=true).
#
# Fix being asserted: the per-peer salvage ring buffer (recordSalvage on
# every encrypted send + replaySalvage on keyChanged rekey) re-encrypts
# the dropped plaintexts with the new key and re-sends them. The tunnel
# recovers: ping succeeds after the desync, encrypt counters advance, and
# the rekey/salvage log signal appears.
#
# This test:
#   - Establishes the tunnel via baseline ping.
#   - Restarts agent-b to force desync.
#   - Sends a ping immediately after restart (stale-key path).
#   - Asserts encrypt-success counter advances and rekey/salvage log fires.

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

cleanup() {
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

echo "=========================================="
echo "P1-010 tunnel desync recovery"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1

# Wait for both to register.
COUNT=0
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

# Establish tunnel and warm crypto on both sides.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

log_test "baseline ping a->b ok"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "baseline ping ok"
else
    log_fail "baseline ping failed — environment broken"
    exit 1
fi

# Capture pre-restart counters.
PRE_OK=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_success // 0')

log_test "force desync: docker compose restart agent-b"
$DC restart agent-b >/dev/null 2>&1
# Wait for b's new daemon to expose IPC (registered, node_id queryable).
for _ in $(seq 1 60); do
    NID=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
    [ -n "$NID" ] && [ "$NID" != "0" ] && break
    sleep 1
done
[ -n "$NID" ] && [ "$NID" != "0" ] || { log_fail "agent-b did not come back"; exit 1; }
log_pass "agent-b back up (node_id=$NID)"

# Send a ping immediately — agent-a still has stale crypto cached.
# The first encrypted frame uses the stale key → b drops → b sends
# rekey → a installs new key + replaySalvage. The ping may fail on the
# first attempt but must succeed within the salvage/rekey window.
log_test "ping a->b immediately after desync (salvage/rekey path)"
PING_OK=""
for _ in $(seq 1 20); do
    if $DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 4s >/dev/null 2>&1; then
        PING_OK="yes"
        break
    fi
    sleep 1
done
if [ "$PING_OK" = "yes" ]; then
    log_pass "ping recovered after desync"
else
    log_fail "ping never recovered after desync"
    echo "--- agent-a tunnel state ---"
    $DC exec -T agent-a pilotctl --json info 2>&1 | jq '.data | {tunnel_encryption_success, tunnel_encryption_failure, encrypted_peers}'
    echo "--- agent-a recent log ---"
    $DC logs agent-a 2>&1 | tail -25
fi

# Confirm encrypt counter advanced — sanity that the tunnel did move.
POST_OK=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_success // 0')
log_test "encrypt-success counter advanced post-recovery"
if [ "$POST_OK" -gt "$PRE_OK" ]; then
    log_pass "encrypt_ok ${PRE_OK} -> ${POST_OK}"
else
    log_fail "encrypt_ok stuck at ${PRE_OK}"
fi

# Confirm the salvage path actually fired (or peer.rekeyed log appears).
log_test "rekey + salvage signal in agent-a logs"
REKEY_LOGS=$($DC logs agent-a 2>&1 | grep -cE "peer rekeyed|desync salvage replayed" || echo 0)
if [ "$REKEY_LOGS" -ge 1 ]; then
    log_pass "rekey/salvage observed (${REKEY_LOGS} entries)"
else
    log_fail "no rekey/salvage signal — fix may not have fired"
    $DC logs agent-a 2>&1 | tail -20
fi

log_test "no panics in either daemon"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
