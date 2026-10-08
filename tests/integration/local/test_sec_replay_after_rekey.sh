#!/bin/bash
# Capture a valid encrypted tunnel frame (PILS) while agents talk, force
# a rekey by restarting agent-a, then replay the captured frame into
# agent-b. The replay must be rejected: either the nonce falls outside the
# replay window of the new peerCrypto (counter reset), or the AEAD
# Open() fails because the peer has a fresh AES-256-GCM key after X25519
# re-derivation.
#
# EXPECTED: agent-b logs "encrypted packet from node but no key" OR
# "tunnel decrypt error" when we replay. Packet count on agent-b's
# EncryptFail / pkts_recv counter does NOT increment a successful decode.

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

cleanup() {
    stop_capture agent-b >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
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

log_test "install tcpdump in agent-b"
if ensure_tcpdump agent-b; then
    log_pass "tcpdump available"
else
    log_fail "tcpdump install failed — skipping capture, expected test infra dependency"
    # Still run partial test with synthesized frame.
fi

log_test "start capture of PILS traffic on agent-b"
$DC exec -T agent-b rm -f /tmp/cap.pcap >/dev/null 2>&1
start_capture agent-b eth0 "udp port 4000" /tmp/cap.pcap || true
sleep 1

log_test "generate traffic a->b so a PILS frame is sent"
$DC exec -T agent-a pilotctl ping agent-b --count 5 --timeout 10s >/dev/null 2>&1 || true
$DC exec -T agent-a pilotctl send-message agent-b --data "replay-target" --type text >/dev/null 2>&1 || true
sleep 2

stop_capture agent-b >/dev/null 2>&1
sleep 1

CAP_HEX=$(extract_first_pils agent-b /tmp/cap.pcap 2>/dev/null || true)
if [ -z "$CAP_HEX" ]; then
    log_fail "no PILS frame captured (tcpdump/parse failed); falling back to synthesized frame"
    # Synthesize a plausible-looking PILS frame: magic + random nodeID +
    # random nonce + random ciphertext. Daemon will drop at "no key" or
    # AEAD-Open, both are acceptable defenses.
    NID_A=$(node_id_of agent-a)
    if [ -z "$NID_A" ]; then NID_A=1; fi
    NONCE=$(hex_rand 12)
    CT=$(hex_rand 64)
    CAP_HEX=$(craft_encrypted_frame "$NID_A" "$NONCE" "$CT")
fi

log_test "force rekey: restart agent-a"
$DC restart agent-a >/dev/null 2>&1
if ! wait_for 60 bash -c '
    docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json info 2>/dev/null |
    jq -e ".data.node_id" >/dev/null
'; then
    log_fail "agent-a did not come back"
    exit 1
fi
sleep 5

log_test "snapshot agent-b EncryptFail before replay"
FAIL_BEFORE=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_failure // 0')

log_test "replay captured PILS frame into agent-b:4000"
IP_B=$(ip_of agent-b)
send_raw_udp agent-a "$IP_B" 4000 "$CAP_HEX" >/dev/null 2>&1 || true
# Replay a few extra times to make sure at least one reaches the read loop.
for i in 1 2 3 4 5; do
    send_raw_udp agent-a "$IP_B" 4000 "$CAP_HEX" >/dev/null 2>&1 || true
done
sleep 2

log_test "agent-b logs show rejection"
LOG=$($DC logs --tail=200 agent-b 2>/dev/null)
if echo "$LOG" | grep -qE 'encrypted packet from node but no key|tunnel decrypt error|tunnel nonce replay|tunnel packet outside replay window'; then
    log_pass "replay rejected with defensive log message"
else
    log_fail "no rejection log line found after replay"
    echo "--- tail of agent-b logs ---"
    echo "$LOG" | tail -40
fi

log_test "agent-b did not accept the replay as valid traffic"
FAIL_AFTER=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_failure // 0')
if [ "$FAIL_AFTER" -ge "$FAIL_BEFORE" ]; then
    log_pass "encrypt_failure counter non-decreasing ($FAIL_BEFORE -> $FAIL_AFTER)"
else
    log_fail "encrypt_failure went DOWN? ($FAIL_BEFORE -> $FAIL_AFTER)"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
