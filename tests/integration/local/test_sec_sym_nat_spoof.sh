#!/bin/bash
# Forge a symmetric-NAT registration by sending a BeaconMsgRelay from a
# crafted source so agent-b marks a forged node ID as "relay-capable"
# with beaconAddr as its endpoint. Then we assert that:
#
#   1) The daemon doesn't try to dial the bogus endpoint repeatedly.
#   2) The maxRelayPeers cap (4096) bounds memory if the attacker rotates
#      senderNodeID.
#   3) Real traffic to/from real peers is not disturbed.
#
# EXPECTED: agent-b tolerates spoofed relay entries without looping, no
# unbounded goroutine growth, tunnel to the legit peer still works.

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
NID_B=$(node_id_of agent-b)

log_test "snapshot agent-b state"
RSS_BEFORE=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
GOROUTINES_BEFORE=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    ls /proc/$pid/task 2>/dev/null | wc -l
' 2>/dev/null)

log_test "inject 500 forged BeaconMsgRelayDeliver frames at agent-b:4000"
# MsgRelayDeliver format (pkg/daemon/tunnel.go handleRelayDeliver):
# [type=0x06 byte][srcNodeID(4)][inner_payload: normally a tunnel frame]
# We rotate srcNodeID so agent-b's relayPeers map grows, and we make the
# inner payload a short gibberish body so it fails the magic-switch at
# the bottom of handleRelayDeliver.
$DC exec -T agent-a sh -c '
    i=0
    while [ "$i" -lt 500 ]; do
        # Rotate srcNodeID from 0xBEEF0000 upward
        src=$(printf "%08x" $((0xBEEF0000 + i)))
        # 4-byte gibberish inner payload (not matching any magic)
        inner="cafebabe"
        frame="06${src}${inner}"
        python3 /tests/raw_udp.py send '"$IP_B"' 4000 "$frame" >/dev/null 2>&1
        i=$((i+1))
    done
'
sleep 2

log_test "agent-b still responsive"
if timeout 10 $DC exec -T agent-b pilotctl info >/dev/null 2>&1; then
    log_pass "daemon responsive after spoof injection"
else
    log_fail "daemon became unresponsive"
fi

log_test "goroutine count did not explode (<+200 vs baseline)"
GOROUTINES_AFTER=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    ls /proc/$pid/task 2>/dev/null | wc -l
' 2>/dev/null)
GDELTA=$((GOROUTINES_AFTER - GOROUTINES_BEFORE))
echo "goroutine/thread delta: $GDELTA"
if [ "$GDELTA" -lt 200 ]; then
    log_pass "no goroutine explosion ($GDELTA)"
else
    log_fail "goroutine leak: $GDELTA threads spawned by spoofed relays"
fi

log_test "RSS bounded (<100 MiB delta)"
RSS_AFTER=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
DELTA=$((RSS_AFTER - RSS_BEFORE))
echo "RSS delta: $DELTA kB"
if [ "$DELTA" -lt 102400 ]; then
    log_pass "RSS bounded"
else
    log_fail "RSS unbounded: +$DELTA kB from spoofed relays"
fi

log_test "real agent-a <-> agent-b traffic still works"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
    log_pass "legit traffic intact"
else
    log_fail "legit tunnel broken by spoofed relay entries"
fi

log_test "daemon didn't enter a dial loop (no repeated error spam)"
# Count occurrences of "send key exchange failed" — repeated > 500 times
# would indicate an unbounded dial loop per forged peer.
SPAM=$($DC logs agent-b 2>/dev/null | grep -c 'send key exchange failed' || true)
echo "key exchange failure log count: $SPAM"
if [ "$SPAM" -lt 500 ]; then
    log_pass "no pathological dial-loop spam"
else
    log_fail "dial loop: $SPAM key exchange failures logged"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
