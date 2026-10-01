#!/bin/bash
# Race: large send-file with mid-transfer rekey.
#
# Agent-a sends a 20 MiB random file to agent-b. Partway through the transfer
# we force a rekey by restarting agent-b (which invalidates agent-a's cached
# crypto). The file transfer must either:
#   a) complete successfully with SHA-256 matching (preferred), OR
#   b) fail loudly with a clear error (not "success" with missing bytes)
#
# What we never want: ack reports full size but received file is short /
# corrupted. That is P1-009-class silent data loss.

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
echo "Race: send-file during forced rekey"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1

log_test "create 20 MiB random source on agent-a"
$DC exec -T agent-a bash -c 'dd if=/dev/urandom of=/tmp/rekey-race.bin bs=1M count=20 status=none'
SRC_SHA=$($DC exec -T agent-a sha256sum /tmp/rekey-race.bin | awk '{print $1}')
SRC_SZ=$($DC exec -T agent-a bash -c 'wc -c </tmp/rekey-race.bin' | tr -d ' \r\n')
log_pass "source ready size=$SRC_SZ sha=${SRC_SHA:0:12}..."

# Launch send-file in the background.
log_test "launch send-file in background"
$DC exec -d agent-a bash -c '
    rm -f /tmp/send.out
    pilotctl --json send-file agent-b /tmp/rekey-race.bin >/tmp/send.out 2>&1
    echo SENDER_DONE >>/tmp/send.out
'

# Wait briefly, then force rekey via agent-b restart.
sleep 0.2
log_test "restart agent-b to force rekey mid-transfer"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 30); do
    NID=$($DC exec -T agent-b bash -c 'pilotctl --json info 2>/dev/null' | jq -r '.data.node_id // empty' 2>/dev/null)
    [ -n "$NID" ] && [ "$NID" != "0" ] && break
    sleep 0.5
done
log_pass "agent-b restarted node_id=$NID"

# Wait for sender to finish (allow generous time for retry / reconnect).
log_test "wait for sender to return (up to 90 s)"
DONE=""
for _ in $(seq 1 90); do
    DONE=$($DC exec -T agent-a bash -c "grep -c SENDER_DONE /tmp/send.out 2>/dev/null" | tr -d ' \r\n')
    [ "${DONE:-0}" = "1" ] && break
    sleep 1
done
if [ "${DONE:-0}" = "1" ]; then
    log_pass "sender returned"
else
    log_fail "sender still running after 90s"
fi

log_test "sender reports success OR loud error (never silent corruption)"
OUT=$($DC exec -T agent-a bash -c 'cat /tmp/send.out')
OK=$(echo "$OUT" | jq -r ".status // empty" 2>/dev/null)
ACK=$(echo "$OUT" | jq -r '.data.ack // empty' 2>/dev/null | grep -oE '[0-9]+' | head -n1)
ERR=$(echo "$OUT" | jq -r '.error // empty' 2>/dev/null)

if [ "$OK" = "ok" ] && [ -n "$ACK" ] && [ "$ACK" -ge "$SRC_SZ" ]; then
    # Sender claims full delivery → verify receiver side sha.
    log_test "verify receiver file sha matches source (ack claims full delivery)"
    RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^rekey-race-' | head -n1" | tr -d ' \r\n')
    if [ -z "$RECV" ]; then
        log_fail "sender claims ack=$ACK but no file landed on receiver — SILENT DATA LOSS"
    else
        DST_SHA=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
        DST_SZ=$($DC exec -T agent-b bash -c "wc -c </root/.pilot/received/$RECV" | tr -d ' \r\n')
        if [ "$SRC_SHA" = "$DST_SHA" ] && [ "$SRC_SZ" = "$DST_SZ" ]; then
            log_pass "sha256 intact across rekey ($DST_SZ bytes)"
        else
            log_fail "size/sha mismatch: src=$SRC_SZ/${SRC_SHA:0:12}... dst=$DST_SZ/${DST_SHA:0:12}... — CORRUPTION"
        fi
    fi
elif [ -n "$ERR" ] && [ "$ERR" != "null" ]; then
    log_pass "sender failed loudly with error: '$ERR' (no silent corruption)"
else
    log_fail "ambiguous result ok=$OK ack=$ACK err=$ERR raw=$(echo "$OUT" | head -c 300)"
fi

log_test "no panics in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
