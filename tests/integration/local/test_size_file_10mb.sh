#!/bin/bash
# Large payload: 10 MiB send-file with SHA-256 integrity verification.

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
SIZE_MB=10

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Large payload: send-file ${SIZE_MB} MiB"
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

log_test "create ${SIZE_MB} MiB random file on agent-a"
$DC exec -T agent-a bash -c "dd if=/dev/urandom of=/tmp/size-${SIZE_MB}m.bin bs=1M count=${SIZE_MB} status=none"
SRC_SZ=$($DC exec -T agent-a bash -c "wc -c </tmp/size-${SIZE_MB}m.bin" | tr -d ' \r\n')
SRC_SHA=$($DC exec -T agent-a sha256sum "/tmp/size-${SIZE_MB}m.bin" | awk '{print $1}')
log_pass "src size=$SRC_SZ sha=${SRC_SHA:0:12}..."

log_test "send file to agent-b"
OUT=$($DC exec -T agent-a bash -c "pilotctl --json send-file agent-b /tmp/size-${SIZE_MB}m.bin --timeout 180s 2>&1")
ACK=$(echo "$OUT" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
if [ -n "$ACK" ] && [ "$ACK" -ge "$SRC_SZ" ]; then
    log_pass "ack=$ACK >= $SRC_SZ"
else
    log_fail "send failed ack=$ACK src=$SRC_SZ raw=$(echo "$OUT" | head -c 300)"
    exit 1
fi

log_test "receiver file sha256 matches source"
for _ in $(seq 1 30); do
    RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^size-${SIZE_MB}m-' | head -n1" | tr -d ' \r\n')
    [ -n "$RECV" ] && break
    sleep 0.5
done
if [ -z "$RECV" ]; then
    log_fail "no received file found"
    exit 1
fi
DST_SZ=$($DC exec -T agent-b bash -c "wc -c </root/.pilot/received/$RECV" | tr -d ' \r\n')
DST_SHA=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ "$SRC_SHA" = "$DST_SHA" ] && [ "$SRC_SZ" = "$DST_SZ" ]; then
    log_pass "size+sha exact ($DST_SZ bytes)"
else
    log_fail "mismatch: src=$SRC_SZ/${SRC_SHA:0:12}... dst=$DST_SZ/${DST_SHA:0:12}..."
fi

log_test "no panics in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
