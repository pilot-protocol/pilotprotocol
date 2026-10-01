#!/bin/bash
# Large payload: 500 MiB file MUST be rejected cleanly.
#
# A 500 MiB send-file must NOT:
#   - silently truncate
#   - OOM the daemon
#   - succeed with partial content
# It should either return a clear "too large" / "size limit exceeded" error
# at input validation, OR complete fully with byte-exact integrity. Anything
# in between is a bug.
# DURATION: 10min

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
SIZE_MB=500

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Large payload: 500 MiB reject or complete cleanly"
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

log_test "create ${SIZE_MB} MiB random file"
$DC exec -T agent-a bash -c "dd if=/dev/urandom of=/tmp/huge.bin bs=1M count=${SIZE_MB} status=none"
SRC_SZ=$($DC exec -T agent-a bash -c "wc -c </tmp/huge.bin" | tr -d ' \r\n')
SRC_SHA=$($DC exec -T agent-a sha256sum /tmp/huge.bin | awk '{print $1}')
log_pass "src=$SRC_SZ sha=${SRC_SHA:0:12}..."

log_test "attempt send (may be rejected or complete)"
OUT=$($DC exec -T agent-a bash -c "pilotctl --json send-file agent-b /tmp/huge.bin --timeout 900s 2>&1")
OK=$(echo "$OUT" | jq -r '.status // ""' 2>/dev/null)
ERR=$(echo "$OUT" | jq -r '.error // ""' 2>/dev/null)
ACK=$(echo "$OUT" | jq -r '.data.ack // empty' 2>/dev/null | grep -oE '[0-9]+' | head -n1)

if [ "$OK" = "ok" ] && [ -n "$ACK" ] && [ "$ACK" -ge "$SRC_SZ" ]; then
    # Claims success — verify byte-exact.
    log_test "success claimed — verify full sha256"
    RECV=""
    for _ in $(seq 1 180); do
        RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^huge-' | head -n1" | tr -d ' \r\n')
        [ -n "$RECV" ] && break
        sleep 1
    done
    if [ -n "$RECV" ]; then
        DST_SHA=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
        DST_SZ=$($DC exec -T agent-b bash -c "wc -c </root/.pilot/received/$RECV" | tr -d ' \r\n')
        if [ "$SRC_SHA" = "$DST_SHA" ] && [ "$SRC_SZ" = "$DST_SZ" ]; then
            log_pass "completed fully size=$DST_SZ sha match"
        else
            log_fail "SILENT CORRUPTION: ack=$ACK but sha/size differ (src=$SRC_SZ/${SRC_SHA:0:12} dst=$DST_SZ/${DST_SHA:0:12})"
        fi
    else
        log_fail "ack=$ACK but no file on receiver — SILENT LOSS"
    fi
elif [ -n "$ERR" ] && [ "$ERR" != "null" ] && [ "$ERR" != "" ]; then
    log_pass "rejected cleanly with error: '$ERR'"
else
    log_fail "ambiguous outcome ok=$OK ack=$ACK err='$ERR' raw=$(echo "$OUT" | head -c 300)"
fi

log_test "daemon still alive after 500 MiB attempt (no OOM)"
NID_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$NID_A" ] && [ "$NID_A" != "0" ] && [ -n "$NID_B" ] && [ "$NID_B" != "0" ]; then
    log_pass "both daemons alive (no OOM) a=$NID_A b=$NID_B"
else
    log_fail "daemon died: a='$NID_A' b='$NID_B'"
fi

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|OOM|out of memory" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
