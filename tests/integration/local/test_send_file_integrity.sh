#!/bin/bash
# Send-file byte-exact integrity across sizes.
#
# test_tasks_and_edge.sh only validates that the send-file ack byte
# count is >= original size. This suite goes further: three files
# with random content at 1 KiB / 50 KiB / 200 KiB are sent from
# agent-a to agent-b, and we compute sha256 on both sides to catch
# silent corruption that a size-only check would miss.
#
# Targets:
#   - chunking bugs where a multi-chunk payload reassembles with
#     the wrong ordering
#   - padding/header leak where the received bytes contain framing
#     bytes that were supposed to be stripped
#   - bit-flips in the encrypted tunnel path that survive the ack
#     but corrupt content
#   - off-by-one at file-boundary flush
#
# Files are named with a distinct prefix per size so that the
# received/ basename lookup is deterministic.

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
echo "Send-file integrity across sizes"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

# Make sure we start with an empty received/ on agent-b.
$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1

# ----- 1. Create 3 files on agent-a -----
log_test "create 3 random files on agent-a: tiny.bin=1KiB, medium.bin=50KiB, big.bin=200KiB"
$DC exec -T agent-a bash -c '
    dd if=/dev/urandom of=/tmp/tiny.bin   bs=1024 count=1   status=none
    dd if=/dev/urandom of=/tmp/medium.bin bs=1024 count=50  status=none
    dd if=/dev/urandom of=/tmp/big.bin    bs=1024 count=200 status=none
'
SUM_TINY=$($DC   exec -T agent-a sha256sum /tmp/tiny.bin   | awk '{print $1}')
SUM_MED=$($DC    exec -T agent-a sha256sum /tmp/medium.bin | awk '{print $1}')
SUM_BIG=$($DC    exec -T agent-a sha256sum /tmp/big.bin    | awk '{print $1}')
if [ -n "$SUM_TINY" ] && [ -n "$SUM_MED" ] && [ -n "$SUM_BIG" ]; then
    log_pass "sha256 tiny=${SUM_TINY:0:12}... med=${SUM_MED:0:12}... big=${SUM_BIG:0:12}..."
else
    log_fail "could not compute source sha256 (tiny=$SUM_TINY med=$SUM_MED big=$SUM_BIG)"
    exit 1
fi

# ----- 2. Send all 3 files from agent-a -> agent-b -----
log_test "send all 3 files and check each ack byte count meets minimum"
sent_ok=0
for f in /tmp/tiny.bin /tmp/medium.bin /tmp/big.bin; do
    SZ=$($DC exec -T agent-a bash -c "wc -c <$f" | tr -d ' \r\n')
    OUT=$($DC exec -T agent-a pilotctl --json send-file agent-b "$f" 2>&1)
    ACK=$(echo "$OUT" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
    if [ -n "$ACK" ] && [ "$ACK" -ge "$SZ" ]; then
        sent_ok=$((sent_ok+1))
    else
        echo "  [fail] $f size=$SZ ack=$ACK raw=$(echo "$OUT" | head -c 200)"
    fi
done
if [ "$sent_ok" = "3" ]; then
    log_pass "all 3 files acked"
else
    log_fail "only $sent_ok/3 files acked"
    exit 1
fi

# ----- 3. agent-b received/ has 3 files -----
log_test "agent-b received/ has 3 files"
for _ in $(seq 1 20); do
    NREC=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null | wc -l' | tr -d ' \r\n')
    if [ "$NREC" = "3" ]; then break; fi
    sleep 0.5
done
if [ "$NREC" = "3" ]; then
    log_pass "3 files present on receiver"
else
    log_fail "received=$NREC/3"
    $DC exec -T agent-b bash -c 'ls -la /root/.pilot/received' 2>&1 | sed 's/^/    /'
    exit 1
fi

# Helper: locate the received path whose basename matches the source file.
# Received files are named {stem}-{ts}-{seq}{ext}, where "stem" is the
# source filename with its extension stripped (e.g. tiny.bin -> tiny-*.bin).
find_recv() {
    local source_basename=$1
    local stem="${source_basename%.*}"
    $DC exec -T agent-b bash -c "ls /root/.pilot/received | grep '^${stem}-' | head -n1" | tr -d ' \r\n'
}

# ----- 4. sha256 matches for each -----
cmp_sha() {
    local src_sum=$1 prefix=$2 label=$3
    local path
    path=$(find_recv "$prefix")
    if [ -z "$path" ]; then
        log_fail "no received file with prefix '$prefix-*' for $label"
        return
    fi
    local dst_sum
    dst_sum=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$path" 2>/dev/null | awk '{print $1}')
    if [ "$src_sum" = "$dst_sum" ]; then
        log_pass "$label sha256 matches (${src_sum:0:12}...) file=$path"
    else
        log_fail "$label sha256 mismatch: src=${src_sum:0:12}... dst=${dst_sum:0:12}... file=$path"
    fi
}

log_test "tiny.bin (1 KiB) sha256 matches"
cmp_sha "$SUM_TINY" "tiny.bin" "tiny"
log_test "medium.bin (50 KiB) sha256 matches"
cmp_sha "$SUM_MED"  "medium.bin" "medium"
log_test "big.bin (200 KiB) sha256 matches"
cmp_sha "$SUM_BIG"  "big.bin" "big"

# ----- 5. received file sizes match source byte counts -----
log_test "received file sizes match source byte counts exactly"
sz_ok=0
for spec in "tiny.bin:1024" "medium.bin:51200" "big.bin:204800"; do
    prefix=${spec%:*}
    want=${spec#*:}
    path=$(find_recv "$prefix")
    [ -z "$path" ] && continue
    got=$($DC exec -T agent-b bash -c "wc -c </root/.pilot/received/$path" | tr -d ' \r\n')
    if [ "$got" = "$want" ]; then
        sz_ok=$((sz_ok+1))
    else
        echo "  size mismatch for $prefix: got=$got want=$want"
    fi
done
if [ "$sz_ok" = "3" ]; then
    log_pass "all 3 sizes exact"
else
    log_fail "$sz_ok/3 sizes matched"
fi

# ----- 6. No panic/fatal in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Send-file integrity summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
