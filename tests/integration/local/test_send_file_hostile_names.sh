#!/bin/bash
# Send-file with hostile filenames.
#
# Parallel to test_send_file_integrity.sh (random content across sizes)
# but stressing the filename / metadata path instead of the byte stream.
#
# Hostile inputs:
#   1. "spaces in name.bin" (1 KiB) - shell escaping across IPC
#   2. "dots...extra.bin"   (1 KiB) - filename-stem extraction edge
#   3. "zero.bin"           (0 B)   - empty payload boundary
#   4. missing file                 - clean rejection, no crash
#
# Asserts byte-exact sha256, basename stem preserved on the receiver
# side (`{stem}-{ts}-{seq}{ext}`), and that the missing-file case is
# rejected with a clean error rather than panicking the daemon.

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
echo "Send-file hostile filenames"
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

$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1

# ----- 1. Create the three source files on agent-a -----
log_test "create source files: 'spaces in name.bin', 'dots...extra.bin', 'zero.bin'"
$DC exec -T agent-a bash -c '
    dd if=/dev/urandom of="/tmp/spaces in name.bin" bs=1024 count=1 status=none
    dd if=/dev/urandom of="/tmp/dots...extra.bin"   bs=1024 count=1 status=none
    : >"/tmp/zero.bin"
'
SUM_SP=$($DC exec -T agent-a bash -c 'sha256sum "/tmp/spaces in name.bin"' | awk '{print $1}')
SUM_DT=$($DC exec -T agent-a bash -c 'sha256sum "/tmp/dots...extra.bin"'   | awk '{print $1}')
SUM_ZR=$($DC exec -T agent-a bash -c 'sha256sum "/tmp/zero.bin"'           | awk '{print $1}')
if [ -n "$SUM_SP" ] && [ -n "$SUM_DT" ] && [ -n "$SUM_ZR" ]; then
    log_pass "source sums ready"
else
    log_fail "source sha256 missing (sp=$SUM_SP dt=$SUM_DT zr=$SUM_ZR)"
    exit 1
fi

# ----- 2. Send the three files -----
log_test "send file with spaces in name"
OUT_SP=$($DC exec -T agent-a pilotctl --json send-file agent-b "/tmp/spaces in name.bin" 2>&1)
ACK_SP=$(echo "$OUT_SP" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
if [ -n "$ACK_SP" ] && [ "$ACK_SP" -ge 1024 ]; then
    log_pass "spaces ack=$ACK_SP"
else
    log_fail "spaces send failed: $(echo "$OUT_SP" | head -c 300)"
fi

log_test "send file with dots...extra.bin"
OUT_DT=$($DC exec -T agent-a pilotctl --json send-file agent-b "/tmp/dots...extra.bin" 2>&1)
ACK_DT=$(echo "$OUT_DT" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
if [ -n "$ACK_DT" ] && [ "$ACK_DT" -ge 1024 ]; then
    log_pass "dots ack=$ACK_DT"
else
    log_fail "dots send failed: $(echo "$OUT_DT" | head -c 300)"
fi

log_test "send zero-byte file"
OUT_ZR=$($DC exec -T agent-a pilotctl --json send-file agent-b "/tmp/zero.bin" 2>&1)
# For zero-byte: ack may be 0 or absent; we care that the call does not error
if echo "$OUT_ZR" | jq -e '.status == "ok"' >/dev/null 2>&1 || \
   echo "$OUT_ZR" | jq -e '.data.ack // empty' >/dev/null 2>&1; then
    log_pass "zero-byte send accepted: $(echo "$OUT_ZR" | head -c 150)"
else
    log_fail "zero-byte send rejected: $(echo "$OUT_ZR" | head -c 300)"
fi

# ----- 3. Send a file that does not exist -----
log_test "send-file of missing path is rejected cleanly"
OUT_MS=$($DC exec -T agent-a pilotctl --json send-file agent-b "/tmp/definitely-not-there.bin" 2>&1)
if echo "$OUT_MS" | grep -qiE "not.*exist|no such|not.*found|cannot open|invalid"; then
    log_pass "missing file error: $(echo "$OUT_MS" | head -c 200)"
else
    log_fail "unexpected missing-file outcome: $(echo "$OUT_MS" | head -c 300)"
fi

# ----- 4. Locate each received file by stem prefix -----
log_test "receiver has 2 or 3 files (spaces + dots required; zero may be present)"
for _ in $(seq 1 20); do
    NREC=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null | wc -l' | tr -d ' \r\n')
    if [ "$NREC" -ge 2 ]; then break; fi
    sleep 0.5
done
if [ "$NREC" -ge 2 ]; then
    log_pass "received=$NREC"
    $DC exec -T agent-b ls /root/.pilot/received 2>&1 | sed 's/^/    /'
else
    log_fail "received=$NREC (wanted at least 2)"
    exit 1
fi

# Helper: find a received file whose stem starts with a given prefix.
# NOTE: filenames may contain spaces, so only strip CR/LF, not spaces.
find_recv() {
    local stem=$1
    $DC exec -T agent-b bash -c "ls /root/.pilot/received | grep -F '${stem}' | head -n1" | tr -d '\r\n'
}

# ----- 5. Byte-exact sha256 for spaces -----
log_test "'spaces in name.bin' sha256 matches"
PATH_SP=$(find_recv "spaces in name")
if [ -z "$PATH_SP" ]; then
    log_fail "no received file matches 'spaces in name'"
else
    DST_SP=$($DC exec -T agent-b bash -c "sha256sum \"/root/.pilot/received/$PATH_SP\"" | awk '{print $1}')
    if [ "$SUM_SP" = "$DST_SP" ]; then
        log_pass "spaces OK: $PATH_SP"
    else
        log_fail "spaces mismatch: src=${SUM_SP:0:12}... dst=${DST_SP:0:12}..."
    fi
fi

# ----- 6. Byte-exact sha256 for dots -----
log_test "'dots...extra.bin' sha256 matches"
PATH_DT=$(find_recv "dots")
if [ -z "$PATH_DT" ]; then
    log_fail "no received file matches 'dots'"
else
    DST_DT=$($DC exec -T agent-b bash -c "sha256sum \"/root/.pilot/received/$PATH_DT\"" | awk '{print $1}')
    if [ "$SUM_DT" = "$DST_DT" ]; then
        log_pass "dots OK: $PATH_DT"
    else
        log_fail "dots mismatch: src=${SUM_DT:0:12}... dst=${DST_DT:0:12}..."
    fi
fi

# ----- 7. No panic/fatal in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Hostile-filename test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
