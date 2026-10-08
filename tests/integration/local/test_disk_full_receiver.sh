#!/bin/bash
# Chaos Matrix 3: receiver's /root/.pilot/received directory is out of
# space. Sender must get a clean error, receiver must not panic, and
# already-received files must remain intact. No silent truncation.
#
# IDEAL FIXTURE: bind-mount a 1 MiB tmpfs at agent-b:/root/.pilot/received
# via a compose override (e.g. docker-compose.multi.diskfull.yml). That
# override is NOT in the repo today — authoring it is out of scope for
# this test per the prompt. This script implements a CLOSE equivalent
# that runs on the stock compose stack:
#
#   1. Pre-fill /root/.pilot/received on agent-b with a >90%-full sparse
#      ballast using `fallocate` (or `dd if=/dev/zero`), making the disk
#      effectively full for subsequent writes.
#   2. Then try to send a 2 MiB file from a->b. Expected: either clean
#      rejection (sender gets an error) OR receiver writes 0-length and
#      later deletes. Forbidden: panic, daemon crash, incomplete file
#      left on disk reported as COMPLETED.
#
# If the caller wires up the tmpfs override, they can set
# PILOT_DISKFULL_PREPARED=1 and this test will skip the ballast step.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Disk-full receiver"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b bash -c 'rm -f /root/.pilot/received/__ballast.bin' >/dev/null 2>&1 || true
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

# ----- 1. Prepare disk-full condition ----------
log_test "prepare disk-full at agent-b:/root/.pilot/received"
$DC exec -T agent-b mkdir -p /root/.pilot/received >/dev/null 2>&1

if [ "${PILOT_DISKFULL_PREPARED:-0}" = "1" ]; then
    log_pass "user provided tmpfs override — skipping ballast"
else
    # Compute free bytes, allocate all-but-512KiB as ballast.
    FREE=$($DC exec -T agent-b bash -c "df -B1 /root/.pilot/received | awk 'NR==2 {print \$4}'" | tr -d '\r\n')
    if [ -z "$FREE" ] || [ "$FREE" -lt 1048576 ]; then
        log_fail "cannot determine free bytes ($FREE) — need tmpfs override"
        echo "    Set PILOT_DISKFULL_PREPARED=1 and wire a compose override"
        echo "    with tmpfs: { /root/.pilot/received: { size: 1m } }"
        exit 1
    fi
    # leave 256KiB headroom so daemon metadata writes still succeed
    BALLAST=$((FREE - 262144))
    $DC exec -T agent-b bash -c "fallocate -l $BALLAST /root/.pilot/received/__ballast.bin 2>/dev/null || dd if=/dev/zero of=/root/.pilot/received/__ballast.bin bs=1M count=$((BALLAST / 1048576)) 2>/dev/null"
    NEW_FREE=$($DC exec -T agent-b bash -c "df -B1 /root/.pilot/received | awk 'NR==2 {print \$4}'" | tr -d '\r\n')
    if [ "$NEW_FREE" -lt 524288 ]; then
        log_pass "disk effectively full (free=$NEW_FREE bytes)"
    else
        log_fail "ballast too small; free=$NEW_FREE after fill"
        exit 1
    fi
fi

# ----- 2. Attempt send-file larger than free space ----
log_test "send-file 2 MiB to full receiver — expect clean failure"
$DC exec -T agent-a bash -c 'head -c 2097152 /dev/urandom >/tmp/df2m.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/df2m.dat | awk '{print $1}')
SF=$($DC exec -T agent-a timeout 60 pilotctl --json send-file agent-b /tmp/df2m.dat 2>&1)
SF_RC=$?

# Check what actually landed on agent-b.
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^df2m-' | head -n1" | tr -d '\r\n')
DST=""
DST_SIZE=0
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" 2>/dev/null | awk '{print $1}')
    DST_SIZE=$($DC exec -T agent-b stat -c%s "/root/.pilot/received/$RECV" 2>/dev/null | tr -d '\r\n')
fi

# Acceptable outcomes:
#   (a) sender returned non-zero, no/empty/truncated recv file
#   (b) sender got success AND file is intact (disk wasn't as full as
#       we thought — fail the test as setup invalid, see below)
#   Forbidden: sender success but recv truncated silently (data corruption)

SENDER_OK=""
echo "$SF" | jq -e '.status == "ok"' >/dev/null 2>&1 && SENDER_OK="yes"

if [ -z "$SENDER_OK" ] || [ "$SF_RC" -ne 0 ]; then
    log_pass "send-file returned error (rc=$SF_RC) as expected on full disk"
elif [ "$DST" = "$SRC" ] && [ -n "$DST" ]; then
    # sender claimed ok and bytes match — the ballast must have been
    # defeated. Treat as inconclusive.
    log_fail "inconclusive: sender OK and file intact; ballast did not fill disk"
else
    # WORST case: sender claimed ok but receiver truncated.
    log_fail "CORRUPTION: sender ok but dst size=$DST_SIZE sha=${DST:0:12}..."
fi

# ----- 3. Receiver daemon still alive --------------
log_test "agent-b daemon still responsive"
if $DC exec -T agent-b pilotctl daemon status --check >/dev/null 2>&1; then
    log_pass "daemon responsive"
else
    log_fail "daemon hung after disk-full"
fi

# ----- 4. Nothing the receiver kept claims to be 'complete' ---
# Any residual partial should be deleted or zero-length, not reported
# as a successful delivery.
log_test "no partial file kept as complete"
if [ -n "$RECV" ] && [ "$DST_SIZE" -gt 0 ] && [ "$DST_SIZE" -lt 2097152 ] && [ "$DST" != "$SRC" ]; then
    log_fail "truncated file left on disk: name=$RECV size=$DST_SIZE"
else
    log_pass "no stale partial file"
fi

# ----- 5. After freeing space, a subsequent send works ---
log_test "free space and send small file successfully"
$DC exec -T agent-b rm -f /root/.pilot/received/__ballast.bin >/dev/null 2>&1
# and any truncated file
[ -n "$RECV" ] && $DC exec -T agent-b rm -f "/root/.pilot/received/$RECV" >/dev/null 2>&1
sleep 1
$DC exec -T agent-a bash -c 'head -c 2048 /dev/urandom >/tmp/dfok.dat'
SRC2=$($DC exec -T agent-a sha256sum /tmp/dfok.dat | awk '{print $1}')
$DC exec -T agent-a timeout 20 pilotctl --json send-file agent-b /tmp/dfok.dat >/tmp/dfok_sf.out 2>&1
RECV2=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^dfok-' | head -n1" | tr -d '\r\n')
DST2=""
[ -n "$RECV2" ] && DST2=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV2" | awk '{print $1}')
if [ "$SRC2" = "$DST2" ] && [ -n "$DST2" ]; then
    log_pass "post-recovery send ok"
else
    log_fail "post-recovery send failed: src=${SRC2:0:12}... dst=${DST2:0:12}..."
fi

log_test "no panic/fatal in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
