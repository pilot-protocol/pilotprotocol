#!/bin/bash
# Chaos Matrix 3: clock JUMPS BACKWARDS on agent-b (NTP correction, VM
# suspend/resume, faulty RTC). AEAD nonce / replay-window code must not
# accept "past" sequence numbers as fresh, and deadline code must not
# recompute negative timeouts that fire immediately.
#
# Same environment caveat as test_clock_skew_receiver.sh: requires
# CAP_SYS_TIME (for date -s) OR faketime. SKIPs cleanly when neither
# is available.
#
# What we assert:
#   - daemon survives the jump (no panic/fatal)
#   - replay window does NOT corrupt: fresh frames after rollback are
#     still accepted, OLD frames would still be rejected (we can only
#     approximate this by checking that fresh ops work after rollback)
#   - deadline-sensitive ops still complete

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
log_skip() { echo -e "[$(ts)] ${YELLOW}[SKIP]${NC} $*"; }

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Clock rollback (receiver -120s)"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b bash -c 'date -s "$(date -u)" 2>/dev/null' >/dev/null 2>&1 || true
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

# Warm the tunnel so the rekey state (which uses wall clock in some
# impls) is established pre-rollback.
$DC exec -T agent-a pilotctl ping agent-b --count 3 --timeout 5s >/dev/null 2>&1 || true

# ----- rollback -----
log_test "roll clock back -120s on agent-b"
ORIG=$($DC exec -T agent-b date -u +%s | tr -d '\r\n')
NEW=$((ORIG - 120))
if ! $DC exec -T agent-b bash -c "date -u -s @$NEW" >/dev/null 2>&1; then
    log_skip "clock rollback requires CAP_SYS_TIME; container lacks it"
    echo "Passed: $PASSED  Failed: $FAILED"
    exit 0
fi
APPLIED=$($DC exec -T agent-b date -u +%s | tr -d '\r\n')
DELTA=$((ORIG - APPLIED))
if [ "$DELTA" -ge 100 ]; then
    log_pass "clock rolled back ~${DELTA}s"
else
    log_fail "rollback insufficient (delta=$DELTA)"
    exit 1
fi

# ----- fresh ops must still work -----
log_test "post-rollback send-file still works"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/rb.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/rb.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/rb.dat >/tmp/rb_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^rb-' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "post-rollback send-file sha match"
else
    log_fail "send-file mismatch src=${SRC:0:12}... dst=${DST:0:12}..."
fi

log_test "no panic/fatal after rollback"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
