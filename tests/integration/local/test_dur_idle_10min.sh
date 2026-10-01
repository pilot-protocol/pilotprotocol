#!/bin/bash
# Duration: 10 min idle, memory + fd snapshot at T=0 and T=10min.
# Delta must be below a sane threshold (no idle leak).
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
# PILOT_DUR_COMPRESS=1 shrinks idle from 10min to 60s so the test can run
# in the fast tier. Nightly leaves full 10min for real leak detection.
if [ "${PILOT_DUR_COMPRESS:-0}" = "1" ]; then
    IDLE_SEC=60
else
    IDLE_SEC=600
fi

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: 10 min idle mem/fd delta"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

# Warm up so tunnel state is established.
$DC exec -T agent-a bash -c 'pilotctl ping agent-b --count 1 --timeout 10s' >/dev/null 2>&1

snapshot() {
    # Emit "<rss_kb> <fd_count>" for agent-b daemon.
    $DC exec -T agent-b bash -c '
        pid=$(pgrep -f "pilot-daemon" | head -n1)
        if [ -z "$pid" ]; then echo "0 0"; exit 0; fi
        rss=$(awk "/^VmRSS:/{print \$2}" /proc/$pid/status 2>/dev/null)
        fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        echo "${rss:-0} ${fds:-0}"
    '
}

log_test "T=0 snapshot"
T0=$(snapshot)
RSS0=$(echo "$T0" | awk '{print $1}')
FD0=$(echo "$T0" | awk '{print $2}')
log_pass "T0: rss=${RSS0}KiB fds=${FD0}"

log_test "idle for ${IDLE_SEC}s"
sleep $IDLE_SEC
log_pass "idle done"

log_test "T=end snapshot"
T1=$(snapshot)
RSS1=$(echo "$T1" | awk '{print $1}')
FD1=$(echo "$T1" | awk '{print $2}')
log_pass "T1: rss=${RSS1}KiB fds=${FD1}"

DRSS=$((RSS1 - RSS0))
DFD=$((FD1 - FD0))
echo "    delta: rss=${DRSS}KiB fds=${DFD}"

log_test "rss delta < 20 MiB"
if [ "$DRSS" -lt 20480 ]; then
    log_pass "rss delta ${DRSS}KiB within budget"
else
    log_fail "rss delta ${DRSS}KiB exceeds 20 MiB budget"
fi

log_test "fd delta < 10"
if [ "$DFD" -lt 10 ] && [ "$DFD" -gt -10 ]; then
    log_pass "fd delta ${DFD} within budget"
else
    log_fail "fd delta ${DFD} exceeds ±10"
fi

log_test "no panics over 10 min"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
