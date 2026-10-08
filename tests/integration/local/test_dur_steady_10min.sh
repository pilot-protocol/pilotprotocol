#!/bin/bash
# Duration: steady 10 msg/s for 10 min, mem/fd stability.
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
# PILOT_DUR_COMPRESS=1 shrinks to 60s for the fast tier; nightly gets the full 10min.
if [ "${PILOT_DUR_COMPRESS:-0}" = "1" ]; then
    DUR=60   # 1 min compressed
else
    DUR=600  # 10 min
fi
RATE=10   # msg/s

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: steady ${RATE} msg/s x ${DUR}s"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

snapshot() {
    $DC exec -T agent-a bash -c '
        pid=$(pgrep -f "pilot-daemon" | head -n1)
        if [ -z "$pid" ]; then echo "0 0"; exit 0; fi
        rss=$(awk "/^VmRSS:/{print \$2}" /proc/$pid/status 2>/dev/null)
        fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        echo "${rss:-0} ${fds:-0}"
    '
}

log_test "T=0 snapshot (agent-a)"
T0=$(snapshot)
RSS0=$(echo "$T0" | awk '{print $1}')
FD0=$(echo "$T0" | awk '{print $2}')
log_pass "T0: rss=${RSS0}KiB fds=${FD0}"

# Start steady load.
SLEEP_S=$(awk "BEGIN{print 1.0/$RATE}")
log_test "start steady send loop ${RATE}/s for ${DUR}s"
$DC exec -d agent-a bash -c "
    rm -f /tmp/steady.log
    end=\$((\$(date +%s) + $DUR))
    sent=0
    # Send synchronously — backgrounding spawns thousands of pilotctl
    # processes which warps the RSS / fd snapshot the assertion is
    # checking. Synchronous loop self-throttles and gives a fair signal.
    while [ \$(date +%s) -lt \$end ]; do
        pilotctl send-message agent-b --data 'steady' --type text >/dev/null 2>&1 || true
        sent=\$((sent+1))
        sleep $SLEEP_S
    done
    echo \"SENT=\$sent\" >/tmp/steady.log
"

# Sleep through load.
sleep $((DUR + 5))

log_test "T=end snapshot (agent-a)"
T1=$(snapshot)
RSS1=$(echo "$T1" | awk '{print $1}')
FD1=$(echo "$T1" | awk '{print $2}')
log_pass "T1: rss=${RSS1}KiB fds=${FD1}"

DRSS=$((RSS1 - RSS0))
DFD=$((FD1 - FD0))
echo "    delta: rss=${DRSS}KiB fds=${DFD}"

log_test "rss delta < 100 MiB over 10 min of load"
if [ "$DRSS" -lt 102400 ]; then
    log_pass "rss delta ${DRSS}KiB within budget"
else
    log_fail "rss delta ${DRSS}KiB exceeds budget"
fi

log_test "fd delta < 50"
if [ "$DFD" -lt 50 ] && [ "$DFD" -gt -50 ]; then
    log_pass "fd delta ${DFD} within budget"
else
    log_fail "fd delta ${DFD} exceeds ±50"
fi

log_test "expected send volume reached"
SENT=$($DC exec -T agent-a bash -c "awk -F= '/^SENT/{print \$2}' /tmp/steady.log 2>/dev/null" | tr -d ' \r\n')
EXPECTED=$((DUR * RATE))
# Target is nominal RATE msg/s, but pilotctl CLI per-call overhead
# (daemon IPC + dial + send + return) makes 10 msg/s aspirational on
# constrained hosts — standalone the loop sustains ~6/s, but under
# run-all.sh parallelism (9 other tests competing for Docker), rate
# drops to ~3.5/s. This test is about leak detection across sustained
# load, not raw throughput, so accept a very loose floor (25%) as
# "load was actually applied". Real throughput is covered by
# test_stress_edge.
MIN=$((EXPECTED * 25 / 100))
if [ "${SENT:-0}" -ge "$MIN" ]; then
    log_pass "sent=$SENT (>=25% of $EXPECTED target — load applied)"
else
    log_fail "sent=$SENT much less than target $EXPECTED (load didn't run)"
fi

log_test "no panics / leaks in logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected|goroutine leak" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
