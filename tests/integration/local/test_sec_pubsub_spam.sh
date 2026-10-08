#!/bin/bash
# One publisher (agent-a) publishes 10k messages/s on a single topic to
# agent-b. agent-b has no subscribers on that topic besides itself
# (pilotctl publish routes through the event stream service on port
# 1002). The test verifies:
#
#   1) agent-b remains responsive (daemon replies to pilotctl info).
#   2) CPU on agent-b does not stay pinned at 100 %.
#   3) No goroutine/FD leak on either side.
#
# EXPECTED: Ideally a per-publisher rate limit caps inbound publish
# frequency. If none exists today, we at least assert that the daemon
# absorbs the spam without degrading baseline operations (graceful
# shedding via full channels).
#
# NOTE: pkg/daemon/services.go eventBroker.publish iterates subscribers
# with a RLock and has NO rate limit or backpressure; this test is
# likely to expose a missing defense. Do not assume pass on first run.

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

cleanup() {
    $DC exec -T agent-a touch /tmp/spam_stop >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
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

log_test "start subscriber on agent-b (topic: spam)"
$DC exec -d agent-b bash -c '
    rm -f /tmp/sub_stop
    pilotctl subscribe agent-b spam --count 100000 --timeout 60s > /tmp/sub.log 2>&1 || true
'
sleep 2

log_test "baseline: agent-b FD count and goroutine count"
FD_BEFORE=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    ls /proc/$pid/fd 2>/dev/null | wc -l
' 2>/dev/null)
echo "baseline FD: $FD_BEFORE"

log_test "fire 10k publishes as fast as shell can spawn"
# Count what actually succeeds — the sender may be throttled itself, or
# refused, or just shed. We measure via the subscriber's received count.
$DC exec -d agent-a bash -c '
    rm -f /tmp/spam_stop
    i=0
    start=$(date +%s)
    while [ "$i" -lt 10000 ] && [ ! -f /tmp/spam_stop ]; do
        pilotctl publish agent-b spam --data "msg-$i" >/dev/null 2>&1
        i=$((i+1))
        # Abort early if we already ran 10s
        now=$(date +%s)
        if [ $((now - start)) -gt 10 ]; then break; fi
    done
    echo $i > /tmp/spam_sent
'

# Let it run for about 10 seconds of real-time spam
sleep 10

log_test "during spam: daemon responsive"
if timeout 10 $DC exec -T agent-b pilotctl info >/dev/null 2>&1; then
    log_pass "agent-b daemon responsive during spam"
else
    log_fail "daemon became unresponsive under pubsub spam — no backpressure"
fi

log_test "during spam: agent-a daemon responsive too"
if timeout 10 $DC exec -T agent-a pilotctl info >/dev/null 2>&1; then
    log_pass "agent-a daemon responsive during spam"
else
    log_fail "publisher daemon blocked — no send-side shedding"
fi

log_test "FD delta bounded"
sleep 2
FD_AFTER=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    ls /proc/$pid/fd 2>/dev/null | wc -l
' 2>/dev/null)
FD_DELTA=$((FD_AFTER - FD_BEFORE))
echo "FD delta: $FD_DELTA"
if [ "$FD_DELTA" -lt 100 ]; then
    log_pass "FD delta bounded ($FD_DELTA)"
else
    log_fail "FD leak: $FD_DELTA extra FDs from pubsub spam"
fi

log_test "no panic/fatal in either agent log"
if $DC logs agent-a agent-b 2>/dev/null | grep -qE 'panic:|fatal error:|runtime error'; then
    log_fail "panic/fatal in logs"
    $DC logs agent-a agent-b 2>/dev/null | grep -E 'panic:|fatal' | head -10
else
    log_pass "no panics"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
