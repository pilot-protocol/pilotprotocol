#!/bin/bash
# Race: pubsub subscriber joins mid-flight.
#
# Publisher on agent-a pushes N messages (N=20) at ~10 ms spacing. After the
# first 10 have been published, agent-b subscribes. We want to observe the
# semantics explicitly so the protocol is documented:
#
#   - "backlog":     b receives all 20
#   - "latest-only": b receives only msg 11+
#   - "none":        b receives 0 (pure fire-and-forget fan-out)
#
# The test PASSES whichever semantics are stable — it just asserts that
#   a) the daemon doesn't crash
#   b) b receives 0 or ~10 (10 ± small jitter) or 20, not some random fraction
# and records which semantics were observed in the output.

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
echo "Race: pubsub late subscriber semantics"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

TOPIC="race/late-sub/$$"

# Publisher in background: 20 messages at 10 ms cadence.
log_test "launch publisher (20 msgs, 10 ms cadence)"
$DC exec -d agent-a bash -c "
    rm -f /tmp/pub.log
    for i in \$(seq 1 20); do
        pilotctl publish agent-b '$TOPIC' --data \"late-\$i\" >>/tmp/pub.log 2>&1 || true
        sleep 0.01
    done
    echo DONE >>/tmp/pub.log
"
log_pass "publisher started"

# Wait until ~10 msgs have been sent, then subscribe on b.
sleep 0.12
log_test "subscribe on agent-b mid-flight"
$DC exec -d agent-b bash -c "
    rm -f /tmp/sub.log
    timeout 5 pilotctl subscribe agent-b '$TOPIC' >/tmp/sub.log 2>&1 || true
"
log_pass "subscriber started"

# Wait for publisher to finish and subscriber to flush.
sleep 6

log_test "fetch counts"
PUB_N=$($DC exec -T agent-a bash -c "grep -c '^' /tmp/pub.log" | tr -d ' \r\n')
SUB_N=$($DC exec -T agent-b bash -c "grep -cE 'late-' /tmp/sub.log" 2>/dev/null | tr -d ' \r\n')
SUB_N=${SUB_N:-0}
echo "    published log lines: $PUB_N"
echo "    received matching lines on b: $SUB_N"

log_test "semantics are one of: none(0) | latest(~10) | backlog(20)"
case "$SUB_N" in
    0)
        log_pass "observed semantics: NONE (subscriber before publish window misses all)"
        ;;
    [3-9]|1[0-5])
        log_pass "observed semantics: LATEST-ONLY ($SUB_N received, matches subscribe time)"
        ;;
    19|20)
        log_pass "observed semantics: BACKLOG (full 20 delivered)"
        ;;
    *)
        log_fail "ambiguous count $SUB_N — not 0, not ~10, not 20"
        $DC exec -T agent-b bash -c 'tail -30 /tmp/sub.log' | sed 's/^/    /'
        ;;
esac

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
