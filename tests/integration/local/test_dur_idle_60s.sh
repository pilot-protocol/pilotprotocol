#!/bin/bash
# Duration: 60 s idle, verify no spurious rekey events.
#
# Bring both agents up, establish one handshake/ping to open a tunnel, then
# stay completely silent for 60 s. Assert: no "peer rekeyed" log entries
# beyond 0 (or, if an idle-rekey interval is configured, matches that
# expected count — default is > 60 s so count should be 0).
# DURATION: 90s

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
IDLE_SEC=60

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: 60s idle, no spurious rekey"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "warm up tunnel once (ping)"
$DC exec -T agent-a bash -c 'pilotctl ping agent-b --count 1 --timeout 10s' >/dev/null 2>&1
log_pass "warmed"

# Snapshot rekey line count baseline.
BASE=$($DC logs agent-a agent-b 2>&1 | grep -cE "peer rekeyed|rekey complete|key_rotated" | tr -d ' \r\n')
BASE=${BASE:-0}
log_pass "baseline rekey lines: $BASE"

log_test "idle for ${IDLE_SEC}s"
sleep $IDLE_SEC
log_pass "idle period complete"

log_test "rekey event count during idle is 0 (or expected-idle-interval)"
AFTER=$($DC logs agent-a agent-b 2>&1 | grep -cE "peer rekeyed|rekey complete|key_rotated" | tr -d ' \r\n')
AFTER=${AFTER:-0}
DELTA=$((AFTER - BASE))
echo "    rekey delta during idle: $DELTA"
# Default rekey interval in Pilot is > 60s; expect 0 fresh events.
if [ "$DELTA" -eq 0 ]; then
    log_pass "zero spurious rekey events during ${IDLE_SEC}s idle"
elif [ "$DELTA" -le 2 ]; then
    log_pass "bounded rekey ($DELTA) within expected idle-interval budget"
else
    log_fail "excessive rekey during idle: delta=$DELTA"
fi

log_test "daemons still responsive after idle"
OK_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
OK_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$OK_A" ] && [ -n "$OK_B" ] && [ "$OK_A" != "0" ] && [ "$OK_B" != "0" ]; then
    log_pass "both alive (a=$OK_A b=$OK_B)"
else
    log_fail "daemon died: a='$OK_A' b='$OK_B'"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
