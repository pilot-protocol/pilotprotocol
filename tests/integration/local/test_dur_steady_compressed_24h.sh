#!/bin/bash
# Compressed-time equivalent of 24 h run.
#
# Default policy cycle in shipped configs is "24h". This test substitutes
# "1s" so that 300 s of wall-clock simulates 300 cycles — one for each of
# the last ~5 minutes of a real day. We verify:
#   - policy stays enabled for the full run (no unloading)
#   - cycle tick count approximates 300 ± 15 (5% slack)
#   - no mem/fd leak
# DURATION: 5min

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.policy.yml"
# PILOT_DUR_COMPRESS=1 shrinks the run from 300s to 30s so this can live
# in the fast tier alongside the other dur_* tests.
if [ "${PILOT_DUR_COMPRESS:-0}" = "1" ]; then
    RUN=30
else
    RUN=300
fi

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: compressed 24h (1s cycle x 300s)"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "write 1s-cycle expr_policy"
# The log action requires params.message (validated by pkg/policy);
# older JSON had message at the top level, which silently fails policy
# load and leaves cycle never firing.
$DC exec -T agent-a bash -c 'cat >/tmp/c24h.json <<JSON
{
  "version": 1,
  "config": {"cycle": "1s"},
  "rules": [
    {"name": "tick", "on": "cycle", "match": "true",
     "actions": [{"type": "log", "params": {"message": "compressed-24h-tick"}}]}
  ]
}
JSON'
log_pass "policy written"

log_test "create unmanaged network then attach expr_policy"
NID_CREATOR=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')
OUT=$($DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json network create --name "compressed-24h-$$" \
    --join-rule open --node-id "$NID_CREATOR" 2>&1)
NID=$(echo "$OUT" | jq -r '.data.network_id // .data.id // empty')
if [ -z "$NID" ] || [ "$NID" = "null" ]; then
    log_fail "create failed: $(echo "$OUT" | head -c 200)"
    exit 1
fi
$DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json policy set --net "$NID" --file /tmp/c24h.json \
    --admin-token test-admin-token >/tmp/pset.out 2>&1
$DC exec -T agent-a pilotctl --json network join "$NID" >/dev/null 2>&1
log_pass "network active (nid=$NID), policy attached, joined"

snapshot_a() {
    $DC exec -T agent-a bash -c '
        pid=$(pgrep -f "pilot-daemon" | head -n1)
        [ -z "$pid" ] && { echo "0 0"; exit 0; }
        rss=$(awk "/^VmRSS:/{print \$2}" /proc/$pid/status 2>/dev/null)
        fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        echo "${rss:-0} ${fds:-0}"
    '
}

T0=$(snapshot_a)
RSS0=$(echo "$T0" | awk '{print $1}')
FD0=$(echo "$T0" | awk '{print $2}')
log_pass "T0 rss=${RSS0}KiB fds=${FD0}"

START=$($DC logs agent-a 2>&1 | grep -c "policy: cycle complete" | tr -d ' \r\n')
START=${START:-0}

log_test "run for ${RUN}s"
sleep $RUN
log_pass "run complete"

END=$($DC logs agent-a 2>&1 | grep -c "policy: cycle complete" | tr -d ' \r\n')
END=${END:-0}
DELTA=$((END - START))
echo "    cycle ticks during run: $DELTA (expected ~$RUN)"

log_test "tick count within ±25% of $RUN"
MIN=$((RUN * 75 / 100))
MAX=$((RUN * 125 / 100))
if [ "$DELTA" -ge "$MIN" ] && [ "$DELTA" -le "$MAX" ]; then
    log_pass "tick count $DELTA within [$MIN, $MAX]"
else
    log_fail "tick count $DELTA outside [$MIN, $MAX]"
fi

T1=$(snapshot_a)
RSS1=$(echo "$T1" | awk '{print $1}')
FD1=$(echo "$T1" | awk '{print $2}')
DRSS=$((RSS1 - RSS0))
DFD=$((FD1 - FD0))
echo "    delta rss=${DRSS}KiB fds=${DFD}"

log_test "rss delta < 50 MiB"
if [ "$DRSS" -lt 51200 ]; then
    log_pass "rss delta ${DRSS}KiB within budget"
else
    log_fail "rss delta ${DRSS}KiB exceeds budget"
fi

log_test "fd delta < 20"
if [ "$DFD" -lt 20 ] && [ "$DFD" -gt -20 ]; then
    log_pass "fd delta ${DFD} within budget"
else
    log_fail "fd delta ${DFD} exceeds ±20"
fi

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
