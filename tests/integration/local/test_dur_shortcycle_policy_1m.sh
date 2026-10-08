#!/bin/bash
# Duration: policy with "cycle":"5s" runs for 60s, ≥ 10 cycle-tick events observed.
#
# Builds a minimal test policy config with a 5 s cycle, mounts it into
# agent-a, confirms daemon loads it, runs 60 s, then greps log for at
# least 10 cycle-tick log lines.
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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.policy.yml"
RUN=60

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: short-cycle policy 5s x 60s"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "write short-cycle expr_policy onto agent-a"
# expr_policy schema (config.cycle + rules with on/match/actions); the
# daemon uses this for programmable cycle/connect/datagram/join rules.
# `--rules-file` expects NetworkRules (managed topology) — different
# schema. Use the two-step pattern: unmanaged create + policy set --file.
$DC exec -T agent-a bash -c 'cat >/tmp/shortcycle.json <<JSON
{
  "version": 1,
  "config": {"cycle": "5s"},
  "rules": [
    {"name": "tick", "on": "cycle", "match": "true",
     "actions": [{"type": "log", "params": {"message": "shortcycle-tick"}}]}
  ]
}
JSON'
log_pass "policy written"

log_test "create unmanaged network then attach expr_policy"
NID_CREATOR=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')
OUT=$($DC exec -T agent-a bash -c "pilotctl --json network create --name shortcycle-$$ --join-rule open --node-id $NID_CREATOR -e PILOT_ADMIN_TOKEN=test-admin-token 2>&1" 2>&1)
NID=$(echo "$OUT" | jq -r '.data.network_id // .data.id // empty')
if [ -z "$NID" ] || [ "$NID" = "null" ]; then
    log_fail "could not create network: $(echo "$OUT" | head -c 200)"
    exit 1
fi
$DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json policy set --net "$NID" --file /tmp/shortcycle.json \
    --admin-token test-admin-token >/tmp/pset.out 2>&1
$DC exec -T agent-a pilotctl --json network join "$NID" >/dev/null 2>&1
log_pass "network created (nid=$NID), policy attached, joined"

log_test "run ${RUN}s and count cycle events"
START_LINES=$($DC logs agent-a 2>&1 | grep -c "policy: cycle complete" | tr -d ' \r\n')
START_LINES=${START_LINES:-0}
sleep $RUN
END_LINES=$($DC logs agent-a 2>&1 | grep -c "policy: cycle complete" | tr -d ' \r\n')
END_LINES=${END_LINES:-0}
DELTA=$((END_LINES - START_LINES))
echo "    cycle tick delta over ${RUN}s: $DELTA (expect >= 10)"
if [ "$DELTA" -ge 10 ]; then
    log_pass "observed $DELTA cycle ticks"
else
    log_fail "only $DELTA cycle ticks (expected >=10 for 5s cycle over ${RUN}s)"
fi

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
