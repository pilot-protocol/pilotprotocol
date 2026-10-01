#!/bin/bash
# Race: lookup fires slightly before register completes.
#
# We stop agent-b, then the runner fires a tight loop of `pilotctl lookup`
# (by known node_id) while simultaneously starting agent-b. Under race, the
# first few lookups should cleanly report "not found" and later ones should
# observe the registration. A buggy implementation might:
#   - report stale (pre-restart) endpoint
#   - return a half-written record (invalid JSON)
#   - deadlock the TCP registry conn under interleaved lookup/register

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
echo "Race: lookup vs register"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

B_NID=$($DC exec -T agent-b pilotctl --json info | jq -r '.data.node_id')
if [ -z "$B_NID" ] || [ "$B_NID" = "0" ]; then
    log_fail "could not read agent-b node_id"
    exit 1
fi
log_pass "agent-b node_id=$B_NID"

# Stop agent-b.
log_test "stop agent-b (registry TTL will age out the entry shortly)"
$DC stop agent-b >/dev/null 2>&1
# Clear agent-b from rendezvous to make the race meaningful (fresh register
# after short downtime); we simulate by simply bouncing.
sleep 2
log_pass "agent-b stopped"

# Launch a hammer lookup loop on agent-a.
log_test "launch 200 back-to-back lookups on agent-a"
$DC exec -d agent-a bash -c "
    rm -f /tmp/lookups.log
    for i in \$(seq 1 200); do
        pilotctl --json lookup $B_NID >>/tmp/lookups.log 2>&1
        echo >>/tmp/lookups.log
        sleep 0.01
    done
    echo LU_DONE >>/tmp/lookups.log
"

# After a short delay start agent-b again, creating the race window.
sleep 0.05
log_test "start agent-b during hammer"
$DC start agent-b >/dev/null 2>&1

# Wait for hammer loop to finish.
sleep 5

log_test "all lookup responses are valid JSON (no half-written record)"
BAD=$($DC exec -T agent-a bash -c '
    bad=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [ "$line" = "LU_DONE" ] && continue
        # lookup may return a human status line OR JSON; accept both but
        # flag if a JSON-starting line fails to parse.
        if echo "$line" | grep -q "^{"; then
            echo "$line" | jq -e . >/dev/null 2>&1 || bad=$((bad+1))
        fi
    done </tmp/lookups.log
    echo $bad
' | tr -d ' \r\n')
if [ "${BAD:-0}" = "0" ]; then
    log_pass "no malformed JSON lookup responses"
else
    log_fail "$BAD malformed JSON responses"
fi

log_test "eventually lookups observe the re-registered endpoint"
# Wait for agent-b to be fully ready again, then issue one final lookup.
for _ in $(seq 1 30); do
    NID=$($DC exec -T agent-b bash -c 'pilotctl --json info 2>/dev/null' | jq -r '.data.node_id // empty' 2>/dev/null)
    [ -n "$NID" ] && [ "$NID" != "0" ] && break
    sleep 0.5
done
FINAL=$($DC exec -T agent-a pilotctl --json lookup "$B_NID" 2>/dev/null)
EP=$(echo "$FINAL" | jq -r '.data.endpoint // .data.address // ""')
if [ -n "$EP" ] && [ "$EP" != "null" ]; then
    log_pass "post-restart lookup resolves: endpoint='$EP'"
else
    log_fail "post-restart lookup empty: $FINAL"
fi

log_test "no panics / races in daemon or rendezvous logs"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
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
