#!/bin/bash
# Matrix 2 F-series: peer restarted, then sender sends file.
#
# Scenario: agent-b is restarted cleanly (docker compose restart).
# Identity is preserved. Agent-a's cached tunnel state is stale.
# Unlike the mid-rekey tests, this one DOES a warm-up ping (per
# the documented workaround in P1-009). The test's job is to verify
# the basic peer-restart path works end-to-end, bytes intact.

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
echo "Peer restarted: send-file still works"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "agents up"

# Establish initial tunnel
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 \
    || { log_fail "warm-up failed"; exit 1; }

log_test "restart agent-b"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "b did not re-register"; exit 1; }
log_pass "agent-b back"

# Re-warm tunnel after restart (documented P1-009 workaround).
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1 || true

log_test "send-file 64 KiB a->b after restart"
$DC exec -T agent-a bash -c 'head -c 65536 /dev/urandom >/tmp/pr.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/pr.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/pr.dat >/tmp/pr_sf.out 2>&1
RC=$?

RECV=$($DC exec -T agent-b bash -c "ls -1 /root/.pilot/received 2>/dev/null | grep -i 'pr-' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ -n "$DST" ] && [ "$SRC" = "$DST" ]; then
    log_pass "file delivered intact after b restart (rc=$RC)"
elif [ -z "$DST" ]; then
    log_fail "file not delivered after restart (rc=$RC)"
    cat /tmp/pr_sf.out 2>/dev/null | sed 's/^/    /' | head -20
else
    log_fail "sha256 mismatch src=${SRC:0:12} dst=${DST:0:12}"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
