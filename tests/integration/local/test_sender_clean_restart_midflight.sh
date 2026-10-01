#!/bin/bash
# CLEAN restart (docker compose restart, SIGTERM+grace) of agent-a.
# Unlike SIGKILL, this gives the daemon a chance to flush + close
# connections. Post-restart:
#   - agent-a re-registers and rebuilds tunnel
#   - fresh send-file works (tunnel came back cleanly)

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Clean restart of agent-a mid-flight"
echo "=========================================="

cleanup() {
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

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# ----- restart agent-a cleanly ------
log_test "restart agent-a cleanly"
$DC restart agent-a >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "agent-a re-registered post-restart"
else
    log_fail "agent-a did not re-register"
    exit 1
fi

# warm tunnel after restart
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# ----- fresh send-file -----
log_test "fresh send-file post-restart"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/clean.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/clean.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/clean.dat >/tmp/clean_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^clean-' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "file sha match post-restart"
else
    log_fail "file mismatch post-restart"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
