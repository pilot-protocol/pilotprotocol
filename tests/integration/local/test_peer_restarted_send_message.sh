#!/bin/bash
# Matrix 2 F-series: peer restarted, send-message works.
# Mirror of test_peer_restarted_send_file.sh for the send-message path.

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
echo "Peer restarted: send-message still works"
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

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1 || true

log_test "send-message a->b after restart"
TOKEN="pr-msg-$(date +%s%N)"
SM=$($DC exec -T agent-a bash -c "timeout 20 pilotctl --json send-message agent-b --data '$TOKEN' --type text" 2>&1)
RC=$?
if [ "$RC" -eq 0 ] && echo "$SM" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_pass "send-message returned ok"
else
    log_fail "send-message failed rc=$RC: $(echo "$SM" | head -c 300)"
fi

log_test "agent-b inbox contains the token"
sleep 2
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
if echo "$INBOX" | grep -q "$TOKEN"; then
    log_pass "inbox has token"
else
    log_fail "token missing from inbox (message silently dropped)"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
