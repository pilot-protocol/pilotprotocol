#!/bin/bash
# Matrix 2 F-series: force relay, send-message.
# See test_force_relay_send_file.sh for partition rationale.
# P1-010 may cause this to hang; authored per spec.

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
# shellcheck source=chaos_helpers.sh
source ./chaos_helpers.sh

echo "=========================================="
echo "Force relay: send-message"
echo "=========================================="

cleanup() {
    heal_partition agent-a "$IP_B" >/dev/null 2>&1 || true
    heal_partition agent-b "$IP_A" >/dev/null 2>&1 || true
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
log_pass "agents up"

IP_A=$(resolve_service_ip agent-a)
IP_B=$(resolve_service_ip agent-b)
[ -n "$IP_A" ] && [ -n "$IP_B" ] || { log_fail "resolve failed"; exit 1; }

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

log_test "partition direct UDP a<->b"
apply_partition agent-a "$IP_B"
apply_partition agent-b "$IP_A"
log_pass "direct path dropped"

sleep 10  # let relay-probe flip

log_test "send-message via relay"
TOKEN="relay-msg-$(date +%s%N)"
SM=$($DC exec -T agent-a bash -c "timeout 45 pilotctl --json send-message agent-b --data '$TOKEN' --type text" 2>&1)
RC=$?
sleep 3
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
if echo "$INBOX" | grep -q "$TOKEN"; then
    log_pass "message delivered via relay"
else
    log_fail "message not delivered (rc=$RC) — likely P1-010"
    echo "$SM" | head -c 300 | sed 's/^/    /'
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
