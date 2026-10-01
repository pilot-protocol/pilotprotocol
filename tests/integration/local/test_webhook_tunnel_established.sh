#!/bin/bash
# Webhook: tunnel.established.
# Configure both sides, warm up the tunnel once with a ping, and assert
# at least one POST per side with .body.event == "tunnel.established".
#
# EXPECTED: fires on each side the first time a tunnel key is installed
# (and again on rekey). IS wired (pkg/daemon/tunnel.go:621,701).

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.webhooks.yml"
SINK="http://webhook-sink:18080"
LOG="/var/log/webhooks.jsonl"

cd "$(dirname "$0")" || exit 1
cleanup() { $DC down -v >/dev/null 2>&1; }
source ./webhook_helpers.sh
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
ensure_webhook_sink_ready || { log_fail "webhook-sink never came up"; exit 1; }
$DC up -d agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 $((60 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

$DC exec -T agent-a pilotctl set-webhook "$SINK/a" >/dev/null 2>&1
$DC exec -T agent-b pilotctl set-webhook "$SINK/b" >/dev/null 2>&1
log_pass "webhooks set"

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"tunnel.established\"' $LOG 2>/dev/null; true" | tail -1)

log_test "agent-a pings agent-b (warms tunnel)"
$DC exec -T agent-a pilotctl ping agent-b --count 3 --timeout 10s >/tmp/ping.txt 2>&1 \
    && log_pass "ping ok" || log_fail "ping failed"

sleep 12

AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"tunnel.established\"' $LOG 2>/dev/null; true" | tail -1)
DELTA=$((AFTER - BEFORE))
log_test "at least 2 tunnel.established webhooks (one per side) (delta=$DELTA)"
if [ "$DELTA" -ge 2 ]; then log_pass "tunnel.established fired on both sides"; else log_fail "expected delta>=2 got $DELTA"; fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
