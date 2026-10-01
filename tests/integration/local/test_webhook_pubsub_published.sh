#!/bin/bash
# Webhook: pubsub.published.
# Configure the publisher (agent-a) to POST webhooks, publish one message,
# assert exactly one .body.event == "pubsub.published" POST.
#
# EXPECTED: fires once per publish. "pubsub.published" IS wired
# (pkg/daemon/services.go:408).

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
source ./webhook_helpers.sh
cleanup() { $DC down -v >/dev/null 2>&1; }
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

# `pubsub.published` fires inside handlePublish on the BROKER side, which
# is the addressee of the publish RPC (agent-b in this test) — not the
# publisher. Webhook must be set on agent-b.
$DC exec -T agent-b pilotctl set-webhook "$SINK/b" >/dev/null 2>&1
log_pass "agent-b webhook set"

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"pubsub.published\"' $LOG 2>/dev/null; true" | tail -1)

log_test "agent-a publishes one event to agent-b on topic 'sensor/wh'"
$DC exec -T agent-a pilotctl publish agent-b sensor/wh --data "v=1" >/tmp/p.txt 2>&1 \
    && log_pass "publish ok" || log_fail "publish failed"

sleep 12

AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"pubsub.published\"' $LOG 2>/dev/null; true" | tail -1)
DELTA=$((AFTER - BEFORE))
log_test "exactly one pubsub.published webhook (delta=$DELTA)"
if [ "$DELTA" -eq 1 ]; then log_pass "pubsub.published fired once"; else log_fail "expected delta=1 got $DELTA"; fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
