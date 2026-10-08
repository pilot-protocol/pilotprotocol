#!/bin/bash
# Webhook: file.delivered.
# Configure the sender (agent-a) to POST webhooks to the sink, send a file,
# and assert exactly one POST whose .body.event == "file.delivered" arrives.
#
# EXPECTED: fires once per send-file completed on the sender side.
# NOTE: as of this writing pkg/daemon only emits "file.received" (receiver-side).
# If "file.delivered" is not yet wired on the sender, this test WILL FAIL and
# that failure is the finding.

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

log_test "fresh webhooks stack"
$DC down -v >/dev/null 2>&1
ensure_webhook_sink_ready || { log_fail "webhook-sink never came up"; exit 1; }
$DC up -d agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 $((60 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
if [ "${COUNT:-0}" -lt 2 ]; then log_fail "agents did not register"; exit 1; fi
log_pass "both agents registered"

# Configure the sender's webhook URL.
log_test "configure agent-a webhook -> $SINK/a"
$DC exec -T agent-a pilotctl set-webhook "$SINK/a" >/dev/null 2>&1 \
    && log_pass "webhook set on agent-a" \
    || log_fail "set-webhook failed"

# Wait for sink to be warm.
for _ in $(seq 1 10); do
    $DC exec -T webhook-sink test -f "$LOG" && break
    sleep 1
done

# Snapshot count before.
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"file.delivered\"' $LOG 2>/dev/null; true" | tail -1)

log_test "agent-a sends file to agent-b"
$DC exec -T agent-a bash -c 'echo "payload-$(date +%s)" > /tmp/x.bin && pilotctl send-file agent-b /tmp/x.bin' >/tmp/sf.txt 2>&1 \
    && log_pass "send-file ok" \
    || log_fail "send-file failed"

# Give webhook delivery time (async, with up to 3 retries).
sleep 8

AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"file.delivered\"' $LOG 2>/dev/null; true" | tail -1)
DELTA=$((AFTER - BEFORE))
log_test "exactly one file.delivered webhook (delta=$DELTA)"
if [ "$DELTA" -eq 1 ]; then
    log_pass "file.delivered fired once"
else
    log_fail "expected delta=1 got delta=$DELTA (event likely not wired in pkg/daemon/webhook emit sites)"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
