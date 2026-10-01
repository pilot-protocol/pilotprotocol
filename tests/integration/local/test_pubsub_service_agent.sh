#!/bin/bash
# Pub/sub service-agent pattern: an event-driven worker subscribes to
# incoming commands and publishes responses back on a reply topic.
#
# Unlike test_pubsub_fanout.sh (which only checks transport fan-out) and
# test_service_agent.sh (inbox request/reply), this test exercises the
# event-stream as a service bus:
#   agent-b subscribes to topic "commands" on its own address, streaming
#   NDJSON events. For every event it receives, it publishes a correlated
#   response to agent-a on topic "results". agent-a runs a bounded
#   subscriber that collects N responses.
#
# Failure modes this catches that other tests don't:
#  - the NDJSON streaming path in cmdSubscribe (count=0) vs the bounded
#    form (count>0)
#  - re-entrancy: the same daemon is both subscriber and publisher in the
#    worker loop
#  - correlation: every published command must produce exactly one matched
#    response (no drops, no dupes)
#  - topic isolation under an active service worker: events on unrelated
#    topics must NOT trigger a response

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
echo "Pub/sub service-agent integration"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# ----- 1. Start the service worker on agent-b -----
# Subscribe to "commands" topic with count=0 + timeout — this streams one
# JSON event per line. For every event, publish a correlated reply to
# agent-a on topic "results".
log_test "start command-processor worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop
    pilotctl --json subscribe agent-b commands --timeout 60s 2>/dev/null | while IFS= read -r line; do
        [ -f /tmp/worker_stop ] && break
        DATA=$(echo "$line" | jq -r ".data // empty" 2>/dev/null)
        if [ -n "$DATA" ]; then
            echo "$(date +%H:%M:%S.%N) worker received: $DATA" >> /tmp/worker.log
            pilotctl publish agent-a results --data "reply:$DATA" >>/tmp/worker.log 2>&1 || true
        fi
    done
    echo "worker exited" >> /tmp/worker.log
'
sleep 3
log_pass "worker launched"

# ----- 2. Start the bounded result collector on agent-a -----
log_test "start result collector on agent-a (expects 5 events)"
$DC exec -d agent-a bash -c '
    pilotctl --json subscribe agent-a results --count 5 --timeout 45s > /tmp/collector.log 2>&1
'
sleep 2
log_pass "collector launched"

# ----- 3. Publish 5 distinct commands to agent-b -----
log_test "agent-a publishes 5 distinct commands"
SENT=0
for i in 1 2 3 4 5; do
    OUT=$($DC exec -T agent-a pilotctl --json publish agent-b commands --data "cmd-$i" 2>&1)
    if echo "$OUT" | jq -e '.status == "ok"' >/dev/null 2>&1; then
        SENT=$((SENT+1))
    fi
done
if [ "$SENT" -eq 5 ]; then
    log_pass "5 commands published"
else
    log_fail "only $SENT/5 publishes succeeded"
fi

# ----- 4. Wait for collector to finish (it has --count 5 --timeout 45s) -----
log_test "collector receives 5 replies within 45s"
COLLECTED=""
for _ in $(seq 1 50); do
    OUT=$($DC exec -T agent-a cat /tmp/collector.log 2>/dev/null)
    EVTS=$(echo "$OUT" | jq -r '.data.events | length' 2>/dev/null)
    TIMEOUT_FLAG=$(echo "$OUT" | jq -r '.data.timeout // false' 2>/dev/null)
    if [ "$EVTS" = "5" ] || [ "$TIMEOUT_FLAG" = "true" ] || [ -n "$EVTS" ] && [ "$EVTS" != "null" ]; then
        COLLECTED="$OUT"
        break
    fi
    sleep 1
done

if [ -z "$COLLECTED" ]; then
    COLLECTED=$($DC exec -T agent-a cat /tmp/collector.log 2>/dev/null)
fi

EVT_COUNT=$(echo "$COLLECTED" | jq -r '.data.events | length' 2>/dev/null)
if [ "$EVT_COUNT" = "5" ]; then
    log_pass "collector got 5 replies"
else
    log_fail "collector got $EVT_COUNT/5 replies (timeout=$(echo "$COLLECTED" | jq -r '.data.timeout // "?"'))"
    echo "$COLLECTED" | head -c 500
    echo
fi

# ----- 5. Verify 1:1 correlation: each cmd-N has a matching reply:cmd-N -----
log_test "each command has a matching reply"
MATCHED=0
for i in 1 2 3 4 5; do
    if echo "$COLLECTED" | jq -e --arg want "reply:cmd-$i" '.data.events[]? | select(.data == $want)' >/dev/null 2>&1; then
        MATCHED=$((MATCHED+1))
    fi
done
if [ "$MATCHED" -eq 5 ]; then
    log_pass "all 5 commands correlated 1:1 with replies"
else
    log_fail "only $MATCHED/5 commands correlated"
fi

# ----- 6. Topic isolation: publish on an unrelated topic, worker does not react -----
# We start a fresh bounded collector with a short timeout and publish to
# "sidechannel" on agent-b. If the worker (subscribed only to "commands")
# misbehaves and reacts to other topics, we'll see a bogus reply surface.
log_test "worker does not react to unrelated topic"
$DC exec -d agent-a bash -c '
    pilotctl --json subscribe agent-a results --count 1 --timeout 5s > /tmp/iso_collector.log 2>&1
'
sleep 1
$DC exec -T agent-a pilotctl --json publish agent-b sidechannel --data "noise-$(date +%s)" >/dev/null 2>&1
sleep 6

ISO=$($DC exec -T agent-a cat /tmp/iso_collector.log 2>/dev/null)
ISO_EVTS=$(echo "$ISO" | jq -r '.data.events | length // 0' 2>/dev/null)
ISO_TIMEOUT=$(echo "$ISO" | jq -r '.data.timeout // false' 2>/dev/null)
if [ "$ISO_EVTS" = "0" ] && [ "$ISO_TIMEOUT" = "true" ]; then
    log_pass "no cross-topic reply (worker stayed on 'commands')"
else
    log_fail "unexpected cross-topic leak (events=$ISO_EVTS timeout=$ISO_TIMEOUT): $(echo "$ISO" | head -c 200)"
fi

# ----- 7. Worker log shows 5 inbound commands processed -----
log_test "worker log shows 5 inbound commands"
WL_COUNT=$($DC exec -T agent-b bash -c "grep -c 'worker received: cmd-' /tmp/worker.log 2>/dev/null" | tr -d '[:space:]')
if [ "$WL_COUNT" = "5" ]; then
    log_pass "worker saw 5 commands in its log"
else
    log_fail "worker log shows $WL_COUNT 'worker received: cmd-' lines (expected 5)"
    $DC exec -T agent-b cat /tmp/worker.log | tail -20
fi

# ----- 8. No panics/fatals in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Stop worker gracefully.
$DC exec -T agent-b bash -c "touch /tmp/worker_stop" >/dev/null 2>&1

echo
echo "=========================================="
echo "Pub/sub service-agent test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
