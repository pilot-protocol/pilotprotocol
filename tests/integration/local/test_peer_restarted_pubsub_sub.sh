#!/bin/bash
# Matrix 2 F-series: subscriber restarts — does it re-subscribe
# automatically to get future events?
#
# Scenario:
#   1. sub on b subscribes to TOPIC.
#   2. publisher a publishes EVENT1 — b receives it.
#   3. agent-b is restarted.
#   4. After b comes back, a publishes EVENT2.
#   5. ASSERT: b's subscriber (or any re-started subscriber process
#      on b reading the same topic) receives EVENT2. If the daemon
#      persists subscriptions, the original sub process may be
#      replaced by a fresh `subscribe` call after restart.
#
# Note: the spec is silent on whether subscriptions are durable.
# This test is therefore a behavior probe: if subscriptions are
# not durable, b must still be reachable for a fresh subscribe.

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
echo "Peer restart: subscriber re-subscription"
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

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

TOPIC="pr-sub-$(date +%s)"
EV1="pre-restart-$(date +%s%N)"
EV2="post-restart-$(date +%s%N)"

log_test "initial subscribe on b"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 15s > /tmp/pre_sub.log 2>&1"
sleep 2

log_test "publish EVENT1 before restart"
$DC exec -T agent-a pilotctl publish agent-b "$TOPIC" --data "$EV1" >/dev/null 2>&1
sleep 5

if $DC exec -T agent-b cat /tmp/pre_sub.log 2>/dev/null | jq -e --arg p "$EV1" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
    log_pass "EVENT1 received pre-restart"
else
    log_fail "EVENT1 not received — topic plumbing broken before the real test"
fi

log_test "restart agent-b"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "b did not re-register"; exit 1; }
log_pass "agent-b back"

# Re-warm then re-subscribe. If subscription durability existed,
# skipping this would still work; we probe both paths.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1 || true

log_test "re-subscribe after restart"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 15s > /tmp/post_sub.log 2>&1"
sleep 2

log_test "publish EVENT2 after restart"
$DC exec -T agent-a pilotctl publish agent-b "$TOPIC" --data "$EV2" >/dev/null 2>&1
sleep 8

GOT=""
for _ in $(seq 1 10); do
    out=$($DC exec -T agent-b cat /tmp/post_sub.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "$EV2" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        GOT="yes"; break
    fi
    sleep 1
done
if [ "$GOT" = "yes" ]; then
    log_pass "re-subscribed subscriber received EVENT2"
else
    log_fail "EVENT2 not received after restart"
    $DC exec -T agent-b cat /tmp/post_sub.log 2>/dev/null | head -c 400 | sed 's/^/    /'
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
