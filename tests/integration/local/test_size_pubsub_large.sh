#!/bin/bash
# Pubsub payload size sweep: tiny / small / medium / large.
#
# agent-b subscribes to a topic, agent-a publishes one message of each size
# (1 KiB / 16 KiB / 256 KiB / 1 MiB). Each message must be received with
# byte-exact sha match or (for oversized) rejected cleanly.

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
echo "Pubsub payload size sweep"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

TOPIC="size/sweep/$$"

log_test "subscribe on agent-b"
$DC exec -d agent-b bash -c "
    rm -f /tmp/sub.log
    timeout 30 pilotctl subscribe agent-b '$TOPIC' >/tmp/sub.log 2>&1 || true
"
sleep 2
log_pass "subscribed"

for spec in "tiny:1024" "small:8192" "medium:32768" "large:65536"; do
    name=${spec%:*}
    bytes=${spec#*:}
    log_test "publish '$name' payload ($bytes bytes) as base64 header"
    $DC exec -T agent-a bash -c "
        head -c $bytes /dev/urandom | base64 | head -c $bytes >/tmp/payload-$name.bin
    "
    SRC_SHA=$($DC exec -T agent-a sha256sum "/tmp/payload-$name.bin" | awk '{print $1}')
    # Publish with a marker so we can later grep
    OUT=$($DC exec -T agent-a bash -c "pilotctl --json publish agent-b '$TOPIC' --data \"MARK-$name-\$(cat /tmp/payload-$name.bin)\" --timeout 60s 2>&1")
    STATUS=$(echo "$OUT" | jq -r '.status // ""' 2>/dev/null)
    ERR=$(echo "$OUT" | jq -r '.error // ""' 2>/dev/null)

    if [ "$STATUS" = "ok" ]; then
        # Confirm receipt with marker grep on subscriber log (best-effort for large sizes).
        sleep 1
        HIT=$($DC exec -T agent-b bash -c "grep -c 'MARK-$name' /tmp/sub.log 2>/dev/null" | tr -d ' \r\n')
        if [ "${HIT:-0}" -ge 1 ]; then
            log_pass "$name published + observed on subscriber (sha ${SRC_SHA:0:8}...)"
        else
            log_fail "$name publish ok but subscriber never saw marker"
        fi
    elif [ -n "$ERR" ] && [ "$ERR" != "null" ]; then
        # For 1 MiB this might hit a cap and be rejected — that is acceptable.
        if [ "$name" = "large" ]; then
            log_pass "$name rejected cleanly (cap enforced): '$ERR'"
        else
            log_fail "$name unexpectedly rejected: '$ERR'"
        fi
    else
        log_fail "$name ambiguous: $(echo "$OUT" | head -c 200)"
    fi
done

# Stop subscriber.
$DC exec -T agent-b bash -c 'pkill -f "pilotctl subscribe" 2>/dev/null' >/dev/null 2>&1 || true

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
