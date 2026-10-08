#!/bin/bash
# Chaos Matrix 3: netem delay 200ms +/-50ms on agent-b eth0 x all ops.
# 200ms is WAN-ish RTT; verifies default timers are not tuned for
# localhost-only. All ops must complete within their natural timeouts
# (possibly with larger caller-supplied timeout).

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
source ./chaos_helpers.sh

echo "=========================================="
echo "Chaos: 200ms delay x all op families"
echo "=========================================="

cleanup() {
    strip_chaos agent-b >/dev/null 2>&1
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

log_test "apply 200ms +/-50ms delay on agent-b eth0"
apply_delay agent-b 200 >/dev/null 2>&1 || { log_fail "netem delay failed"; exit 1; }
log_pass "netem delay applied"

log_test "ping under 200ms delay"
if $DC exec -T agent-a pilotctl ping agent-b --count 4 --timeout 15s >/tmp/cd_ping.txt 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed"
fi

log_test "send-message under delay"
if $DC exec -T agent-a timeout 30 pilotctl --json send-message agent-b --data "delay200" --type text >/dev/null 2>&1; then
    log_pass "send-message ok"
else
    log_fail "send-message failed"
fi

log_test "send-file 16 KiB under 200ms delay"
$DC exec -T agent-a bash -c 'head -c 16384 /dev/urandom >/tmp/dly.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/dly.dat | awk '{print $1}')
$DC exec -T agent-a timeout 90 pilotctl --json send-file agent-b /tmp/dly.dat >/tmp/dly_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^dly-' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "send-file sha match"
else
    log_fail "send-file mismatch src=${SRC:0:12}... dst=${DST:0:12}..."
fi

log_test "pubsub publish under delay"
if $DC exec -T agent-a timeout 20 pilotctl publish agent-b sensor/delay --data "d=200" >/dev/null 2>&1; then
    log_pass "publish ok"
else
    log_fail "publish failed"
fi

log_test 'trust handshake under delay (real CLI: `handshake` + receiver `approve`)'
if $DC exec -T agent-a timeout 20 pilotctl handshake agent-b "chaos-probe" >/dev/null 2>&1; then
    log_pass "handshake ok"
else
    log_fail "handshake failed"
fi

log_test "pilotctl find agent-b (registry lookup) under delay"
RG=$($DC exec -T agent-a timeout 20 pilotctl --json find agent-b 2>&1)
if echo "$RG" | jq -e '.data.address // empty' >/dev/null 2>&1; then
    log_pass "registry lookup ok"
else
    log_fail "registry lookup failed: $(echo "$RG" | head -c 200)"
fi

log_test "strip delay and sanity ping"
strip_chaos agent-b
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-chaos ping ok"
else
    log_fail "post-chaos ping failed"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
