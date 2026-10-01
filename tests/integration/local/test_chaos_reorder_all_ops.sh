#!/bin/bash
# Chaos Matrix 3: packet reorder 25% 50% on agent-b eth0 x full op
# catalog. tc netem reorder requires a baseline delay to actually
# shuffle packets; apply_reorder() in chaos_helpers.sh adds 10ms for
# that reason.
#
# Ops exercised: ping, send-message, send-file, pubsub, trust, register.

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
echo "Chaos: 25% reorder x all op families"
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

log_test "apply 25% reorder on agent-b eth0"
apply_reorder agent-b 25 >/dev/null 2>&1 || { log_fail "netem reorder failed"; exit 1; }
log_pass "netem reorder applied"

# ping
log_test "ping under reorder"
if $DC exec -T agent-a pilotctl ping agent-b --count 4 --timeout 15s >/dev/null 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed"
fi

# send-message
log_test "send-message under reorder"
if $DC exec -T agent-a timeout 20 pilotctl --json send-message agent-b --data "hello-reorder" --type text >/dev/null 2>&1; then
    log_pass "send-message ok"
else
    log_fail "send-message failed"
fi

# send-file — reorder stress the sequence-gap tracking
log_test "send-file 16 KiB under reorder (sha256)"
$DC exec -T agent-a bash -c 'head -c 16384 /dev/urandom >/tmp/reo.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/reo.dat | awk '{print $1}')
$DC exec -T agent-a timeout 60 pilotctl --json send-file agent-b /tmp/reo.dat >/tmp/reo_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^reo-' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "send-file sha match under reorder"
else
    log_fail "send-file mismatch src=${SRC:0:12}... dst=${DST:0:12}..."
fi

# pubsub
log_test "pubsub publish under reorder"
if $DC exec -T agent-a timeout 15 pilotctl publish agent-b sensor/reorder --data "r=1" >/dev/null 2>&1; then
    log_pass "publish ok"
else
    log_fail "publish failed"
fi

# trust (real CLI: `handshake` + receiver `approve`)
log_test "trust handshake under reorder"
if $DC exec -T agent-a timeout 15 pilotctl handshake agent-b "chaos-probe" >/dev/null 2>&1; then
    log_pass "handshake ok"
else
    log_fail "handshake failed"
fi

# registry lookup (bare `pilotctl register` is anon-reject-path)
log_test "pilotctl find agent-b (registry lookup) under reorder"
RG=$($DC exec -T agent-a timeout 15 pilotctl --json find agent-b 2>&1)
if echo "$RG" | jq -e '.data.address // empty' >/dev/null 2>&1; then
    log_pass "registry lookup ok"
else
    log_fail "registry lookup failed: $(echo "$RG" | head -c 200)"
fi

log_test "strip reorder and sanity-ping"
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
