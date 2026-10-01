#!/bin/bash
# Chaos Matrix 3: 30% packet loss x the full op family. 30% is the "hard"
# corner of the envelope; per PROBLEM-REGISTRY P1-010 this reliably
# surfaces the retransmit-gap regression. Per TEST-PLAN the test is
# authored against the spec (every op must either succeed or fail
# cleanly within its own timeout — NEVER silent data loss) so if any
# op sticks, that IS the finding.

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
echo "Chaos: 30% loss x all op families (P1-010)"
echo "=========================================="

cleanup() {
    strip_chaos agent-b >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

log_test "fresh chaos-capable stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

# Warm tunnel BEFORE chaos so keys are established cleanly.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

log_test "apply 30% loss on agent-b eth0"
apply_loss agent-b 30 >/dev/null 2>&1 || { log_fail "could not apply netem"; exit 1; }
log_pass "netem 30% loss applied"

# ----- ping -----
log_test "ping a->b under 30% loss (long timeout)"
if $DC exec -T agent-a pilotctl ping agent-b --count 6 --timeout 30s >/tmp/cl30_ping.txt 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed — retransmit gap"
fi

# ----- send-message -----
log_test "send-message under 30% loss"
SM=$($DC exec -T agent-a timeout 30 pilotctl --json send-message agent-b --data "hello-loss30" --type text 2>&1)
if [ $? -eq 0 ]; then
    log_pass "send-message ok"
else
    log_fail "send-message failed: $(echo "$SM" | head -c 200)"
fi

# ----- send-file -----
log_test "send-file 8 KiB under 30% loss (sha256 match or clean fail)"
$DC exec -T agent-a bash -c 'head -c 8192 /dev/urandom >/tmp/cl30.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/cl30.dat | awk '{print $1}')
$DC exec -T agent-a timeout 120 pilotctl --json send-file agent-b /tmp/cl30.dat >/tmp/cl30_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^cl30-' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ -n "$DST" ] && [ "$SRC" = "$DST" ]; then
    log_pass "send-file sha match under 30% loss"
elif [ -z "$DST" ]; then
    log_fail "send-file did not deliver (possibly known P1-010)"
else
    log_fail "send-file CORRUPTION src=${SRC:0:12}... dst=${DST:0:12}..."
fi

# ----- pubsub publish -----
log_test "pubsub publish under 30% loss"
if $DC exec -T agent-a timeout 30 pilotctl publish agent-b sensor/chaos --data "loss30=1" >/dev/null 2>&1; then
    log_pass "publish ok"
else
    log_fail "publish failed under loss"
fi

# ----- trust handshake (real CLI: `handshake` + receiver `approve`) -----
log_test "trust handshake under 30% loss"
if $DC exec -T agent-a timeout 30 pilotctl handshake agent-b "chaos-probe" >/dev/null 2>&1; then
    log_pass "handshake ok"
else
    log_fail "handshake failed"
fi

# ----- registry lookup (bare `pilotctl register` is anon-reject-path) -----
log_test "pilotctl find agent-b (registry lookup) under 30% loss"
RG=$($DC exec -T agent-a timeout 20 pilotctl --json find agent-b 2>&1)
if echo "$RG" | jq -e '.data.address // empty' >/dev/null 2>&1; then
    log_pass "registry lookup ok"
else
    log_fail "registry lookup failed: $(echo "$RG" | head -c 200)"
fi

# ----- recovery check -----
log_test "strip chaos and verify post-chaos ping works"
strip_chaos agent-b
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-chaos ping ok"
else
    log_fail "post-chaos ping failed"
fi

log_test "no panic/fatal in agent logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
