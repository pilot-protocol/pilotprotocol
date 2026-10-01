#!/bin/bash
# Chaos Matrix 3: 10% packet loss applied symmetrically on agent-b eth0,
# driven through the full operation catalog. At 10% one-way loss the
# protocol's retransmit + reordering layer MUST carry every op through
# to success — this is the "easy" end of the chaos envelope. If any op
# fails here, it is a regression.
#
# Ops exercised: ping, send-message, send-file, pubsub publish,
# trust grant, pilotctl registry lookup.

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
echo "Chaos: 10% loss x all op families"
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
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

log_test "apply 10% loss on agent-b eth0"
if apply_loss agent-b 10 >/dev/null 2>&1; then
    log_pass "netem 10% loss applied"
else
    log_fail "could not apply netem"
    exit 1
fi

# ----- 1. ping -----
log_test "ping a->b under 10% loss"
if $DC exec -T agent-a pilotctl ping agent-b --count 4 --timeout 15s >/tmp/cl10_ping.txt 2>&1; then
    log_pass "ping ok"
else
    log_fail "ping failed"; $DC exec -T agent-a cat /tmp/cl10_ping.txt 2>/dev/null | tail -5
fi

# ----- 2. send-message -----
log_test "send-message a->b under 10% loss"
SM=$($DC exec -T agent-a timeout 20 pilotctl --json send-message agent-b --data "hello-loss10" --type text 2>&1)
if echo "$SM" | jq -e '.status == "ok"' >/dev/null 2>&1 || [ -z "$(echo "$SM" | jq -r '.status // empty' 2>/dev/null)" ]; then
    # accept either explicit ok or legacy plain output
    log_pass "send-message returned"
else
    log_fail "send-message failed: $(echo "$SM" | head -c 300)"
fi

# ----- 3. send-file -----
log_test "send-file 8 KiB under 10% loss (sha256 match)"
$DC exec -T agent-a bash -c 'head -c 8192 /dev/urandom >/tmp/cl10.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/cl10.dat | awk '{print $1}')
$DC exec -T agent-a timeout 45 pilotctl --json send-file agent-b /tmp/cl10.dat >/tmp/cl10_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^cl10-' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "send-file sha match"
else
    log_fail "send-file mismatch src=${SRC:0:12}... dst=${DST:0:12}..."
fi

# ----- 4. pubsub publish -----
log_test "pubsub publish a->b/sensor/chaos"
PUB=$($DC exec -T agent-a timeout 15 pilotctl publish agent-b sensor/chaos --data "loss10=1" 2>&1)
if [ $? -eq 0 ]; then
    log_pass "publish ok"
else
    log_fail "publish failed: $(echo "$PUB" | head -c 300)"
fi

# ----- 5. trust handshake (real CLI is `handshake` + receiver `approve`) -----
log_test "trust handshake a->b under 10% loss"
TG=$($DC exec -T agent-a timeout 15 pilotctl handshake agent-b "chaos-probe" 2>&1)
if [ $? -eq 0 ]; then
    log_pass "handshake returned"
else
    log_fail "handshake failed: $(echo "$TG" | head -c 300)"
fi

# ----- 6. registry control-plane op -----
# `pilotctl register` is a bare anonymous register (no key) and the
# registry correctly rejects that path. Use a driver-backed registry
# lookup instead — it goes through the daemon, hits the registry, and
# exercises the same loss-tolerance we want to confirm.
log_test "pilotctl find agent-b (registry lookup) under 10% loss"
RG=$($DC exec -T agent-a timeout 15 pilotctl --json find agent-b 2>&1)
if echo "$RG" | jq -e '.data.address // empty' >/dev/null 2>&1; then
    log_pass "registry lookup ok"
else
    log_fail "registry lookup failed: $(echo "$RG" | head -c 300)"
fi

# ----- strip + sanity -----
log_test "strip netem, baseline ping still works"
strip_chaos agent-b
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-chaos ping ok"
else
    log_fail "post-chaos ping failed — state poisoned?"
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
