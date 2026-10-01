#!/bin/bash
# Chaos Matrix 3: install iptables DROP between agent-a and agent-b
# while operations are in flight. Each op must fail CLEANLY (bounded
# timeout, clear error, no deadlock) rather than hang the daemon.
#
# Unlike test_ping_ghost_peer.sh (peer process dead), here the peer is
# fully alive — only the L3 path is blocked. Rendezvous remains
# reachable by both sides so the control plane is not perturbed.

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
echo "Partition a<->b mid-flight (iptables DROP)"
echo "=========================================="

cleanup() {
    # best-effort heal even if script died mid-partition
    B_IP=$(resolve_service_ip agent-b 2>/dev/null)
    A_IP=$(resolve_service_ip agent-a 2>/dev/null)
    [ -n "$B_IP" ] && heal_partition agent-a "$B_IP" 2>/dev/null || true
    [ -n "$A_IP" ] && heal_partition agent-b "$A_IP" 2>/dev/null || true
    strip_chaos agent-a >/dev/null 2>&1
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

# Warm the tunnel so cached state is present when we partition.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

A_IP=$(resolve_service_ip agent-a)
B_IP=$(resolve_service_ip agent-b)
if [ -z "$A_IP" ] || [ -z "$B_IP" ]; then
    log_fail "could not resolve agent IPs (A=$A_IP B=$B_IP)"
    exit 1
fi
log_pass "resolved agent-a=$A_IP agent-b=$B_IP"

log_test "install bidirectional partition a<->b"
apply_partition agent-a "$B_IP"
apply_partition agent-b "$A_IP"
# Sanity: raw UDP drop must kill ping under bounded time.
if $DC exec -T agent-a timeout 4 ping -c 1 -W 2 "$B_IP" >/dev/null 2>&1; then
    log_fail "partition not effective — ICMP still flows"
    exit 1
else
    log_pass "partition is effective"
fi

# ----- ping must fail inside its timeout ----------
log_test "pilotctl ping bounded-fail under partition (--timeout 4s)"
T0=$(date +%s)
$DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 4s >/dev/null 2>&1
RC=$?
T1=$(date +%s)
DT=$((T1 - T0))
if [ "$RC" -ne 0 ] && [ "$DT" -le 10 ]; then
    log_pass "ping failed in ${DT}s under partition (rc=$RC)"
else
    log_fail "ping did not bound: rc=$RC dt=${DT}s"
fi

# ----- send-message must not false-ack ------------
log_test "send-message under partition must not claim delivery"
SM=$($DC exec -T agent-a bash -c 'timeout 10 pilotctl --json send-message agent-b --data "partitioned" --type text' 2>&1)
ACK=$(echo "$SM" | jq -r '.data.ack // empty' 2>/dev/null)
if [ -z "$ACK" ] || [ "$ACK" = "null" ]; then
    log_pass "send-message did not false-ack"
else
    log_fail "send-message claimed delivery: ack=$ACK"
fi

# ----- send-file must fail ------------------------
log_test "send-file under partition — must fail/timeout cleanly"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/part.dat'
T0=$(date +%s)
$DC exec -T agent-a timeout 15 pilotctl --json send-file agent-b /tmp/part.dat >/tmp/part_sf.out 2>&1
T1=$(date +%s)
DT=$((T1 - T0))
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^part-' | head -n1" | tr -d '\r\n')
if [ -z "$RECV" ] && [ "$DT" -le 20 ]; then
    log_pass "send-file did not deliver and terminated in ${DT}s"
else
    log_fail "send-file: recv=$RECV dt=${DT}s (unexpected)"
fi

# ----- pubsub publish must not loop/panic ---------
log_test "publish under partition — must fail bounded, not spin"
T0=$(date +%s)
$DC exec -T agent-a timeout 10 pilotctl publish agent-b sensor/part --data "x=1" >/dev/null 2>&1
T1=$(date +%s)
DT=$((T1 - T0))
if [ "$DT" -le 15 ]; then
    log_pass "publish bounded in ${DT}s"
else
    log_fail "publish hung ${DT}s"
fi

# ----- heal + verify recovery --------------------
log_test "heal partition and ping a->b recovers"
heal_partition agent-a "$B_IP"
heal_partition agent-b "$A_IP"
OK=""
for _ in $(seq 1 30); do
    if $DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 4s >/dev/null 2>&1; then
        OK="yes"
        break
    fi
    sleep 1
done
if [ "$OK" = "yes" ]; then
    log_pass "ping recovered post-heal"
else
    log_fail "ping still fails after heal — state poisoned"
fi

log_test "no panic/fatal in logs during partition"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
