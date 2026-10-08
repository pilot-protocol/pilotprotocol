#!/bin/bash
# Network emulation smoke test: 30% packet loss on agent-b's interface.
#
# Spins up the chaos-augmented topology (NET_ADMIN-capable agents),
# applies `tc qdisc ... netem loss 30%` on agent-b's eth0, then drives
# real traffic (send-file) from a to b. Baseline expectation: the
# protocol's retransmit + reordering recovers. Loss drops are asymmetric
# (only affects ingress to agent-b) so key-exchange handshakes get
# stressed too.
#
# Targets:
#   - confirm NET_ADMIN + iproute2 are present and functional in the
#     agent containers (fail-fast if not — most chaos suite depends on it)
#   - demonstrate the tc netem harness works end-to-end, then strip it
#   - show the daemon's existing retransmit layer survives 30% loss on
#     one side of a 2-agent topology
#
# If this test flakes because the protocol genuinely loses data at 30%,
# that IS the finding — log it and move on.

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

echo "=========================================="
echo "Chaos: 30% packet loss on agent-b ingress"
echo "=========================================="

log_test "start stack with NET_ADMIN overlay"
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

# ----- 1. Confirm NET_ADMIN works ---------------------------------
log_test "agent-b has NET_ADMIN + iproute2 (tc qdisc show succeeds)"
if $DC exec -T agent-b tc qdisc show dev eth0 >/dev/null 2>&1; then
    log_pass "tc available"
else
    log_fail "tc qdisc fails — NET_ADMIN missing or iproute2 missing"
    exit 1
fi

# ----- 2. Apply 30% packet loss on agent-b's eth0 ------------------
log_test "apply 30% ingress+egress loss on agent-b eth0"
if $DC exec -T agent-b tc qdisc add dev eth0 root netem loss 30% 2>&1 | grep -qi error; then
    log_fail "tc netem add failed"
    exit 1
fi
QDISC=$($DC exec -T agent-b tc qdisc show dev eth0 2>&1)
if echo "$QDISC" | grep -q "netem.*loss 30%"; then
    log_pass "netem applied: $QDISC"
else
    log_fail "netem qdisc unexpected: $QDISC"
    exit 1
fi

# ----- 3. send-file survives under loss ----------------------------
log_test "send-file 4 KiB completes under 30% loss"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/chaos.dat' >/dev/null 2>&1
SRC_SUM=$($DC exec -T agent-a sha256sum /tmp/chaos.dat | awk '{print $1}')
SF=$($DC exec -T agent-a timeout 45 pilotctl --json send-file agent-b /tmp/chaos.dat 2>&1)
ACK=$(echo "$SF" | jq -r '.data.ack // empty' 2>/dev/null)
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received | grep '^chaos-' | head -n1" | tr -d '\r\n')
DST_SUM=""
if [ -n "$RECV" ]; then
    DST_SUM=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ "$SRC_SUM" = "$DST_SUM" ] && [ -n "$DST_SUM" ]; then
    log_pass "file round-trip intact (ack=$ACK sha=${SRC_SUM:0:12}...)"
else
    log_fail "file loss/mismatch src=${SRC_SUM:0:12}... dst=${DST_SUM:0:12}... ack=$ACK"
fi

# ----- 4. Remove chaos, verify normal restoration ------------------
log_test "strip netem qdisc and verify clean traffic again"
$DC exec -T agent-b tc qdisc del dev eth0 root >/dev/null 2>&1
QDISC_POST=$($DC exec -T agent-b tc qdisc show dev eth0 2>&1)
if echo "$QDISC_POST" | grep -q "netem"; then
    log_fail "netem still present after delete: $QDISC_POST"
else
    log_pass "netem removed cleanly"
fi

# Sanity ping post-chaos
log_test "sanity ping after chaos removed"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-chaos ping ok"
else
    log_fail "post-chaos ping failed"
fi

# ----- 5. No panics in daemon logs ---------------------------------
log_test "no panic/fatal in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Chaos smoke summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
