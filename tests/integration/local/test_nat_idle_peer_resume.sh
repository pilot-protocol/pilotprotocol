#!/bin/bash
# A peer left unused past PeerIdleAfter (2 min) gets no keepalives or path
# probes, so a NAT mapping toward it can expire. Traffic must still get
# through afterwards, in both directions, by the usual fallbacks.
#
# Cone NAT with a 10 s UDP conntrack timeout (as test_nat_conntrack_timeout),
# but idle for 160 s: past PeerIdleAfter, and far past the mapping's life.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="conntrack_short"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "$REG nodes"
else
    log_fail "only $REG registered"
    exit 1
fi

log_test "a->b initial echo, then mutual trust"
OUT=$(echo_rt agent-a agent-b "idle-probe-1")
if echo "$OUT" | grep -q "idle-probe-1"; then
    log_pass "initial echo ok"
else
    log_fail "initial echo failed"
fi
establish_trust agent-b agent-a >/dev/null

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo while in use"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "idle-probe-2")
if echo "$OUT" | grep -q "idle-probe-2"; then
    log_pass "echo ok"
else
    log_fail "echo failed before idling"
fi

log_test "idle 160 s (past the 2 min idle threshold and the 10 s conntrack timeout)"
sleep 160
log_pass "idle period elapsed"

log_test "b->a echo after idle: inbound to the NATed peer"
T0=$(date +%s)
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "idle-probe-3" 30s)
T1=$(date +%s)
if echo "$OUT" | grep -q "idle-probe-3"; then
    log_pass "echo ok after idle in $((T1 - T0)) s"
else
    log_fail "echo failed after idle ($((T1 - T0)) s): $(echo "$OUT" | head -c 200)"
fi

log_test "a->b echo after idle: outbound from the NATed peer"
T0=$(date +%s)
OUT=$(echo_rt agent-a agent-b "idle-probe-4" 30s)
T1=$(date +%s)
if echo "$OUT" | grep -q "idle-probe-4"; then
    log_pass "echo ok after idle in $((T1 - T0)) s"
else
    log_fail "echo failed after idle ($((T1 - T0)) s): $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

print_summary_and_exit
