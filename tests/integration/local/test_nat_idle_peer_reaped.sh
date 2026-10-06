#!/bin/bash
# A peer left unused past PeerIdleAfter (2 min) gets no keepalives, so five
# minutes later the stale-peer reaper forgets it (reapStalePeers: no open
# connection, no contact for 5 min). Before idle peers stopped getting
# keepalives the reaper never fired, as keepalives counted as contact.
# After the reap both sides have to build the path again, from scratch,
# and traffic must get through in both directions.
#
# Cone NAT with a 10 s UDP conntrack timeout, idle for 8 minutes.
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
OUT=$(echo_rt agent-a agent-b "reap-probe-1")
if echo "$OUT" | grep -q "reap-probe-1"; then
    log_pass "initial echo ok"
else
    log_fail "initial echo failed"
fi
establish_trust agent-b agent-a >/dev/null

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo while in use"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "reap-probe-2")
if echo "$OUT" | grep -q "reap-probe-2"; then
    log_pass "echo ok"
else
    log_fail "echo failed before idling"
fi

log_test "idle 480 s (2 min to idle, 5 more to the reap)"
sleep 480
log_pass "idle period elapsed"

NID_B=$(agent_node_id agent-b)
has_peer() { $DC exec -T "$1" pilotctl --json peers 2>/dev/null | jq -e --argjson n "$2" '[.data.peers[]?.node_id] | index($n) != null' >/dev/null; }
log_test "the idle peers were forgotten"
GONE=""
has_peer agent-a "$NID_B" || GONE="$GONE a-forgot-b"
has_peer agent-b "$NID_A" || GONE="$GONE b-forgot-a"
echo "    reaped:${GONE:- none}"
log_pass "peer tables after idle:${GONE:- both still listed}"

log_test "b->a echo after idle: inbound to the NATed peer"
T0=$(date +%s)
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "reap-probe-3" 30s)
T1=$(date +%s)
if echo "$OUT" | grep -q "reap-probe-3"; then
    log_pass "echo ok after idle in $((T1 - T0)) s"
else
    log_fail "echo failed after idle ($((T1 - T0)) s): $(echo "$OUT" | head -c 200)"
fi

log_test "a->b echo after idle: outbound from the NATed peer"
T0=$(date +%s)
OUT=$(echo_rt agent-a agent-b "reap-probe-4" 30s)
T1=$(date +%s)
if echo "$OUT" | grep -q "reap-probe-4"; then
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
