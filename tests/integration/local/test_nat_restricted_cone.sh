#!/bin/bash
# Chunk J — NAT traversal: restricted/port-restricted cone.
#
# Topology: agent-a is behind nat-gw on private-a (198.51.100.0/24);
# rendezvous + agent-b are on public (192.0.2.0/24). The gateway runs
# stock Linux NAT (iptables MASQUERADE) which behaves as a port-
# restricted cone — inbound traffic to agent-a's mapped port is only
# accepted from (ip, port) pairs agent-a has previously contacted.
#
# Expectation: Pilot's beacon hole-punch makes both sides send a probe
# to each other so conntrack on nat-gw admits the peer's return path.
# Once established, agent-b should be able to send a message to agent-a
# and get a round-trip.
#
# Subnets are RFC5737 TEST-NET ranges so Pilot's IsPrivate() filter
# accepts the STUN-discovered gateway IP as the registered endpoint.
#
# EXPECTED:
#   - Both agents register with rendezvous (2 nodes in /api/public-stats).
#   - `pilotctl connect agent-b:7` from agent-a succeeds (echo works).
#   - agent-a's registered endpoint is nat-gw's public IP (not the
#     private 198.51.100.20), confirming STUN saw the NATed endpoint.

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

DC="docker compose -f docker-compose.multi.nat.yml"
export NAT_MODE="cone"

cd "$(dirname "$0")" || exit 1

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "boot NAT overlay (mode=cone)"
$DC down -v >/dev/null 2>&1
if ! $DC up -d --build rendezvous nat-gw agent-a agent-b >/tmp/nat.up.log 2>&1; then
    log_fail "compose up failed"
    tail -30 /tmp/nat.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register through NAT"
REG=""
for _ in $(seq 1 60); do
    REG=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    [ "${REG:-0}" -ge 2 ] && break
    sleep 1
done
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "rendezvous sees $REG nodes"
else
    log_fail "only $REG nodes registered"
    echo "--- nat-gw ---"; $DC logs nat-gw 2>&1 | tail -20 | sed 's/^/    /'
    echo "--- agent-a ---"; $DC logs agent-a 2>&1 | tail -20 | sed 's/^/    /'
    exit 1
fi

log_test "agent-a's registered endpoint is the gateway public IP"
# A NATed node registers as non-public, so its real_addr is not exposed
# via `pilotctl lookup`. The authoritative record is the daemon's own
# "daemon registered" log line, which includes the endpoint STUN saw.
NID_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')
ENDPOINT=$($DC logs agent-a 2>&1 \
    | grep 'daemon registered' \
    | grep -oE 'endpoint=[^ "]+' \
    | tail -n1 \
    | sed -E 's/^endpoint=//')
echo "    agent-a node_id=$NID_A endpoint=$ENDPOINT"
EXPECT_PUB="${NAT_PUB:-192.0.2}.30"
EXPECT_PRV="${NAT_PRV:-198.51.100}."
if echo "$ENDPOINT" | grep -qF "$EXPECT_PUB"; then
    log_pass "endpoint is nat-gw public ip ($ENDPOINT)"
elif echo "$ENDPOINT" | grep -qF "$EXPECT_PRV"; then
    log_fail "endpoint leaks private-a IP: $ENDPOINT (STUN didn't discover NAT mapping)"
elif echo "$ENDPOINT" | grep -qE '^\[::1\]|^127\.0\.0\.1'; then
    log_fail "endpoint fell back to loopback ($ENDPOINT) — STUN failed or reply not forwarded"
else
    log_fail "unexpected endpoint: $ENDPOINT"
fi

log_test "agent-a -> agent-b echo roundtrip via hole-punch"
OUT=$(echo "nat-probe" | timeout 15 $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 10s 2>&1)
if echo "$OUT" | grep -q "nat-probe"; then
    log_pass "echo ok through cone-NAT hole-punch"
else
    log_fail "echo failed: $(echo "$OUT" | head -c 200)"
    echo "--- agent-a logs ---"
    $DC logs agent-a 2>&1 | tail -40 | sed 's/^/    /'
fi

log_test "agent-b -> agent-a direction also works (return hole-punch)"
# Inbound SYNs from a peer that hasn't completed a handshake are
# rejected by Pilot policy ("SYN rejected: untrusted source"). To
# exercise the reverse path we first establish mutual trust via the
# handshake+approve dance, then try the echo. This isolates "did NAT
# traversal work?" from "did trust authorise the SYN?".
AGENT_A_ADDR="0:0000.0000.$(printf %04x "$NID_A")"
NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

# handshake takes either a hostname or pilot address; approve takes
# a raw numeric node_id. A handshake from an untrusted peer arrives
# via relay (direct SYNs get dropped), so it can take 10–30s to show
# up on agent-a. Poll for the pending request before approving,
# otherwise approve would no-op against an empty queue.
echo "    NID_A=$NID_A NID_B=$NID_B (A_ADDR=$AGENT_A_ADDR)"
HS_OUT=$($DC exec -T agent-b pilotctl --json handshake "$AGENT_A_ADDR" "NAT reverse-path test" 2>&1)
echo "    handshake b->a: $HS_OUT" | head -c 300
for _ in $(seq 1 30); do
    if $DC logs agent-a 2>&1 | grep -q "relayed handshake request pending approval.*from_node_id=$NID_B"; then
        break
    fi
    sleep 1
done
AP_OUT=$($DC exec -T agent-a pilotctl --json approve "$NID_B" 2>&1)
echo "    approve a->b: $AP_OUT" | head -c 300
# Give the mutual-trust sync a beat to propagate back to agent-b.
sleep 2

OUT2=$(echo "reverse" | timeout 15 $DC exec -T agent-b pilotctl connect "$AGENT_A_ADDR" 7 --timeout 10s 2>&1)
if echo "$OUT2" | grep -q "reverse"; then
    log_pass "reverse echo ok (trusted + return hole-punch)"
else
    # On a port-restricted cone this CAN still fail if the beacon
    # didn't coordinate a second punch — that would be a real Pilot
    # finding worth investigating.
    log_fail "reverse echo failed: $(echo "$OUT2" | head -c 200)"
fi

log_test "no panics in any agent log"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
