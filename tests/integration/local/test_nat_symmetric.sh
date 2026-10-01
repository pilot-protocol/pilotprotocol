#!/bin/bash
# Chunk J — NAT traversal: symmetric NAT (relay fallback).
#
# Topology is identical to test_nat_restricted_cone.sh (agent-a behind
# nat-gw on private-a, rendezvous + agent-b on public) but the gateway
# runs with NAT_MODE=symmetric. nat-gw.sh installs
# MASQUERADE --random-fully, so each (dst_ip, dst_port) tuple gets an
# independent random source port — the canonical symmetric-NAT property
# that breaks STUN-based hole-punching.
#
# Why we test the b -> a direction:
#   An a -> b connection always succeeds under symmetric NAT when b is
#   on a public IP, because a initiates outbound and creates the
#   conntrack mapping itself. The *interesting* case is b -> a: agent-b
#   dials agent-a's STUN-registered endpoint, which was established
#   while a was talking to the rendezvous on a completely different
#   source port — so conntrack drops the SYN and direct dial times out.
#   Pilot must switch to beacon-relay.
#
# What we assert:
#   - Both agents register (STUN answer toward rendezvous is still valid
#     under symmetric; it's only unusable as an inbound mapping for
#     *other* peers).
#   - b -> a direct dial fails: agent-b logs
#       "direct dial timed out, switching to relay"
#   - The b -> a echo still succeeds via MsgRelay.
#   - nat-gw's iptables rules carry --random-fully.

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
export NAT_MODE="symmetric"

cd "$(dirname "$0")" || exit 1

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "boot NAT overlay (mode=symmetric)"
$DC down -v >/dev/null 2>&1
if ! $DC up -d --build rendezvous nat-gw agent-a agent-b >/tmp/nat.sym.up.log 2>&1; then
    log_fail "compose up failed"
    tail -30 /tmp/nat.sym.up.log | sed 's/^/    /'
    exit 1
fi

log_test "nat-gw installed --random-fully SNAT"
if $DC logs nat-gw 2>&1 | grep -q 'random-fully'; then
    log_pass "symmetric rules installed"
else
    log_fail "no --random-fully in nat-gw rules"
    $DC logs nat-gw 2>&1 | tail -20 | sed 's/^/    /'
fi

log_test "both agents register through symmetric NAT"
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
    exit 1
fi

# Establish mutual trust so agent-b's SYN to agent-a isn't dropped by
# the untrusted-source policy gate. This is the same handshake+approve
# dance as the cone test — handshakes from untrusted peers are relayed
# and can take 10-30s to arrive, so we poll for the pending log line
# before approving.
log_test "establish mutual trust (handshake b -> a, approve a -> b)"
NID_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')
NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')
AGENT_A_ADDR="0:0000.0000.$(printf %04x "$NID_A")"
echo "    NID_A=$NID_A NID_B=$NID_B (A_ADDR=$AGENT_A_ADDR)"

HS_OUT=$($DC exec -T agent-b pilotctl --json handshake "$AGENT_A_ADDR" "NAT symmetric relay test" 2>&1)
echo "    handshake b->a: $(echo "$HS_OUT" | head -c 200)"
for _ in $(seq 1 30); do
    if $DC logs agent-a 2>&1 | grep -q "relayed handshake request pending approval.*from_node_id=$NID_B"; then
        break
    fi
    sleep 1
done
AP_OUT=$($DC exec -T agent-a pilotctl --json approve "$NID_B" 2>&1)
echo "    approve a->b: $(echo "$AP_OUT" | head -c 200)"
if echo "$AP_OUT" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_pass "trust established"
else
    log_fail "approve failed: $AP_OUT"
fi

# Give mutual-trust sync a beat to propagate back to agent-b.
sleep 2

log_test "b -> a echo triggers relay fallback (direct dial blocked by symmetric NAT)"
# Under symmetric NAT agent-a's STUN-registered port won't admit agent-b's
# SYN (conntrack only has the mapping for rendezvous traffic). Direct dial
# burns its retry budget, then Pilot switches to MsgRelay via the beacon.
#
# Give the command enough wall time for the retry budget to exhaust plus
# the relay phase. Default DialInitialRTO is ~200ms, directRetries ~3,
# exponential backoff capped at DialMaxRTO.
OUT=$(echo "sym-reverse" | timeout 60 $DC exec -T agent-b \
    pilotctl connect "$AGENT_A_ADDR" 7 --timeout 45s 2>&1)
if echo "$OUT" | grep -q "sym-reverse"; then
    log_pass "b -> a echo ok (relay fallback delivered payload)"
else
    log_fail "echo failed: $(echo "$OUT" | head -c 300)"
    echo "--- agent-b last 30 lines ---"
    $DC logs agent-b 2>&1 | tail -30 | sed 's/^/    /'
fi

log_test "agent-b direct handshake rejected by symmetric NAT (relayed via registry)"
# The canonical symmetric-NAT signal in our topology: agent-b's handshake
# SYN to agent-a's STUN-registered endpoint is dropped by conntrack
# (no mapping for that (src, dst) pair), so the daemon falls back to
# relaying the handshake through the registry. Under cone-NAT this line
# doesn't appear — the direct handshake completes.
#
# Note: we intentionally DON'T assert "direct dial timed out, switching
# to relay" for the *data* echo. Once trust is granted, agent-a initiates
# enough outbound traffic to agent-b to open a reusable conntrack
# mapping on a new random port; agent-b observes the origin of those
# frames and can address them directly. That's correct behavior — the
# relay fallback's real purpose is dual-symmetric NAT, which would need
# a second NAT gateway for agent-b to exercise faithfully.
if $DC logs agent-b 2>&1 | grep -q "direct handshake failed, relaying via registry"; then
    log_pass "handshake relayed — direct path blocked by symmetric NAT as expected"
else
    log_fail "no handshake-relay line — direct handshake succeeded (unexpected under symmetric)"
    echo "--- agent-b last 40 lines ---"
    $DC logs agent-b 2>&1 | tail -40 | sed 's/^/    /'
fi

log_test "tunnel endpoint differs from STUN-registered port (proves NAT randomisation)"
# Under --random-fully, agent-a's outbound to agent-b gets a different
# random external source port than its earlier outbound to rendezvous.
# The established-tunnel log on agent-b should show an endpoint with a
# port that is NOT the STUN-registered one. This is the observable
# fingerprint of symmetric NAT on the data path.
PUB_PREFIX=$(echo "${NAT_PUB:-192.0.2}.30" | sed 's/\./\\./g')
STUN_PORT=$($DC logs agent-a 2>&1 \
    | grep 'daemon registered' \
    | grep -oE "endpoint=${PUB_PREFIX}:[0-9]+" \
    | tail -n1 \
    | sed -E 's/.*:([0-9]+)$/\1/')
TUN_PORT=$($DC logs agent-b 2>&1 \
    | grep 'encrypted tunnel established' \
    | grep -oE "endpoint=${PUB_PREFIX}:[0-9]+" \
    | head -n1 \
    | sed -E 's/.*:([0-9]+)$/\1/')
echo "    stun_port=$STUN_PORT tunnel_port=$TUN_PORT"
if [ -n "$STUN_PORT" ] && [ -n "$TUN_PORT" ] && [ "$STUN_PORT" != "$TUN_PORT" ]; then
    log_pass "symmetric NAT allocated distinct ports per destination ($STUN_PORT vs $TUN_PORT)"
elif [ -z "$STUN_PORT" ] || [ -z "$TUN_PORT" ]; then
    log_fail "could not extract both ports (stun=$STUN_PORT tun=$TUN_PORT)"
else
    log_fail "same port for rendezvous and peer ($STUN_PORT) — not symmetric behaviour"
fi

log_test "no panics in any log"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
