#!/bin/bash
# Send a BeaconMsgRelay (0x05) to the rendezvous/beacon service asking it
# to deliver to a destination node ID that has NEVER registered via
# BeaconMsgDiscover. The beacon's relayWorker in pkg/beacon/server.go
# does a 3-tier lookup (local nodes, peer nodes, else drop); tier 3
# MUST be "unknown destination — drop" and NOT "reflect to caller".
#
# The amplification concern: if the beacon blindly forwarded relay
# payloads to the senderID's endpoint (or broadcast), a spoofed-source
# attacker could use the beacon as a UDP amplifier. Spec: beacon requires
# prior discovery registration for the destination to be relayable.
#
# EXPECTED:
#   - beacon.relayNotFound counter increments.
#   - beacon does NOT send an answering datagram to the attacker IP.
#   - beacon logs "relay dest not found".

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

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1
# shellcheck source=sec_helpers.sh
source ./sec_helpers.sh

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if ! wait_for 60 bash -c '
    c=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r ".total_nodes // 0")
    [ "$c" -ge 2 ]
'; then
    log_fail "agents did not register"
    exit 1
fi

BEACON_IP=$(ip_of rendezvous)
BEACON_PORT=9001

log_test "record pre-attack state in beacon logs"
# Use agent-a as the attacker vantage (it's on the same bridge).
# Craft a relay packet: [0x05][senderID=0xBAD1][destID=0xFFFFFFFF][payload]
PAYLOAD=$(hex_rand 32)
FRAME=$(craft_beacon_relay $((0x0000BAD1)) $((0xFFFFFFFF)) "$PAYLOAD")

log_test "fire 20 relay requests at beacon for nonexistent dest"
for _ in $(seq 1 20); do
    send_raw_udp agent-a "$BEACON_IP" "$BEACON_PORT" "$FRAME" >/dev/null 2>&1 || true
done
sleep 2

log_test "beacon logs show 'relay dest not found' (tier-3 drop)"
# relayStatsLoop logs on 60s ticker, but individual drops log immediately
# per pkg/beacon/server.go:406 ("relay dest not found").
LOG=$($DC logs --tail=300 rendezvous 2>/dev/null)
if echo "$LOG" | grep -qE 'relay dest not found'; then
    log_pass "beacon dropped packets with unknown destination"
else
    log_fail "beacon did not emit expected drop log — may be reflecting!"
    echo "$LOG" | tail -30
fi

log_test "attacker (agent-a) receives NO BeaconMsgRelayDeliver reflections"
# Use raw_udp.py capture mode to bind on agent-a:55555 and listen briefly.
# If the beacon amplified, we'd expect it to deliver to our UDP socket
# here (we used our own observed-endpoint in MsgDiscover earlier, so in
# the general case the beacon would know to send to 4000; for this test
# we check that the beacon does NOT deliver anything unexpected).
# We inspect agent-a's logs for any unexpected BeaconMsgRelayDeliver
# handling that would indicate reflection back.
AGENT_A_LOG=$($DC logs --tail=200 agent-a 2>/dev/null)
if echo "$AGENT_A_LOG" | grep -qE 'unexpected relay|unknown beacon message|BeaconMsgRelayDeliver.*0xBAD1'; then
    log_fail "agent-a received reflected relay delivery — amplification path open"
else
    log_pass "no reflection detected at attacker"
fi

log_test "spoofed-source attack: send relay claiming to be a THIRD party"
# Real attack vector: beacon-relay to a registered dest with a spoofed
# senderNodeID pointing at a victim. The beacon delivers MsgRelayDeliver
# to the dest; the dest may then reply back to the SPOOFED src, which
# does not originate from the attacker. This amplifies if (victim's node
# ID) resolves, which only happens if the victim registered — so a
# third-party-to-third-party abuse requires a registered victim. We
# exercise the protection requirement: senderID in a relay is NOT
# validated against source IP at all, so the beacon MUST NOT treat the
# relay as sufficient to update endpoint state about senderID (otherwise
# the attacker can change a victim's apparent endpoint).
NID_A=$(node_id_of agent-a)
NID_B=$(node_id_of agent-b)
if [ -n "$NID_A" ] && [ -n "$NID_B" ]; then
    # Pretend to be agent-a (sender=NID_A) relaying to agent-b (dest=NID_B)
    # but we actually send from agent-b's container pointing back at a
    # fake endpoint. If the beacon rewrites agent-a's endpoint based on
    # this, subsequent real traffic from agent-a would go astray.
    SPOOF_FRAME=$(craft_beacon_relay "$NID_A" "$NID_B" "$(hex_rand 32)")
    send_raw_udp agent-b "$BEACON_IP" "$BEACON_PORT" "$SPOOF_FRAME" >/dev/null 2>&1 || true
    sleep 2

    # Legit traffic from agent-a should still work if beacon kept
    # endpoint state for agent-a bound to its original discover.
    if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
        log_pass "beacon did not overwrite agent-a's endpoint from a relay senderID"
    else
        log_fail "legit traffic broken — beacon trusted relay senderID as endpoint identity"
    fi
else
    log_test "skip spoof-senderID subcase — could not read node IDs"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
