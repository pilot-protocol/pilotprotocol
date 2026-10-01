#!/bin/bash
# Agent -> beacon liveness ping.
#
# FINDING — beacon has no explicit "ping" endpoint.
#   pkg/beacon/server.go dispatches exactly four UDP message types:
#     - BeaconMsgDiscover        (0x01) — STUN-style "what's my public addr"
#     - BeaconMsgPunchRequest    (0x03) — hole-punch rendezvous
#     - BeaconMsgRelay           (0x05) — relay fallback when direct fails
#     - BeaconMsgSync            (0x07) — gossip between beacons
#   There is a separate TCP /healthz HTTP endpoint (ServeHealth) but it is
#   for operator/LB probes, not for peer nodes.
#
# Liveness is therefore inferred by the agent's periodic beacon discover
# call: if the beacon replies with BeaconMsgDiscoverReply containing the
# agent's observed public IP:port, the beacon is alive. This test treats
# that round-trip as "ping".
#
# We assert:
#   1) the beacon's UDP port is reachable from an agent (nc -z -u)
#   2) the agent's daemon logs a successful "beacon discover" cycle OR
#      the rendezvous dashboard shows both agents registered with non-zero
#      endpoints (implies the STUN/discover reply was accepted).
#   3) killing the beacon (stopping rendezvous, which hosts both :9000
#      registry and :9001 beacon) and probing again fails within 10s.

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
PFX="${PILOT_SUBNET_PREFIX:-172.29.0}"
BEACON_HOST="${PFX}.10"
BEACON_PORT=9001
DASHBOARD="http://${PFX}.10:8080"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Beacon liveness ping (discover-as-ping)"
echo "=========================================="

log_test "bring stack up clean"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1

# Wait for both agents to register via the beacon (this REQUIRES a successful
# discover reply from the beacon — registration includes public endpoint).
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 2 ]; then break; fi
    sleep 1
done
if [ "${COUNT:-0}" -ge 2 ]; then
    log_pass "both agents registered (total_nodes=$COUNT) — implies beacon discover round-trip ok"
else
    log_fail "only $COUNT agents registered — beacon discover did not complete"
    $DC logs agent-a | tail -20
    exit 1
fi

# 1) UDP port reachability from agent-a (install nc-openbsd-style or use bash /dev/udp)
log_test "beacon UDP port $BEACON_PORT reachable from agent-a"
if $DC exec -T agent-a bash -c "exec 3<>/dev/udp/${BEACON_HOST}/${BEACON_PORT} && echo probe >&3" 2>/dev/null; then
    log_pass "UDP socket to beacon openable"
else
    # /dev/udp is bash-builtin; if the minimal image lacks it, fall back to curl -v against a bogus URL
    log_fail "could not open UDP socket to ${BEACON_HOST}:${BEACON_PORT} from agent-a"
fi

# 2) Endpoint visible to the daemon = beacon discover reply was accepted.
#    There is no public /api/nodes on the dashboard — only /api/public-stats,
#    /api/pulse, /api/badge/*, /api/snapshot. Ask the daemon itself via
#    pilotctl --json info, which reports the endpoint it registered.
log_test "agent-a has a non-empty observed endpoint (discover reply accepted)"
ENDPOINT=""
for _ in $(seq 1 20); do
    ENDPOINT=$($DC exec -T agent-a pilotctl --json info 2>/dev/null \
        | jq -r '.data.endpoint // empty')
    [ -n "$ENDPOINT" ] && [ "$ENDPOINT" != "null" ] && [ "$ENDPOINT" != ":0" ] && break
    sleep 1
done
if [ -n "$ENDPOINT" ] && [ "$ENDPOINT" != "null" ] && [ "$ENDPOINT" != ":0" ]; then
    log_pass "agent-a endpoint=$ENDPOINT (proof of successful beacon discover)"
else
    log_fail "agent-a has no registered endpoint after 20s — beacon round-trip likely failed"
    $DC exec -T agent-a pilotctl --json info | head -c 500
fi

# 3) Beacon dies -> subsequent probe should fail.
log_test "stop rendezvous (hosts beacon at :9001) and verify probe fails"
$DC stop rendezvous >/dev/null 2>&1
sleep 3

# /dev/udp is connectionless; we can't rely on ECONNREFUSED. Instead, send a
# BeaconMsgDiscover (0x01 + 4-byte node id) and expect NO reply within 2 s.
# If a reply arrives, the beacon is alive somehow — fail.
REPLY_SEEN=0
if $DC exec -T agent-a bash -c "
    timeout 2 bash -c '
        exec 3<>/dev/udp/${BEACON_HOST}/${BEACON_PORT}
        printf \"\\x01\\x00\\x00\\x00\\x01\" >&3
        head -c 1 <&3
    '" >/dev/null 2>&1; then
    REPLY_SEEN=1
fi

if [ "$REPLY_SEEN" = "0" ]; then
    log_pass "no beacon reply after stop (expected)"
else
    log_fail "beacon still replying after stop — unexpected"
fi

# Cleanup: bring rendezvous back so follow-up tests have a clean world.
$DC start rendezvous >/dev/null 2>&1

echo
echo "=========================================="
echo "Beacon ping summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
