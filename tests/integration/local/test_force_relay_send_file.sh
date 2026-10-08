#!/bin/bash
# Matrix 2 F-series: force beacon-relay path, send file.
#
# We block direct UDP between agent-a and agent-b (both directions)
# via iptables so their only reachable path is the beacon (rendezvous
# hosts the relay on :9001). File must still arrive.
#
# KNOWN RISK (see PROBLEM-REGISTRY P1-010): the relayProbeLoop bug
# overwrites the direct peer endpoint with the beacon address after
# the first relay packet, causing subsequent "direct probes" to
# silently fan off into the beacon and get dropped. A stuck tunnel
# here is the EXPECTED finding, not a test defect.

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

# Chaos overlay grants NET_ADMIN so iptables works.
DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1
# shellcheck source=chaos_helpers.sh
source ./chaos_helpers.sh

echo "=========================================="
echo "Force beacon-relay path: send-file"
echo "(expected-red if P1-010 still open)"
echo "=========================================="

cleanup() {
    heal_partition agent-a "$IP_B" >/dev/null 2>&1 || true
    heal_partition agent-b "$IP_A" >/dev/null 2>&1 || true
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
log_pass "agents up"

IP_A=$(resolve_service_ip agent-a)
IP_B=$(resolve_service_ip agent-b)
[ -n "$IP_A" ] && [ -n "$IP_B" ] || { log_fail "could not resolve agent IPs"; exit 1; }

# Warm tunnel BEFORE partition so agents discover each other; beacon
# relay still gets exercised once direct is cut.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

log_test "iptables DROP direct UDP a<->b (both directions)"
apply_partition agent-a "$IP_B"
apply_partition agent-b "$IP_A"
log_pass "direct path severed; beacon relay is the only route"

# Give the relay-probe loop time to notice the direct peer is gone
# and flip the tunnel to relay mode.
sleep 10

log_test "send-file 32 KiB via relay path"
$DC exec -T agent-a bash -c 'head -c 32768 /dev/urandom >/tmp/relay.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/relay.dat | awk '{print $1}')
# Big timeout: relay is slower + may wedge on P1-010.
$DC exec -T agent-a timeout 90 pilotctl --json send-file agent-b /tmp/relay.dat >/tmp/relay_sf.out 2>&1
RC=$?
RECV=$($DC exec -T agent-b bash -c "ls -1 /root/.pilot/received 2>/dev/null | grep -i 'relay' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ -n "$DST" ] && [ "$SRC" = "$DST" ]; then
    log_pass "file relayed intact (rc=$RC)"
elif [ -z "$DST" ]; then
    log_fail "file not delivered via relay (rc=$RC) — likely P1-010"
    cat /tmp/relay_sf.out 2>/dev/null | sed 's/^/    /' | head -20
else
    log_fail "CORRUPTION src=${SRC:0:12} dst=${DST:0:12}"
fi

log_test "beacon relay stats show forwarded>0"
STATS=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null)
FWD=$(echo "$STATS" | jq -r '.relay_forwarded // 0')
if [ "$FWD" -gt 0 ] 2>/dev/null; then
    log_pass "beacon forwarded=$FWD"
else
    log_fail "beacon has no relay forwards: $STATS"
fi

log_test "no panic/fatal in logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
