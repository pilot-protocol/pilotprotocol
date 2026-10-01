#!/bin/bash
# Chaos Matrix 3: restart beacon/rendezvous (same container) mid-flight.
# Beacon is port 9001 of the rendezvous container; it drives hole-punch
# and relay. Restart simulates operational maintenance.
#
# Agents must:
#   - survive the beacon outage (existing tunnels keep working)
#   - NOT panic when beacon TCP/UDP endpoints disappear
#   - resume beacon-assisted ops (e.g. re-discover) after beacon back up
#
# Differs from test_rendezvous_restart_midflight.sh — that test stops
# the whole rendezvous container (beacon AND registry). Here we want to
# simulate "only the beacon is sick, registry HTTP still answers" but
# because they are in the same container today, we treat a container
# restart as the best available approximation and document that
# ambiguity.

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
echo "Beacon restart mid-flight"
echo "=========================================="

cleanup() {
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

# Warm the tunnel before the restart so data-plane is cached.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# ----- Restart beacon container ---------------------
log_test "docker compose restart rendezvous (beacon container)"
$DC restart rendezvous >/dev/null 2>&1

# Give the container a moment to come back.
for _ in $(seq 1 60); do
    if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats >/dev/null 2>&1; then break; fi
    sleep 1
done
if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats >/dev/null 2>&1; then
    log_pass "rendezvous+beacon container back online"
else
    log_fail "rendezvous did not come back"
    exit 1
fi

# ----- Both agents must re-register -----
log_test "both agents re-register post-beacon-restart"
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "total_nodes=$COUNT" || log_fail "only $COUNT agents after beacon restart"

# ----- fresh lookup still works (beacon-assisted discovery) ----
log_test "pilotctl lookup works post-beacon-restart"
LK=$($DC exec -T agent-a pilotctl --json find agent-b 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -n "$ADDR" ]; then
    log_pass "lookup ok: $ADDR"
else
    log_fail "lookup empty: $(echo "$LK" | head -c 300)"
fi

log_test "no panic/fatal in agent logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
