#!/bin/bash
# Matrix 2 F-series: same identity re-registers from a new endpoint.
#
# Scenario: agent-b is restarted with a different -endpoint value.
# The registry must supersede the previous endpoint in agent-b's
# record (same node_id since identity.json is preserved, new UDP
# endpoint). Stale entry at the old endpoint must be pruned.

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

echo "=========================================="
echo "Identity re-register with new endpoint"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "agents up"

NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id')
[ -n "$NID_B" ] || { log_fail "could not read b's node_id"; exit 1; }

# Capture the original endpoint b registered at.
LU1=$($DC exec -T agent-a pilotctl --json lookup "$NID_B" 2>/dev/null)
EP1=$(echo "$LU1" | jq -r '.data.node.endpoint // .data.endpoint // empty')
[ -n "$EP1" ] || { log_fail "could not read agent-b endpoint from lookup"; exit 1; }
log_pass "initial endpoint: $EP1"

# Replace agent-b's daemon in-place (don't compose-stop the container,
# since that may garbage-collect it on some Docker setups). The
# existing container has the identity file at /root/.pilot/identity.json
# which we want to preserve so node_id stays stable.
log_test "replace agent-b daemon in-place with -listen :4001"
PFX="${PILOT_SUBNET_PREFIX:-172.29.0}"
$DC exec -T agent-b bash -c '
    pkill -f pilot-daemon 2>/dev/null || true
    sleep 1
    rm -f /tmp/pilot.sock
' >/dev/null 2>&1

$DC exec -d agent-b bash -c "
    pilot-daemon \
        -registry ${PFX}.10:9000 \
        -beacon ${PFX}.10:9001 \
        -hostname agent-b \
        -identity /root/.pilot/identity.json \
        -email agent-b@p2p.test \
        -endpoint ${PFX}.21:4001 \
        -listen :4001 \
        -public \
        -keepalive 5s \
        -log-level info \
        >/tmp/daemon-new.log 2>&1
"

# Wait for the new daemon to register.
for _ in $(seq 1 60); do
    LU2=$($DC exec -T agent-a pilotctl --json lookup "$NID_B" 2>/dev/null)
    EP2=$(echo "$LU2" | jq -r '.data.node.endpoint // .data.endpoint // empty')
    if [ -n "$EP2" ] && [ "$EP2" != "$EP1" ]; then break; fi
    sleep 1
done
log_pass "new endpoint seen in registry: $EP2"

log_test "registry entry superseded: new endpoint reflects :4001"
if echo "$EP2" | grep -q ":4001$"; then
    log_pass "endpoint updated to $EP2"
else
    log_fail "endpoint still $EP2 (expected suffix :4001, was $EP1)"
fi

log_test "node_id remains the same (same identity)"
NID_B2=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id')
if [ "$NID_B2" = "$NID_B" ]; then
    log_pass "node_id preserved: $NID_B"
else
    log_fail "node_id changed: $NID_B -> $NID_B2"
fi

log_test "only one registry entry for this identity (no stale duplicate)"
STATS=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null)
TOTAL=$(echo "$STATS" | jq -r '.total_nodes // 0')
if [ "$TOTAL" = "2" ]; then
    log_pass "registry has exactly 2 nodes (a + b)"
else
    log_fail "registry has $TOTAL nodes — stale duplicate suspected"
fi

log_test "agent-a can still reach agent-b at the new endpoint"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
    log_pass "ping ok to new endpoint"
else
    log_fail "ping failed after endpoint change — a may be caching old endpoint"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
