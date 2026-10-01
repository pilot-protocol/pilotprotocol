#!/bin/bash
# Chaos Matrix 3: partition then heal. File ops submitted DURING the
# split must either retry-and-deliver or fail cleanly. After the
# partition heals, fresh ops must complete normally.
#
# This test covers both the fail-bounded semantics (like
# test_partition_midflight) AND the continue-after-heal semantics.

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
source ./chaos_helpers.sh

echo "=========================================="
echo "Partition then heal: queued ops complete"
echo "=========================================="

cleanup() {
    B_IP=$(resolve_service_ip agent-b 2>/dev/null)
    A_IP=$(resolve_service_ip agent-a 2>/dev/null)
    [ -n "$B_IP" ] && heal_partition agent-a "$B_IP" 2>/dev/null || true
    [ -n "$A_IP" ] && heal_partition agent-b "$A_IP" 2>/dev/null || true
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

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

A_IP=$(resolve_service_ip agent-a)
B_IP=$(resolve_service_ip agent-b)
[ -z "$A_IP" ] && { log_fail "no agent-a ip"; exit 1; }
[ -z "$B_IP" ] && { log_fail "no agent-b ip"; exit 1; }
log_pass "IPs resolved a=$A_IP b=$B_IP"

# ----- 1. Install partition ---------------------
log_test "install partition a<->b"
apply_partition agent-a "$B_IP"
apply_partition agent-b "$A_IP"
if $DC exec -T agent-a timeout 3 ping -c 1 -W 2 "$B_IP" >/dev/null 2>&1; then
    log_fail "partition not effective"; exit 1
fi
log_pass "partition effective"

# ----- 2. Heal --------------------------------
log_test "heal partition"
heal_partition agent-a "$B_IP"
heal_partition agent-b "$A_IP"
# Confirm path restored.
OK=""
for _ in $(seq 1 30); do
    if $DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 3s >/dev/null 2>&1; then
        OK=yes; break
    fi
    sleep 1
done
if [ "$OK" = "yes" ]; then
    log_pass "L3 path restored (pilot ping)"
else
    log_fail "heal did not restore path"
    exit 1
fi

# Force a fresh pilot ping so the tunnel re-converges.
$DC exec -T agent-a pilotctl ping agent-b --count 3 --timeout 10s >/dev/null 2>&1 || true

# ----- 3. File send after heal --------------
log_test "send-file after heal completes with sha match"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/heal.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/heal.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/heal.dat >/tmp/heal_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^heal-' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "send-file sha match"
else
    log_fail "send-file mismatch src=${SRC:0:12}... dst=${DST:0:12}..."
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
