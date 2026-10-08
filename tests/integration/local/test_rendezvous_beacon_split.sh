#!/bin/bash
# Chaos Matrix 3: split-service failure — only the BEACON side of
# rendezvous stops answering while the REGISTRY side keeps working.
# Since registry and beacon currently share a container, we simulate
# the split by blocking the beacon's UDP port (9001) on the rendezvous
# container via iptables, leaving the TCP registry port (9000) and the
# dashboard (8080) reachable.
#
# Expected behavior per spec:
#   - registry ops (lookup, register, send-message probe) still
#     succeed
#   - beacon-dependent ops (hole-punch, relay fallback) degrade — but
#     already-established tunnels between public agents keep working
#   - no panic, daemons stay responsive
#
# This explores the "half-dead rendezvous" scenario that plain
# test_rendezvous_restart_midflight.sh doesn't reach.

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
echo "Rendezvous/beacon split — only beacon down"
echo "=========================================="

cleanup() {
    # heal any iptables rules on rendezvous
    $DC exec -T rendezvous bash -c '
        iptables -S INPUT 2>/dev/null | grep -- "--comment pilot-beacon-split" | while read -r line; do
            rule=$(echo "$line" | sed "s/^-A /-D /")
            iptables $rule 2>/dev/null || true
        done
        true
    ' >/dev/null 2>&1 || true
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

# ----- block beacon port only ----
log_test "block UDP/9001 on rendezvous (beacon dies, registry stays)"
$DC exec -T rendezvous iptables -I INPUT -p udp --dport 9001 -m comment --comment pilot-beacon-split -j DROP >/dev/null 2>&1
# Verify: registry still answers
if $DC exec -T agent-a bash -c 'curl -fsS --max-time 3 http://$(getent hosts rendezvous | awk "{print \$1}"):8080/api/public-stats >/dev/null'; then
    log_pass "registry HTTP still reachable"
else
    log_fail "registry HTTP broken too — split did not isolate beacon"
    exit 1
fi

# ----- registry-only lookup still works ----
log_test "pilotctl lookup works (registry-only path)"
if $DC exec -T agent-a pilotctl --json find agent-b >/tmp/lk.txt 2>&1 \
    && jq -e '.data.address // empty' /tmp/lk.txt >/dev/null 2>&1; then
    log_pass "lookup ok without beacon"
else
    log_fail "lookup failed with only beacon down (registry split broken)"
fi

log_test "send-message over existing tunnel succeeds without beacon"
SM=$($DC exec -T agent-a pilotctl --json send-message agent-b "beacon-split" 2>&1)
if echo "$SM" | jq -e '.data.ack // empty' >/dev/null 2>&1 \
    || echo "$SM" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_pass "send-message delivered without beacon"
else
    log_fail "send-message failed without beacon: $(echo "$SM" | head -c 200)"
fi

log_test "agent daemons remain responsive"
if $DC exec -T agent-a pilotctl daemon status --check >/dev/null 2>&1 \
    && $DC exec -T agent-b pilotctl daemon status --check >/dev/null 2>&1; then
    log_pass "both daemons responsive"
else
    log_fail "daemon(s) hung"
fi

log_test "no panic/fatal in logs"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

# ----- remove block, sanity ------
log_test "restore beacon, post-restore ops work"
$DC exec -T rendezvous iptables -D INPUT -p udp --dport 9001 -m comment --comment pilot-beacon-split -j DROP >/dev/null 2>&1 || true
sleep 2
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "post-restore ping ok"
else
    log_fail "post-restore ping failed"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
