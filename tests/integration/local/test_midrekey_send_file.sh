#!/bin/bash
# Matrix 2 F-series: send-file while a rekey is in flight.
#
# Direct P1-009 regression test. The test forces the tunnel into a
# fresh-key window immediately before a send-file and asserts the
# transfer completes AND the bytes match. This is the exact shape
# that currently wedges in production (see PROBLEM-REGISTRY P1-009):
# cmdTaskSendResults and send-file share the same VirtualConn layer,
# and the first frame through a rekey window can be silently dropped.
#
# Force-rekey technique (no CLI primitive exists — task #146 tracks a
# `pilotctl rotate-key` hot-path wired to tunnel.go's rekey request
# path):
#   - restart agent-b so its tunnel identity state for a is gone; a
#     still holds stale crypto for b
#   - immediately (no warm-up ping, unlike test_task_accepted_*) fire
#     send-file a->b
#   - file must still land with matching sha256

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
echo "Mid-rekey: send-file (P1-009 regression)"
echo "=========================================="

cleanup() {
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

# ----- 1. Warm tunnel (establish keys a<->b) -----
log_test "warm-up ping a->b establishes initial tunnel crypto"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "tunnel warm"
else
    log_fail "warm-up ping failed"; exit 1
fi

# ----- 2. Force a rekey: restart agent-b. This invalidates a's cached
#         crypto because b comes back needing a fresh key exchange.
log_test "restart agent-b to force rekey"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agent-b did not re-register"; exit 1; }
log_pass "agent-b back up, rekey window open"

# ----- 3. Immediately send-file (no warm-up ping on purpose — P1-009)
log_test "send-file 64 KiB a->b immediately during rekey window"
$DC exec -T agent-a bash -c 'head -c 65536 /dev/urandom >/tmp/midrekey.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/midrekey.dat | awk '{print $1}')

# 30s timeout: tunnel has up to ~10s of rekey turbulence; if send-file
# cannot complete within this, that IS the P1-009 finding.
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/midrekey.dat >/tmp/midrekey_sf.out 2>&1
RC=$?

# ----- 4. Verify receiver has the file and bytes match.
log_test "agent-b received file and sha256 matches"
RECV=$($DC exec -T agent-b bash -c "ls -1 /root/.pilot/received 2>/dev/null | grep -i 'midrekey' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ -n "$DST" ] && [ "$SRC" = "$DST" ]; then
    log_pass "sha256 match after mid-rekey send-file (rc=$RC)"
elif [ -z "$DST" ]; then
    log_fail "file not delivered (rc=$RC) — P1-009 regression repro"
    cat /tmp/midrekey_sf.out 2>/dev/null | sed 's/^/    /' | head -20
else
    log_fail "sha256 MISMATCH: src=${SRC:0:12} dst=${DST:0:12}"
fi

# ----- 5. No panic in either agent.
log_test "no panic/fatal in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
