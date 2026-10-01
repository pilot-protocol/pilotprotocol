#!/bin/bash
# Observability: EncryptOK metric delta.
# Send M files from agent-a to agent-b, then read agent-a's
# pilotctl --json info -> .data.tunnel_encryption_success. Verify the
# counter increased by at least M (one encrypted frame per outbound file
# at minimum; in practice many more since files span multiple frames).
#
# EXPECTED: tunnel_encryption_success_after - before >= M.

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
M_FILES=5

cd "$(dirname "$0")" || exit 1
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

# Warm tunnel.
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1
sleep 2

BEFORE=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_success // 0')
log_test "EncryptOK before = $BEFORE"

log_test "send $M_FILES files a->b"
for i in $(seq 1 "$M_FILES"); do
    $DC exec -T agent-a bash -c "echo 'payload-$i-$(date +%s%N)' > /tmp/m$i.bin && pilotctl send-file agent-b /tmp/m$i.bin" >/dev/null 2>&1 \
        || log_fail "file $i send failed"
done
log_pass "$M_FILES files sent"

sleep 3

AFTER=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.tunnel_encryption_success // 0')
DELTA=$((AFTER - BEFORE))
log_test "EncryptOK after = $AFTER (delta=$DELTA, want >= $M_FILES)"

if [ "$DELTA" -ge "$M_FILES" ]; then
    log_pass "EncryptOK increased by >= M ($DELTA >= $M_FILES)"
else
    log_fail "EncryptOK delta=$DELTA too small for $M_FILES files"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
