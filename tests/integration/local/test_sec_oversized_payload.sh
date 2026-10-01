#!/bin/bash
# Send a message whose --data payload is ~1 MiB. Input validation at
# pilotctl or at the daemon's send-message boundary must reject the
# payload BEFORE allocating it into the heap, OR the daemon must
# handle the large payload gracefully. The daemon RSS must not
# balloon to gigabytes, and the attempt must either succeed or return a
# clear size-limit error.
#
# EXPECTED:
#   - pilotctl exits non-zero with a size-limit error, OR
#   - pilotctl exits zero and delivers the message (daemon accepts large msgs).
#   - agent-a daemon RSS stays under a sane bound (< 500 MiB delta).
#   - daemon remains responsive to pilotctl info after the attempt.
#
# NOTE: protocol.Packet.Marshal caps payload at 65535 per frame, so the
# transport will never serialize a 1 GiB payload in one shot — but the
# driver / pilotctl path allocates + sends via IPC, which can still OOM
# if no guard exists. This test exposes that gap via send-message.

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
log_pass "both agents registered"

log_test "record baseline agent-a daemon RSS"
RSS_BEFORE=$($DC exec -T agent-a sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_BEFORE=${RSS_BEFORE:-0}
echo "baseline RSS: ${RSS_BEFORE} kB"

log_test "attempt send-message with ~1 MiB data payload"
# Build 1 MiB of ASCII inside agent-a. Timeout in case the daemon enters a
# huge alloc loop. We accept either:
#   (a) pilotctl exits non-zero (size rejected by pilotctl or daemon)
#   (b) pilotctl exits zero (daemon accepted and streamed the message)
# Failure condition: daemon becomes unresponsive or RSS balloons.
$DC exec -T agent-a sh -c '
    big=$(printf "%0.sA" $(seq 1 1048576))
    timeout 30 pilotctl --json send-message agent-b --data "$big" --type text
' >/tmp/ovr_out.txt 2>&1
RC=$?
OUT=$(cat /tmp/ovr_out.txt 2>/dev/null)

if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qiE 'too large|invalid|exceeds|payload.*limit|error'; then
    log_pass "oversized send-message rejected (rc=$RC)"
else
    # Daemon accepted it — that is permissible provided it doesn't OOM.
    log_pass "oversized send-message accepted without error (rc=$RC); checking memory below"
fi

log_test "agent-a daemon still responsive after oversized send-message"
if timeout 10 $DC exec -T agent-a pilotctl info >/dev/null 2>&1; then
    log_pass "daemon responsive"
else
    log_fail "daemon became unresponsive — likely stuck in huge alloc path"
fi

log_test "agent-a daemon RSS stayed bounded (<500 MiB delta)"
RSS_AFTER=$($DC exec -T agent-a sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_AFTER=${RSS_AFTER:-0}
DELTA=$((RSS_AFTER - RSS_BEFORE))
echo "RSS after: ${RSS_AFTER} kB  (delta: ${DELTA} kB)"
# 500 MiB = 512000 kB
if [ "$DELTA" -lt 512000 ]; then
    log_pass "RSS delta ${DELTA} kB within 500 MiB bound"
else
    log_fail "RSS ballooned by ${DELTA} kB — memory guard missing"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
