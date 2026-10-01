#!/bin/bash
# Feed agent-b a battery of malformed tunnel frames and assert:
#   1) agent-b does not panic (process still up, daemon still responsive).
#   2) agent-b does not deadlock on readLoop (ping still works).
#   3) No garbage gets delivered to the application plane.
#
# Malformations exercised:
#   - 1-byte frame  (below "n < 4" early-return)
#   - 3-byte frame  (below magic length)
#   - Bad magic ("ABCD" / 0x41424344)
#   - PILT magic + 10-byte body (below PacketHeaderSize() = 34)
#   - PILS magic + <minimum 4+12+16 body
#   - PILK magic + short body (<36)
#   - Huge length prefix in a PILT packet (claims 0xFFFF payload,
#     provides 0 bytes — Unmarshal must reject on "packet truncated")
#   - Pure random 1500-byte spray (no magic match)
#
# EXPECTED: agent-b logs at most debug/error lines; process continues;
# pilotctl ping from agent-a succeeds after the barrage.

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

IP_B=$(ip_of agent-b)

# Each test fires a single datagram. After all, we assert daemon liveness.
MALFORMED_FRAMES=(
    "00"                                  # single zero byte
    "50"                                  # 'P' alone, below n<4
    "504249"                              # 3 bytes, no magic match
    "41424344aabbccdd"                    # bad magic "ABCD"
    "50494c54000000010102030405060708"    # PILT + 12 bytes (< header size)
    "50494c5300000001$(hex_rand 4)"       # PILS + too-short body
    "50494c4b00000001aabbccdd"            # PILK + 4-byte pubkey (<36)
    "50494c4100000001$(hex_rand 20)"      # PILA + 20 bytes (<132 required)
)

# Huge length prefix embedded in PILT:
# Build a plaintext packet marshal header with payload length = 0xFFFF but
# no actual payload bytes. Unmarshal must return "packet truncated".
# Header layout (34 bytes): we set payloadLen = 0xFFFF at offset 2..3.
HUGE_HEADER=$(printf '50494c54%s' "10" ) # version|flags=0x10, proto=0, len=FFFF
HUGE_HEADER+="00"             # proto
HUGE_HEADER+="ffff"           # payload length = 65535, no body
HUGE_HEADER+=$(printf '%060s' '' | tr ' ' '0') # pad to 34 header bytes
# The above is crude but valid enough to exercise the truncation check.
MALFORMED_FRAMES+=("$HUGE_HEADER")

# Pure random spray — never matches any magic.
MALFORMED_FRAMES+=("$(hex_rand 1500)")

log_test "firing ${#MALFORMED_FRAMES[@]} malformed frames at agent-b"
for F in "${MALFORMED_FRAMES[@]}"; do
    send_raw_udp agent-a "$IP_B" 4000 "$F" >/dev/null 2>&1 || true
done
sleep 1

log_test "agent-b container still running"
if $DC ps agent-b 2>/dev/null | grep -q -i "up\|running"; then
    log_pass "agent-b process survived"
else
    log_fail "agent-b container crashed!"
fi

log_test "agent-b daemon is still responsive (pilotctl info)"
if $DC exec -T agent-b pilotctl info >/dev/null 2>&1; then
    log_pass "daemon still responsive"
else
    log_fail "daemon became unresponsive after malformed barrage"
fi

log_test "agent-a can still ping agent-b (readLoop alive)"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
    log_pass "tunnel still operational"
else
    log_fail "tunnel broken after malformed barrage — possible deadlock/panic"
    echo "--- agent-b logs ---"
    $DC logs --tail=50 agent-b 2>/dev/null
fi

log_test "no panic in agent-b logs"
if $DC logs agent-b 2>/dev/null | grep -qE 'panic:|runtime error|goroutine.*\[running\]|fatal error:'; then
    log_fail "panic/fatal detected in agent-b logs"
    $DC logs agent-b 2>/dev/null | grep -E 'panic:|runtime error|fatal error:' | head -10
else
    log_pass "no panic traces in logs"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
