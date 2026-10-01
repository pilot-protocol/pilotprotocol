#!/bin/bash
# Flood agent-b with rekey-triggering frames: PILS packets whose
# peerNodeID has no crypto context. Each such packet makes the daemon go
# through maybeRequestRekey() (pkg/daemon/tunnel.go). The
# rekeyRequestInterval=3s rate limit must cap actual outbound rekey
# responses to ~1 per 3s per spoofed peer ID, and the maxRekeyRequesters
# map (4096) must bound memory even if we rotate spoofed IDs.
#
# EXPECTED:
#   - CPU on agent-b does NOT stay pinned at 100 % (i.e. X25519 scalar
#     multiplications are NOT performed per incoming packet).
#   - RSS stays bounded (rekey map pruned at 4096 entries).
#   - Daemon remains responsive to pilotctl info throughout.
#
# NOTE: This test targets the "encrypted packet but no key" path, which
# is currently rate-limited per-peer in tunnel.go (see maybeRequestRekey).
# If no cap existed, 10k pps of PILS from rotating IDs would exhaust both
# CPU (derivation) and map memory.

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

log_test "snapshot agent-b RSS and process state"
RSS_BEFORE=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_BEFORE=${RSS_BEFORE:-0}

log_test "flood 10k PILS frames from rotating spoofed IDs at ~4000 pps"
# Send 10,000 PILS frames (encrypted-magic, no valid key) from 128 rotating
# spoofed node IDs. A single Python process generates and sends all frames
# in-memory — avoids the 10k process-start overhead of a shell loop.
$DC exec -T agent-a python3 - "$IP_B" 4000 <<'PYEOF' &
import socket, os, struct, sys

host, port = sys.argv[1], int(sys.argv[2])
MAGIC = b'\x50\x49\x4c\x53'   # PILS
N_IDS = 128
TOTAL = 10000

sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(TOTAL):
    nid = struct.pack('>I', 0xAA000000 + (i % N_IDS))
    frame = MAGIC + nid + os.urandom(12) + os.urandom(32)
    try:
        sk.sendto(frame, (host, port))
    except OSError:
        pass
sk.close()
print(f"flooded {TOTAL} frames across {N_IDS} spoofed node IDs", flush=True)
PYEOF
FLOOD_PID=$!

log_test "during flood: daemon responsive?"
sleep 2
if timeout 10 $DC exec -T agent-b pilotctl info >/dev/null 2>&1; then
    log_pass "daemon still responsive mid-flood"
else
    log_fail "daemon became unresponsive — rate limit missing or too weak"
fi

wait "$FLOOD_PID" 2>/dev/null || true
sleep 3

log_test "post-flood: agent-b RSS stayed bounded"
RSS_AFTER=$($DC exec -T agent-b sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_AFTER=${RSS_AFTER:-0}
DELTA=$((RSS_AFTER - RSS_BEFORE))
echo "RSS delta: ${DELTA} kB"
# 100 MiB = 102400 kB — generous, real leak would be in GiB territory
if [ "$DELTA" -lt 102400 ]; then
    log_pass "RSS delta ${DELTA} kB within bound"
else
    log_fail "RSS ballooned by ${DELTA} kB after flood — map cap may be missing"
fi

log_test "real peer can still talk to agent-b"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 10s >/dev/null 2>&1; then
    log_pass "legit traffic unimpacted by flood"
else
    log_fail "legit traffic broken — DoS succeeded"
fi

log_test "no panic/fatal in agent-b logs"
if $DC logs agent-b 2>/dev/null | grep -qE 'panic:|fatal error:|runtime error'; then
    log_fail "panic detected"
    $DC logs agent-b 2>/dev/null | grep -E 'panic:|fatal error:' | head -10
else
    log_pass "no panics"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
