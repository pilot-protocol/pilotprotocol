#!/bin/bash
# Chaos Matrix 3: receiver (agent-b) is SIGKILL'd in the middle of a
# large send-file transfer. Assertions per spec:
#   - sender returns a clean error (no false success ack)
#   - no panic on agent-a
#   - after agent-b is restarted, no corrupt partial file is visible
#     in /root/.pilot/received AS IF IT WERE COMPLETE (i.e. the
#     receiver's partial-file tracking is sane)
#   - a fresh send-file after restart completes cleanly with sha match

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
echo "SIGKILL agent-b mid-send-file"
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
log_pass "both agents registered"

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# ----- Build a 4 MiB payload so we have wire time to kill mid-flight ---
log_test "prepare 4 MiB payload on agent-a"
$DC exec -T agent-a bash -c 'head -c 4194304 /dev/urandom >/tmp/midkill.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/midkill.dat | awk '{print $1}')
log_pass "payload ready ($SRC)"

# ----- Kick off send-file in background on agent-a, then kill b ------
log_test "start send-file in background, then SIGKILL agent-b"
$DC exec -d agent-a bash -c 'timeout 60 pilotctl --json send-file agent-b /tmp/midkill.dat >/tmp/sf.out 2>&1; echo "rc=$?" >>/tmp/sf.out'

# Wait briefly for transfer to start.
sleep 2

$DC kill agent-b >/dev/null 2>&1
sleep 1
if $DC ps --status running --services 2>/dev/null | grep -q "^agent-b$"; then
    log_fail "agent-b still running after kill"
    exit 1
fi
log_pass "agent-b SIGKILL'd mid-transfer"

# ----- Wait for send-file to return ---------
log_test "send-file on agent-a returns (not hung)"
for _ in $(seq 1 60); do
    if $DC exec -T agent-a bash -c '[ -s /tmp/sf.out ] && grep -q "^rc=" /tmp/sf.out'; then break; fi
    sleep 1
done
RC=$($DC exec -T agent-a bash -c 'grep "^rc=" /tmp/sf.out | tail -n1' | tr -d '\r\n')
SF_OUT=$($DC exec -T agent-a bash -c 'cat /tmp/sf.out' 2>/dev/null)
if echo "$RC" | grep -q "^rc="; then
    log_pass "send-file returned ($RC)"
else
    log_fail "send-file hung — sender stuck after receiver died"
fi

# ----- Sender MUST NOT have reported 'ok' success --------
log_test "sender did NOT claim success after receiver died"
SUCCESS=""
echo "$SF_OUT" | jq -e '.status == "ok" and .data.ack != null' >/dev/null 2>&1 && SUCCESS="yes"
if [ -z "$SUCCESS" ]; then
    log_pass "no false-success ack"
else
    log_fail "sender CLAIMED delivery to dead receiver: $SF_OUT"
fi

# ----- No panic on agent-a -----------
log_test "no panic/fatal on agent-a"
BAD=$($DC logs agent-a 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs on a" || log_fail "agent-a: $BAD"

# ----- Restart agent-b, check partial-file state ---------
log_test "restart agent-b"
$DC up -d agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "agent-b re-registered" || log_fail "agent-b did not re-register"

# Any midkill-* file must either be absent OR match the full sha.
log_test "no silent-corrupt partial file on agent-b"
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^midkill-' | head -n1" | tr -d '\r\n')
if [ -z "$RECV" ]; then
    log_pass "no partial file left (acceptable)"
else
    DST_SIZE=$($DC exec -T agent-b stat -c%s "/root/.pilot/received/$RECV" 2>/dev/null | tr -d '\r\n')
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
    if [ "$DST_SIZE" = "4194304" ] && [ "$DST" = "$SRC" ]; then
        log_pass "file survived (full sha match, size=$DST_SIZE)"
    else
        log_fail "truncated/partial file left as 'complete': size=$DST_SIZE sha=${DST:0:12}... vs src=${SRC:0:12}..."
    fi
fi

# ----- Post-restart fresh send works ---------
log_test "fresh send-file post-restart completes with sha match"
$DC exec -T agent-a bash -c 'head -c 8192 /dev/urandom >/tmp/post.dat'
SRC2=$($DC exec -T agent-a sha256sum /tmp/post.dat | awk '{print $1}')
# warm the tunnel
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/post.dat >/tmp/post_sf.out 2>&1
RECV2=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^post-' | head -n1" | tr -d '\r\n')
DST2=""
[ -n "$RECV2" ] && DST2=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV2" | awk '{print $1}')
if [ "$SRC2" = "$DST2" ] && [ -n "$DST2" ]; then
    log_pass "post-restart send ok"
else
    log_fail "post-restart send mismatch src=${SRC2:0:12}... dst=${DST2:0:12}..."
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
