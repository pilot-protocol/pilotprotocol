#!/bin/bash
# Chaos Matrix 3: sender (agent-a) SIGKILL'd mid send-file. Receiver
# (agent-b) must clean up its in-flight partial so the directory does
# not accumulate zombie half-files, and must NOT report the file as
# successfully delivered.

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
echo "SIGKILL agent-a mid-send-file"
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

# ----- 4 MiB payload so we have time to kill mid-transfer -----
log_test "prepare 4 MiB payload on agent-a"
$DC exec -T agent-a bash -c 'head -c 4194304 /dev/urandom >/tmp/sk.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/sk.dat | awk '{print $1}')
log_pass "payload ready"

# ----- start send-file in BG, then kill agent-a -----
log_test "start send-file BG, SIGKILL agent-a"
$DC exec -d agent-a bash -c 'timeout 60 pilotctl --json send-file agent-b /tmp/sk.dat >/tmp/sf.out 2>&1; echo "rc=$?" >>/tmp/sf.out'
sleep 2
$DC kill agent-a >/dev/null 2>&1
sleep 1
if $DC ps --status running --services 2>/dev/null | grep -q "^agent-a$"; then
    log_fail "agent-a still running"
    exit 1
fi
log_pass "agent-a dead mid-transfer"

# ----- agent-b must clean up in a bounded time ------
# Acceptable: no sk-* file in received dir, OR if one remains it must
# NOT match the full sha (not falsely complete).
log_test "agent-b has no falsely-complete partial file (wait up to 60s)"
MATCH_FULL=""
KEPT_PARTIAL=""
for _ in $(seq 1 60); do
    RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^sk-' | head -n1" | tr -d '\r\n')
    if [ -z "$RECV" ]; then
        # clean
        KEPT_PARTIAL=""
        MATCH_FULL=""
        # wait a little to be sure nothing gets materialized late
        sleep 2
        RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^sk-' | head -n1" | tr -d '\r\n')
        if [ -z "$RECV" ]; then
            break
        fi
    fi
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" 2>/dev/null | awk '{print $1}')
    DST_SIZE=$($DC exec -T agent-b stat -c%s "/root/.pilot/received/$RECV" 2>/dev/null | tr -d '\r\n')
    if [ "$DST" = "$SRC" ] && [ "$DST_SIZE" = "4194304" ]; then
        # race: whole file landed before we killed
        MATCH_FULL="yes"
        break
    fi
    KEPT_PARTIAL="$RECV size=$DST_SIZE"
    sleep 1
done

if [ -n "$MATCH_FULL" ]; then
    log_pass "entire file landed before SIGKILL took effect (acceptable race)"
elif [ -z "$KEPT_PARTIAL" ]; then
    log_pass "agent-b cleaned up partial"
else
    log_fail "agent-b left partial file on disk: $KEPT_PARTIAL"
fi

# ----- no panic on agent-b --------
log_test "no panic/fatal on agent-b"
BAD=$($DC logs agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

# ----- agent-b daemon still responsive ---------
log_test "agent-b daemon responsive"
if $DC exec -T agent-b pilotctl daemon status --check >/dev/null 2>&1; then
    log_pass "daemon responsive"
else
    log_fail "daemon hung after sender death"
fi

# ----- restart a, fresh send works --------
log_test "restart agent-a; fresh send-file completes"
$DC up -d agent-a >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "agent-a re-registered" || log_fail "agent-a did not re-register"

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true
$DC exec -T agent-a bash -c 'head -c 8192 /dev/urandom >/tmp/post.dat'
SRC2=$($DC exec -T agent-a sha256sum /tmp/post.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/post.dat >/tmp/post_sf.out 2>&1
RECV2=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^post-' | head -n1" | tr -d '\r\n')
DST2=""
[ -n "$RECV2" ] && DST2=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV2" | awk '{print $1}')
if [ "$SRC2" = "$DST2" ] && [ -n "$DST2" ]; then
    log_pass "post-restart send ok"
else
    log_fail "post-restart send mismatch"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
