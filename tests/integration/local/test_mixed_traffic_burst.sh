#!/bin/bash
# Mixed-traffic burst: send-file + send-message, all launched in
# parallel from agent-a to agent-b. The receiver has distinct service
# goroutines. This test pushes 5 of each kind concurrently to see
# whether:
#
#   - the goroutines share any mutex that gets contended so hard it
#     drops or reorders work
#   - the Connection-accept path on one service starves another
#   - the shared inboxSeq atomic stays monotonic across file and
#     message saves interleaved at ms resolution
#   - a message is never mis-routed into the received/ folder, and
#     vice versa (frame-type tag survives)

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
N=5

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Mixed-traffic burst ($N of each kind)"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received /root/.pilot/inbox && mkdir -p /root/.pilot/received /root/.pilot/inbox' >/dev/null 2>&1

# ----- 1. Prepare source files on agent-a --------------------------
log_test "create $N source files on agent-a"
$DC exec -T agent-a bash -c "
    rm -f /tmp/mix-*.dat
    for i in \$(seq 1 $N); do
        printf 'MIX-%d ' \"\$i\" >/tmp/mix-\$i.dat
        head -c 1024 /dev/urandom | base64 | head -c 1024 >>/tmp/mix-\$i.dat
    done
" >/dev/null 2>&1
log_pass "source files ready"

# ----- 2. Launch mixed parallel bursts -----------------------------
log_test "launch $N file + $N message in parallel"
$DC exec -T agent-a bash -c "
    rm -f /tmp/mix_send_*.out /tmp/mix_msg_*.out
    pids=''
    for i in \$(seq 1 $N); do
        (pilotctl --json send-file    agent-b /tmp/mix-\$i.dat                              >/tmp/mix_send_\$i.out 2>&1) & pids=\"\$pids \$!\"
        (pilotctl --json send-message agent-b --data \"msg-\$i payload\" --type text        >/tmp/mix_msg_\$i.out  2>&1) & pids=\"\$pids \$!\"
    done
    for p in \$pids; do wait \$p; done
"
log_pass "bursts complete"

# ----- 3. Per-kind success counts ---------------------------------
log_test "all $N send-file calls acked"
ok_f=0
for i in $(seq 1 $N); do
    ACK=$($DC exec -T agent-a bash -c "cat /tmp/mix_send_$i.out 2>/dev/null | jq -r '.data.ack // empty'" | grep -c "^ACK FILE")
    [ "$ACK" = "1" ] && ok_f=$((ok_f+1))
done
if [ "$ok_f" = "$N" ]; then log_pass "send-file: $ok_f/$N acked"
else log_fail "send-file acks: $ok_f/$N"
fi

log_test "all $N send-message calls acked"
ok_m=0
for i in $(seq 1 $N); do
    ACK=$($DC exec -T agent-a bash -c "cat /tmp/mix_msg_$i.out 2>/dev/null | jq -r '.data.ack // empty'" | grep -c "TEXT")
    [ "$ACK" = "1" ] && ok_m=$((ok_m+1))
done
if [ "$ok_m" = "$N" ]; then log_pass "send-message: $ok_m/$N acked"
else log_fail "send-message acks: $ok_m/$N"
fi

# ----- 4. Receiver has exactly N of each, no cross-routing --------
log_test "agent-b received/ has exactly $N files"
NFILES=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null | wc -l' | tr -d ' \r\n')
if [ "$NFILES" = "$N" ]; then log_pass "received files: $NFILES"
else log_fail "received files: $NFILES (want $N)"
    $DC exec -T agent-b ls /root/.pilot/received/ 2>&1 | sed 's/^/    /'
fi

log_test "agent-b inbox has exactly $N text messages"
INBOX=$($DC exec -T agent-b bash -c 'pilotctl --json inbox' 2>&1)
NMSGS=$(echo "$INBOX" | jq -r '.data.messages | length // 0')
if [ "$NMSGS" = "$N" ]; then log_pass "inbox messages: $NMSGS"
else log_fail "inbox messages: $NMSGS (want $N)"
fi

# ----- 5. Message bodies round-trip -------------------------------
log_test "each 'msg-<i> payload' appears exactly once in inbox"
miss_m=0
for i in $(seq 1 $N); do
    HAS=$(echo "$INBOX" | jq -r --arg d "msg-$i payload" '[.data.messages[]? | select(.data == $d)] | length')
    if [ "$HAS" != "1" ]; then
        miss_m=$((miss_m+1))
        echo "  [miss] msg-$i count=$HAS"
    fi
done
if [ "$miss_m" = "0" ]; then log_pass "all $N message bodies unique and present"
else log_fail "$miss_m missing/duplicate message bodies"
fi

# ----- 6. Per-file sha256 round-trip -----------------------------
log_test "each mix-<i>.dat sha256 matches on receiver"
miss_f=0
for i in $(seq 1 $N); do
    SRC=$($DC exec -T agent-a sha256sum "/tmp/mix-$i.dat" | awk '{print $1}')
    RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received | grep '^mix-$i-' | head -n1" | tr -d '\r\n')
    if [ -z "$RECV" ]; then
        miss_f=$((miss_f+1))
        echo "  [miss] no recv for mix-$i"
        continue
    fi
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
    if [ "$SRC" != "$DST" ]; then
        miss_f=$((miss_f+1))
        echo "  [bad ] mix-$i src=${SRC:0:12}... dst=${DST:0:12}..."
    fi
done
if [ "$miss_f" = "0" ]; then log_pass "all $N file payloads intact"
else log_fail "$miss_f file mismatches"
fi

# ----- 7. No panic/fatal in daemon logs --------------------------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"
else log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Mixed-traffic summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
