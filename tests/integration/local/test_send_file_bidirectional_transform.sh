#!/bin/bash
# Bidirectional send-file service agent: uppercase file transform.
#
# Service agent on agent-b polls its received/ directory for new
# *.txt files, reads the contents, uppercases the text, and sends
# the result back to agent-a as a new file. Exercises the
# request/reply pattern *entirely via the dataexchange TypeFile
# path* — no task submission, no inbox messaging — in both
# directions on the same pair.
#
# Targets:
#   - any asymmetry in the send-file path that would stall b->a
#     after a successful a->b (e.g. trust gate only relaxed on
#     one direction, crypto key state not bidirectional)
#   - reply file correctly surfaces the uppercased content
#   - reply filename convention survives the round trip
#   - worker does not loop on its own replies (it watches incoming
#     *.txt but sends back upper-*.txt which must not re-trigger)

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
echo "Bidirectional file-transform service agent"
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

$DC exec -T agent-a bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1
$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1

# ----- 1. Start the transform worker on agent-b --------------------
log_test "start transform worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log /tmp/seen.list
    touch /tmp/seen.list
    while [ ! -f /tmp/worker_stop ]; do
        for f in /root/.pilot/received/*.txt; do
            [ ! -f "$f" ] && continue
            # Skip files we already processed or that are our own replies.
            bn=$(basename "$f")
            case "$bn" in
                upper-*) continue ;;
            esac
            if grep -qxF "$bn" /tmp/seen.list; then continue; fi
            echo "$bn" >>/tmp/seen.list
            content=$(cat "$f")
            upper=$(printf "%s" "$content" | tr "[:lower:]" "[:upper:]")
            # Strip the receiver-side "-{ts}-{seq}.txt" tail to recover
            # the original stem; the inbound was "{stem}-{ts}-{seq}.txt".
            stem=$(echo "$bn" | sed -E "s/-[0-9]{8}-[0-9]{6}\.[0-9]{3}-[0-9]{6}\.txt$//")
            reply=/tmp/upper-${stem}.txt
            printf "%s" "$upper" >"$reply"
            pilotctl send-file agent-a "$reply" >>/tmp/worker.log 2>&1 || true
            rm -f "$reply"
        done
        sleep 0.15
    done
'
sleep 1
log_pass "worker started"

# ----- 2. Send hello.txt from agent-a -> agent-b -------------------
log_test "send hello.txt from agent-a"
$DC exec -T agent-a bash -c 'printf "hello world, this is a pilot agent" >/tmp/hello.txt' >/dev/null 2>&1
OUT=$($DC exec -T agent-a pilotctl --json send-file agent-b /tmp/hello.txt 2>&1)
ACK=$(echo "$OUT" | jq -r '.data.ack // empty')
if [ -n "$ACK" ]; then
    log_pass "a->b ack: $ACK"
else
    log_fail "a->b send did not ack: $(echo "$OUT" | head -c 300)"
    exit 1
fi

# ----- 3. Wait for upper-hello-*.txt on agent-a --------------------
log_test "reply file upper-hello-*.txt lands on agent-a within 10s"
RECV_PATH=""
for _ in $(seq 1 40); do
    RECV_PATH=$($DC exec -T agent-a bash -c 'ls /root/.pilot/received 2>/dev/null | grep "^upper-hello-" | head -n1' | tr -d '\r\n')
    if [ -n "$RECV_PATH" ]; then break; fi
    sleep 0.25
done
if [ -n "$RECV_PATH" ]; then
    log_pass "reply arrived: $RECV_PATH"
else
    log_fail "no reply file after 10s"
    $DC exec -T agent-a ls -la /root/.pilot/received/ 2>&1 | sed 's/^/    /'
    $DC exec -T agent-b cat /tmp/worker.log 2>&1 | tail -20 | sed 's/^/    worker.log: /'
    exit 1
fi

# ----- 4. Verify content is uppercased ------------------------------
log_test "reply content is uppercase of original"
GOT=$($DC exec -T agent-a cat "/root/.pilot/received/$RECV_PATH")
WANT="HELLO WORLD, THIS IS A PILOT AGENT"
if [ "$GOT" = "$WANT" ]; then
    log_pass "content matches: $GOT"
else
    log_fail "content mismatch: got='$GOT' want='$WANT'"
fi

# ----- 5. Send a second file to confirm worker keeps running -------
log_test "send second file after reply, verify second reply lands"
$DC exec -T agent-a bash -c 'printf "another message from a" >/tmp/note.txt' >/dev/null 2>&1
OUT2=$($DC exec -T agent-a pilotctl --json send-file agent-b /tmp/note.txt 2>&1)
ACK2=$(echo "$OUT2" | jq -r '.data.ack // empty')
if [ -z "$ACK2" ]; then
    log_fail "second a->b send did not ack: $(echo "$OUT2" | head -c 200)"
else
    RECV2=""
    for _ in $(seq 1 40); do
        RECV2=$($DC exec -T agent-a bash -c 'ls /root/.pilot/received 2>/dev/null | grep "^upper-note-" | head -n1' | tr -d '\r\n')
        if [ -n "$RECV2" ]; then break; fi
        sleep 0.25
    done
    if [ -n "$RECV2" ]; then
        GOT2=$($DC exec -T agent-a cat "/root/.pilot/received/$RECV2")
        if [ "$GOT2" = "ANOTHER MESSAGE FROM A" ]; then
            log_pass "second round-trip OK ($RECV2)"
        else
            log_fail "second content mismatch: got='$GOT2'"
        fi
    else
        log_fail "no second reply"
    fi
fi

# ----- 6. Worker did not echo its own upper-* reply ----------------
log_test "agent-b did not recursively process its own upper-* reply"
LOOP=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null | grep -c "^upper-upper-"' | tr -d ' \r\n')
if [ "$LOOP" = "0" ]; then
    log_pass "no self-echo on receiver side"
else
    log_fail "found $LOOP upper-upper-* files — worker re-processed its own reply"
fi

# ----- 7. No panic/fatal in daemon logs ---------------------------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Bidirectional file-transform summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
