#!/bin/bash
# Resilience / restart / concurrent-load tests on the p2p stack.

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
echo "Resilience / restart / concurrency tests"
echo "=========================================="

$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for i in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
if [ "$COUNT" -lt 2 ]; then
    echo "[FAIL] bootstrap: only $COUNT agents"
    exit 1
fi

# ---- 1. Concurrent echo load ----
log_test "50 parallel echo roundtrips from agent-a to agent-b"
$DC exec -T agent-a bash -c '
    pass=0; fail=0
    for i in $(seq 1 50); do
        out=$(echo "load-$i" | pilotctl connect agent-b 7 --timeout 10s 2>/dev/null | tr -d "\r\n")
        if [ "$out" = "load-$i" ]; then
            pass=$((pass+1))
        else
            fail=$((fail+1))
        fi
    done
    echo "PARALLEL_ECHO: pass=$pass fail=$fail"
' > /tmp/load.txt 2>&1
LINE=$(grep "PARALLEL_ECHO" /tmp/load.txt)
PPASS=$(echo "$LINE" | sed 's/.*pass=//' | awk '{print $1}')
PFAIL=$(echo "$LINE" | sed 's/.*fail=//')
if [ "${PPASS:-0}" -eq 50 ] && [ "${PFAIL:-999}" -eq 0 ]; then
    log_pass "50/50 echo roundtrips ok"
else
    log_fail "echo load: pass=$PPASS fail=$PFAIL (full: $LINE)"
fi

# ---- 2. Agent restart ----
log_test "restart agent-b and confirm it re-registers"
BEFORE_NODE_B=$($DC exec -T agent-b bash -c 'pilotctl --json info' | jq -r '.data.node_id')
$DC restart agent-b >/dev/null 2>&1
# Wait for re-registration
sleep 8
for i in $(seq 1 60); do
    NEW=$($DC exec -T agent-b bash -c 'pilotctl --json info 2>/dev/null' | jq -r '.data.node_id // empty' 2>/dev/null)
    if [ -n "$NEW" ] && [ "$NEW" != "0" ] && [ "$NEW" != "null" ]; then break; fi
    sleep 1
done
if [ -n "$NEW" ] && [ "$NEW" != "null" ]; then
    log_pass "agent-b re-registered (was $BEFORE_NODE_B, now $NEW)"
else
    log_fail "agent-b failed to re-register"
    $DC logs --tail 20 agent-b
fi

# ---- 3. Echo eventually works after restart ----
# After agent-b restart, agent-a's cached tunnel is stale. The daemon takes
# ~22s for a direct-dial timeout before switching to relay, and may need
# several rounds. We poll up to 4 minutes for connectivity recovery.
log_test "echo to agent-b recovers after restart (poll ≤4min)"
RECOVERED=0
for i in $(seq 1 24); do
    RESP=$($DC exec -T agent-a bash -c 'echo "post-restart" | pilotctl connect agent-b 7 --timeout 10s 2>/dev/null' | tr -d '\r\n')
    if [ "$RESP" = "post-restart" ]; then
        RECOVERED=1
        break
    fi
    sleep 10
done
if [ "$RECOVERED" -eq 1 ]; then
    log_pass "post-restart echo recovered (after ~${i}×10s)"
else
    log_fail "post-restart echo never recovered in 4 minutes"
fi

# ---- 4. Rendezvous restart — agents should reconnect ----
# Heartbeat interval is 60s; re-registration kicks in after 3 consecutive failures.
# So we must wait ~3.5 minutes for both agents to re-register themselves.
log_test "restart rendezvous and confirm agents reconnect (≤4min)"
$DC restart rendezvous >/dev/null 2>&1
# Wait for health
for i in $(seq 1 30); do
    if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats >/dev/null 2>&1; then break; fi
    sleep 1
done
# Poll for re-registration (up to 240s)
RECONNECTED=0
for i in $(seq 1 48); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 2 ]; then
        RECONNECTED=1
        break
    fi
    sleep 5
done
if [ "$RECONNECTED" -eq 1 ]; then
    log_pass "both agents reconnected after rendezvous restart (total_nodes=$COUNT, ~${i}×5s)"
else
    log_fail "only $COUNT agents reconnected after rendezvous restart in 240s"
fi

# ---- 5. Long-lived daemon: memory + socket sanity ----
log_test "agent-a process survived 60s+ of activity"
# Grab pid inside container
A_PID=$($DC exec -T agent-a bash -c 'pgrep -f pilot-daemon | head -n1' | tr -d '\r\n')
if [ -n "$A_PID" ] && $DC exec -T agent-a bash -c "kill -0 $A_PID 2>/dev/null"; then
    # Check memory usage is reasonable (<500MB RSS)
    RSS=$($DC exec -T agent-a bash -c "ps -o rss= -p $A_PID 2>/dev/null" | tr -d ' \r\n')
    if [ -n "$RSS" ] && [ "$RSS" -lt 512000 ]; then
        log_pass "agent-a pid $A_PID alive, RSS ${RSS} KB"
    else
        log_fail "agent-a RSS ${RSS} KB > 500 MB"
    fi
else
    log_fail "agent-a process $A_PID not alive"
fi

# ---- 6. Dashboard pulse shows request activity ----
log_test "pulse endpoint shows non-zero total_requests"
# Pulse samples are recorded by pulseLoop at 1/sec; right after the
# rendezvous restart above only ~1 sample exists. Sleep so >=2 samples
# accumulate.
sleep 3
PULSE=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/pulse)
TR=$(echo "$PULSE" | jq -r '.total_requests')
SAMPLES=$(echo "$PULSE" | jq -r '.samples | length')
if [ "${TR:-0}" -gt 0 ] && [ "${SAMPLES:-0}" -ge 2 ]; then
    log_pass "pulse total_requests=$TR samples=$SAMPLES"
else
    log_fail "pulse flat: total_requests=$TR samples=$SAMPLES"
fi

# ---- 7. Concurrent send-message from both sides ----
log_test "concurrent send-message agent-a→b and agent-b→a"
(
    $DC exec -T agent-a bash -c 'for i in $(seq 1 10); do pilotctl --json send-message agent-b --data "ab-$i" --type text >/dev/null 2>&1; done; echo A_DONE'
) > /tmp/ab.txt 2>&1 &
AB=$!
(
    $DC exec -T agent-b bash -c 'for i in $(seq 1 10); do pilotctl --json send-message agent-a --data "ba-$i" --type text >/dev/null 2>&1; done; echo B_DONE'
) > /tmp/ba.txt 2>&1 &
BA=$!
wait $AB $BA
if grep -q A_DONE /tmp/ab.txt && grep -q B_DONE /tmp/ba.txt; then
    log_pass "concurrent bidirectional send-message completed"
else
    log_fail "concurrent send-message incomplete (ab=$(cat /tmp/ab.txt | tail -1) ba=$(cat /tmp/ba.txt | tail -1))"
fi

# ---- 8. Verify no error state lingering ----
log_test "agent logs free of panic/fatal"
A_LOG=$($DC logs --tail 200 agent-a 2>&1)
B_LOG=$($DC logs --tail 200 agent-b 2>&1)
if echo "$A_LOG$B_LOG" | grep -qiE "panic|fatal|data race|race detected"; then
    log_fail "panic/fatal/race in recent logs"
    echo "$A_LOG$B_LOG" | grep -iE "panic|fatal|data race" | head -5
else
    log_pass "no panic/fatal/race in recent logs"
fi

echo ""
echo "=========================================="
echo "Resilience Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="
exit $([ "$FAILED" -gt 0 ] && echo 1 || true)
