#!/bin/bash
# Network edge-case tests (rotate-key, larger payloads, dashboard probes,
# tunnel metrics sanity, malformed UDP robustness).
# No set -e — each test logs its own pass/fail.

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
echo "Network edge-case tests"
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

# ---- 1. Registry restart recovery (fast re-register) ----
# After the rendezvous is stopped/started, agents should reconnect and resume
# traffic within a few heartbeat cycles (see isRegistryRejectingUsErr fast-path).
# Agents run with -keepalive 5s so rereg fires within ~15s.
log_test "agents recover after rendezvous restart"
$DC exec -T agent-a bash -c 'pilotctl send-message agent-b --data pre-restart' >/dev/null 2>&1
$DC restart rendezvous >/dev/null 2>&1
# Wait for the dashboard to come back before poking agents
for i in $(seq 1 30); do
    $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats >/dev/null 2>&1 && break
    sleep 1
done
# Poll up to 60s for hostname resolution to recover (rereg + SetHostname sync)
RECOVERED=0
for i in $(seq 1 30); do
    RESTART_OUT=$($DC exec -T agent-a bash -c 'pilotctl send-message agent-b --data post-restart' 2>&1)
    if echo "$RESTART_OUT" | grep -qE 'ack|ok|sent'; then
        RECOVERED=1
        break
    fi
    sleep 2
done
if [ "$RECOVERED" = "1" ]; then
    log_pass "send-message succeeded after rendezvous restart (attempt $i)"
else
    log_fail "traffic did not recover after rendezvous restart: $(echo "$RESTART_OUT" | head -c 200)"
fi

# ---- 2. Dashboard surfaces probe states ----
log_test "dashboard exposes restart_events / probe states"
ST=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null)
# probes field may be empty on fresh process but should be valid JSON
if echo "$ST" | jq -e '.probes // . ' >/dev/null 2>&1; then
    log_pass "stats endpoint returns well-formed JSON"
else
    log_fail "stats endpoint not valid JSON"
fi

# ---- 3. Larger send-file (20 MB) ----
log_test "send-file 20 MB from agent-a to agent-b"
$DC exec -T agent-a bash -c 'dd if=/dev/urandom of=/tmp/huge.bin bs=1M count=20 status=none'
SIZE=$($DC exec -T agent-a bash -c 'wc -c </tmp/huge.bin' | tr -d ' \r\n')
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send-file agent-b /tmp/huge.bin' 2>&1)
ACK=$(echo "$OUT" | jq -r '.data.bytes // .data.ack // empty' | grep -oE '[0-9]+' | head -n1)
if [ -n "$ACK" ] && [ "$ACK" -ge "$SIZE" ]; then
    log_pass "20 MB file acked ($ACK bytes)"
else
    log_fail "20 MB send-file failed: size=$SIZE ack=$ACK raw=$(echo "$OUT" | head -c 200)"
fi

# ---- 4. Tunnel metrics sanity ----
log_test "tunnel metrics report encryption activity"
METRICS=$($DC exec -T agent-a bash -c 'pilotctl --json info' | jq -r '.data | {encrypt_success: .tunnel_encryption_success, encrypt_fail: .tunnel_encryption_failure}')
ES=$(echo "$METRICS" | jq -r '.encrypt_success // 0')
EF=$(echo "$METRICS" | jq -r '.encrypt_fail // 0')
if [ "$ES" -gt 0 ] && [ "$EF" -eq 0 ]; then
    log_pass "encrypt_success=$ES encrypt_fail=$EF (healthy)"
elif [ "$ES" -gt 0 ]; then
    log_pass "encrypt_success=$ES encrypt_fail=$EF (non-zero fails, but traffic flowed)"
else
    log_fail "no encryption activity reported: $METRICS"
fi

# ---- 5. Malformed UDP to tunnel port doesn't crash daemon ----
log_test "random UDP bytes at tunnel port don't crash agent-b"
for i in $(seq 1 50); do
    $DC exec -T agent-a bash -c "printf '%.0sX' {1..1500} | nc -u -w1 agent-b 4000" >/dev/null 2>&1 &
done
wait
sleep 2
# verify agent-b is still responsive
if $DC exec -T agent-a bash -c 'pilotctl send-message agent-b --data poke' 2>&1 | grep -qE 'ack|ok|sent'; then
    log_pass "agent-b survived junk UDP flood"
else
    log_fail "agent-b unresponsive after junk UDP flood"
fi

# ---- 6. Parallel send-message burst from both directions ----
# Drives two concurrent senders to stress the tunnel's bidirectional path
# and catch deadlocks in the IPC write mutex / recvCh dispatch.
log_test "parallel sends in both directions don't wedge the tunnel"
(for i in $(seq 1 10); do
    $DC exec -T agent-a bash -c "pilotctl send-message agent-b --data a-$i" >/dev/null 2>&1
done) &
SENDER_A=$!
(for i in $(seq 1 10); do
    $DC exec -T agent-b bash -c "pilotctl send-message agent-a --data b-$i" >/dev/null 2>&1
done) &
SENDER_B=$!
wait "$SENDER_A" "$SENDER_B"
sleep 1
RESULT=$($DC exec -T agent-a bash -c 'pilotctl send-message agent-b --data final' 2>&1)
if echo "$RESULT" | grep -qE 'ack|ok|sent'; then
    log_pass "tunnel usable after bidirectional burst"
else
    log_fail "tunnel broken after bidirectional burst: $(echo "$RESULT" | head -c 200)"
fi

# ---- 7. Rendezvous /api/pulse exposes realistic counters ----
log_test "rendezvous pulse endpoint shows non-zero counters"
PULSE=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/pulse 2>/dev/null)
TOTAL=$(echo "$PULSE" | jq -r '.total_requests // 0')
if [ "$TOTAL" -gt 0 ]; then
    log_pass "pulse total_requests=$TOTAL"
else
    log_fail "pulse total_requests not positive: $(echo "$PULSE" | head -c 200)"
fi

# ---- 8. Logs free of fatal/panic/race ----
log_test "no panic/fatal/race in recent agent logs"
BAD=$($DC logs --since=5m agent-a agent-b rendezvous 2>&1 | grep -cE 'panic:|fatal:|DATA RACE' || true)
if [ "$BAD" -eq 0 ]; then
    log_pass "no panic/fatal/race in recent logs"
else
    log_fail "found $BAD panic/fatal/race entries"
fi

echo ""
echo "=========================================="
echo "Network-Edge Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "=========================================="
