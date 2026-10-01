#!/bin/bash
# Multi-container P2P integration test.
# Runs inside p2p-runner; directs the runner's daemon at the local rendezvous,
# then talks to agent-a and agent-b over the docker bridge.

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

PFX="${PILOT_SUBNET_PREFIX:-172.29.0}"
REGISTRY="${PFX}.10:9000"
BEACON="${PFX}.10:9001"
DASHBOARD="http://${PFX}.10:8080"

# pilotctl reads PILOT_REGISTRY for direct-to-registry commands (lookup,
# register, rotate-key). Otherwise it defaults to the global registry.
export PILOT_REGISTRY="$REGISTRY"

echo "=========================================="
echo "Multi-container P2P integration test"
echo "Registry: $REGISTRY"
echo "=========================================="

# Wait for both agents to register with the local rendezvous
log_test "Waiting for agent-a and agent-b to register"
for i in $(seq 1 60); do
    COUNT=$(curl -fsS "$DASHBOARD/api/public-stats" 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then
        log_pass "Both agents registered (total_nodes=$COUNT)"
        break
    fi
    sleep 1
done
if [ "$COUNT" -lt 2 ]; then
    log_fail "Only $COUNT agents registered after 60s"
    curl -s "$DASHBOARD/api/public-stats" | head -c 500
    exit 1
fi

# Start runner's own daemon
log_test "Starting runner daemon"
mkdir -p /root/.pilot
pilot-daemon \
    -registry "$REGISTRY" \
    -beacon "$BEACON" \
    -hostname runner \
    -identity /root/.pilot/identity.json \
    -email runner@p2p.test \
    -log-level error \
    > /tmp/runner-daemon.log 2>&1 &
RUNNER_PID=$!

for i in $(seq 1 60); do
    if [ -S /tmp/pilot.sock ]; then
        NID=$(pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
        if [ -n "$NID" ] && [ "$NID" != "0" ] && [ "$NID" != "null" ]; then
            log_pass "Runner daemon started (node=$NID)"
            break
        fi
    fi
    sleep 1
done
if [ -z "$NID" ]; then
    log_fail "Runner daemon failed to register"
    tail -30 /tmp/runner-daemon.log
    exit 1
fi

cleanup() {
    log_test "Stopping runner daemon"
    kill $RUNNER_PID 2>/dev/null
    wait $RUNNER_PID 2>/dev/null
}
trap cleanup EXIT

# ----- Discovery -----
log_test "find agent-a by hostname"
ADDR_A=$(pilotctl find agent-a 2>/dev/null | awk '/Address:/{print $2}' | head -n1)
if [ -n "$ADDR_A" ]; then
    log_pass "agent-a resolved: $ADDR_A"
else
    pilotctl find agent-a
    log_fail "Could not resolve agent-a"
fi

log_test "find agent-b by hostname"
ADDR_B=$(pilotctl find agent-b 2>/dev/null | awk '/Address:/{print $2}' | head -n1)
if [ -n "$ADDR_B" ]; then
    log_pass "agent-b resolved: $ADDR_B"
else
    log_fail "Could not resolve agent-b"
fi

# ----- ICMP-like ping -----
log_test "ping agent-a"
if pilotctl ping agent-a --count 3 --timeout 10s >/tmp/ping-a.txt 2>&1; then
    log_pass "ping agent-a OK"
else
    log_fail "ping agent-a failed"
    tail -5 /tmp/ping-a.txt
fi

log_test "ping agent-b"
if pilotctl ping agent-b --count 3 --timeout 10s >/tmp/ping-b.txt 2>&1; then
    log_pass "ping agent-b OK"
else
    log_fail "ping agent-b failed"
    tail -5 /tmp/ping-b.txt
fi

# ----- Echo service -----
log_test "echo to agent-a"
MSG="p2p-echo-$$"
RESP=$(echo "$MSG" | pilotctl connect agent-a 7 --timeout 10s 2>/dev/null | tr -d '\r\n')
if [ "$RESP" = "$MSG" ]; then
    log_pass "echo agent-a roundtrip ok ('$RESP')"
else
    log_fail "echo agent-a mismatch: got '$RESP' want '$MSG'"
fi

log_test "echo to agent-b"
MSG="p2p-echo-$(date +%N)"
RESP=$(echo "$MSG" | pilotctl connect agent-b 7 --timeout 10s 2>/dev/null | tr -d '\r\n')
if [ "$RESP" = "$MSG" ]; then
    log_pass "echo agent-b roundtrip ok ('$RESP')"
else
    log_fail "echo agent-b mismatch: got '$RESP' want '$MSG'"
fi

# ----- Data-exchange text / JSON / file -----
# Port 1001 is the data-exchange service
log_test "send text to agent-a (port 1001)"
if pilotctl send agent-a 1001 --data "hello from runner $(date +%s)" --timeout 10s >/tmp/send-text.txt 2>&1; then
    log_pass "text send ok"
else
    log_fail "text send failed"; tail -5 /tmp/send-text.txt
fi

log_test "send-message JSON to agent-b"
if pilotctl send-message agent-b --data '{"type":"msg","val":42}' --type json >/tmp/send-json.txt 2>&1; then
    log_pass "JSON send ok"
else
    log_fail "JSON send failed"; tail -5 /tmp/send-json.txt
fi

log_test "send-file to agent-a"
echo "p2p test payload $(date)" > /tmp/testfile.txt
if pilotctl send-file agent-a /tmp/testfile.txt >/tmp/send-file.txt 2>&1; then
    log_pass "file send ok"
else
    log_fail "file send failed"; tail -5 /tmp/send-file.txt
fi

# ----- Event stream (publish goes TO a node with a topic) -----
log_test "publish event to agent-a"
if pilotctl publish agent-a sensor/p2p --data "temp=42.1" >/tmp/pub.txt 2>&1; then
    log_pass "event published"
else
    log_fail "publish failed"; tail -5 /tmp/pub.txt
fi

# ----- Peers list -----
log_test "list peers"
if pilotctl peers >/tmp/peers.txt 2>&1; then
    PEERS=$(wc -l </tmp/peers.txt)
    log_pass "peers listed ($PEERS lines)"
else
    log_fail "peers command failed"
fi

# ----- Handshake -----
log_test "handshake to agent-a"
if pilotctl handshake agent-a --timeout 10s >/tmp/hs.txt 2>&1; then
    log_pass "handshake agent-a sent"
else
    log_fail "handshake failed"; tail -5 /tmp/hs.txt
fi

# ----- Status / info -----
log_test "daemon status"
if pilotctl daemon status --check >/dev/null 2>&1; then
    log_pass "daemon status ok"
else
    log_fail "daemon status failed"
fi

log_test "info"
if pilotctl info >/tmp/info.txt 2>&1; then
    log_pass "info ok"
else
    log_fail "info failed"
fi

# ----- Tags / hostname / visibility -----
log_test "set-tags"
if pilotctl set-tags tag1 tag2 >/tmp/tags.txt 2>&1; then
    log_pass "tags set"
else
    log_fail "tags set failed"; tail -5 /tmp/tags.txt
fi

log_test "clear-tags"
if pilotctl clear-tags >/tmp/ctags.txt 2>&1; then
    log_pass "tags cleared"
else
    log_fail "clear-tags failed"
fi

log_test "set-public"
if pilotctl set-public >/tmp/vis.txt 2>&1; then
    log_pass "visibility public"
else
    log_fail "set-public failed"; tail -5 /tmp/vis.txt
fi

log_test "set-private"
if pilotctl set-private >/tmp/vis2.txt 2>&1; then
    log_pass "visibility private"
else
    log_fail "set-private failed"
fi

log_test "set-hostname runner-renamed"
if pilotctl set-hostname runner-renamed >/tmp/hn.txt 2>&1; then
    log_pass "hostname changed"
else
    log_fail "set-hostname failed"; tail -5 /tmp/hn.txt
fi

log_test "clear-hostname"
if pilotctl clear-hostname >/tmp/hnc.txt 2>&1; then
    log_pass "hostname cleared"
else
    log_fail "clear-hostname failed"
fi

# ----- Diagnostics -----
log_test "health"
if pilotctl health >/tmp/health.txt 2>&1; then
    log_pass "health ok"
else
    log_fail "health failed"
fi

log_test "context"
if pilotctl context >/tmp/ctx.txt 2>&1; then
    log_pass "context ok"
else
    log_fail "context failed"
fi

log_test "traceroute to agent-a (address form)"
if pilotctl traceroute "$ADDR_A" --timeout 10s >/tmp/tr.txt 2>&1; then
    log_pass "traceroute ok"
else
    log_fail "traceroute failed"; tail -5 /tmp/tr.txt
fi

log_test "bench to agent-a (0.1MB)"
if pilotctl bench agent-a 1 --timeout 20s >/tmp/bench.txt 2>&1; then
    log_pass "bench ok"
else
    log_fail "bench failed"; tail -5 /tmp/bench.txt
fi

log_test "lookup node 1 (agent-a node_id)"
if pilotctl lookup 1 >/tmp/lu.txt 2>&1; then
    log_pass "lookup ok"
else
    log_fail "lookup failed"
fi

log_test "pending handshakes"
if pilotctl pending >/tmp/pending.txt 2>&1; then
    log_pass "pending ok"
else
    log_fail "pending failed"
fi

log_test "trust list"
if pilotctl trust >/tmp/trust.txt 2>&1; then
    log_pass "trust list ok"
else
    log_fail "trust list failed"
fi

log_test "connections"
if pilotctl connections >/tmp/conns.txt 2>&1; then
    log_pass "connections ok"
else
    log_fail "connections failed"
fi

log_test "config get"
if pilotctl config >/tmp/cfg.txt 2>&1; then
    log_pass "config ok"
else
    log_fail "config failed"
fi

# ----- Pulse endpoint sanity -----
log_test "rendezvous /api/pulse returns samples"
PULSE=$(curl -fsS "$DASHBOARD/api/pulse" 2>/dev/null)
SAMPLES=$(echo "$PULSE" | jq -r '.samples | length')
TOT=$(echo "$PULSE" | jq -r '.total_requests')
if [ "${SAMPLES:-0}" -ge 1 ] && [ "${TOT:-0}" -gt 0 ]; then
    log_pass "pulse ok (samples=$SAMPLES total_requests=$TOT)"
else
    log_fail "pulse weird: samples=$SAMPLES total=$TOT"
fi

echo ""
echo "=========================================="
echo "P2P Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

mkdir -p /results
echo "passed=$PASSED failed=$FAILED" > /results/p2p_summary.txt

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
