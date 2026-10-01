#!/bin/bash
# Stress & protocol edge-case tests.
#   - Large send-file (5 MB)
#   - Handshake reject flow leaves no trust
#   - Agent-a (sender) restart recovery
#   - Visibility toggle under traffic
#   - Tunnel metrics sanity

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
echo "Stress / protocol edge-case tests"
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

# ---- 1. Large file send (5 MB) ----
log_test "send-file 5 MB from agent-a to agent-b"
$DC exec -T agent-a bash -c 'dd if=/dev/urandom of=/tmp/big.bin bs=1M count=5 status=none'
SIZE=$($DC exec -T agent-a bash -c 'wc -c </tmp/big.bin' | tr -d ' \r\n')
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send-file agent-b /tmp/big.bin 2>&1' 2>&1)
ACK=$(echo "$OUT" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
if [ -n "$ACK" ] && [ "$ACK" -ge "$SIZE" ]; then
    log_pass "5 MB file acked ($ACK bytes)"
else
    log_fail "5 MB send-file failed: size=$SIZE ack=$ACK raw=$(echo "$OUT" | head -c 200)"
fi

# ---- 2. Handshake reject leaves no trust ----
log_test "handshake reject flow leaves no trust"
$DC exec -T agent-a bash -c 'pilotctl handshake agent-b "reject-test"' >/tmp/hs1.txt 2>&1
sleep 1
SRC=$($DC exec -T agent-a bash -c 'pilotctl --json info' | jq -r '.data.node_id')
# agent-b rejects
if $DC exec -T agent-b bash -c "pilotctl reject $SRC test-reason" >/tmp/rej.txt 2>&1; then
    sleep 1
    # Verify agent-b's pending list does NOT show this handshake anymore
    PENDING=$($DC exec -T agent-b bash -c 'pilotctl --json pending' | jq -r --argjson nid "$SRC" '.data.pending[]? | select(.node_id == $nid) | .node_id' 2>/dev/null)
    TRUSTED=$($DC exec -T agent-b bash -c 'pilotctl --json trust' | jq -r --argjson nid "$SRC" '.data.trusted[]? | select(.node_id == $nid) | .node_id' 2>/dev/null)
    if [ -z "$PENDING" ] && [ -z "$TRUSTED" ]; then
        log_pass "reject removed pending and did not add trust"
    else
        log_fail "after reject: pending=$PENDING trusted=$TRUSTED"
    fi
else
    log_fail "reject command failed"
fi

# ---- 3. Agent-a (sender) restart recovery ----
log_test "restart agent-a and verify echo to agent-b recovers"
$DC restart agent-a >/dev/null 2>&1
# Wait for agent-a socket + re-registration
for i in $(seq 1 60); do
    NID=$($DC exec -T agent-a bash -c 'pilotctl --json info 2>/dev/null' | jq -r '.data.node_id // empty' 2>/dev/null)
    [ -n "$NID" ] && [ "$NID" != "null" ] && [ "$NID" != "0" ] && break
    sleep 1
done
# Poll echo for up to 30s (rekey is immediate under fix; sender restart means
# sender has fresh keys, triggers rekey naturally on first send)
RECOVERED=0
for i in $(seq 1 6); do
    RESP=$($DC exec -T agent-a bash -c 'echo "sender-restart" | pilotctl connect agent-b 7 --timeout 10s 2>/dev/null' | tr -d '\r\n')
    if [ "$RESP" = "sender-restart" ]; then
        RECOVERED=1
        break
    fi
    sleep 5
done
if [ "$RECOVERED" -eq 1 ]; then
    log_pass "post-sender-restart echo recovered (after ~${i}×5s)"
else
    log_fail "post-sender-restart echo never recovered"
fi

# ---- 4. Echo from agent-b → agent-a after sender restart ----
# This tests that agent-b's stale tunnel to agent-a ALSO recovers (reverse direction)
log_test "reverse echo agent-b → agent-a after agent-a restart"
RECOVERED=0
for i in $(seq 1 6); do
    RESP=$($DC exec -T agent-b bash -c 'echo "reverse" | pilotctl connect agent-a 7 --timeout 10s 2>/dev/null' | tr -d '\r\n')
    if [ "$RESP" = "reverse" ]; then
        RECOVERED=1
        break
    fi
    sleep 5
done
if [ "$RECOVERED" -eq 1 ]; then
    log_pass "reverse echo recovered (after ~${i}×5s)"
else
    log_fail "reverse echo never recovered — my rekey fix may not handle sender-restart reverse direction"
fi

# ---- 5. Visibility toggle under traffic ----
log_test "visibility toggle (public→private→public) survives under traffic"
$DC exec -T agent-a bash -c '
    for i in $(seq 1 10); do
        pilotctl --json send-message agent-b --data "vis-$i" --type text >/dev/null 2>&1
    done
' >/tmp/vis.txt 2>&1 &
VPID=$!
sleep 1
$DC exec -T agent-b bash -c 'pilotctl set-private' >/dev/null 2>&1
sleep 1
$DC exec -T agent-b bash -c 'pilotctl set-public' >/dev/null 2>&1
wait $VPID 2>/dev/null
# After toggling back to public, send-message should still succeed
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send-message agent-b --data "after-toggle" --type text' 2>&1)
if echo "$OUT" | jq -e '.data.ack' >/dev/null 2>&1; then
    log_pass "send-message works after visibility toggle"
else
    log_fail "send-message failed after toggle: $(echo "$OUT" | head -c 200)"
fi

# ---- 6. Tunnel metrics are non-zero & sane ----
log_test "tunnel metrics: encryption success counter advances"
INFO=$($DC exec -T agent-a bash -c 'pilotctl --json info')
ENC_OK=$(echo "$INFO" | jq -r '.data.tunnel_encryption_success // 0')
ENC_FAIL=$(echo "$INFO" | jq -r '.data.tunnel_encryption_failure // 0')
PKTS_SENT=$(echo "$INFO" | jq -r '.data.pkts_sent // 0')
if [ "${ENC_OK:-0}" -gt 0 ] && [ "${PKTS_SENT:-0}" -gt 0 ]; then
    log_pass "tunnel metrics ok: enc_ok=$ENC_OK enc_fail=$ENC_FAIL pkts_sent=$PKTS_SENT"
else
    log_fail "tunnel metrics flat: enc_ok=$ENC_OK pkts_sent=$PKTS_SENT"
fi

# ---- 7. Port allocation: many ephemeral connections don't exhaust ----
log_test "30 sequential connect-and-close don't exhaust ephemeral ports"
$DC exec -T agent-a bash -c '
    ok=0; bad=0
    for i in $(seq 1 30); do
        out=$(echo "ep-$i" | pilotctl connect agent-b 7 --timeout 5s 2>/dev/null | tr -d "\r\n")
        if [ "$out" = "ep-$i" ]; then
            ok=$((ok+1))
        else
            bad=$((bad+1))
        fi
    done
    echo "EPH: ok=$ok bad=$bad"
' > /tmp/eph.txt 2>&1
LINE=$(grep "^EPH" /tmp/eph.txt)
OK=$(echo "$LINE" | sed 's/.*ok=//' | awk '{print $1}')
BAD=$(echo "$LINE" | sed 's/.*bad=//')
if [ "${OK:-0}" -eq 30 ] && [ "${BAD:-999}" -eq 0 ]; then
    log_pass "30/30 ephemeral connections ok"
else
    log_fail "ephemeral connections: ok=$OK bad=$BAD"
fi

# ---- 8. Logs still clean after stress ----
log_test "no panic/fatal/race in logs after stress run"
A_LOG=$($DC logs --tail 400 agent-a 2>&1)
B_LOG=$($DC logs --tail 400 agent-b 2>&1)
R_LOG=$($DC logs --tail 200 rendezvous 2>&1)
if echo "$A_LOG$B_LOG$R_LOG" | grep -qiE "panic|fatal|data race|race detected"; then
    log_fail "panic/fatal/race detected in logs"
    echo "$A_LOG$B_LOG$R_LOG" | grep -iE "panic|fatal|data race" | head -5
else
    log_pass "no panic/fatal/race after stress"
fi

echo ""
echo "=========================================="
echo "Stress/Edge Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="
exit $([ "$FAILED" -gt 0 ] && echo 1 || true)
