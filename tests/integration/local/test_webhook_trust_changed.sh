#!/bin/bash
# Webhook: trust.changed.
# Drive one trust-state change (handshake approve, then revoke) and assert
# that each transition produces exactly one webhook event describing the
# transition.
#
# EXPECTED: one POST per trust transition with .body.event matching the
# generic name "trust.changed".
# NOTE: pkg/daemon emits finer-grained events today — "handshake.approved",
# "trust.revoked", "trust.revoked_by_peer" — but no unified "trust.changed".
# This test accepts any of those as the "trust changed" signal to match
# the current implementation, but ALSO separately checks for the
# canonical "trust.changed" name.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.webhooks.yml"
SINK="http://webhook-sink:18080"
LOG="/var/log/webhooks.jsonl"

cd "$(dirname "$0")" || exit 1
cleanup() { $DC down -v >/dev/null 2>&1; }
source ./webhook_helpers.sh
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
ensure_webhook_sink_ready || { log_fail "webhook-sink never came up"; exit 1; }
$DC up -d agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 $((120 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

$DC exec -T agent-a pilotctl set-webhook "$SINK/a" >/dev/null 2>&1
$DC exec -T agent-b pilotctl set-webhook "$SINK/b" >/dev/null 2>&1
log_pass "webhooks set on a+b"

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done

# --- 1. Handshake grant (a -> b) ---
log_test "handshake a->b (trust granted)"
$DC exec -T agent-a pilotctl handshake agent-b --timeout 10s >/tmp/hs.txt 2>&1 || true
sleep 3
# Auto-approve on receiver side; if manual, approve it now.
PID=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null | jq -r '.data.pending[0].node_id // empty' 2>/dev/null)
if [ -n "$PID" ] && [ "$PID" != "null" ]; then
    $DC exec -T agent-b pilotctl approve "$PID" >/dev/null 2>&1 || true
fi
sleep 12

GRANT=$($DC exec -T webhook-sink sh -c "grep -cE '\"event\":\"(trust\\.changed|handshake\\.approved|handshake\\.auto_approved)\"' $LOG 2>/dev/null; true" | tail -1)
log_test "at least one grant event observed (got=$GRANT)"
if [ "$GRANT" -ge 1 ]; then log_pass "grant signal present"; else log_fail "no grant event fired"; fi

# --- 2. Revoke ---
log_test "untrust b on agent-a (trust revoked)"
BEFORE_REV=$($DC exec -T webhook-sink sh -c "grep -cE '\"event\":\"(trust\\.changed|trust\\.revoked|trust\\.revoked_by_peer)\"' $LOG 2>/dev/null; true" | tail -1)
# untrust wants a node_id, not a hostname — look up agent-b's id via info.
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if [ -n "$PEER_B" ]; then
    $DC exec -T agent-a pilotctl untrust "$PEER_B" >/dev/null 2>&1 || true
fi
sleep 12
AFTER_REV=$($DC exec -T webhook-sink sh -c "grep -cE '\"event\":\"(trust\\.changed|trust\\.revoked|trust\\.revoked_by_peer)\"' $LOG 2>/dev/null; true" | tail -1)
DELTA_REV=$((AFTER_REV - BEFORE_REV))
if [ "$DELTA_REV" -ge 1 ]; then log_pass "revoke signal present (delta=$DELTA_REV)"; else log_fail "no revoke event fired"; fi

# --- 3. Strict canonical name ---
log_test "canonical 'trust.changed' event present"
CANON=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"trust.changed\"' $LOG 2>/dev/null; true" | tail -1)
if [ "$CANON" -ge 1 ]; then
    log_pass "trust.changed present ($CANON)"
else
    log_fail "trust.changed NOT wired (saw only handshake.* and trust.revoked variants)"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
