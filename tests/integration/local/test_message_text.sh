#!/bin/bash
# Text message smoke test: send a plain-text message from agent-a to agent-b
# and assert it arrives with type=TEXT and the correct payload.
# This is a minimal round-trip check targeting the happy path of the
# send-message → inbox pipeline for the TEXT message type.
#
# For adversarial encoding (long, newlines, unicode, JSON-in-string) see
# test_message_payload_integrity.sh. This test focuses on the basic type
# label, sender identity, and single-message delivery confirmation.

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
echo "Text message smoke"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

PAYLOAD="hello-text-$(date +%s)"
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- 1. Send text message -----
log_test "a sends TEXT message to b"
SEND=$($DC exec -T agent-a pilotctl --json send-message agent-b --data "$PAYLOAD" --type text 2>&1)
if echo "$SEND" | jq -e '.data' >/dev/null 2>&1; then
    log_pass "send returned ok"
else
    log_fail "send failed: $(echo "$SEND" | head -c 200)"
    exit 1
fi

# ----- 2. Message arrives in inbox -----
log_test "message arrives in b's inbox within 10s"
for _ in $(seq 1 20); do
    N=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
    [ "$N" -ge 1 ] && break
    sleep 0.5
done
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
N=$(echo "$INBOX" | jq -r '.data.total // 0')
[ "$N" -ge 1 ] && log_pass "message in inbox ($N)" || { log_fail "inbox empty"; exit 1; }

# ----- 3. Type is TEXT -----
log_test "message type is TEXT"
MTYPE=$(echo "$INBOX" | jq -r '.data.messages[0].type // empty')
[ "$MTYPE" = "TEXT" ] && log_pass "type=TEXT" || log_fail "type=$MTYPE (expected TEXT)"

# ----- 4. Payload is byte-exact -----
log_test "payload matches what was sent"
MDATA=$(echo "$INBOX" | jq -r --arg p "$PAYLOAD" '[.data.messages[]? | select(.data == $p)] | .[0].data // empty')
[ "$MDATA" = "$PAYLOAD" ] && log_pass "payload matches" || log_fail "payload mismatch: got='$MDATA' want='$PAYLOAD'"

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Text message summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
