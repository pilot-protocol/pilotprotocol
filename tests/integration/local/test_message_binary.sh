#!/bin/bash
# Binary message smoke test: send a message with --type binary from agent-a
# to agent-b. Binary payloads are base64-encoded at the CLI boundary; the
# daemon stores and delivers them as-is. This test validates that:
#   - the type label is preserved as BINARY
#   - the payload is the same string that was sent (CLI encodes/decodes
#     consistently)
#   - no double-encoding occurs between send and inbox read
#
# We use a base64-encoded payload to simulate binary data. The round-trip
# must preserve the exact base64 string so application code can re-decode.

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
echo "Binary message smoke"
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

# Simulate binary data: 32 random bytes, base64-encoded.
BIN_PAYLOAD=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)
echo "Binary payload (base64, len=${#BIN_PAYLOAD}): $BIN_PAYLOAD"
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- 1. Send binary message -----
log_test "a sends BINARY message to b"
SEND=$($DC exec -T agent-a pilotctl --json send-message agent-b --data "$BIN_PAYLOAD" --type binary 2>&1)
if echo "$SEND" | jq -e '.data' >/dev/null 2>&1; then
    log_pass "send returned ok"
else
    log_fail "send failed: $(echo "$SEND" | head -c 200)"
    exit 1
fi

# ----- 2. Message arrives -----
log_test "message arrives in b's inbox within 10s"
for _ in $(seq 1 20); do
    N=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
    [ "$N" -ge 1 ] && break
    sleep 0.5
done
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
N=$(echo "$INBOX" | jq -r '.data.total // 0')
[ "$N" -ge 1 ] && log_pass "message in inbox ($N)" || { log_fail "inbox empty"; exit 1; }

# ----- 3. Type is BINARY -----
log_test "message type is BINARY"
MTYPE=$(echo "$INBOX" | jq -r '.data.messages[0].type // empty')
[ "$MTYPE" = "BINARY" ] && log_pass "type=BINARY" || log_fail "type=$MTYPE (expected BINARY)"

# ----- 4. Payload is byte-exact -----
log_test "binary payload survives round-trip byte-exact"
MDATA=$(echo "$INBOX" | jq -r --arg p "$BIN_PAYLOAD" '[.data.messages[]? | select(.data == $p)] | .[0].data // empty')
if [ "$MDATA" = "$BIN_PAYLOAD" ]; then
    log_pass "payload matches"
else
    log_fail "payload mismatch (got_len=${#MDATA} want_len=${#BIN_PAYLOAD})"
    echo "  got:  ${MDATA:0:60}"
    echo "  want: ${BIN_PAYLOAD:0:60}"
fi

log_test "no panics/fatals"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "=========================================="
echo "Binary message summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
