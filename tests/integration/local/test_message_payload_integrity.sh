#!/bin/bash
# Payload-integrity round-trip for the dataexchange service.
#
# agent-a sends four messages to agent-b, each built to stress a
# different encoding boundary:
#   1. Large TEXT   - 8 KiB of 'x' characters (buffer / chunking)
#   2. JSON mixed   - double-quote, backslash, newline, tab embedded
#                     inside a JSON string (escape correctness)
#   3. Unicode TEXT - UTF-8 emoji + accented chars (multi-byte safety)
#   4. Huge TEXT    - 16 KiB of a repeating alphanumeric pattern
#                     (single message larger than typical MTU)
#
# For each, agent-b reads its inbox and we assert the received .data
# is byte-exact with what was sent. The inbox is JSON-serialized by
# the daemon, so any mishandling of escapes, unicode, or message
# chunking will surface as a mismatch.
#
# This targets bugs that pure fan-out / FIFO tests can't see:
#   - silent truncation of large payloads at some internal boundary
#   - double-escaping or loss of backslash/quote in JSON serialization
#   - UTF-8 bytes treated as ASCII somewhere in the write path
#   - base64 / hex re-encoding inserting artifacts

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
echo "Message payload integrity"
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

$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- Build payloads --------------------------------------------------
# Use printf so we don't pick up shell-expansion quirks from `echo -e`.
# Large text
LARGE_TEXT=$(printf 'x%.0s' $(seq 1 8192))
# Huge text: alternating 16-char pattern to catch block-boundary bugs
HUGE_PATTERN="0123456789abcdef"
HUGE_TEXT=""
for _ in $(seq 1 1024); do HUGE_TEXT="$HUGE_TEXT$HUGE_PATTERN"; done    # 1024 * 16 = 16 KiB
# Escape-heavy JSON: embed literal "  \  \n  \t  " and a JSON-ish payload
# Expected ROUND-TRIP string (what server-side .data field should equal).
JSON_DATA='{"q":"he said \"hi\" and \\ backslash\nnewline\t tab"}'
# Unicode: emoji + accented chars
UNI_DATA="café — 🛰️ orbit ✈ 😀"

echo "LARGE_TEXT len=${#LARGE_TEXT}"
echo "HUGE_TEXT  len=${#HUGE_TEXT}"
echo "JSON_DATA  len=${#JSON_DATA}"
echo "UNI_DATA   len=${#UNI_DATA}  (byte length: $(printf '%s' "$UNI_DATA" | wc -c))"

# ----- 1. Send all four messages from agent-a -> agent-b ---------------
# Use pilotctl --json for deterministic response. Send via stdin on
# pilotctl is not supported, so we pass --data.
log_test "agent-a sends 4 messages with varied payloads"
$DC exec -T agent-a pilotctl --json send-message agent-b --data "$LARGE_TEXT" --type text >/dev/null 2>&1
$DC exec -T agent-a pilotctl --json send-message agent-b --data "$JSON_DATA"  --type json >/dev/null 2>&1
$DC exec -T agent-a pilotctl --json send-message agent-b --data "$UNI_DATA"   --type text >/dev/null 2>&1
$DC exec -T agent-a pilotctl --json send-message agent-b --data "$HUGE_TEXT"  --type text >/dev/null 2>&1
log_pass "4 sends issued"

# ----- 2. Wait for 4 messages in agent-b's inbox -----------------------
log_test "agent-b inbox contains all 4 messages within 15s"
for _ in $(seq 1 30); do
    TOTAL=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
    if [ "$TOTAL" = "4" ]; then break; fi
    sleep 0.5
done
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
TOTAL=$(echo "$INBOX" | jq -r '.data.total // 0')
if [ "$TOTAL" = "4" ]; then
    log_pass "4 messages landed"
else
    log_fail "only $TOTAL/4 arrived"
    echo "$INBOX" | jq -r '.data.messages[]? | "  type=\(.type) len=\(.data|length)"'
fi

# Helper: extract first inbox message whose data length matches N.
match_by_len() {
    local want=$1
    echo "$INBOX" | jq -r --argjson n "$want" '[.data.messages[]? | select((.data|length) == $n)] | .[0].data // empty'
}

# ----- 3. Large text (8 KiB of 'x') round-trip is byte-exact ----------
log_test "large text (8 KiB) byte-exact round-trip"
GOT_LARGE=$(match_by_len ${#LARGE_TEXT})
if [ "$GOT_LARGE" = "$LARGE_TEXT" ]; then
    log_pass "large text matches (len=${#LARGE_TEXT})"
else
    log_fail "large text mismatch: got_len=${#GOT_LARGE} want_len=${#LARGE_TEXT}"
    echo "    first 80 got:  $(printf '%s' "$GOT_LARGE"  | head -c 80)"
    echo "    first 80 want: $(printf '%s' "$LARGE_TEXT" | head -c 80)"
fi

# ----- 4. Huge text (16 KiB pattern) round-trip is byte-exact ---------
log_test "huge text (16 KiB) byte-exact round-trip"
GOT_HUGE=$(match_by_len ${#HUGE_TEXT})
if [ "$GOT_HUGE" = "$HUGE_TEXT" ]; then
    log_pass "huge text matches (len=${#HUGE_TEXT})"
else
    log_fail "huge text mismatch: got_len=${#GOT_HUGE} want_len=${#HUGE_TEXT}"
    echo "    first 80 got:  $(printf '%s' "$GOT_HUGE"  | head -c 80)"
    echo "    first 80 want: $(printf '%s' "$HUGE_TEXT" | head -c 80)"
fi

# ----- 5. JSON escape-heavy string round-trip is byte-exact -----------
log_test "JSON escape-heavy payload byte-exact round-trip"
GOT_JSON=$(echo "$INBOX" | jq -r --arg d "$JSON_DATA" '[.data.messages[]? | select(.data == $d)] | .[0].data // empty')
if [ "$GOT_JSON" = "$JSON_DATA" ]; then
    log_pass "JSON data matches"
else
    log_fail "JSON data mismatch"
    echo "    got:  $GOT_JSON"
    echo "    want: $JSON_DATA"
fi

# ----- 6. Unicode payload round-trip is byte-exact --------------------
log_test "UTF-8 unicode payload byte-exact round-trip"
GOT_UNI=$(echo "$INBOX" | jq -r --arg d "$UNI_DATA" '[.data.messages[]? | select(.data == $d)] | .[0].data // empty')
if [ "$GOT_UNI" = "$UNI_DATA" ]; then
    log_pass "unicode matches: $GOT_UNI"
else
    log_fail "unicode mismatch"
    echo "    got:  $GOT_UNI"
    echo "    want: $UNI_DATA"
    echo "    got bytes:  $(printf '%s' "$GOT_UNI" | xxd | head -2)"
    echo "    want bytes: $(printf '%s' "$UNI_DATA" | xxd | head -2)"
fi

# ----- 7. Type labels preserved for each message ----------------------
log_test "message types preserved (3 TEXT + 1 JSON)"
T_TEXT=$(echo "$INBOX" | jq -r '[.data.messages[]? | select(.type == "TEXT")] | length')
T_JSON=$(echo "$INBOX" | jq -r '[.data.messages[]? | select(.type == "JSON")] | length')
if [ "$T_TEXT" = "3" ] && [ "$T_JSON" = "1" ]; then
    log_pass "types: TEXT=$T_TEXT JSON=$T_JSON"
else
    log_fail "type mix wrong: TEXT=$T_TEXT JSON=$T_JSON (want 3/1)"
fi

# ----- 8. No panic/fatal in daemon logs -------------------------------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Payload integrity summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
