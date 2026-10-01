#!/bin/bash
# Inbox display order: messages should list in the order they were received,
# not grouped by message type. The inbox saves files under
# ~/.pilot/inbox/{type}-{ts-ms}-{seq}.json, which means a plain
# os.ReadDir() (alpha order) groups by type prefix first: e.g. a binary
# message that arrived SECOND ends up displayed before a text message
# that arrived FIRST, because "binary-..." sorts before "text-...".
#
# For a service agent watching its inbox, this inverts the effective
# processing order whenever request types are mixed. This test sends an
# interleaved sequence (text, binary, text, json, text) and asserts the
# inbox returns them in chronological (received_at) order.

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
echo "Inbox chronological ordering integration"
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
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# Clear agent-b's inbox.
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- Send 5 messages from agent-a to agent-b in interleaved types -----
# Payload uniquely identifies the position in the send order so we can
# verify ordering regardless of type.
log_test "send 5 messages of mixed types in chronological order"
declare -a TYPES=(text binary text json text)
for i in 1 2 3 4 5; do
    T=${TYPES[$((i-1))]}
    DATA="pos-$i"
    # JSON type requires a valid JSON payload.
    if [ "$T" = "json" ]; then
        DATA="{\"pos\":$i}"
    fi
    OUT=$($DC exec -T agent-a pilotctl --json send-message agent-b --data "$DATA" --type "$T" 2>&1)
    if ! echo "$OUT" | jq -e '.status == "ok"' >/dev/null 2>&1; then
        log_fail "send pos-$i ($T) failed: $(echo "$OUT" | head -c 200)"
        exit 1
    fi
    sleep 0.3
done
log_pass "5 messages sent"

# Wait until agent-b's inbox has 5 messages.
for _ in $(seq 1 20); do
    N=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.total // 0')
    if [ "$N" -ge 5 ]; then break; fi
    sleep 1
done
if [ "$N" -ge 5 ]; then
    log_pass "agent-b inbox has $N messages"
else
    log_fail "agent-b inbox only has $N/5 messages"
    exit 1
fi

# ----- Inbox order must be chronological (pos-1..pos-5) -----
log_test "pilotctl inbox returns messages in chronological (send) order"
INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
# Each message's data field encodes the position. Extract just the integer
# trailing "pos-" (or from the json payload).
ORDER=$(echo "$INBOX" | jq -r '
    .data.messages[].data
    | capture("pos-(?<n>[0-9]+)|\"pos\":(?<n2>[0-9]+)")
    | (.n // .n2)
' | tr '\n' ' ')
EXPECTED="1 2 3 4 5 "
if [ "$ORDER" = "$EXPECTED" ]; then
    log_pass "inbox order is chronological: $ORDER"
else
    log_fail "inbox order is NOT chronological"
    echo "  expected: $EXPECTED"
    echo "  got:      $ORDER"
    echo "  raw received_at values:"
    echo "$INBOX" | jq -r '.data.messages[].received_at' | sed 's/^/    /'
fi

# ----- received_at timestamps must also be monotonically non-decreasing -----
log_test "received_at is monotonically non-decreasing"
TIMES=$(echo "$INBOX" | jq -r '.data.messages[].received_at')
PREV=""
MONO=1
while IFS= read -r T; do
    if [ -n "$PREV" ] && [[ "$T" < "$PREV" ]]; then
        MONO=0
    fi
    PREV="$T"
done <<< "$TIMES"
if [ "$MONO" = "1" ]; then
    log_pass "received_at is monotonic"
else
    log_fail "received_at is NOT monotonic"
    echo "$TIMES" | sed 's/^/    /'
fi

# ----- No panics/fatals -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Inbox ordering test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
