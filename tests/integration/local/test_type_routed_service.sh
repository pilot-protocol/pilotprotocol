#!/bin/bash
# Type-routed service agent: agent-b runs a worker that processes ONLY
# JSON messages out of its inbox and leaves text/binary ones untouched.
# A realistic service shape — pick your protocol by message type.
#
# agent-a sends 2 JSON + 2 text + 2 binary messages (interleaved). The
# service worker on agent-b parses each JSON payload, extracts a `.req`
# id, and replies to agent-a with `json-reply:<req>`. text/binary are
# skipped and must remain in agent-b's inbox.
#
# Asserts:
#  - agent-a gets exactly 2 JSON replies correlated to its 2 JSON reqs
#  - agent-b's post-run inbox still contains 4 messages (2 text + 2 binary)
#  - no panics on either side

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
echo "Type-routed service agent integration"
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

$DC exec -T agent-a pilotctl --json inbox --clear >/dev/null 2>&1
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- 1. Start the selective JSON-only worker on agent-b -----
# Worker scans each inbox file, parses its "type" field, processes ONLY
# if type=="JSON", and removes the inbox file only for JSON matches.
# Text/binary messages stay in the inbox untouched.
log_test "start JSON-only worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/svc.log /tmp/svc_stop
    INBOX=/root/.pilot/inbox
    while [ ! -f /tmp/svc_stop ]; do
        for f in $(ls -1 $INBOX/*.json 2>/dev/null); do
            TYPE=$(jq -r ".type // \"\"" "$f" 2>/dev/null)
            if [ "$TYPE" != "JSON" ]; then
                continue
            fi
            FROM=$(jq -r ".from // \"\"" "$f" 2>/dev/null)
            DATA=$(jq -r ".data // \"\"" "$f" 2>/dev/null)
            REQ=$(echo "$DATA" | jq -r ".req // \"?\"" 2>/dev/null)
            echo "$(date +%H:%M:%S.%N) JSON handled req=$REQ from=$FROM" >> /tmp/svc.log
            if [ -n "$FROM" ] && [ "$FROM" != "null" ]; then
                pilotctl --json send-message "$FROM" --data "json-reply:$REQ" --type text >>/tmp/svc.log 2>&1 || true
            fi
            rm -f "$f"
        done
        sleep 0.2
    done
    echo svc-exit >> /tmp/svc.log
'
sleep 1
log_pass "worker running"

# ----- 2. Send 2 JSON + 2 text + 2 binary from agent-a, interleaved -----
log_test "agent-a sends 2 JSON, 2 text, 2 binary messages"
# Interleaved so if there's any ordering-sensitive bug it'd surface.
for i in 1 2; do
    $DC exec -T agent-a pilotctl --json send-message agent-b --data "{\"req\":$i}" --type json >/dev/null
    $DC exec -T agent-a pilotctl --json send-message agent-b --data "txt-$i" --type text >/dev/null
    $DC exec -T agent-a pilotctl --json send-message agent-b --data "bin-$i" --type binary >/dev/null
    sleep 0.15
done
log_pass "6 messages sent"

# ----- 3. Wait for exactly 2 JSON replies on agent-a -----
log_test "agent-a receives exactly 2 json-reply:* messages within 10s"
REPLIES=0
for _ in $(seq 1 20); do
    REPLIES=$($DC exec -T agent-a pilotctl --json inbox 2>/dev/null \
        | jq -r '[.data.messages[]? | select(.data | startswith("json-reply:"))] | length')
    if [ "$REPLIES" = "2" ]; then break; fi
    sleep 0.5
done
if [ "$REPLIES" = "2" ]; then
    log_pass "got 2 replies"
else
    log_fail "got $REPLIES/2 replies"
    $DC exec -T agent-b cat /tmp/svc.log 2>&1 | tail -10 | sed 's/^/    /'
fi

# ----- 4. Replies correlate: req=1 and req=2 both reported back -----
log_test "json replies are correlated 1:1"
INBOX=$($DC exec -T agent-a pilotctl --json inbox)
MATCHED=0
for i in 1 2; do
    if echo "$INBOX" | jq -e --arg w "json-reply:$i" '.data.messages[]? | select(.data == $w)' >/dev/null 2>&1; then
        MATCHED=$((MATCHED+1))
    fi
done
if [ "$MATCHED" = "2" ]; then
    log_pass "req 1 and req 2 both came back"
else
    log_fail "only $MATCHED/2 reqs correlated"
fi

# ----- 5. agent-b's inbox still has text + binary messages (4 leftovers) -----
log_test "agent-b retained 4 non-JSON messages in inbox"
B_IN=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
LEFT=$(echo "$B_IN" | jq -r '.data.total // 0')
# Types should all be non-JSON.
NON_JSON=$(echo "$B_IN" | jq -r '[.data.messages[]? | select(.type != "JSON")] | length')
JSON_LEFT=$(echo "$B_IN" | jq -r '[.data.messages[]? | select(.type == "JSON")] | length')
if [ "$LEFT" = "4" ] && [ "$NON_JSON" = "4" ] && [ "$JSON_LEFT" = "0" ]; then
    log_pass "agent-b inbox has 4 non-JSON (0 JSON left)"
else
    log_fail "agent-b inbox total=$LEFT non_json=$NON_JSON json=$JSON_LEFT"
    echo "$B_IN" | jq -r '.data.messages[]? | "  type=\(.type) data=\(.data)"'
fi

# ----- 6. Correct payloads retained: 2 text (txt-1, txt-2) + 2 binary (bin-1, bin-2) -----
log_test "retained messages are the exact 2 text + 2 binary payloads"
TXT_KEEPERS=$(echo "$B_IN" | jq -r '[.data.messages[]? | select(.type == "TEXT") | .data] | sort | join(",")')
BIN_KEEPERS=$(echo "$B_IN" | jq -r '[.data.messages[]? | select(.type == "BINARY") | .data] | sort | join(",")')
if [ "$TXT_KEEPERS" = "txt-1,txt-2" ] && [ "$BIN_KEEPERS" = "bin-1,bin-2" ]; then
    log_pass "retained payloads match expectations"
else
    log_fail "unexpected retention (text=\"$TXT_KEEPERS\" binary=\"$BIN_KEEPERS\")"
fi

# ----- 7. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup worker
$DC exec -T agent-b touch /tmp/svc_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Type-routed service test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
