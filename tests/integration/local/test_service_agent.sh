#!/bin/bash
# Service-agent request/reply pattern: agent-b runs a responder loop that
# watches its inbox and replies to each incoming message; agent-a acts as
# the calling client. Exercises the same pattern the docs describe for
# service agents on network 9.

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

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Service agent (request/reply) integration"
echo "=========================================="

log_test "Starting p2p stack"
docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1
docker compose -f docker-compose.multi.yml up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered (count=$COUNT)"
else
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# Clear inboxes so we start clean.
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox --clear >/dev/null
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json inbox --clear >/dev/null

# ----- 1. Start responder loop on agent-b -----
log_test "Starting responder loop on agent-b (echo service)"
docker compose -f docker-compose.multi.yml exec -d agent-b bash -c "
set -e
INBOX_DIR=/root/.pilot/inbox
while [ ! -f /tmp/responder_stop ]; do
    for f in \$(ls -1 \$INBOX_DIR/*.json 2>/dev/null); do
        FROM=\$(jq -r '.from' \"\$f\" 2>/dev/null)
        DATA=\$(jq -r '.data' \"\$f\" 2>/dev/null)
        echo \"\$(date +%H:%M:%S.%N) file=\$f from=\$FROM data=\$DATA\" >> /tmp/responder_trace.log
        if [ -n \"\$FROM\" ] && [ \"\$FROM\" != \"null\" ]; then
            pilotctl --json send-message \"\$FROM\" --data \"echo: \$DATA\" --type text >>/tmp/responder_sent.log 2>&1
        fi
        rm -f \"\$f\"
    done
    sleep 0.2
done
echo responder-exit >> /tmp/responder_sent.log
"
sleep 1
log_pass "responder loop started"

# ----- 2. Client sends 5 requests, gets 5 replies -----
log_test "agent-a sends 5 requests and receives 5 echoes"
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox --clear >/dev/null

for i in 1 2 3 4 5; do
    docker compose -f docker-compose.multi.yml exec -T agent-a \
        pilotctl --json send-message agent-b --data "req-$i" --type text >/dev/null
done

# Give the responder a few cycles to process + reply.
REPLIES=0
for _ in $(seq 1 30); do
    REPLIES=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox | jq -r '[.data.messages[]? | select(.data | startswith("echo: req-"))] | length')
    if [ "$REPLIES" -ge 5 ]; then break; fi
    sleep 1
done
if [ "$REPLIES" -ge 5 ]; then
    log_pass "got $REPLIES echo replies"
else
    log_fail "only got $REPLIES/5 echo replies"
    docker compose -f docker-compose.multi.yml exec -T agent-b cat /tmp/responder_sent.log 2>&1 | tail -10
fi

# ----- 3. Replies contain all 5 request bodies (correlation) -----
log_test "each reply echoes the original request body"
MISSING=""
INBOX=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox)
for i in 1 2 3 4 5; do
    if ! echo "$INBOX" | jq -e --arg needle "echo: req-$i" '.data.messages[]? | select(.data == $needle)' >/dev/null 2>&1; then
        MISSING="$MISSING req-$i"
    fi
done
if [ -z "$MISSING" ]; then
    log_pass "all 5 responses correlate to their requests"
else
    log_fail "missing echoes for:$MISSING"
fi

# ----- 4. Service down → messages queue; service back up → drained -----
log_test "service outage: messages queue while responder stopped"
docker compose -f docker-compose.multi.yml exec -T agent-b touch /tmp/responder_stop
sleep 2  # let the loop notice the flag

docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox --clear >/dev/null
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json inbox --clear >/dev/null

# Send with responder down — messages should pile up on agent-b's inbox and
# NOT get echoed back.
for i in 1 2 3; do
    docker compose -f docker-compose.multi.yml exec -T agent-a \
        pilotctl --json send-message agent-b --data "queued-$i" --type text >/dev/null
done
sleep 3

QUEUED=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json inbox | jq -r '.data.total')
CLIENT_ECHOES=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox | jq -r '[.data.messages[]? | select(.data | startswith("echo: queued-"))] | length')
if [ "$QUEUED" -ge 3 ] && [ "$CLIENT_ECHOES" = "0" ]; then
    log_pass "messages queued on service inbox (queued=$QUEUED) and no echoes delivered"
else
    log_fail "outage test broken (queued=$QUEUED client_echoes=$CLIENT_ECHOES)"
fi

# ----- 5. Responder restart drains the queue -----
log_test "restarting responder drains queued requests"
docker compose -f docker-compose.multi.yml exec -T agent-b rm -f /tmp/responder_stop
# Start a fresh loop — the old one already exited on the flag.
docker compose -f docker-compose.multi.yml exec -d agent-b bash -c "
set -e
INBOX_DIR=/root/.pilot/inbox
while [ ! -f /tmp/responder_stop ]; do
    for f in \$(ls -1 \$INBOX_DIR/*.json 2>/dev/null); do
        FROM=\$(jq -r '.from' \"\$f\" 2>/dev/null)
        DATA=\$(jq -r '.data' \"\$f\" 2>/dev/null)
        if [ -n \"\$FROM\" ] && [ \"\$FROM\" != \"null\" ]; then
            pilotctl --json send-message \"\$FROM\" --data \"echo: \$DATA\" --type text >>/tmp/responder_sent.log 2>&1
        fi
        rm -f \"\$f\"
    done
    sleep 0.2
done
echo responder-exit >> /tmp/responder_sent.log
"

DRAINED=0
for _ in $(seq 1 30); do
    DRAINED=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox | jq -r '[.data.messages[]? | select(.data | startswith("echo: queued-"))] | length')
    if [ "$DRAINED" -ge 3 ]; then break; fi
    sleep 1
done
if [ "$DRAINED" -ge 3 ]; then
    log_pass "queued requests drained after restart (echoes=$DRAINED)"
else
    log_fail "restart failed to drain queue (echoes=$DRAINED)"
fi

# ----- 6. Concurrent clients: N parallel requests all get replies -----
log_test "8 parallel client requests all get replies"
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox --clear >/dev/null

for i in $(seq 1 8); do
    docker compose -f docker-compose.multi.yml exec -d agent-a \
        bash -c "pilotctl --json send-message agent-b --data 'para-$i' --type text >/dev/null 2>&1"
done

PARA=0
for _ in $(seq 1 30); do
    PARA=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json inbox | jq -r '[.data.messages[]? | select(.data | startswith("echo: para-"))] | length')
    if [ "$PARA" -ge 8 ]; then break; fi
    sleep 1
done
if [ "$PARA" -ge 8 ]; then
    log_pass "all 8 parallel requests got echoed (count=$PARA)"
else
    log_fail "only $PARA/8 parallel echoes delivered"
fi

# ----- 7. No panic/fatal in either daemon log -----
log_test "no panics/fatals during the service-agent workload"
BAD=$(docker compose -f docker-compose.multi.yml logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found panic/fatal entries: $BAD"
fi

# Cleanup responder
docker compose -f docker-compose.multi.yml exec -T agent-b touch /tmp/responder_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Service agent test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
