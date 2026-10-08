#!/bin/bash
# Ping / send to a "ghost peer" — a node that WAS registered and
# had a live tunnel, but was then killed without a graceful unregister.
# Rendezvous still has its record, agent-a still has cached crypto, but
# the real UDP endpoint is dead.
#
# Differs from test_tasks_and_edge.sh "ping unknown hostname" — that tests
# an entirely unresolvable name. This tests a resolvable name whose
# endpoint no longer answers. The dial layer MUST:
#   - fail within the caller-supplied timeout (not spin forever)
#   - not poison the sender's local state (once b returns, a must work)
#   - not panic, fatal, or deadlock on agent-a
#
# This is the Matrix row "peer gone (ghost)" × {ping, send-message}.

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
echo "Ping / send to a ghost peer"
echo "=========================================="

log_test "fresh stack"
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

# ----- 1. Warm up tunnel so crypto + peer cache on agent-a are populated
log_test "warm-up ping a->b so agent-a has cached crypto+endpoint"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1; then
    log_pass "tunnel warm"
else
    log_fail "warmup ping failed — env not ready"
    exit 1
fi

# ----- 2. Kill agent-b HARD (no graceful unregister) ------------------
# -t 0: no SIGTERM grace, jump straight to SIGKILL. Rendezvous will NOT
# receive an unregister, so agent-b appears alive in the registry for a
# while. agent-a's local caches are unchanged.
log_test "SIGKILL agent-b (no graceful unregister)"
$DC kill agent-b >/dev/null 2>&1
sleep 1
if $DC ps --status running --services | grep -q "^agent-b$"; then
    log_fail "agent-b still running after kill"
    exit 1
else
    log_pass "agent-b is dead"
fi

# ----- 3. ping must fail within its declared timeout ------------------
log_test "ping a->b (ghost) fails within --timeout 4s"
T0=$(date +%s)
$DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 4s >/tmp/ghost_ping.txt 2>&1
RC=$?
T1=$(date +%s)
DELTA=$((T1 - T0))
if [ "$RC" -ne 0 ] && [ "$DELTA" -le 10 ]; then
    log_pass "ping failed in ${DELTA}s (rc=$RC)"
else
    log_fail "ping did not bound its own timeout: rc=$RC delta=${DELTA}s"
fi

# ----- 4. send-message must fail cleanly -----------------------------
log_test "send-message a->b (ghost) fails with clear error"
SM=$($DC exec -T agent-a bash -c 'timeout 10 pilotctl --json send-message agent-b --data "to-ghost" --type text' 2>&1)
RC=$?
if [ "$RC" -ne 0 ] || echo "$SM" | jq -e '.status == "error"' >/dev/null 2>&1; then
    log_pass "send-message refused (rc=$RC)"
else
    # Pilot historically accepts the enqueue even if peer is dead; fail only
    # if it claims success WITH an ack field set (i.e. lies about delivery).
    ACK=$(echo "$SM" | jq -r '.data.ack // empty' 2>/dev/null)
    if [ -n "$ACK" ] && [ "$ACK" != "null" ]; then
        log_fail "send-message CLAIMED delivery to dead peer: ack=$ACK"
    else
        log_pass "send-message returned without false-ack"
    fi
fi

# ----- 5. agent-a must not have panicked ----------------------------
log_test "agent-a has no panic/fatal after ghost attempts"
BAD=$($DC logs agent-a 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "agent-a log clean"
else
    log_fail "agent-a log: $BAD"
fi

# ----- 6. Bring agent-b back; a's cache must NOT be poisoned --------
log_test "restart agent-b; ping a->b works again"
$DC up -d agent-b >/dev/null 2>&1
# Wait for agent-b to be registered again.
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
OK=""
for _ in $(seq 1 20); do
    if $DC exec -T agent-a pilotctl ping agent-b --count 1 --timeout 4s >/dev/null 2>&1; then
        OK="yes"
        break
    fi
    sleep 1
done
if [ "$OK" = "yes" ]; then
    log_pass "ping a->b restored after ghost recovered"
else
    log_fail "a's state poisoned — ping still fails after b came back"
fi

echo
echo "=========================================="
echo "Ghost-peer summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
