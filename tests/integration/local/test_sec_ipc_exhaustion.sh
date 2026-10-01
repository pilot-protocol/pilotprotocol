#!/bin/bash
# Open 10k concurrent connections to the daemon's IPC Unix socket
# (/tmp/pilot.sock). The IPCServer (pkg/daemon/ipc.go) currently has NO
# per-client or total-client cap — see P2-002 in the problem registry.
# A per-process FD limit is the only natural bound.
#
# EXPECTED (spec):
#   - A per-client or total-connection cap fires BEFORE we exhaust the
#     process's FD table.
#   - Daemon remains responsive to a legitimate pilotctl invocation from
#     the same container throughout and after the test.
#
# LIKELY (current impl):
#   - Daemon accepts until FD limit, then accept() starts returning
#     EMFILE; dashboard / webhook / tunnel may degrade.
#   - This test IS expected to surface P2-002 as a red-on-first-run.

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
# shellcheck source=sec_helpers.sh
source ./sec_helpers.sh

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if ! wait_for 60 bash -c '
    c=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r ".total_nodes // 0")
    [ "$c" -ge 2 ]
'; then
    log_fail "agents did not register"
    exit 1
fi

# Raise the nofile limit INSIDE the container if possible — we want to
# exercise the daemon's cap, not the kernel default. If this is denied
# (no CAP_SYS_RESOURCE in the container), the test still runs at the
# default limit.
$DC exec -T agent-a sh -c 'ulimit -n 20000 2>/dev/null || true' >/dev/null 2>&1

log_test "attempt 10k concurrent IPC connections"
# Python one-liner: open N unix-domain sockets, then AFTER a settle
# window count the ones still alive. Server-side TCP accept() always
# succeeds at the kernel layer — the IPC cap closes excess sockets
# post-accept, which the client observes as EOF on the next read.
OPEN=$($DC exec -T agent-a python3 - <<'PY'
import socket, time
SOCK = "/tmp/pilot.sock"
N = 10000
conns = []
for _ in range(N):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(SOCK)
        conns.append(s)
    except Exception:
        break
# Give server a moment to close connections beyond its cap.
time.sleep(2)
alive = 0
for s in conns:
    try:
        s.setblocking(False)
        buf = s.recv(1)
        # EOF (b"") means server closed; any exception other than
        # BlockingIOError also means closed.
        if buf == b"":
            continue
    except BlockingIOError:
        alive += 1
    except Exception:
        pass
print(alive)
PY
)
OPEN=${OPEN:-0}
echo "successfully opened IPC conns: $OPEN"

log_test "daemon still responds to pilotctl info from a NEW connection"
# Slight sleep to let server-side cleanup catch up if anything.
sleep 2
if timeout 10 $DC exec -T agent-a pilotctl info >/dev/null 2>&1; then
    log_pass "daemon responsive after IPC exhaustion attempt"
else
    log_fail "daemon unreachable — new pilotctl IPC connects fail"
fi

log_test "per-client cap enforced (OPEN should be well below 10000)"
# Spec says there should be a cap. If there's no cap, OPEN will be close
# to 10000 (bounded only by nofile). If there's a cap, OPEN will be a
# much smaller explicit number.
if [ "$OPEN" -lt 2048 ]; then
    log_pass "IPC connection count capped at $OPEN"
else
    log_fail "no IPC cap detected ($OPEN conns opened) — see P2-002"
fi

log_test "no agent-a panic on accept() exhaustion"
if $DC logs agent-a 2>/dev/null | grep -qE 'panic:|fatal error:|too many open files'; then
    LOGMATCH=$($DC logs agent-a 2>/dev/null | grep -E 'panic:|fatal error:|too many open files' | head -3)
    # "too many open files" is a soft issue (expected if cap missing), but
    # a hard panic is a fail.
    if echo "$LOGMATCH" | grep -qE 'panic:|fatal error:'; then
        log_fail "panic under IPC pressure"
    else
        log_pass "EMFILE seen but no panic (still indicates missing cap)"
    fi
else
    log_pass "no panic/EMFILE in logs"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
