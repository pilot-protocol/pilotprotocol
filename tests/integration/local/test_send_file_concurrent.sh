#!/bin/bash
# Concurrent send-file burst.
#
# Agent-a launches 10 send-file invocations in parallel, each with a
# distinct 2 KiB payload that encodes its own index. Targets:
#
#   - receiver accept loop: a new goroutine per dataexchange.Connection
#     must coexist without clobbering the shared inboxSeq atomic
#   - inbox seq uniqueness: every received file must land on disk with
#     a distinct -000NNN suffix (no overwrite, no drop)
#   - per-connection read serialization: a single conn handles exactly
#     one frame here, so we stress the accept path, not in-conn framing
#   - whole-frame sha256 round-trip under contention, not just under
#     sequential sends (existing test_send_file_integrity.sh covers
#     sequential 1K/50K/200K)
#
# Source filenames share the same stem template "burst-NN.dat" so
# that when the receiver strips the extension and appends the seq,
# a race in stem extraction (same basename in the same millisecond
# would collide without the seq) is directly observable.

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
N=10

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Concurrent send-file burst ($N parallel)"
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

$DC exec -T agent-b bash -c 'rm -rf /root/.pilot/received && mkdir -p /root/.pilot/received' >/dev/null 2>&1

# ----- 1. Create N distinct 2 KiB source files on agent-a ----------
# Use non-zero-padded indices (1..10) so that bash's arithmetic
# context doesn't misinterpret leading zeros as octal ("08", "09").
log_test "create $N source files with distinct content"
$DC exec -T agent-a bash -c "
    rm -f /tmp/burst-*.dat
    for i in \$(seq 1 $N); do
        head -c 2048 /dev/urandom | base64 | head -c 2048 >/tmp/burst-\$i.dat
        printf '__FILE_%d__' \"\$i\" >>/tmp/burst-\$i.dat
    done
" >/dev/null 2>&1

# Compute source checksums into /tmp/src_sums.txt keyed by index so we
# don't need bash-4 associative arrays on the outer host shell.
SUMS_FILE=$(mktemp)
for i in $(seq 1 $N); do
    SUM=$($DC exec -T agent-a sha256sum "/tmp/burst-$i.dat" | awk '{print $1}')
    if [ -z "$SUM" ]; then
        log_fail "missing source sha256 for burst-$i.dat"
        rm -f "$SUMS_FILE"
        exit 1
    fi
    echo "$i $SUM" >>"$SUMS_FILE"
done
log_pass "source set ready ($N distinct checksums)"

# ----- 2. Launch N parallel send-file calls ------------------------
log_test "launch $N parallel send-file calls from agent-a"
$DC exec -T agent-a bash -c "
    rm -f /tmp/send-*.out
    pids=''
    for i in \$(seq 1 $N); do
        (pilotctl --json send-file agent-b /tmp/burst-\$i.dat >/tmp/send-\$i.out 2>&1) &
        pids=\"\$pids \$!\"
    done
    for p in \$pids; do wait \$p; done
"

# ----- 3. Verify each send reported an ack byte count >= 2048 -----
acked=0
for i in $(seq 1 $N); do
    ACK=$($DC exec -T agent-a bash -c "cat /tmp/send-$i.out 2>/dev/null | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1")
    if [ -n "$ACK" ] && [ "$ACK" -ge 2048 ]; then
        acked=$((acked+1))
    else
        RAW=$($DC exec -T agent-a bash -c "cat /tmp/send-$i.out 2>/dev/null | head -c 200")
        echo "  [warn] burst-$i ack missing or short: $RAW"
    fi
done
if [ "$acked" -ge $N ]; then
    log_pass "all $N sends acked (>=2048 bytes each)"
else
    log_fail "only $acked/$N sends acked"
fi

# ----- 4. Receiver has exactly N files -----------------------------
log_test "receiver has exactly $N files in received/"
for _ in $(seq 1 30); do
    NREC=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null | wc -l' | tr -d ' \r\n')
    if [ "$NREC" = "$N" ]; then break; fi
    sleep 0.5
done
if [ "$NREC" = "$N" ]; then
    log_pass "received=$N"
else
    log_fail "received=$NREC, expected $N"
    $DC exec -T agent-b ls /root/.pilot/received/ 2>&1 | sed 's/^/    /'
fi

# ----- 5. All seq suffixes are distinct ----------------------------
log_test "all received filenames carry distinct -000NNN seq suffixes"
SEQS=$($DC exec -T agent-b bash -c 'ls /root/.pilot/received 2>/dev/null' | grep -oE '\-[0-9]{6}\.dat$' | sort)
UNIQ=$(echo "$SEQS" | sort -u | wc -l | tr -d ' ')
TOT=$(echo "$SEQS" | wc -l | tr -d ' ')
if [ "$UNIQ" = "$TOT" ] && [ "$TOT" = "$N" ]; then
    log_pass "all $N seqs unique"
else
    log_fail "seq counts: total=$TOT unique=$UNIQ (want $N/$N)"
    echo "$SEQS" | sed 's/^/    /'
fi

# ----- 6. Per-index sha256 round-trip ------------------------------
log_test "per-index sha256 matches (no cross-payload swap)"
mismatches=0
missing=0
for i in $(seq 1 $N); do
    # Each burst-N source maps to burst-N-{ts}-{seq}.dat on receiver.
    # Anchor the index match with a trailing "-" so burst-1 does not
    # match burst-10.
    RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received | grep '^burst-$i-' | head -n1" | tr -d '\r\n')
    if [ -z "$RECV" ]; then
        missing=$((missing+1))
        echo "  [miss] no recv match for burst-$i"
        continue
    fi
    SRC_SUM=$(awk -v k="$i" '$1==k {print $2}' "$SUMS_FILE")
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
    if [ "$SRC_SUM" != "$DST" ]; then
        mismatches=$((mismatches+1))
        echo "  [bad ] burst-$i src=${SRC_SUM:0:12}... dst=${DST:0:12}... file=$RECV"
    fi
done
rm -f "$SUMS_FILE"
if [ "$missing" = "0" ] && [ "$mismatches" = "0" ]; then
    log_pass "all $N payloads round-tripped by index"
else
    log_fail "missing=$missing mismatches=$mismatches"
fi

# ----- 7. No panic/fatal in daemon logs ---------------------------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Concurrent send-file summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
