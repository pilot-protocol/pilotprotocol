#!/bin/bash
# Parallel integration-test runner with workload-aware scheduling.
#
# Distributes tests across N worker slots. Each worker gets its own
# docker-compose project + /24 subnet so `$DC down -v` / `$DC up -d`
# stay scoped per worker and don't collide. NAT tests use a dedicated
# 3-lane semaphore (each lane has its own RFC5737 / RFC2544 subnet
# pair) so up to 3 NAT tests can overlap.
#
# Known-long tests are scheduled first (instead of alphabetical) so they
# overlap with the short tests rather than showing up as a tail.
#
# Usage:
#   ./run-all.sh                 # default concurrency=10 (match CPU count)
#   ./run-all.sh -j 6            # 6 workers
#   ./run-all.sh -j 4 test_task_*.sh
#   ./run-all.sh --list          # print discovered tests (scheduled order) and exit
#
# Output:
#   logs/<test_name>.log         # full stdout+stderr per test
#   logs/summary.md              # aggregated pass/fail/timing markdown
#   logs/.timing.tsv             # per-task worker/start/end for post-hoc analysis
#
# Exit code: 0 if all passed, 1 if any failed.

cd "$(dirname "$0")" || exit 1

# Many tests bound a host-side command with timeout(1), which macOS does
# not ship. Without it each of those calls fails with "command not found"
# and the test reports a product failure. Fall back to the bundled shim.
if ! command -v timeout >/dev/null 2>&1; then
    PATH="$PWD/shims:$PATH"
    export PATH
fi

JOBS=8
LIST_ONLY=0
PATTERNS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -j)
            JOBS="$2"
            shift 2
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        -h|--help)
            sed -n '2,24p' "$0"
            exit 0
            ;;
        *)
            PATTERNS="$PATTERNS $1"
            shift
            ;;
    esac
done

# Discover tests into a newline-separated list.
if [ -z "$PATTERNS" ]; then
    TESTS=$(ls test_*.sh 2>/dev/null | sort)
else
    TESTS=""
    for pat in $PATTERNS; do
        for f in $pat; do
            [ -f "$f" ] && TESTS="$TESTS
$f"
        done
    done
    TESTS=$(printf '%s\n' "$TESTS" | sed '/^$/d' | sort -u)
fi

# Always exclude: the runner itself, the in-container p2p driver, the
# python SDK test, and test_cli.sh. test_cli.sh is the in-container driver
# for the Dockerfile image: run on the host it starts with
# `pkill -9 -f pilot-daemon` and then launches a daemon against the public
# network, which kills the developer's own daemon.
TESTS=$(printf '%s\n' "$TESTS" | grep -v '^run-all\.sh$' | grep -v '^test_p2p\.sh$' | grep -v '^test_sdk\.py$' | grep -v '^test_cli\.sh$')

if [ -z "$TESTS" ]; then
    echo "no tests matched" >&2
    exit 2
fi

# Scheduler: put known-long tests FIRST so they overlap with short tests
# rather than becoming a tail. Durations from a prior rerun (logs.rerun5).
# Any test not in this list runs after the long-tail at default priority.
LONG_FIRST="
test_resilience.sh
test_dur_steady_10min.sh
test_dur_idle_10min.sh
test_dur_steady_compressed_24h.sh
test_sec_rekey_flood.sh
test_size_task_result_10mb.sh
test_chaos_loss30_all_ops.sh
test_size_file_100mb.sh
test_force_relay_task.sh
test_rendezvous_restart_midflight.sh
test_nat_conntrack_timeout.sh
test_splitbrain_heal.sh
test_task_accept_expiry.sh
test_receiver_sigkill_midtask.sh
test_race_polo_read_write.sh
test_beacon_restart_midflight.sh
test_sec_sybil_reputation.sh
"

ORDERED=""
for t in $LONG_FIRST; do
    if printf '%s\n' "$TESTS" | grep -qx "$t"; then
        ORDERED="$ORDERED
$t"
    fi
done
# Append all remaining tests that weren't in LONG_FIRST, preserving sort order.
LONG_RE=$(printf '%s\n' $LONG_FIRST | sed '/^$/d' | paste -sd '|' -)
REMAINING=$(printf '%s\n' "$TESTS" | grep -vE "^(${LONG_RE})\$")
TESTS=$(printf '%s\n%s\n' "$ORDERED" "$REMAINING" | sed '/^$/d')

if [ "$LIST_ONLY" = "1" ]; then
    printf '%s\n' "$TESTS"
    exit 0
fi

NTESTS=$(printf '%s\n' "$TESTS" | wc -l | tr -d ' ')

LOGDIR="logs"
rm -rf "$LOGDIR"
mkdir -p "$LOGDIR"

QUEUE="$LOGDIR/.queue"
RESULTS="$LOGDIR/.results"
TIMING="$LOGDIR/.timing.tsv"
LOCKDIR="$LOGDIR/.lock.d"
# NAT semaphore: 5 "lanes" — each lane owns a distinct pair of
# non-routable /24s so up to 5 NAT tests can run at the same time.
# Without enough lanes, NAT tests serialize behind a too-small mutex
# and Docker IPAM occasionally refuses overlapping subnet creation
# when lanes get reused before their previous tests fully tore down.
# Bumped from 3 to 5 — eliminates the "compose up failed" / "only 1
# registered" flakes on test_nat_dual_symmetric and friends.
NATLANE0="$LOGDIR/.natlane0.d"
NATLANE1="$LOGDIR/.natlane1.d"
NATLANE2="$LOGDIR/.natlane2.d"
NATLANE3="$LOGDIR/.natlane3.d"
NATLANE4="$LOGDIR/.natlane4.d"
printf '%s\n' "$TESTS" >"$QUEUE"
: >"$RESULTS"
: >"$TIMING"
rmdir "$LOCKDIR" "$NATLANE0" "$NATLANE1" "$NATLANE2" "$NATLANE3" "$NATLANE4" 2>/dev/null || true

# Portable mutex (macOS lacks flock). mkdir is atomic on POSIX fs.
acquire_lock() {
    while ! mkdir "$LOCKDIR" 2>/dev/null; do
        sleep 0.05
    done
}
release_lock() {
    rmdir "$LOCKDIR" 2>/dev/null || true
}

# Try to grab any free NAT lane. Returns lane index (0/1/2) on stdout
# or blocks forever polling. Each lane's subnet pair is set in the
# caller via NAT_PUB / NAT_PRV env before running the test.
acquire_nat_lane() {
    while true; do
        for lane in 0 1 2 3 4; do
            local dir
            case "$lane" in
                0) dir="$NATLANE0" ;;
                1) dir="$NATLANE1" ;;
                2) dir="$NATLANE2" ;;
                3) dir="$NATLANE3" ;;
                4) dir="$NATLANE4" ;;
            esac
            if mkdir "$dir" 2>/dev/null; then
                echo "$lane"
                return
            fi
        done
        sleep 0.15
    done
}
release_nat_lane() {
    local lane="$1"
    case "$lane" in
        0) rmdir "$NATLANE0" 2>/dev/null ;;
        1) rmdir "$NATLANE1" 2>/dev/null ;;
        2) rmdir "$NATLANE2" 2>/dev/null ;;
        3) rmdir "$NATLANE3" 2>/dev/null ;;
        4) rmdir "$NATLANE4" 2>/dev/null ;;
    esac
}

echo "==> $NTESTS tests, $JOBS parallel workers, 5 NAT lanes"
RUN_START=$(date +%s)

# Pre-pull images that the webhook overlay depends on. Without this,
# 8 parallel workers race to pull `python:3.12-slim` on first use,
# stretching the cold-start past the webhook-sink healthcheck budget
# and producing 4-5 spurious failures per run. Single-shot pull here
# warms the local image cache so every test starts the container
# instantly.
docker pull -q python:3.12-slim >/dev/null 2>&1 || true

# Worker: pops tests one at a time from $QUEUE under lock. Each test
# runs with a worker-scoped compose project + subnet so parallel workers
# don't fight over container names or IPs.
worker() {
    wid="$1"
    proj="pilot-w${wid}"
    prefix="172.29.$((10+wid))"
    export COMPOSE_PROJECT_NAME="$proj"
    export PILOT_SUBNET_PREFIX="$prefix"
    # Under N-way parallel docker churn, registration round-trips and
    # policy IPCs can double in wall-clock vs. standalone runs. Scale
    # stack-boot wait budgets in tests that honor PILOT_TEST_WAIT_MULT
    # (see _lib.sh::_wait_budget, nat_test_common.sh::wait_registered).
    export PILOT_TEST_WAIT_MULT="${PILOT_TEST_WAIT_MULT:-2}"

    while true; do
        acquire_lock
        test=$(head -n 1 "$QUEUE")
        if [ -n "$test" ]; then
            sed -i.bak '1d' "$QUEUE"
            rm -f "$QUEUE.bak"
        fi
        release_lock

        if [ -z "$test" ]; then
            break
        fi

        log="$LOGDIR/${test%.sh}.log"

        # NAT lane acquisition + per-lane subnet pair.
        is_nat=0
        lane=""
        case "$test" in test_nat_*) is_nat=1 ;; esac
        if [ "$is_nat" = "1" ]; then
            lane=$(acquire_nat_lane)
            case "$lane" in
                0) export NAT_PUB="192.0.2";  export NAT_PRV="198.51.100" ;;
                1) export NAT_PUB="198.18.0"; export NAT_PRV="198.18.1"  ;;
                2) export NAT_PUB="198.18.2"; export NAT_PRV="198.18.3"  ;;
                3) export NAT_PUB="198.18.4"; export NAT_PRV="198.18.5"  ;;
                4) export NAT_PUB="198.18.6"; export NAT_PRV="198.18.7"  ;;
            esac
            # nat-gw.sh reads these names; export both spellings for compat.
            export PUBLIC_SUBNET="$NAT_PUB"
            export PRIVATE_SUBNET="$NAT_PRV"
        fi

        t0=$(date +%s)
        t0_wall=$(date '+%H:%M:%S')
        echo "[worker-$wid] $test start @ $t0_wall${lane:+ nat-lane=$lane}" >&2
        bash "$test" >"$log" 2>&1
        rc=$?
        t1=$(date +%s)
        dur=$((t1 - t0))

        [ "$is_nat" = "1" ] && release_nat_lane "$lane"

        status="PASS"
        [ $rc -ne 0 ] && status="FAIL"
        echo "[worker-$wid] $test $status (${dur}s)" >&2

        acquire_lock
        printf '%s\t%s\t%s\t%s\n' "$test" "$status" "$dur" "$rc" >>"$RESULTS"
        printf '%s\t%s\t%s\t%s\t%s\n' "$wid" "$t0" "$t1" "${lane:--}" "$test" >>"$TIMING"
        release_lock

        # Best-effort cleanup so the next test this worker picks up starts
        # from a clean slate.
        docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1 || true
    done
}

# Spawn workers.
PIDS=""
i=0
while [ $i -lt "$JOBS" ]; do
    worker "$i" &
    PIDS="$PIDS $!"
    i=$((i+1))
done

for p in $PIDS; do
    wait "$p"
done

RUN_END=$(date +%s)
TOTAL_DUR=$((RUN_END - RUN_START))

# Aggregate summary.
PASS=0
FAIL=0
TOTAL=0
SERIAL_DUR=0
while IFS="$(printf '\t')" read -r t_test t_status t_dur t_rc; do
    TOTAL=$((TOTAL + 1))
    SERIAL_DUR=$((SERIAL_DUR + t_dur))
    case "$t_status" in
        PASS) PASS=$((PASS + 1)) ;;
        *)    FAIL=$((FAIL + 1)) ;;
    esac
done <"$RESULTS"

SPEEDUP="?"
if [ "$TOTAL_DUR" -gt 0 ]; then
    SPEEDUP=$(awk -v s="$SERIAL_DUR" -v w="$TOTAL_DUR" 'BEGIN{printf "%.2fx", s/w}')
fi

# Per-worker utilization: sum of (end-start) per wid / wall-clock.
UTIL=$(awk -F'\t' -v rs="$RUN_START" -v re="$RUN_END" '
{
  wid=$1; t0=$2; t1=$3
  busy[wid] += (t1 - t0)
  if (wid > maxwid) maxwid = wid
}
END {
  wall = re - rs
  if (wall <= 0) wall = 1
  for (w = 0; w <= maxwid; w++) {
    pct = 100.0 * (busy[w] / wall)
    printf "w%d=%.1f%% ", w, pct
  }
}' "$TIMING")

{
    echo "# Integration test run summary"
    echo
    echo "- Run duration: ${TOTAL_DUR}s"
    echo "- Workers: $JOBS"
    echo "- Tests: $TOTAL (pass=$PASS, fail=$FAIL)"
    echo "- Serial sum: ${SERIAL_DUR}s (speedup = $SPEEDUP)"
    echo "- Utilization: $UTIL"
    echo
    echo "| Status | Test | Duration | Exit |"
    echo "|--------|------|----------|------|"
    awk -F'\t' '{printf "%s\t%s\t%s\t%s\n", ($2=="FAIL"?"0":"1"), $3, $1, $4}' "$RESULTS" \
        | sort -k1,1 -k2,2nr \
        | awk -F'\t' '{print $3 "\t" ($1=="0"?"FAIL":"PASS") "\t" $2 "\t" $4}' \
        | while IFS="$(printf '\t')" read -r r_test r_status r_dur r_rc; do
            echo "| $r_status | \`$r_test\` | ${r_dur}s | $r_rc |"
        done
    echo
    if [ "$FAIL" -gt 0 ]; then
        echo "## Failed logs"
        echo
        while IFS="$(printf '\t')" read -r f_test f_status f_dur f_rc; do
            [ "$f_status" = "FAIL" ] || continue
            echo "### \`$f_test\` (exit=$f_rc, ${f_dur}s)"
            echo
            echo '```'
            tail -n 30 "$LOGDIR/${f_test%.sh}.log" 2>/dev/null || echo "(no log)"
            echo '```'
            echo
        done <"$RESULTS"
    fi
} >"$LOGDIR/summary.md"

rm -f "$QUEUE"
rmdir "$LOCKDIR" 2>/dev/null || true

echo
cat "$LOGDIR/summary.md"
echo
echo "==> full logs in $LOGDIR/   timing in $TIMING"
[ "$FAIL" -eq 0 ]
