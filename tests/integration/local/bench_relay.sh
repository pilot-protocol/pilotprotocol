#!/bin/bash
# Bench relay vs direct steady-state throughput.
#
# Uses `pilotctl bench` which opens ONE long-lived connection to the
# echo port and pumps data through it — that gives clean steady-state
# numbers (the per-file send-file path was hitting retransmit stalls
# from connection-setup churn between iterations; see P1-010).

set -u
export COMPOSE_PROJECT_NAME="pilot-bench"
export PILOT_SUBNET_PREFIX="172.29.99"

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.bench.yml"

cd "$(dirname "$0")" || exit 1
# shellcheck source=chaos_helpers.sh
source ./chaos_helpers.sh

cleanup() {
    [ -n "${IP_A:-}" ] && [ -n "${IP_B:-}" ] && {
        heal_partition agent-a "$IP_B" >/dev/null 2>&1 || true
        heal_partition agent-b "$IP_A" >/dev/null 2>&1 || true
    }
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

SIZES_MB="${BENCH_SIZES_MB:-1 5 10 25 50}"
ITER="${BENCH_ITER:-3}"

RESULTS=""
record() { RESULTS="${RESULTS}$1	$2	$3	$4	$5
"; }

# Inner: run pilotctl bench, parse send-throughput from --json output.
# Returns "rc dur_ms send_MBps total_MBps".
time_bench() {
    local mode="$1" size_mb="$2"
    local out rc
    out=$($DC exec -T agent-a pilotctl --json bench agent-b "$size_mb" --timeout 600s 2>&1)
    rc=$?

    local sent_bytes recv_bytes send_dur total_dur send_mbps total_mbps total_dur_ms
    if [ "$rc" -eq 0 ]; then
        sent_bytes=$(echo "$out" | jq -r '.data.sent_bytes // empty')
        recv_bytes=$(echo "$out" | jq -r '.data.recv_bytes // empty')
        send_dur=$(echo "$out" | jq -r '.data.send_duration_ms // empty')
        total_dur=$(echo "$out" | jq -r '.data.total_duration_ms // empty')
        send_mbps=$(echo "$out" | jq -r '.data.send_throughput_mbps // empty')
        total_mbps=$(echo "$out" | jq -r '.data.total_throughput_mbps // empty')
        if [ -z "$total_dur" ] || [ "$total_dur" = "null" ]; then
            # Older bench output: only seconds-level fields. Compute from raw.
            send_dur=$(echo "$out" | jq -r '.data.send_duration_seconds // 0')
            total_dur=$(echo "$out" | jq -r '.data.total_duration_seconds // 0')
            total_dur_ms=$(awk -v s="$total_dur" 'BEGIN{printf "%d", s*1000}')
            send_mbps=$(echo "$out" | jq -r '.data.send_throughput_mbps // 0')
            total_mbps=$(echo "$out" | jq -r '.data.total_throughput_mbps // 0')
        else
            total_dur_ms="$total_dur"
        fi
        # Sanity: recv_bytes must equal sent_bytes (otherwise echo path lost data)
        if [ -n "$recv_bytes" ] && [ -n "$sent_bytes" ] && [ "$recv_bytes" != "$sent_bytes" ]; then
            echo "1 0 0 0"
            return
        fi
        echo "0 ${total_dur_ms:-0} ${send_mbps:-0} ${total_mbps:-0}"
        return
    fi
    echo "1 0 0 0"
}

run_mode() {
    local mode="$1"
    echo "==> $mode-path measurements (pilotctl bench)"
    for s in $SIZES_MB; do
        for i in $(seq 1 "$ITER"); do
            printf "  %-6s %3d MB iter %d ... " "$mode" "$s" "$i"
            read rc dur_ms send_mbps total_mbps < <(time_bench "$mode" "$s")
            if [ "$rc" -eq 0 ]; then
                printf "%6d ms send=%5s MB/s rt=%5s MB/s\n" "$dur_ms" "$send_mbps" "$total_mbps"
                record "$mode" "$s" "$i" "$dur_ms" "$total_mbps"
            else
                printf "FAIL\n"
                record "$mode" "$s" "$i" 0 0
            fi
        done
    done
}

# ---------- Boot ----------
echo "==> bench: starting fresh stack on $PILOT_SUBNET_PREFIX/24"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "${COUNT:-0}" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { echo "agents did not register" >&2; exit 1; }

IP_A=$(resolve_service_ip agent-a)
IP_B=$(resolve_service_ip agent-b)
[ -n "$IP_A" ] && [ -n "$IP_B" ] || { echo "could not resolve agent IPs" >&2; exit 1; }

# Warm tunnel + a short bench round so cwnd is primed.
$DC exec -T agent-a pilotctl ping agent-b --count 3 --timeout 5s >/dev/null 2>&1 || true
$DC exec -T agent-a pilotctl bench agent-b 1 --timeout 30s >/dev/null 2>&1 || true

# ---------- Direct ----------
run_mode direct

# ---------- Apply partition for relay ----------
echo "==> partitioning a<->b for relay measurements"
apply_partition agent-a "$IP_B"
apply_partition agent-b "$IP_A"
sleep 12
$DC exec -T agent-a pilotctl bench agent-b 1 --timeout 30s >/dev/null 2>&1 || true

run_mode relay

# ---------- Summary ----------
echo
echo "==> raw results (mode  size_MB  iter  dur_ms  total_MB/s)"
printf '%s' "$RESULTS"

echo
echo "==> per-(mode,size) statistics across ${ITER} iterations"
printf "%-7s %-8s %-9s %-9s %-9s %-9s\n" "mode" "size_MB" "min_ms" "median" "max_ms" "med_MB/s"
echo "$RESULTS" | awk -F'\t' '
NF>=5 && $4>0 {
    key=$1"\t"$2; n[key]++; d[key,n[key]]=$4; m[key,n[key]]=$5
}
END {
    for (k in n) {
        cnt = n[k]
        for (i=1;i<=cnt;i++) ms[i]=d[k,i]+0
        for (i=1;i<=cnt;i++) for (j=i+1;j<=cnt;j++)
            if (ms[j]<ms[i]) {t=ms[i];ms[i]=ms[j];ms[j]=t}
        med_ms = (cnt % 2 == 1) ? ms[(cnt+1)/2] : (ms[cnt/2]+ms[cnt/2+1])/2
        for (i=1;i<=cnt;i++) mb[i]=m[k,i]+0
        for (i=1;i<=cnt;i++) for (j=i+1;j<=cnt;j++)
            if (mb[j]<mb[i]) {t=mb[i];mb[i]=mb[j];mb[j]=t}
        med_mbps = (cnt % 2 == 1) ? mb[(cnt+1)/2] : (mb[cnt/2]+mb[cnt/2+1])/2
        split(k, kk, "\t")
        printf "%-7s %-8s %-9s %-9s %-9s %-9s\n", kk[1], kk[2], ms[1], med_ms, ms[cnt], med_mbps
    }
}' | sort -k1,1 -k2,2n
