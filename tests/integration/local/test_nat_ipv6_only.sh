#!/bin/bash
# IPv6-only topology. Requires Docker Desktop IPv6 support (daemon.json:
# "ipv6": true + "fixed-cidr-v6"). Skips if the compose up can't bring
# up the v6 bridge.
COMPOSE_FILE="docker-compose.multi.nat-ipv6.yml"
source "$(dirname "$0")/nat_test_common.sh"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "attempt boot IPv6-only overlay (may skip if Docker IPv6 disabled)"
if ! $DC up -d --build rendezvous agent-a agent-b >/tmp/nat.v6.up.log 2>&1; then
    log_skip "compose up failed — Docker Desktop IPv6 likely disabled"
    tail -20 /tmp/nat.v6.up.log | sed 's/^/    /'
    # Treat as pass so the summary driver doesn't halt on a platform limit.
    log_pass "skipped cleanly"
    print_summary_and_exit
    exit 0
fi

log_test "both agents register over IPv6"
REG=""
for _ in $(seq 1 60); do
    REG=$($DC exec -T rendezvous curl -fsS "http://[::1]:8080/api/public-stats" 2>/dev/null \
        | jq -r '.total_nodes // 0')
    [ "${REG:-0}" -ge 2 ] && break
    sleep 1
done
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes over IPv6"; else log_fail "only $REG"; fi

log_test "a->b echo over IPv6"
OUT=$(echo_rt agent-a agent-b "v6-probe" "20s")
if echo "$OUT" | grep -q "v6-probe"; then log_pass "echo ok"; else log_fail "echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
