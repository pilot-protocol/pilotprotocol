#!/bin/bash
# Rendezvous behind NAT (deliberately odd). The gateway DNATs 9000/9001
# /8080 inward so the rendezvous is reachable via the gateway's public
# IP. Tests whether the bootstrap + beacon path works when the
# rendezvous is itself not directly on a public IP.
COMPOSE_FILE="docker-compose.multi.nat-rend.yml"
source "$(dirname "$0")/nat_test_common.sh"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "boot rendezvous-behind-NAT overlay"
if ! $DC up -d --build nat-gw-rend rendezvous agent-a agent-b >/tmp/nat.rend.up.log 2>&1; then
    log_fail "compose up failed"
    tail -40 /tmp/nat.rend.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register through the DNATed rendezvous"
# rendezvous curl is on the private bridge — use the public gateway IP instead.
REG=""
for _ in $(seq 1 90); do
    REG=$($DC exec -T agent-a curl -fsS "http://${NAT_PUB:-192.0.2}.30:8080/api/public-stats" 2>/dev/null \
        | jq -r '.total_nodes // 0' 2>/dev/null)
    [ "${REG:-0}" -ge 2 ] && break
    sleep 1
done
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes via DNAT"; else log_fail "only $REG"; fi

log_test "a->b echo"
OUT=$(echo_rt agent-a agent-b "rend-probe" "20s")
if echo "$OUT" | grep -q "rend-probe"; then log_pass "echo ok"; else log_fail "echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw-rend 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
