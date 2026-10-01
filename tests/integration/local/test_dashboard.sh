#!/bin/bash
# Dashboard / HTTP surface smoke tests. Runs against the docker-compose.multi
# stack and covers every endpoint exposed by pkg/registry/dashboard.go.

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
echo "Dashboard HTTP surface tests"
echo "=========================================="

$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for i in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done

EP="http://127.0.0.1:8080"
RIP="${PILOT_SUBNET_PREFIX:-172.29.0}.10:8080" # rendezvous bridge IP, reachable from agent-a

# ---- 1. Root HTML dashboard ----
log_test "GET / returns HTML with 200"
CODE=$($DC exec -T rendezvous curl -sS -o /dev/null -w '%{http_code}' "$EP/")
CT=$($DC exec -T rendezvous curl -sSI "$EP/" | awk -F': ' 'tolower($1)=="content-type"{print $2}' | tr -d '\r')
if [ "$CODE" = "200" ] && [[ "$CT" == text/html* ]]; then
    log_pass "root served ($CODE $CT)"
else
    log_fail "root endpoint wrong response: code=$CODE ct=$CT"
fi

# ---- 2. Unknown path returns 404 ----
log_test "GET /does-not-exist returns 404"
CODE=$($DC exec -T rendezvous curl -sS -o /dev/null -w '%{http_code}' "$EP/does-not-exist")
if [ "$CODE" = "404" ]; then
    log_pass "404 on unknown path"
else
    log_fail "expected 404 on unknown path, got $CODE"
fi

# ---- 3. /healthz JSON shape ----
log_test "/healthz returns healthy JSON"
JSON=$($DC exec -T rendezvous curl -fsS "$EP/healthz")
if echo "$JSON" | jq -e '.status == "ok" and (.uptime_seconds | type == "number") and (.nodes_online | type == "number")' >/dev/null 2>&1; then
    log_pass "healthz JSON ok: $(echo "$JSON")"
else
    log_fail "healthz JSON malformed: $(echo "$JSON" | head -c 200)"
fi

# ---- 4. /api/public-stats JSON shape ----
log_test "/api/public-stats has expected keys"
JSON=$($DC exec -T rendezvous curl -fsS "$EP/api/public-stats")
if echo "$JSON" | jq -e 'has("total_nodes") and has("active_nodes") and has("total_requests") and has("uptime_secs")' >/dev/null 2>&1; then
    log_pass "stats shape ok (total_nodes=$(echo "$JSON" | jq -r .total_nodes))"
else
    log_fail "stats shape missing fields: $(echo "$JSON" | head -c 200)"
fi

# ---- 5. /api/pulse JSON shape ----
log_test "/api/pulse has samples array"
JSON=$($DC exec -T rendezvous curl -fsS "$EP/api/pulse")
if echo "$JSON" | jq -e '.samples | type == "array"' >/dev/null 2>&1; then
    log_pass "pulse samples ok (count=$(echo "$JSON" | jq -r '.samples | length'))"
else
    log_fail "pulse shape bad: $(echo "$JSON" | head -c 200)"
fi

# ---- 6. SVG badge endpoints ----
# Only `nodes` and `requests` badges are implemented at the rendezvous
# dashboard (dashboard.go). Trust is a per-peer concept, not network-wide,
# so no trust badge exists.
for badge in nodes requests; do
    log_test "/api/badge/$badge returns valid SVG"
    BODY=$($DC exec -T rendezvous curl -fsS "$EP/api/badge/$badge")
    if echo "$BODY" | head -c 80 | grep -q '^<svg'; then
        log_pass "badge/$badge ok"
    else
        log_fail "badge/$badge not SVG: $(echo "$BODY" | head -c 120)"
    fi
done

# ---- 7. Prometheus /metrics reachable from localhost ----
log_test "/metrics from localhost returns Prometheus format"
CODE=$($DC exec -T rendezvous curl -sS -o /tmp/m -w '%{http_code}' "$EP/metrics")
if [ "$CODE" = "200" ] && $DC exec -T rendezvous grep -q '^pilot_requests_total' /tmp/m; then
    log_pass "metrics ok"
else
    log_fail "metrics bad: code=$CODE"
fi

# ---- 8. /metrics blocked from remote IP ----
log_test "/metrics from remote IP is forbidden"
CODE=$($DC exec -T agent-a curl -sS -o /dev/null -w '%{http_code}' "http://$RIP/metrics")
if [ "$CODE" = "403" ]; then
    log_pass "metrics 403 from remote"
else
    log_fail "metrics should be 403 from remote, got $CODE"
fi

# ---- 9. /metrics spoofed X-Real-IP is still forbidden ----
log_test "/metrics with spoofed X-Real-IP still rejected"
CODE=$($DC exec -T agent-a curl -sS -H 'X-Real-IP: 127.0.0.1' -o /dev/null -w '%{http_code}' "http://$RIP/metrics")
if [ "$CODE" = "403" ]; then
    log_pass "X-Real-IP spoof rejected"
else
    log_fail "X-Real-IP spoof accepted: code=$CODE"
fi

# ---- 10. /debug/pprof/ reachable from localhost, blocked remote ----
log_test "/debug/pprof/ from localhost 200, from remote 403"
L=$($DC exec -T rendezvous curl -sS -o /dev/null -w '%{http_code}' "$EP/debug/pprof/")
R=$($DC exec -T agent-a curl -sS -o /dev/null -w '%{http_code}' "http://$RIP/debug/pprof/")
if [ "$L" = "200" ] && [ "$R" = "403" ]; then
    log_pass "pprof local=$L remote=$R"
else
    log_fail "pprof unexpected: local=$L remote=$R"
fi

# ---- 11. /api/snapshot GET rejected, POST allowed locally ----
log_test "/api/snapshot GET→405, POST→200 locally, POST→403 remote"
G=$($DC exec -T rendezvous curl -sS -o /dev/null -w '%{http_code}' "$EP/api/snapshot")
P=$($DC exec -T rendezvous curl -sS -X POST -o /dev/null -w '%{http_code}' "$EP/api/snapshot")
R=$($DC exec -T agent-a curl -sS -X POST -o /dev/null -w '%{http_code}' "http://$RIP/api/snapshot")
if [ "$G" = "405" ] && [ "$P" = "200" ] && [ "$R" = "403" ]; then
    log_pass "snapshot gating ok (GET=$G POST=$P remote=$R)"
else
    log_fail "snapshot gating wrong: GET=$G POST=$P remote=$R"
fi

# ---- 12. CORS header on public API endpoints ----
log_test "public API responses include Access-Control-Allow-Origin"
ACAO=$($DC exec -T rendezvous curl -sSI "$EP/api/public-stats" | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}' | tr -d '\r')
if [ "$ACAO" = "*" ]; then
    log_pass "ACAO ok on /api/public-stats"
else
    log_fail "ACAO missing or wrong on /api/public-stats: '$ACAO'"
fi

echo ""
echo "=========================================="
echo "Dashboard Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "=========================================="
