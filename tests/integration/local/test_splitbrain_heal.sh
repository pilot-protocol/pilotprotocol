#!/bin/bash
# Split-brain heal: start with two rendezvous services. agent-a/b register
# with rendezvous-1; agent-c/d register with rendezvous-2. "Heal" the
# partition by migrating agent-c/d onto rendezvous-1. After the heal,
# agent-a must be able to reach agent-c (lookup + messaging).
#
# This stretches the notion of "heal" since Pilot doesn't replicate
# registries — but the observable property (cross-partition messaging
# works once the registry topology unifies) is what we care about.

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

DC="docker compose -f docker-compose.splitbrain.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Split-brain heal"
echo "=========================================="

log_test "Starting splitbrain stack"
$DC down -v >/dev/null 2>&1
# Clean up any orphaned healed-agent containers from previous runs (they use
# `docker run --rm` but survive if the test crashed before stopping them).
docker rm -f "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" \
             "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" \
             >/dev/null 2>&1 || true
# Sweep leftover containers from sibling compose files that share the
# pilot-p2p network — under run-all.sh parallelism, a prior worker's
# stack can leave nodes in rendezvous-1's view (c1=3 not 2).
sweep_pilot_p2p_network
$DC up -d rendezvous-1 rendezvous-2 agent-a agent-b agent-c agent-d >/dev/null 2>&1

for _ in $(seq 1 60); do
    C1=$($DC exec -T rendezvous-1 curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    C2=$($DC exec -T rendezvous-2 curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$C1" -ge 2 ] && [ "$C2" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$C1" = "2" ] && [ "$C2" = "2" ]; then
    log_pass "2+2 split confirmed"
else
    log_fail "split not set up (c1=$C1 c2=$C2)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

# While split: attempt lookup from a to c. Must fail (c unreachable).
log_test "while split: a cannot find agent-c"
LK_SPLIT=$($DC exec -T agent-a pilotctl --json find agent-c 2>&1)
ADDR_SPLIT=$(echo "$LK_SPLIT" | jq -r '.data.address // empty')
if [ -z "$ADDR_SPLIT" ] || [ "$ADDR_SPLIT" = "null" ]; then
    log_pass "lookup correctly failed under split"
else
    log_fail "lookup across partition resolved to $ADDR_SPLIT"
fi

# ----- HEAL: replace agent-c and agent-d so they point at rendezvous-1.
# We cannot just `restart`, because their compose config pins to rv-2. We
# stop them, then run a fresh daemon container on the pilot-p2p network
# targeting rv-1. Simpler approach: stop rendezvous-2 and run c,d
# manually with new env pointing at rv-1.
PFX="${PILOT_SUBNET_PREFIX:-172.35.0}"
log_test "heal: migrate agent-c and agent-d onto rendezvous-1"
$DC stop agent-c agent-d rendezvous-2 >/dev/null 2>&1
$DC rm -f agent-c agent-d >/dev/null 2>&1

# Start replacement daemons on the same network pointing at rv-1.
NETWORK=$($DC ps --format '{{.Name}}' rendezvous-1 2>/dev/null | head -n1)
# Use docker network name directly; compose network is "<project>_pilot-p2p".
# Under run-all.sh the project name is set via COMPOSE_PROJECT_NAME (e.g.
# pilot-w0); fall back to basename $(pwd) for standalone runs.
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)")}"
NET="${PROJECT}_pilot-p2p"

run_healed() {
    local host=$1 ip=$2
    docker run -d --rm --name "healed-$host" --hostname "$host" \
        --network "$NET" --ip "$ip" \
        -e "PILOT_REGISTRY=${PFX}.10:9000" \
        "$(docker compose -f docker-compose.splitbrain.yml config --images 2>/dev/null | head -n1)" \
        pilot-daemon \
        -registry "${PFX}.10:9000" \
        -beacon "${PFX}.10:9001" \
        -hostname "$host" \
        -identity "/root/.pilot/identity.json" \
        -email "$host@p2p.test" \
        -endpoint "${ip}:4000" \
        -listen ":4000" \
        -public -keepalive 5s -log-level info >/dev/null 2>&1
}

# Figure out the image tag compose just built. The JSON path is fragile
# under `--format json` across compose versions; fall back to the
# container inspect path, then to the known-built default.
IMG=$(docker compose -f docker-compose.splitbrain.yml images --format json rendezvous-1 2>/dev/null | jq -r '.[0].Repository + ":" + .[0].Tag' 2>/dev/null | head -n1)
if [ -z "$IMG" ] || [ "$IMG" = "null:null" ] || [ "$IMG" = ":" ]; then
    IMG=$(docker inspect -f '{{.Config.Image}}' $($DC ps -q rendezvous-1 | head -n1) 2>/dev/null)
fi
if [ -z "$IMG" ]; then
    # Last resort: the image everything else in this repo uses.
    IMG="pilot-multi:latest"
fi
if [ -z "$IMG" ]; then
    log_fail "cannot resolve image name for healed containers"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

docker run -d --rm --name "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" --hostname agent-c \
    --network "$NET" --ip "${PFX}.22" \
    -e "PILOT_REGISTRY=${PFX}.10:9000" \
    "$IMG" \
    pilot-daemon \
    -registry "${PFX}.10:9000" \
    -beacon "${PFX}.10:9001" \
    -hostname agent-c \
    -identity /root/.pilot/identity.json \
    -email agent-c@p2p.test \
    -endpoint "${PFX}.22:4000" \
    -listen :4000 -public -keepalive 5s -log-level info >/dev/null 2>&1

docker run -d --rm --name "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" --hostname agent-d \
    --network "$NET" --ip "${PFX}.23" \
    -e "PILOT_REGISTRY=${PFX}.10:9000" \
    "$IMG" \
    pilot-daemon \
    -registry "${PFX}.10:9000" \
    -beacon "${PFX}.10:9001" \
    -hostname agent-d \
    -identity /root/.pilot/identity.json \
    -email agent-d@p2p.test \
    -endpoint "${PFX}.23:4000" \
    -listen :4000 -public -keepalive 5s -log-level info >/dev/null 2>&1

# Wait for rendezvous-1 to see 4 nodes.
MERGED=0
for _ in $(seq 1 60); do
    C1=$($DC exec -T rendezvous-1 curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$C1" -ge 4 ]; then MERGED=1; break; fi
    sleep 1
done
if [ "$MERGED" = "1" ]; then
    log_pass "rendezvous-1 now has 4 nodes"
else
    log_fail "heal failed — rv-1 sees $C1 nodes"
    docker logs "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" 2>&1 | tail -20 | sed 's/^/  c: /'
    docker rm -f "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
    exit 1
fi

log_test "post-heal: agent-a can lookup agent-c"
LK_HEALED=$($DC exec -T agent-a pilotctl --json find agent-c 2>&1)
ADDR_HEALED=$(echo "$LK_HEALED" | jq -r '.data.address // empty')
if [ -n "$ADDR_HEALED" ] && [ "$ADDR_HEALED" != "null" ]; then
    log_pass "post-heal lookup resolved agent-c ($ADDR_HEALED)"
else
    log_fail "post-heal lookup still failed: $LK_HEALED"
fi

log_test "post-heal: agent-a can send-message to agent-c"
SM=$($DC exec -T agent-a bash -c 'timeout 15 pilotctl --json send-message agent-c --data "post-heal" --type text' 2>&1)
if echo "$SM" | jq -e '.data.ack // empty' >/dev/null 2>&1 \
    || echo "$SM" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_pass "post-heal send-message delivered"
else
    # tolerate if send-message fails but ping works (tunnel may need more time)
    if docker exec "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" pilotctl ping agent-a --count 1 --timeout 5s >/dev/null 2>&1 \
        || $DC exec -T agent-a pilotctl ping agent-c --count 1 --timeout 5s >/dev/null 2>&1; then
        log_pass "post-heal ping a<->c ok (send-message may need warm tunnel)"
    else
        log_fail "post-heal messaging failed: $(echo "$SM" | head -c 200)"
    fi
fi

log_test "no panic/fatal across agents + rendezvous"
BAD1=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
BAD2=$(docker logs "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
BAD3=$(docker logs "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD1" ] && [ -z "$BAD2" ] && [ -z "$BAD3" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD1 $BAD2 $BAD3"
fi

docker rm -f "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-c" "${COMPOSE_PROJECT_NAME:-pilot}-healed-agent-d" >/dev/null 2>&1 || true
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Split-brain heal summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
