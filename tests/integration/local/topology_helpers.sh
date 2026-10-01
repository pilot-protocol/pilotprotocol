#!/bin/bash
# topology_helpers.sh — shared helpers for multi-agent topology tests.
#
# Source from a test:
#     source "$(dirname "$0")/topology_helpers.sh"
#
# Exported helpers:
#   wait_all_registered <count> <rendezvous-service>
#       Waits up to 90s for the rendezvous dashboard to report total_nodes >= count.
#       <rendezvous-service> is the compose service name (e.g. "rendezvous",
#       "rendezvous-1"). Requires $DC to be set in the caller's scope.
#       Returns 0 on success, 1 on timeout.
#
#   agent_addr_for <compose-file> <service-name>
#       Prints the virtual pilot address ("N:NNNN.HHHH.LLLL") for a given agent
#       service by asking it via `pilotctl info`. Empty string if the agent
#       isn't ready yet.
#
#   wait_for_peer_in_registry <agent-service> <peer-hostname>
#       Waits up to 30s for <agent-service>'s local registry view to include
#       <peer-hostname> via `pilotctl lookup`.

wait_all_registered() {
    local want="$1"
    local rv="${2:-rendezvous}"
    : "${DC:?DC must be set (e.g. DC=\"docker compose -f docker-compose.multiN.yml\")}"
    local count=0
    for _ in $(seq 1 90); do
        count=$($DC exec -T "$rv" curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
            | jq -r '.total_nodes // 0')
        if [ -n "$count" ] && [ "$count" -ge "$want" ]; then
            echo "$count"
            return 0
        fi
        sleep 1
    done
    echo "$count"
    return 1
}

agent_addr_for() {
    local compose_file="$1"
    local service="$2"
    docker compose -f "$compose_file" exec -T "$service" \
        pilotctl --json info 2>/dev/null \
        | jq -r '.data.address // empty'
}

wait_for_peer_in_registry() {
    local svc="$1"
    local peer="$2"
    : "${DC:?DC must be set}"
    for _ in $(seq 1 30); do
        local a
        a=$($DC exec -T "$svc" pilotctl --json lookup "$peer" 2>/dev/null \
            | jq -r '.data.address // empty')
        if [ -n "$a" ]; then
            echo "$a"
            return 0
        fi
        sleep 1
    done
    return 1
}

# sweep_pilot_p2p_network — force-remove any containers still attached to
# the shared pilot-p2p docker network. Tests in this directory have ~10
# compose files that all declare the same network name; leftover
# containers from a prior test (esp. the p2p runner + multi.yml stack)
# block a sibling compose file from recreating the network on `up`. Call
# this before `$DC up` to make tests order-independent.
sweep_pilot_p2p_network() {
    local f
    for f in docker-compose.multi.yml \
             docker-compose.multi3.yml \
             docker-compose.multi5.yml \
             docker-compose.multi10.yml \
             docker-compose.splitbrain.yml \
             docker-compose.ring4.yml \
             docker-compose.star5hub.yml \
             docker-compose.multi.gateway.yml \
             docker-compose.multi.policy.yml \
             docker-compose.multi.webhooks.yml; do
        [ -f "$f" ] && docker compose -f "$f" down -v >/dev/null 2>&1 || true
    done
    docker ps -a --filter "network=local_pilot-p2p" --format '{{.Names}}' 2>/dev/null \
        | xargs -r docker rm -f >/dev/null 2>&1 || true
}
