# Shared helpers for policy engine integration tests.
# Source this file from test_policy_*.sh.
#
# Assumes DC is set by the caller, e.g.:
#   DC="docker compose -f docker-compose.multi.policy.yml"
# and that the compose stack exposes `rendezvous`, `agent-a`, `agent-b`
# with PILOT_ADMIN_TOKEN=test-admin-token on both agents and
# -admin-token test-admin-token on the rendezvous.
#
# Notes on the policy engine (pkg/policy):
#   Events: connect, dial, datagram (gate events: allow/deny verdict);
#           cycle, join, leave (action events, all matching rules fire).
#           NOTE: join/leave are declared in the schema + env.go but
#           NOT wired into the daemon event path today (pkg/daemon/daemon.go
#           only fires connect/dial/datagram/cycle). join/deny/score tests
#           therefore exercise a documented-but-unimplemented code path.
#   Actions: allow, deny, score, tag, evict, evict_where, prune, fill,
#            prune_trust, fill_trust, webhook, log.
#   Cycle minimum: 1 minute (pkg/policy/policy.go:169). Shorter cycles are
#            rejected at validate, and <1m durations are silently promoted
#            to 24h in the daemon cycleLoop. Tests use --force instead.

POLICY_ADMIN_TOKEN="${POLICY_ADMIN_TOKEN:-test-admin-token}"
POLICY_TEST_NET_NAME="${POLICY_TEST_NET_NAME:-pol-test-net}"

# load_policy <agent> <path-inside-container>
#
# Creates a managed network (name=$POLICY_TEST_NET_NAME, open join) on the
# registry, joins both agents, then applies the policy JSON at <path>
# (path is relative to /tests inside the container) to that network.
# Exports POLICY_NET_ID with the assigned network id for the caller.
load_policy() {
    local agent="$1"
    local policy_path="$2"

    if [ -z "$agent" ] || [ -z "$policy_path" ]; then
        echo "usage: load_policy <agent> <policy-path-inside-container>" >&2
        return 2
    fi

    # Stage fixture into the container if needed. Fixtures are NOT baked
    # into Dockerfile.multi; we docker-cp them at test runtime so tests
    # remain self-contained and don't require image rebuilds.
    case "$policy_path" in
        /tests/fixtures/*)
            local rel="${policy_path#/tests/fixtures/}"
            # Fixtures live at tests/integration/fixtures/ (not under local/).
            # Resolve relative to this helper's directory so callers can run
            # from any PWD.
            local helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            local host_path="${helper_dir}/../fixtures/${rel}"
            if [ ! -f "$host_path" ]; then
                echo "load_policy: fixture not on host: $host_path" >&2
                return 1
            fi
            for a in agent-a agent-b; do
                $DC exec -T "$a" mkdir -p "$(dirname "$policy_path")" >/dev/null 2>&1
                $DC cp "$host_path" "$a:$policy_path" >/dev/null 2>&1 || true
            done
            ;;
    esac

    # Create the network (idempotent check first).
    local existing
    existing=$($DC exec -T -e PILOT_ADMIN_TOKEN="$POLICY_ADMIN_TOKEN" "$agent" \
        pilotctl --json network list 2>/dev/null \
        | jq -r --arg n "$POLICY_TEST_NET_NAME" \
          '.data.networks[]? | select(.name == $n) | .id' \
        | head -n1)

    if [ -z "$existing" ] || [ "$existing" = "null" ]; then
        # Resolve creator's node_id. pilotctl network create defaults
        # --node-id to 0; the registry rejects (node 0 not registered),
        # and that error is sanitized to "request failed" by the error
        # whitelist in pkg/registry/server.go — which is why this used
        # to look like a retriable connection error.
        local node_id
        node_id=$($DC exec -T "$agent" pilotctl --json info 2>/dev/null \
            | jq -r '.data.node_id // 0')
        if [ -z "$node_id" ] || [ "$node_id" = "0" ] || [ "$node_id" = "null" ]; then
            echo "load_policy: cannot resolve $agent node_id" >&2
            return 1
        fi

        # 5 attempts with exp backoff — registry occasionally reports
        # connection_failed under stack-boot-race on k8s DinD.
        local create_out attempt backoff
        POLICY_NET_ID=""
        for attempt in 1 2 3 4 5; do
            create_out=$($DC exec -T -e PILOT_ADMIN_TOKEN="$POLICY_ADMIN_TOKEN" "$agent" \
                pilotctl --json network create --name "$POLICY_TEST_NET_NAME" \
                --join-rule open --enterprise --node-id "$node_id" 2>&1)
            POLICY_NET_ID=$(echo "$create_out" | jq -r '.data.network_id // .network_id // empty')
            if [ -n "$POLICY_NET_ID" ] && [ "$POLICY_NET_ID" != "null" ]; then
                break
            fi
            backoff=$((attempt * 2))
            echo "load_policy: create attempt $attempt failed, retrying in ${backoff}s" >&2
            sleep "$backoff"
        done
        if [ -z "$POLICY_NET_ID" ] || [ "$POLICY_NET_ID" = "null" ]; then
            echo "load_policy: failed to create network after 5 attempts:" >&2
            echo "$create_out" >&2
            return 1
        fi
    else
        POLICY_NET_ID="$existing"
    fi

    # Join both agents to the network.
    for a in agent-a agent-b; do
        $DC exec -T -e PILOT_ADMIN_TOKEN="$POLICY_ADMIN_TOKEN" "$a" \
            pilotctl network join "$POLICY_NET_ID" >/dev/null 2>&1 || true
    done

    # Apply the policy to the network. --file resolves inside the container.
    # Retry with exp backoff — under run-all.sh parallelism, the policy-set
    # IPC RPC can race a concurrent registry fetch in the daemon and return
    # an empty error body.
    local set_attempt
    for set_attempt in 1 2 3 4 5; do
        $DC exec -T -e PILOT_ADMIN_TOKEN="$POLICY_ADMIN_TOKEN" "$agent" \
            pilotctl --json policy set --net "$POLICY_NET_ID" \
            --file "$policy_path" --admin-token "$POLICY_ADMIN_TOKEN" \
            >/tmp/policy-set.out 2>&1
        if grep -q '"applied": *true\|"network_id"' /tmp/policy-set.out; then
            break
        fi
        echo "load_policy: policy set attempt $set_attempt failed, retrying" >&2
        sleep $((set_attempt * 2))
    done

    if ! grep -q '"applied": *true\|"network_id"' /tmp/policy-set.out; then
        echo "load_policy: policy set failed after 5 attempts:" >&2
        cat /tmp/policy-set.out >&2
        return 1
    fi

    export POLICY_NET_ID
    echo "load_policy: network_id=$POLICY_NET_ID policy=$policy_path (on $agent)"
}

# force_cycle <agent> <net_id>
# Trigger an immediate cycle tick on the daemon for <net_id>. Uses
# `pilotctl managed cycle --force`, which wraps ForceCycle on the policy runner.
force_cycle() {
    local agent="$1"
    local net_id="$2"
    $DC exec -T "$agent" pilotctl --json managed cycle --force --net "$net_id" \
        2>&1
}

# wait_cycle_tick <seconds>
# Wait <seconds> real-time for at least one natural cycle tick to pass.
# Because the policy engine enforces a 1m minimum cycle at validate-time
# (pkg/policy/policy.go:169) and the daemon promotes <1m to 24h at
# runtime (pkg/daemon/policy_runner.go:508), this helper is primarily
# useful for verifying that ForceCycle-equivalent scheduled behavior
# fires after a short real delay. Most tests should prefer force_cycle.
wait_cycle_tick() {
    local secs="${1:-5}"
    sleep "$secs"
}

# assert_policy_event <agent> <event-name> <min-count>
#
# Greps the daemon logs of <agent> for a line mentioning the policy event
# or its webhook emission. Expected event strings:
#   - cycle complete      -> "policy: cycle complete"
#   - pruned peers        -> "policy: pruned peers"
#   - pruned trust links  -> "policy: pruned trust links"
#   - filled peers        -> "policy: filled peers"
#   - sent trust requests -> "policy: sent trust requests"
#   - evicted peers       -> "policy: evicted peers"
#   - port_rejected       -> "port_rejected" (from gate deny)
#   - datagram_rejected   -> "datagram.port_rejected" or "datagram: rejected"
#
# Returns 0 iff the observed count is >= <min-count>.
assert_policy_event() {
    local agent="$1"
    local event="$2"
    local min_count="${3:-1}"
    local pattern

    case "$event" in
        cycle)              pattern='policy: cycle complete' ;;
        prune_trust)        pattern='policy: pruned trust links' ;;
        fill_trust)         pattern='policy: sent trust requests' ;;
        prune)              pattern='policy: pruned peers' ;;
        fill)               pattern='policy: filled peers' ;;
        evict)              pattern='policy: evicted peers' ;;
        connect_deny)       pattern='SYN rejected: not allowed\|syn\.port_rejected\|port_rejected' ;;
        datagram_deny)      pattern='datagram rejected: not allowed\|datagram\.port_rejected\|datagram.*not allowed' ;;
        webhook)            pattern='policy\.' ;;
        *)                  pattern="$event" ;;
    esac

    local count
    count=$($DC logs "$agent" 2>&1 | grep -cE "$pattern" || true)
    if [ "${count:-0}" -ge "$min_count" ]; then
        return 0
    fi
    echo "assert_policy_event: agent=$agent event=$event pattern=$pattern count=$count want>=$min_count"
    return 1
}

# policy_tags_of <agent> <net_id> <peer_node_id>
# Print the JSON array of tags for a peer in the policy runner's peer set.
policy_tags_of() {
    local agent="$1"
    local net_id="$2"
    local peer_id="$3"
    $DC exec -T "$agent" pilotctl --json managed status --net "$net_id" 2>/dev/null \
        | jq -c --argjson p "$peer_id" \
            '.data.peer_list[]? | select(.node_id == $p) | .tags // []' \
        | head -n1
}

# policy_peer_count <agent> <net_id>
# Print the number of peers in <agent>'s policy runner set for <net_id>.
policy_peer_count() {
    local agent="$1"
    local net_id="$2"
    $DC exec -T "$agent" pilotctl --json managed status --net "$net_id" 2>/dev/null \
        | jq -r '.data.peers // .peers // 0'
}

# node_id_of <agent>
# Print the numeric node_id a daemon self-assigned from the registry.
node_id_of() {
    local agent="$1"
    $DC exec -T "$agent" pilotctl --json info 2>/dev/null \
        | jq -r '.data.node_id // empty'
}

# wait_both_agents_registered [timeout_secs]
# Poll the rendezvous dashboard until total_nodes >= 2.
wait_both_agents_registered() {
    local timeout="${1:-60}"
    local count=0
    for _ in $(seq 1 "$timeout"); do
        count=$($DC exec -T rendezvous \
            curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
            | jq -r '.total_nodes // 0')
        if [ "${count:-0}" -ge 2 ]; then
            return 0
        fi
        sleep 1
    done
    echo "wait_both_agents_registered: only $count registered after ${timeout}s" >&2
    return 1
}

# start_policy_stack
# Bring up the admin-token-enabled compose and wait for registration.
# Caller must have set DC before sourcing.
start_policy_stack() {
    $DC down -v >/dev/null 2>&1 || true
    $DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
    wait_both_agents_registered 60
}

# stop_policy_stack
stop_policy_stack() {
    $DC down -v >/dev/null 2>&1 || true
}
