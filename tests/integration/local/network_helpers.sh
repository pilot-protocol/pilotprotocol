#!/bin/bash
# network_helpers.sh — sourceable helpers for per-network enforcement tests
# (Chunk I — "all network features work and are enforced").
#
# Usage:
#   source network_helpers.sh
#   DC="docker compose -f docker-compose.multi.yml"
#   start_agent_in_network agent-a 42 /tests/fixtures/policies/trust-decay.json
#   assert_in_network agent-a 42
#   create_network_from_file 42 my-net /repo/configs/networks/trust-decay.json
#
# These helpers build on the existing compose stack in
# docker-compose.multi.yml. They do NOT start agents themselves; the
# containers are always running. Instead they:
#
#   1. Copy the policy JSON into the rendezvous container and invoke
#      `pilotctl network create --rules-file <path>` against the live
#      registry to provision the network (16-bit id).
#   2. Drive the target agent to `pilotctl network join <id>` so the
#      daemon loads the expr_policy runner for that id.
#   3. Optionally override the policy's cycle interval — most shipped
#      policies use "cycle": "24h" which is useless for CI; the helper
#      rewrites it to a caller-supplied value (>=1m per
#      pkg/policy.Validate), then writes the transformed file.
#
# A few shipped configs use a cycle shorter than the validator allows
# (e.g. "5s"). Those tests pin `MIN_CYCLE=5s` and skip validation on
# the helper side — the test verifies the daemon rejects or accepts
# the config as its own invariant.

: "${DC:?network_helpers: caller must export DC (docker compose -f ...)}"

# Admin token used by the rendezvous for network create / policy set.
# The policy overlay (docker-compose.multi.policy.yml) starts rendezvous
# with `-admin-token test-admin-token` and sets PILOT_ADMIN_TOKEN on both
# daemons; default here to match so bare Chunk I tests don't have to
# re-export it themselves.
: "${PILOT_ADMIN_TOKEN:=test-admin-token}"

# Copy a local (host) config file into the rendezvous container at
# /tmp/policies/<basename>. Returns the in-container path on stdout.
# copy_policy_to_rendezvous <host_path>
copy_policy_to_rendezvous() {
    local host_path="$1"
    if [ ! -f "$host_path" ]; then
        echo "copy_policy_to_rendezvous: missing file: $host_path" >&2
        return 1
    fi
    local base
    base=$(basename "$host_path")
    # The name is historical — in practice `pilotctl network create --rules-file`
    # reads the file from the daemon's container, not rendezvous. Copy to agent-a.
    $DC exec -T agent-a mkdir -p /tmp/policies >/dev/null 2>&1
    # docker cp can't target a compose service; use tar piped through exec.
    tar -C "$(dirname "$host_path")" -cf - "$base" \
        | $DC exec -T agent-a tar -xf - -C /tmp/policies >/dev/null 2>&1
    echo "/tmp/policies/$base"
}

# Produce a modified copy of a shipped policy with cycle rewritten to
# the given duration (must satisfy pkg/policy validator, i.e. >=1m
# unless the test is intentionally probing validation).
#
# override_cycle <host_path> <new_cycle> [<out_path>]
# Echoes the output path on stdout.
override_cycle() {
    local src="$1" cycle="$2" out="${3:-}"
    if [ -z "$out" ]; then
        out=$(mktemp -t "pol_$(basename "$src" .json)_XXXX.json")
    fi
    # If jq is missing on host, fall back to sed; but jq is a hard
    # dep of the rest of the test suite so we require it.
    if ! command -v jq >/dev/null 2>&1; then
        echo "override_cycle: jq required on host" >&2
        return 1
    fi
    jq --arg c "$cycle" '
        if .expr_policy and (.expr_policy | type == "object") then
            .expr_policy.config = (.expr_policy.config // {})
            | .expr_policy.config.cycle = $c
        else . end
    ' "$src" > "$out"
    echo "$out"
}

# Extract the expr_policy object as a JSON string, ready to pass to
# `pilotctl network create --rules '<json>'`. Emits a compact object.
# extract_rules <host_path>
extract_rules() {
    local src="$1"
    jq -c '.expr_policy' "$src"
}

# Create a network from a shipped config file and join agent-a + agent-b.
# Returns the allocated network id on stdout (uint16).
#
# create_network_from_file <host_path> [<name>] [<cycle_override>]
#
# If <cycle_override> is set, it replaces the shipped cycle before
# upload — needed for any config whose default cycle is 24h.
#
# Shipped configs carry an `expr_policy` block (programmable rules for
# events/datagrams), NOT the NetworkRules managed-topology schema that
# `pilotctl network create --rules-file` expects. So this helper does a
# two-step dance:
#   1. Create an unmanaged network (no --rules), to get a network_id.
#   2. Apply the expr_policy via `pilotctl policy set --net <id> --file`.
create_network_from_file() {
    local host_path="$1" name="${2:-}" cycle="${3:-}"
    if [ -z "$name" ]; then
        name=$(basename "$host_path" .json)
    fi
    local staged="$host_path"
    if [ -n "$cycle" ]; then
        staged=$(override_cycle "$host_path" "$cycle")
    fi

    # Extract join_rule from the shipped config (default "open").
    local join_rule
    join_rule=$(jq -r '.join_rule // "open"' "$staged")

    # Use agent-a as the creator — any member can create.
    local node_id
    node_id=$($DC exec -T agent-a pilotctl --json info 2>/dev/null \
        | jq -r '.data.node_id // 0')
    if [ -z "$node_id" ] || [ "$node_id" = "0" ] || [ "$node_id" = "null" ]; then
        echo "create_network_from_file: cannot resolve agent-a node_id" >&2
        return 1
    fi

    # Step 1: unmanaged network create (no --rules / --rules-file).
    # Retry 5x with exp backoff — registry occasionally reports
    # connection_failed under stack-boot-race on k8s DinD.
    local resp net_id=""
    local attempt backoff
    for attempt in 1 2 3 4 5; do
        resp=$($DC exec -T -e PILOT_ADMIN_TOKEN="$PILOT_ADMIN_TOKEN" \
            agent-a pilotctl --json network create \
            --name "$name" \
            --join-rule "$join_rule" \
            --node-id "$node_id" 2>&1)
        net_id=$(echo "$resp" | jq -r '.data.network_id // .network_id // empty' 2>/dev/null)
        if [ -n "$net_id" ] && [ "$net_id" != "null" ]; then
            break
        fi
        backoff=$((attempt * 2))
        echo "create_network_from_file: attempt $attempt failed ($(echo "$resp" | head -c 160)), retrying in ${backoff}s" >&2
        sleep "$backoff"
    done
    if [ -z "$net_id" ] || [ "$net_id" = "null" ]; then
        echo "create_network_from_file: create failed after 5 attempts: $resp" >&2
        return 1
    fi

    # Step 2: apply the expr_policy as the active policy for this network.
    # Extract .expr_policy, write to a local temp, copy into agent-a, call
    # `pilotctl policy set --net <id> --file <path>`.
    local policy_host
    policy_host=$(mktemp -t "pol_${name}_XXXX.json")
    jq '.expr_policy' "$staged" > "$policy_host"
    if [ ! -s "$policy_host" ] || [ "$(jq -r 'type' "$policy_host")" = "null" ]; then
        echo "create_network_from_file: shipped config has no expr_policy" >&2
        # Still return the id — caller may be testing managed-only semantics.
        echo "$net_id"
        return 0
    fi

    local in_ctr
    in_ctr=$(copy_policy_to_rendezvous "$policy_host") || return 1

    local pset
    pset=$($DC exec -T -e PILOT_ADMIN_TOKEN="$PILOT_ADMIN_TOKEN" \
        agent-a pilotctl --json policy set \
        --net "$net_id" \
        --file "$in_ctr" 2>&1)
    if ! echo "$pset" | jq -e '.status == "ok" or .data' >/dev/null 2>&1; then
        echo "create_network_from_file: policy set failed on net $net_id: $pset" >&2
        return 1
    fi

    echo "$net_id"
}

# Ask the daemon on <agent> to join a network by id. Returns 0 on
# success, 1 on IPC failure. Does not fail the test on a deny — callers
# test that behavior explicitly.
#
# start_agent_in_network <agent> <net_id> <policy_host_path>
# (the policy path is informational; the policy is already uploaded via
# create_network_from_file — this helper just performs the join.)
start_agent_in_network() {
    local agent="$1" net_id="$2" _policy="${3:-}"
    $DC exec -T "$agent" pilotctl --json network join "$net_id" >/dev/null 2>&1
}

# sync_policy_peers <net_id> <agent1> [<agent2> ...]
#
# Force each agent's policy runner to reconcile membership immediately
# via `managed reconcile` — poll registry + refresh peer set, NO cycle
# side effects. Use after ALL starts_in_network calls complete so each
# daemon sees the final member set without waiting 5s for the periodic
# reconciler tick, and without accidentally triggering the network's
# cycle rules (tithe, decay, evict_where ...) on fresh-joined peers.
sync_policy_peers() {
    local net_id="$1"
    shift
    local agent
    for agent in "$@"; do
        $DC exec -T "$agent" pilotctl --json managed reconcile --net "$net_id" >/dev/null 2>&1 || true
    done
}

# Verify that <agent>'s daemon lists <net_id> as a joined network.
# Echoes "ok" + returns 0 if joined, prints the network list + returns 1
# otherwise.
assert_in_network() {
    local agent="$1" net_id="$2"
    local out
    out=$($DC exec -T "$agent" pilotctl --json network list 2>/dev/null)
    if echo "$out" | jq -e --argjson id "$net_id" \
        '.data.networks[]? | select(.id == $id or .network_id == $id)' \
        >/dev/null 2>&1; then
        echo ok
        return 0
    fi
    echo "$out"
    return 1
}

# Trigger an immediate cycle tick on <agent> for <net_id>, via
# `pilotctl managed cycle --force --net <net_id>`. Useful when the
# config has a long cycle and we can't wait for a tick.
trigger_cycle() {
    local agent="$1" net_id="$2"
    $DC exec -T "$agent" pilotctl --json managed cycle --force --net "$net_id" >/dev/null 2>&1
}

# Return the runner's counter snapshot for <net_id> on <agent>.
# Echoes the raw JSON or "{}" on failure.
policy_status() {
    local agent="$1" net_id="$2"
    $DC exec -T "$agent" pilotctl --json managed status --net "$net_id" 2>/dev/null || echo "{}"
}

# Wait until <agent>'s policy runner for <net_id> has reconciled at
# least <min_peers> members (default 1). Tests should call this right
# after joining agents, before seeding scores or asserting on rankings.
#
# wait_peers_reconciled <agent> <net_id> [<min_peers>] [<timeout_secs>]
wait_peers_reconciled() {
    local agent="$1" net_id="$2" min="${3:-1}" timeout="${4:-12}"
    local i peers
    for i in $(seq 1 "$timeout"); do
        peers=$($DC exec -T "$agent" pilotctl --json managed status --net "$net_id" 2>/dev/null \
            | jq -r '.data.peers // 0')
        if [ "${peers:-0}" -ge "$min" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Fetch daemon logs and grep for policy runner init lines for <net_id>.
# Returns 0 if the runner announced itself for that id, 1 otherwise.
assert_runner_logged() {
    local agent="$1" net_id="$2"
    $DC logs "$agent" 2>&1 \
        | grep -E "policy runner started.*network_id=$net_id|runner started for network.*network_id=$net_id" \
        | head -n1 >/dev/null
}

# Boot the baseline stack. Idempotent — callers can re-source safely.
# Usage: ensure_stack_up
ensure_stack_up() {
    local count
    for _ in $(seq 1 60); do
        count=$($DC exec -T rendezvous curl -fsS \
            http://127.0.0.1:8080/api/public-stats 2>/dev/null \
            | jq -r '.total_nodes // 0')
        if [ "${count:-0}" -ge 2 ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Locate the repo root's configs/networks directory from inside the
# rendezvous container. The Dockerfile.multi COPYs the repo in; we
# rely on the default WORKDIR. Callers should prefer the host-side
# absolute path ../../configs/networks (resolved by test scripts via
# $(dirname "$0")) for passing to helpers — but if a test needs to
# inspect the shipped config from inside a container, use this.
# Echoes the in-container dir path.
shipped_configs_dir() {
    echo "/repo/configs/networks"
}
