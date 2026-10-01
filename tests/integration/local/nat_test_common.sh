#!/bin/bash
# nat_test_common.sh — shared helpers for test_nat_*.sh variants.
# Source this from each script.

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
log_skip() { echo -e "[$(ts)] ${YELLOW}[SKIP]${NC} $*"; }

# Default compose file; override per-test by setting COMPOSE_FILE before
# sourcing.
: "${COMPOSE_FILE:=docker-compose.multi.nat.yml}"
DC="docker compose -f ${COMPOSE_FILE}"

cleanup_nat() { $DC down -v >/dev/null 2>&1 || true; }

# Boot rendezvous+nat-gw+agent-a+agent-b. Extra services can be passed
# as args. On failure, prints the tail of the compose-up log and exits.
boot_nat_stack() {
    local extras="${*:-}"
    $DC down -v >/dev/null 2>&1
    log_test "boot compose (mode=${NAT_MODE:-cone})"
    if $DC up -d --build rendezvous nat-gw agent-a agent-b $extras >/tmp/nat.up.log 2>&1; then
        return 0
    fi
    # Under run-all.sh parallelism the worker's lane subnet can still be
    # held by a crashed sibling's network (docker IPAM refuses to reuse
    # the CIDR). Sweep any network using our lane's CIDRs and retry.
    if grep -qi "pool overlaps" /tmp/nat.up.log; then
        log_test "retry after sweeping overlapping docker networks"
        local n cidr
        for n in $(docker network ls --format '{{.Name}}' 2>/dev/null); do
            cidr=$(docker network inspect "$n" 2>/dev/null \
                | jq -r '.[0].IPAM.Config[0].Subnet // empty' 2>/dev/null)
            case "$cidr" in
                "${NAT_PUB:-x}".0/24|"${NAT_PRV:-x}".0/24)
                    docker network rm "$n" >/dev/null 2>&1 || true
                    ;;
            esac
        done
        if $DC up -d --build rendezvous nat-gw agent-a agent-b $extras >/tmp/nat.up.log 2>&1; then
            return 0
        fi
    fi
    log_fail "compose up failed"
    tail -40 /tmp/nat.up.log | sed 's/^/    /'
    exit 1
}

# Wait until $N nodes have registered at the rendezvous. Returns 0 on
# success, 1 on timeout. Optional arg: timeout seconds (default 60).
wait_registered() {
    local want="${1:-2}" timeout="${2:-60}" reg=""
    local mult="${PILOT_TEST_WAIT_MULT:-1}"
    timeout=$((timeout * mult))
    for _ in $(seq 1 "$timeout"); do
        reg=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null \
            | jq -r '.total_nodes // 0')
        [ "${reg:-0}" -ge "$want" ] && { echo "$reg"; return 0; }
        sleep 1
    done
    # On timeout: stay silent so callers using `|| echo "0"` get a single-line value.
    return 1
}

# Fetch agent-a's daemon-observed endpoint from its log (line format:
#   msg="daemon registered" ... endpoint=<ip:port>
# The closing-quote-after-msg breaks naive single-pass grep, so do it in
# two stages.
agent_endpoint() {
    local agent="${1:-agent-a}"
    $DC logs "$agent" 2>&1 \
        | grep 'daemon registered' \
        | grep -oE 'endpoint=[^ "]+' \
        | tail -n1 \
        | sed -E 's/^endpoint=//'
}

# Agent node_id (integer).
agent_node_id() {
    local agent="${1:-agent-a}"
    $DC exec -T "$agent" pilotctl --json info 2>/dev/null \
        | jq -r '.data.node_id // 0'
}

# Build pilot-address string 0:0000.0000.<hex> from numeric node_id.
pilot_addr() {
    local nid="$1"
    printf "0:0000.0000.%04x" "$nid"
}

# Handshake + poll-for-pending + approve dance. Use when you need
# bidirectional trust for a test where a-side is NATed (direct handshake
# gets dropped, must arrive via registry relay).
# Args: initiator_agent target_agent
# On success echoes "ok", returns 0.
establish_trust() {
    local init="$1" tgt="$2"
    local nid_init nid_tgt addr_tgt
    nid_init=$(agent_node_id "$init")
    nid_tgt=$(agent_node_id "$tgt")
    addr_tgt=$(pilot_addr "$nid_tgt")
    $DC exec -T "$init" pilotctl --json handshake "$addr_tgt" "nat test trust" >/dev/null 2>&1
    for _ in $(seq 1 30); do
        if $DC logs "$tgt" 2>&1 | grep -q "relayed handshake request pending approval.*from_node_id=$nid_init"; then
            break
        fi
        sleep 1
    done
    $DC exec -T "$tgt" pilotctl --json approve "$nid_init" >/dev/null 2>&1
    sleep 2
    echo ok
}

# Run echo round-trip: agent $src -> agent $dst port 7. Echoes received
# payload on stdout (empty on failure).
echo_rt() {
    local src="$1" dst_arg="$2" probe="$3" tmout="${4:-15s}"
    echo "$probe" | timeout 45 $DC exec -T "$src" \
        pilotctl connect "$dst_arg" 7 --timeout "$tmout" 2>&1
}

# Standard trailer: print summary and exit non-zero on any failure.
print_summary_and_exit() {
    echo
    echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
    [ "$FAILED" -eq 0 ]
}
