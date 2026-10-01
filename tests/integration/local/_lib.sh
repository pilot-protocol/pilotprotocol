#!/bin/bash
# Shared test lib — sourced by every test_*.sh in this directory.
#
# Provides:
#   - color + log helpers (ts / log_test / log_pass / log_fail / log_info)
#   - PASSED / FAILED counters
#   - wait_for — replaces the `for _ in $(seq 1 60); do ...; sleep 1; done`
#     pattern scattered across ~120 tests with a single helper that reads
#     WAIT_BUDGET from env (laptop=60, k8s Job sets 180 via values.yaml)
#   - teardown — docker compose down -v --remove-orphans; auto-trapped
#     at EXIT
#
# Teardown is auto-installed via `trap teardown EXIT` on source.
# If a test wants to manage its own teardown (multi-phase chaos runs),
# it can `trap - EXIT` after sourcing.

# ---- colors ----
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ---- counters (test-local) ----
PASSED=0
FAILED=0

# ---- logging ----
ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }
log_info() { echo -e "[$(ts)] $*"; }

# ---- wait budget ----
# Laptop default 60s; k8s Job overrides WAIT_BUDGET=180 because per-node
# DinD contention stretches every docker/curl exec. Multiplied by
# PILOT_TEST_WAIT_MULT (k8s sets 3) for stack-boot waits inside tests.
_wait_budget() {
  local base="${WAIT_BUDGET:-60}"
  local mult="${PILOT_TEST_WAIT_MULT:-1}"
  echo $((base * mult))
}

# wait_for '<bash expr>' [budget_seconds]
# Polls once per second. Returns 0 the first tick the expression exits 0;
# returns 1 if the budget runs out. Stderr/stdout of the predicate are
# discarded so loops stay quiet.
#
# Usage:
#   wait_for '[ "$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats | jq -r ".total_nodes // 0")" -ge 2 ]' \
#     && log_pass "both agents registered"
wait_for() {
  local pred="$1"
  local budget="${2:-$(_wait_budget)}"
  local i
  for i in $(seq 1 "$budget"); do
    eval "$pred" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ---- teardown ----
# Idempotent. Preserves the test's exit code so `exit $rc` semantics
# remain correct when invoked via trap.
teardown() {
  local rc=$?
  trap - EXIT
  # Run in subshell so any failure inside teardown doesn't leak.
  (
    if [ -n "${DC:-}" ]; then
      # --remove-orphans catches sidecar containers (gateway, extra
      # agents) that compose-up added but the main `down` line didn't
      # know about.
      $DC down -v --remove-orphans >/dev/null 2>&1 || true
    else
      # No $DC set — try the two most common compose files as a best
      # effort. Costs nothing if they're not up.
      docker compose -f docker-compose.multi.yml down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    # No host-side pkill: every daemon under test runs inside a container
    # that `down -v` just removed. A `pkill -f pilot-daemon` here matches
    # the developer's own daemon on the host and kills it.
  ) || true
  return "$rc"
}

trap teardown EXIT
