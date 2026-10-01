#!/bin/bash
# Rotate a daemon's Ed25519 identity at the registry via `pilotctl rotate-key`.
# The daemon generates a new keypair, signs `rotate:<node_id>:<new_public_key>`
# with the current key, calls registry.RotateKey, then atomically swaps and
# persists the new identity.
#
# EXPECTED: one successful rotation changes the node's public_key in the
# registry AND allows follow-up signed operations (e.g., another rotate-key)
# with the new key.

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
echo "rotate-key registry identity rotation"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/public-stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "${COUNT:-0}" -ge 1 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 1 ] || { log_fail "agent-a did not register"; exit 1; }

NODE_ID=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
PRE_PUBKEY=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.public_key // empty')
if [ -z "$NODE_ID" ] || [ -z "$PRE_PUBKEY" ]; then
    log_fail "could not read node_id/public_key from info"
    exit 1
fi
log_pass "agent-a registered node_id=$NODE_ID"

# --- 1. First rotation ---
log_test "first rotate-key"
ROT1=$($DC exec -T agent-a pilotctl --json rotate-key 2>&1)
RC1=$?
if [ "$RC1" -ne 0 ]; then
    log_fail "rotate-key #1 returned rc=$RC1: $ROT1"
    exit 1
fi
POST_PUBKEY=$(echo "$ROT1" | jq -r '.data.public_key // empty')
if [ -z "$POST_PUBKEY" ]; then
    log_fail "rotate-key #1 response missing public_key: $ROT1"
    exit 1
fi
if [ "$POST_PUBKEY" = "$PRE_PUBKEY" ]; then
    log_fail "public_key did not change after rotate"
    exit 1
fi
log_pass "pubkey changed on rotate #1"

# --- 2. Registry reflects the new key ---
log_test "registry lookup shows rotated pubkey"
LOOKUP_PUB=$($DC exec -T agent-a pilotctl --json lookup "$NODE_ID" 2>/dev/null | jq -r '.data.public_key // empty')
if [ "$LOOKUP_PUB" = "$POST_PUBKEY" ]; then
    log_pass "registry lookup returns new pubkey"
else
    log_fail "registry lookup pubkey=$LOOKUP_PUB expected=$POST_PUBKEY"
fi

# --- 3. Second rotation proves the daemon is signing with the NEW key now ---
# If the daemon kept the old private key internally, the registry would reject
# this second rotate because the signature would verify against the old pubkey
# (which the registry no longer holds).
log_test "second rotate-key (proves new key is active signer)"
ROT2=$($DC exec -T agent-a pilotctl --json rotate-key 2>&1)
RC2=$?
if [ "$RC2" -ne 0 ]; then
    log_fail "rotate-key #2 returned rc=$RC2: $ROT2"
else
    POST2_PUBKEY=$(echo "$ROT2" | jq -r '.data.public_key // empty')
    if [ -n "$POST2_PUBKEY" ] && [ "$POST2_PUBKEY" != "$POST_PUBKEY" ]; then
        log_pass "second rotate succeeded with new pubkey"
    else
        log_fail "second rotate response unexpected: $ROT2"
    fi
fi

# --- 4. Persisted identity on disk matches current in-memory key ---
log_test "identity.json on disk matches rotated pubkey"
DISK_PUB=$($DC exec -T agent-a cat /root/.pilot/identity.json 2>/dev/null | jq -r '.public_key // empty')
INFO_PUB=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.public_key // empty')
if [ -n "$DISK_PUB" ] && [ "$DISK_PUB" = "$INFO_PUB" ]; then
    log_pass "persisted identity matches live pubkey"
else
    log_fail "disk=$DISK_PUB live=$INFO_PUB"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
