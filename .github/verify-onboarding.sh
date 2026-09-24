#!/usr/bin/env bash
# Clean-machine onboarding check for a beta-channel release, inside a container.
# Usage (in container, non-root user): verify.sh <expected-version>
set -uo pipefail
want="$1"; t0=$(date +%s)
step() { printf '[%3ss] %s\n' "$(( $(date +%s) - t0 ))" "$*"; }
step "install (stable channel, official installer)"
curl -fsSL https://pilotprotocol.network/install.sh | sh -s -- --yes >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; }
export PATH="$PATH:$HOME/.pilot/bin"
got=$(cat ~/.pilot/bin/.pilot-version 2>/dev/null); step "installed version: $got (want $want)"
[ "$got" = "$want" ] || exit 2
step "daemon start"; pilotctl daemon start >/tmp/start.log 2>&1 || { tail -20 /tmp/start.log; tail -30 ~/.pilot/pilot*.log 2>/dev/null; exit 3; }
for i in $(seq 1 30); do pilotctl --json info 2>/dev/null | grep -q '"node_id"' && break; sleep 2; done
step "registered: $(pilotctl --json info 2>/dev/null | head -c 160)"
ok=0; for i in 1 2 3; do
  out=$(pilotctl --json send-message list-agents --data '/data {"search":"weather","limit":1}' --wait 2>&1); rc=$?
  if [ $rc = 0 ] && echo "$out" | grep -q '"reply"'; then ok=1; step "first query OK (attempt $i)"; break; fi
  step "query attempt $i failed rc=$rc: $(echo "$out" | head -c 200)"; sleep 10
done
step "peers: $(pilotctl peers 2>&1 | head -1)"
step "orphans/app procs: $(ps -eo ppid,args | grep -c '[.]pilot/apps/')"
pilotctl deregister >/dev/null 2>&1; pilotctl daemon stop >/dev/null 2>&1
[ $ok = 1 ] && step "PASS" || { step "FAIL: no query succeeded"; grep -iE "warn|error" ~/.pilot/*.log 2>/dev/null | tail -15; exit 4; }
