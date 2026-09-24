#!/usr/bin/env bash
# Clean-machine first-contact check. Binaries must already be in ~/.pilot/bin.
# Usage: verify-onboarding.sh <label> <expected-version>
# Prints a machine-readable line: RESULT label=.. os=.. first_try=0|1 attempts=N ttfs=<s|NA> ...
set -uo pipefail
label="$1"; want="$2"; t0=$(date +%s)
step() { printf '[%3ss] %s\n' "$(( $(date +%s) - t0 ))" "$*"; }
export PATH="$PATH:$HOME/.pilot/bin"
got=$(cat ~/.pilot/bin/.pilot-version 2>/dev/null); step "installed version: $got (want $want); pilotctl: $(pilotctl version 2>&1 | head -1)"
[ "$got" = "$want" ] || exit 2
os="$(uname -s)-$(uname -m)"
ts=$(date +%s); step "daemon start"
pilotctl daemon start >/tmp/start.log 2>&1 || { tail -20 /tmp/start.log; tail -30 ~/.pilot/pilot*.log 2>/dev/null; echo "RESULT label=$label os=$os first_try=0 attempts=0 ttfs=NA reason=daemon_start"; exit 3; }
for i in $(seq 1 30); do pilotctl --json info 2>/dev/null | grep -q '"node_id"' && break; sleep 2; done
treg=$(( $(date +%s) - ts ))
step "registered after ${treg}s: $(pilotctl --json info 2>/dev/null | head -c 160)"
ok=0; n=0; ttfs=NA; first=0; a1=NA
for i in 1 2 3 4 5 6; do
  n=$i; ta=$(date +%s)
  out=$(pilotctl --json send-message list-agents --data '/data {"search":"weather","limit":1}' --wait 2>&1); rc=$?
  dur=$(( $(date +%s) - ta ))
  [ $i = 1 ] && a1=$dur
  if [ $rc = 0 ] && echo "$out" | grep -q '"reply"'; then
    ok=1; ttfs=$(( $(date +%s) - ts )); [ $i = 1 ] && first=1
    step "query OK (attempt $i, ${dur}s, ${ttfs}s since daemon start)"; break
  fi
  step "query attempt $i failed rc=$rc after ${dur}s: $(echo "$out" | head -c 240)"; sleep 10
done
echo "RESULT label=$label os=$os first_try=$first attempts=$n ttfs=$ttfs attempt1_s=$a1 reg_s=$treg"
echo "RESULT label=$label os=$os first_try=$first attempts=$n ttfs=$ttfs attempt1_s=$a1 reg_s=$treg" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
step "peers: $(pilotctl peers 2>&1 | head -3 | tr '\n' ' ')"
pilotctl deregister >/dev/null 2>&1; pilotctl daemon stop >/dev/null 2>&1
[ $ok = 1 ] && step "PASS" || { step "FAIL: no query succeeded"; grep -iE "warn|error" ~/.pilot/*.log 2>/dev/null | tail -15; exit 4; }
