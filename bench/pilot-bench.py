#!/usr/bin/env python3
"""pilot-bench — repeatable throughput benchmark for the Pilot overlay.

Workflow:
  1. Record a baseline once:      ./pilot-bench.py run --label baseline
  2. Land a transport change, then:  ./pilot-bench.py run --label after-my-fix
  3. Diff against the baseline:   ./pilot-bench.py compare

Each run measures, per node:
  - ping RTT (dial + echo, parsed from `pilotctl ping`)
  - bulk echo throughput via `pilotctl bench --json` (send rate, round-trip
    goodput, completion %)
  - live transport counters sampled from `pilotctl info --json` during the
    transfer (max/min congestion window, fast retransmits, SRTT) so a slow
    run also says WHY it was slow.

Results are JSON files under ~/.pilot/bench-results/ — one per run, never
overwritten. stdlib only; shells out to pilotctl.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time

RESULTS_DIR = os.path.expanduser(os.environ.get("PILOT_BENCH_DIR", "~/.pilot/bench-results"))
SCHEMA = 1

DEFAULT_NODES = [
    "coingecko-markets-simple",
    "github-public",
    "list-agents",
    "mediawiki-random",
    # pilot-mom is kept in the default set on purpose: its echo port
    # currently returns 0 bytes under load (echo handler exits on
    # ErrSendBufFull, services.go). Expect 0% completion until that is
    # fixed; the benchmark tracks the fix landing.
    "pilot-mom",
]

PING_LINE = re.compile(r"time=([\d.]+)(ms|s)\s+\[dial=([\d.]+)(ms|s)\s+echo=([\d.]+)(ms|s)\]")


def _ms(val, unit):
    return float(val) * (1000.0 if unit == "s" else 1.0)


def run_cmd(args, timeout):
    """Run a pilotctl command, return (exit_code, stdout, stderr)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return -1, e.stdout or "", (e.stderr or "") + "\n[harness: subprocess timeout]"


def ping_node(node, timeout_s):
    """One `pilotctl ping` invocation; parse every seq line."""
    code, out, err = run_cmd(["pilotctl", "ping", node, "--timeout", f"{timeout_s}s"], timeout_s + 10)
    text = out + err
    dials, echos = [], []
    for m in PING_LINE.finditer(text):
        dials.append(_ms(m.group(3), m.group(4)))
        echos.append(_ms(m.group(5), m.group(6)))
    attempts = len(re.findall(r"seq=\d+", text))
    return {
        "attempts": attempts,
        "replies": len(dials),
        "dial_ms_med": round(statistics.median(dials), 1) if dials else None,
        "echo_ms_med": round(statistics.median(echos), 1) if echos else None,
    }


class ConnSampler(threading.Thread):
    """Poll `pilotctl info --json` and keep per-remote-addr extremes for
    echo-port (port 7) connections while a bench transfer is running."""

    def __init__(self, interval=1.0):
        super().__init__(daemon=True)
        self.interval = interval
        self.stop_ev = threading.Event()
        self.by_addr = {}  # remote_addr -> aggregated counters

    def run(self):
        while not self.stop_ev.is_set():
            code, out, _ = run_cmd(["pilotctl", "info", "--json"], 10)
            if code == 0:
                try:
                    conns = json.loads(out).get("data", {}).get("conn_list") or []
                except (json.JSONDecodeError, AttributeError):
                    conns = []
                for c in conns:
                    if c.get("remote_port") != 7:
                        continue
                    addr = c.get("remote_addr", "?").split(":")[0]
                    agg = self.by_addr.setdefault(addr, {
                        "cwnd_max": 0, "cwnd_min": None, "fast_retx": 0,
                        "srtt_ms": None, "samples": 0,
                    })
                    cw = c.get("cong_win") or 0
                    agg["cwnd_max"] = max(agg["cwnd_max"], cw)
                    agg["cwnd_min"] = cw if agg["cwnd_min"] is None else min(agg["cwnd_min"], cw)
                    agg["fast_retx"] = max(agg["fast_retx"], c.get("fast_retx") or 0)
                    agg["srtt_ms"] = c.get("srtt_ms") or agg["srtt_ms"]
                    agg["samples"] += 1
            self.stop_ev.wait(self.interval)

    def stop(self):
        self.stop_ev.set()
        self.join(timeout=5)


def bench_node(node, size_mb, timeout_s):
    """One `pilotctl bench --json` transfer with transport sampling."""
    sampler = ConnSampler()
    sampler.start()
    code, out, err = run_cmd(
        ["pilotctl", "bench", node, str(size_mb), "--json", "--timeout", f"{timeout_s}s"],
        timeout_s + 30,
    )
    sampler.stop()

    trial = {"ok": False, "error": None}
    data = None
    # bench prints the resolve line before JSON in some builds; find the JSON object.
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                data = parsed.get("data", parsed)
                break
            except json.JSONDecodeError:
                continue
    if data is None:
        trial["error"] = (err or out or "no output").strip()[-300:]
        return trial

    sent = data.get("sent_bytes") or 0
    recv = data.get("recv_bytes") or 0
    total_ms = data.get("total_duration_ms") or 0
    trial.update({
        "ok": True,
        "target": data.get("target"),
        "sent_bytes": sent,
        "recv_bytes": recv,
        "send_ms": data.get("send_duration_ms"),
        "send_mbps": round(data.get("send_mbps") or 0, 3),
        "total_ms": total_ms,
        # goodput = payload actually echoed back / wall time, in MB/s
        "rt_goodput_mbps": round(recv / 1048576.0 / (total_ms / 1000.0), 4) if total_ms else 0.0,
        "completion_pct": round(100.0 * recv / sent, 1) if sent else 0.0,
    })
    addr = (data.get("target") or "").split(":")[0]
    if addr in sampler.by_addr:
        trial["transport"] = sampler.by_addr[addr]
    return trial


def run_suite(args):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    nodes = args.nodes.split(",") if args.nodes else DEFAULT_NODES
    ts = datetime.datetime.now(datetime.timezone.utc)

    code, out, _ = run_cmd(["pilotctl", "info", "--json"], 15)
    version = None
    if code == 0:
        try:
            version = json.loads(out)["data"].get("version")
        except (json.JSONDecodeError, KeyError):
            pass

    report = {
        "schema": SCHEMA,
        "ts": ts.isoformat(timespec="seconds"),
        "label": args.label,
        "host": socket.gethostname(),
        "daemon_version": version,
        "params": {"size_mb": args.size_mb, "trials": args.trials,
                   "timeout_s": args.timeout, "nodes": nodes},
        "nodes": {},
    }

    for node in nodes:
        print(f"── {node}", flush=True)
        entry = {"ping": ping_node(node, args.ping_timeout), "trials": []}
        p = entry["ping"]
        print(f"   ping: {p['replies']}/{p['attempts']} replies, "
              f"dial {p['dial_ms_med']} ms, echo {p['echo_ms_med']} ms", flush=True)
        if p["replies"] == 0:
            entry["unreachable"] = True
            print("   UNREACHABLE — skipping transfer trials", flush=True)
        else:
            for i in range(args.trials):
                t = bench_node(node, args.size_mb, args.timeout)
                entry["trials"].append(t)
                if t["ok"]:
                    tr = t.get("transport", {})
                    print(f"   trial {i + 1}: {t['rt_goodput_mbps']:.3f} MB/s round-trip, "
                          f"{t['completion_pct']}% echoed"
                          f" (cwnd {tr.get('cwnd_min', '?')}–{tr.get('cwnd_max', '?')}, "
                          f"fast_retx {tr.get('fast_retx', '?')})", flush=True)
                else:
                    print(f"   trial {i + 1}: FAILED — {t['error']}", flush=True)
        ok = [t for t in entry["trials"] if t["ok"]]
        entry["best_goodput_mbps"] = max((t["rt_goodput_mbps"] for t in ok), default=0.0)
        entry["med_goodput_mbps"] = round(statistics.median([t["rt_goodput_mbps"] for t in ok]), 4) if ok else 0.0
        entry["best_completion_pct"] = max((t["completion_pct"] for t in ok), default=0.0)
        report["nodes"][node] = entry

    reachable = [n for n in report["nodes"].values() if not n.get("unreachable")]
    meds = [n["med_goodput_mbps"] for n in reachable]
    report["summary"] = {
        "reachable_nodes": len(reachable),
        "total_nodes": len(nodes),
        "fleet_med_goodput_mbps": round(statistics.median(meds), 4) if meds else 0.0,
        "fleet_best_goodput_mbps": max((n["best_goodput_mbps"] for n in reachable), default=0.0),
        "fleet_med_completion_pct": round(statistics.median(
            [n["best_completion_pct"] for n in reachable]), 1) if reachable else 0.0,
    }

    fname = ts.strftime("%Y%m%d-%H%M%S") + f"-{args.label}.json"
    path = os.path.join(RESULTS_DIR, fname)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    s = report["summary"]
    print(f"\nfleet: median {s['fleet_med_goodput_mbps']} MB/s · best "
          f"{s['fleet_best_goodput_mbps']} MB/s · median completion "
          f"{s['fleet_med_completion_pct']}% · {s['reachable_nodes']}/{s['total_nodes']} reachable")
    print(f"saved: {path}")
    return 0


def _load_runs():
    if not os.path.isdir(RESULTS_DIR):
        return []
    runs = []
    for f in sorted(os.listdir(RESULTS_DIR)):
        if not f.endswith(".json"):
            continue
        try:
            with open(os.path.join(RESULTS_DIR, f)) as fh:
                r = json.load(fh)
            r["_file"] = f
            runs.append(r)
        except (json.JSONDecodeError, OSError):
            continue
    return runs


def list_runs(_args):
    runs = _load_runs()
    if not runs:
        print(f"no runs in {RESULTS_DIR}")
        return 0
    for r in runs:
        s = r.get("summary", {})
        print(f"{r['_file']:45s} label={r.get('label', '?'):20s} "
              f"med={s.get('fleet_med_goodput_mbps', '?')} MB/s "
              f"completion={s.get('fleet_med_completion_pct', '?')}%")
    return 0


def compare_runs(args):
    runs = _load_runs()
    if not runs:
        print(f"no runs in {RESULTS_DIR}")
        return 1

    def pick(sel, fallback_newest_label=None):
        if sel:
            for r in runs:
                if r["_file"] == sel or r.get("label") == sel:
                    return r
            sys.exit(f"error: no run matching {sel!r}")
        if fallback_newest_label:
            cands = [r for r in runs if r.get("label") == fallback_newest_label]
            return cands[-1] if cands else None
        return None

    base = pick(args.baseline, "baseline")
    if base is None:
        sys.exit("error: no baseline run found — record one with: run --label baseline")
    latest = pick(args.run) or next((r for r in reversed(runs) if r["_file"] != base["_file"]), None)
    if latest is None:
        sys.exit("error: need a second run to compare against the baseline")

    print(f"baseline: {base['_file']}  ({base.get('daemon_version')})")
    print(f"current:  {latest['_file']}  ({latest.get('daemon_version')})\n")
    hdr = f"{'node':28s} {'base MB/s':>10s} {'now MB/s':>10s} {'Δ':>8s} {'base cmpl':>10s} {'now cmpl':>9s}"
    print(hdr)
    print("-" * len(hdr))
    for node in latest["nodes"]:
        b = base["nodes"].get(node, {})
        l = latest["nodes"][node]
        bg, lg = b.get("med_goodput_mbps", 0.0), l.get("med_goodput_mbps", 0.0)
        delta = f"{(lg - bg) / bg * 100.0:+.0f}%" if bg else "n/a"
        print(f"{node:28s} {bg:>10.3f} {lg:>10.3f} {delta:>8s} "
              f"{b.get('best_completion_pct', 0):>9.1f}% {l.get('best_completion_pct', 0):>8.1f}%")
    bs, ls = base["summary"], latest["summary"]
    bg, lg = bs["fleet_med_goodput_mbps"], ls["fleet_med_goodput_mbps"]
    delta = f"{(lg - bg) / bg * 100.0:+.0f}%" if bg else "n/a"
    print("-" * len(hdr))
    print(f"{'FLEET MEDIAN':28s} {bg:>10.3f} {lg:>10.3f} {delta:>8s} "
          f"{bs['fleet_med_completion_pct']:>9.1f}% {ls['fleet_med_completion_pct']:>8.1f}%")
    return 0


def main():
    if shutil.which("pilotctl") is None:
        sys.exit("error: pilotctl not found in PATH")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the benchmark suite and save a result file")
    r.add_argument("--label", default="run", help="label for this run (use 'baseline' for the reference run)")
    r.add_argument("--nodes", default=None, help="comma-separated node hostnames (default: standard set)")
    r.add_argument("--size-mb", type=int, default=1, help="transfer size per trial in MB (default 1)")
    r.add_argument("--trials", type=int, default=2, help="transfer trials per node (default 2)")
    r.add_argument("--timeout", type=int, default=150, help="per-transfer deadline seconds (default 150)")
    r.add_argument("--ping-timeout", type=int, default=15, help="ping invocation timeout seconds")
    r.set_defaults(fn=run_suite)

    c = sub.add_parser("compare", help="diff a run against the baseline")
    c.add_argument("--baseline", default=None, help="baseline file or label (default: newest run labeled 'baseline')")
    c.add_argument("--run", default=None, help="run file or label to compare (default: newest run)")
    c.set_defaults(fn=compare_runs)

    l = sub.add_parser("list", help="list saved runs")
    l.set_defaults(fn=list_runs)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
