# pilot-bench — overlay throughput benchmark

Repeatable throughput measurement for the Pilot overlay, built to track the
transport-efficiency work: record a baseline once, then re-run after every
change and diff the numbers.

## Quick start

```bash
# 1. Record the reference numbers (once):
./bench/pilot-bench.py run --label baseline

# 2. After landing a transport change:
./bench/pilot-bench.py run --label after-ooo-buffer-fix

# 3. Diff against the baseline:
./bench/pilot-bench.py compare
```

Results are JSON files in `~/.pilot/bench-results/` (override with
`PILOT_BENCH_DIR`), one per run, never overwritten.

## What it measures (per node)

| Metric | Source | Meaning |
|---|---|---|
| ping dial / echo ms | `pilotctl ping` | connection setup + small-payload RTT |
| round-trip goodput MB/s | `pilotctl bench --json` | bytes actually echoed back / wall time |
| completion % | `pilotctl bench --json` | how much of the payload survived the round trip before deadline |
| cwnd min–max, fast_retx, srtt | `pilotctl info --json` sampled during transfer | *why* a run was slow (window collapse, retransmit crawl) |

`compare` prints per-node and fleet-median deltas versus the baseline.

## Default node set

A fixed cross-section of the fleet (`coingecko-markets-simple`,
`github-public`, `list-agents`, `mediawiki-random`, `pilot-mom`). Keep the
set stable across runs — the comparison is only meaningful on identical
nodes. `pilot-mom` is expected to show 0% completion until the echo
handler's `ErrSendBufFull` bug (pkg/daemon/services.go, echo loop exits on
transient backpressure) is fixed; it is in the set to verify that fix.

## Known baseline pathologies (2026-08-02)

Recorded before any transport changes; see the fix list these numbers gate:

1. **Slow-start overshoot** — cwnd ramps past path capacity (~550 KB burst
   over a 214 ms RTT relay path) causing mass loss.
2. **Loss amplification** — receiver OOO buffer caps at 128 segments
   (`MaxOOOBuf`, pkg/daemon/ports.go) while `MaxCongWin` allows 256 in
   flight: one loss with >128 outstanding silently drops everything after it.
3. **Recovery crawl** — after an RTO the window collapses to 1 MSS and lost
   segments drain at ~1 per RTO (RTO backs off to 10 s): ~1.3 KB/s.

Theoretical ceiling at current RTT with a safe 512 KB window: ~2.4 MB/s.
Baseline best case: ~0.2 MB/s round-trip.
