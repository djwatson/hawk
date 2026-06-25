#!/usr/bin/env python3
"""Run benchmark seeds one-at-a-time and report mean/sd timing."""

from __future__ import annotations

import argparse
import math
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BenchResult:
  seed: int
  elapsed: float


def parse_elapsed(stdout: str) -> float | None:
  for line in stdout.splitlines():
    if line.startswith("+!CSVLINE!+"):
      fields = line.split(",", maxsplit=2)
      if len(fields) == 3:
        return float(fields[2])
  return None


def run_bench(hawk: str, bench: Path, seed: int) -> BenchResult | str:
  try:
    proc = subprocess.run(
        [hawk, "-s", str(seed), str(bench)],
        capture_output=True, text=True, timeout=120,
    )
  except subprocess.TimeoutExpired:
    return "TIMEOUT"
  if proc.returncode != 0:
    return f"exit {proc.returncode}"
  elapsed = parse_elapsed(proc.stdout)
  if elapsed is None:
    return "no elapsed line"
  return BenchResult(seed=seed, elapsed=elapsed)


def fmt_time(t: float) -> str:
  if t < 60:
    return f"{t:.4f}s"
  return f"{t/60:.2f}m"


def fmt_mean_sd(mean: float, sd: float) -> str:
  # show signif digits based on sd magnitude
  if sd >= 1:
    return f"{mean:.3f}s sd={sd:.3f}s"
  if sd >= 0.01:
    return f"{mean:.4f}s sd={sd:.4f}s"
  return f"{mean:.6f}s sd={sd:.6f}s"


def main() -> int:
  parser = argparse.ArgumentParser(
      description="Run test/bench/*.scm across seeds and compute timing stats."
  )
  parser.add_argument("--hawk", default="./build/hawk")
  parser.add_argument("--bench-dir", default="test/bench")
  parser.add_argument("--seeds", type=int, default=30, help="Number of seeds (0..N-1)")
  parser.add_argument("-j", "--jobs", type=int, default=1, help="Parallel workers (default: 1)")
  args = parser.parse_args()

  hawk = Path(args.hawk)
  if not hawk.exists() or not hawk.is_file():
    print(f"error: {hawk} not found", file=sys.stderr)
    return 1

  benches = sorted(Path(args.bench_dir).glob("*.scm"))
  if not benches:
    print(f"error: no .scm files in {args.bench_dir}", file=sys.stderr)
    return 1

  nseeds = args.seeds
  print(f"hawk: {hawk}")
  print(f"benches: {len(benches)}, seeds: 0..{nseeds - 1}, jobs: {args.jobs}")
  print()

  # Collect all results for final summary
  all_rows: list[tuple[str, float, float, float, float, int, int]] = []
  # (label, mean, sd, min, max, n_success, n_fail)

  for bench in benches:
    label = bench.stem
    results: list[BenchResult] = []
    failures: list[tuple[int, str]] = []

    print(f"----- {label} -----")

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
      futmap = {pool.submit(run_bench, str(hawk), bench, s): s for s in range(nseeds)}
      for fut in as_completed(futmap):
        s = futmap[fut]
        outcome = fut.result()
        if isinstance(outcome, BenchResult):
          results.append(outcome)
          print(f"  seed {s:3d}: {fmt_time(outcome.elapsed)}")
        else:
          failures.append((s, outcome))
          print(f"  seed {s:3d}: FAIL {outcome}")

    # Per-bench summary
    if results:
      times = [r.elapsed for r in results]
      n = len(times)
      mn = sum(times) / n
      var = sum((t - mn) ** 2 for t in times) / n
      sd = math.sqrt(var)
      mn_t = min(times)
      mx_t = max(times)
      all_rows.append((label, mn, sd, mn_t, mx_t, n, len(failures)))
      sd_pct = (sd / mn * 100) if mn > 0 else 0.0
      fail_msg = f", failures={len(failures)}" if failures else ""
      print(f"  -> mean={fmt_time(mn)}  sd={fmt_time(sd)} ({sd_pct:.2f}%)  "
            f"min={fmt_time(mn_t)}  max={fmt_time(mx_t)}  n={n}{fail_msg}")
    else:
      all_rows.append((label, 0.0, 0.0, 0.0, 0.0, 0, len(failures)))
      print(f"  -> NO SUCCESSFUL RUNS")

    if failures:
      for s, why in failures:
        print(f"     seed {s}: {why}")
    print()

  # Final full summary
  print("=" * 72)
  print(f"{'Benchmark':20s} {'mean':>12s} {'sd%':>8s} {'min':>10s} {'max':>10s}  n  fail")
  print("-" * 72)
  grand_fail = 0
  for label, mn, sd, mn_t, mx_t, n, nf in all_rows:
    grand_fail += nf
    if n == 0:
      print(f"{label:20s} {'NO DATA':>12s}")
    else:
      sd_pct = (sd / mn * 100) if mn > 0 else 0.0
      print(f"{label:20s} {fmt_time(mn):>12s} {sd_pct:>7.2f}% {fmt_time(mn_t):>10s} {fmt_time(mx_t):>10s}  {n:3d}  {nf}")
  print("-" * 72)
  print(f"Total benchmarks: {len(benches)}, total runs: {len(benches) * nseeds}, failures: {grand_fail}")
  return 0 if grand_fail == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())
