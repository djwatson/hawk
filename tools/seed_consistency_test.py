#!/usr/bin/env python3
"""Run hawk Scheme tests across seeds and check output consistency."""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import signal
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Task:
  test_path: Path
  seed: int


@dataclass
class Result:
  task: Task
  returncode: int
  stdout: str
  stderr: str
  timed_out: bool = False


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description=(
          "Run all test/*.scm files with hawk for seeds 0..X and report "
          "crashes and output mismatches."
      )
  )
  parser.add_argument(
      "--hawk",
      default="./build/hawk",
      help="Path to hawk executable (default: ./build/hawk)",
  )
  parser.add_argument(
      "--test-glob",
      default="test/*.scm",
      help="Glob for Scheme tests (default: test/*.scm)",
  )
  parser.add_argument(
      "--max-seed",
      type=int,
      default=100,
      help="Run seeds 0..max-seed inclusive (default: 100)",
  )
  parser.add_argument(
      "-j",
      "--jobs",
      type=int,
      default=8,
      help="Number of parallel workers (default: 8)",
  )
  parser.add_argument(
      "--timeout",
      type=float,
      default=None,
      help="Optional per-run timeout in seconds",
  )
  return parser.parse_args()


def classify_exit(returncode: int) -> str:
  if returncode < 0:
    sig = -returncode
    try:
      return f"signal {sig} ({signal.Signals(sig).name})"
    except ValueError:
      return f"signal {sig}"
  return f"exit {returncode}"


def run_one(hawk_path: str, task: Task, timeout: Optional[float]) -> Result:
  cmd = [hawk_path, "-s", str(task.seed), str(task.test_path)]
  try:
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return Result(
        task=task,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        timed_out=False,
    )
  except subprocess.TimeoutExpired as exc:
    return Result(
        task=task,
        returncode=124,
        stdout=exc.stdout or "",
        stderr=(exc.stderr or "") + f"\nTIMEOUT after {timeout} seconds\n",
        timed_out=True,
    )


def main() -> int:
  args = parse_args()

  if args.max_seed < 0:
    print("error: --max-seed must be >= 0", file=sys.stderr)
    return 2
  if args.jobs <= 0:
    print("error: --jobs must be >= 1", file=sys.stderr)
    return 2

  hawk = Path(args.hawk)
  if not hawk.exists():
    print(f"error: hawk binary not found: {hawk}", file=sys.stderr)
    return 2
  if not os.access(hawk, os.X_OK):
    print(f"error: hawk binary is not executable: {hawk}", file=sys.stderr)
    return 2

  tests = sorted(Path(".").glob(args.test_glob))
  if not tests:
    print(f"error: no tests matched glob: {args.test_glob}", file=sys.stderr)
    return 2

  tasks = [Task(test_path=t, seed=s) for t in tests for s in range(args.max_seed + 1)]
  runs_per_test = args.max_seed + 1

  print(
      f"Running {len(tests)} tests x {args.max_seed + 1} seeds = {len(tasks)} runs "
      f"with {args.jobs} workers"
  )

  results_by_test: dict[Path, list[Result]] = defaultdict(list)
  live_baseline_by_test: dict[Path, tuple[int, str]] = {}
  done_count_by_test: dict[Path, int] = defaultdict(int)

  with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
    future_to_task = {
        executor.submit(run_one, str(hawk), task, args.timeout): task for task in tasks
    }
    completed = 0
    total = len(tasks)
    for future in concurrent.futures.as_completed(future_to_task):
      res = future.result()
      results_by_test[res.task.test_path].append(res)
      done_count_by_test[res.task.test_path] += 1
      completed += 1

      if res.returncode != 0:
        reason = "timeout" if res.timed_out else classify_exit(res.returncode)
        print(f"\n  failure: {res.task.test_path} seed {res.task.seed}: {reason}")
      else:
        baseline = live_baseline_by_test.get(res.task.test_path)
        if baseline is None:
          live_baseline_by_test[res.task.test_path] = (res.task.seed, res.stdout)
        elif res.stdout != baseline[1]:
          print(
              "\n  failure: "
              f"{res.task.test_path} seed {res.task.seed}: "
              f"output mismatch (baseline seed {baseline[0]})"
          )

      percent = (completed * 100.0) / total
      print(
          f"\r  progress: {completed}/{total} ({percent:6.2f}%)",
          end="",
          flush=True,
      )

      if done_count_by_test[res.task.test_path] == runs_per_test:
        print(f"\n  {res.task.test_path} finished")
    print()

  crash_count = 0
  mismatch_count = 0

  print("\n=== Seed Consistency Report ===")
  for test in tests:
    test_results = sorted(results_by_test[test], key=lambda r: r.task.seed)

    crashes = [r for r in test_results if r.returncode != 0]
    ok_runs = [r for r in test_results if r.returncode == 0]

    # Use the first successful run as baseline; all successful outputs must match it.
    baseline = ok_runs[0].stdout if ok_runs else None
    mismatches = [
        r
        for r in ok_runs
        if baseline is not None and r.stdout != baseline
    ]

    if not crashes and not mismatches:
      continue

    print(f"\n{test}:")

    if crashes:
      crash_count += len(crashes)
      print(f"  crashes/timeouts ({len(crashes)}):")
      for r in crashes:
        reason = "timeout" if r.timed_out else classify_exit(r.returncode)
        print(f"    seed {r.task.seed}: {reason}")

    if mismatches:
      mismatch_count += len(mismatches)
      print(f"  output mismatches ({len(mismatches)}):")
      for r in mismatches:
        print(f"    seed {r.task.seed}")

    if not ok_runs:
      print("  note: no successful runs for this test; baseline unavailable")

  print("\n=== Summary ===")
  print(f"tests scanned: {len(tests)}")
  print(f"total runs: {len(tasks)}")
  print(f"crashes/timeouts: {crash_count}")
  print(f"mismatched outputs: {mismatch_count}")

  if crash_count == 0 and mismatch_count == 0:
    print("status: OK (all successful outputs matched, no crashes)")
    return 0

  print("status: FAIL (see report above)")
  return 1


if __name__ == "__main__":
  raise SystemExit(main())
