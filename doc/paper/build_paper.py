#!/usr/bin/env python3

import os
import re
import subprocess
import sys
import math
import argparse
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BENCH = ROOT / "doc" / "bench"
GENERATED = HERE / "generated"
BUILD = HERE / "build"
PAPER = HERE / "paper.md"


def parse_benchmarks():
  data = {}
  for arch_dir in sorted(p for p in BENCH.iterdir() if p.is_dir()):
    arch = arch_dir.name
    data[arch] = {}
    for result in sorted(p for p in arch_dir.iterdir() if p.is_file()):
      for line in result.read_text(encoding="utf-8").splitlines():
        match = re.search(r"\+!CSVLINE!\+([^,]+),([^,]+),([0-9.]+)", line)
        if not match:
          continue
        implementation, invocation, seconds = match.group(1), match.group(2), float(match.group(3))
        data[arch].setdefault(invocation, {})[implementation] = seconds
  return data


def comparison_rows_by_arch(data):
  rows_by_arch = defaultdict(list)
  for arch, benches in sorted(data.items()):
    for invocation, results in sorted(benches.items()):
      hawk = next((v for k, v in results.items() if k.lower() == "hawk"), None)
      chez = next((v for k, v in results.items() if k.lower().startswith("chez")), None)
      if not hawk or not chez:
        continue
      # Runtime change relative to Chez. Negative is faster, positive is slower.
      percent = (hawk / chez - 1.0) * 100.0
      name = invocation.split(":", 1)[0]
      rows_by_arch[arch].append((name, percent, hawk / chez))
  return rows_by_arch


def geomean_percent(rows):
  ratio = math.prod(row[2] for row in rows) ** (1.0 / len(rows))
  return (ratio - 1.0) * 100.0


def write_chart(arch, rows):
  import matplotlib
  matplotlib.use("Agg")
  import matplotlib.pyplot as plt

  GENERATED.mkdir(parents=True, exist_ok=True)
  rows = sorted(rows, key=lambda row: row[1])
  rows.append(("TOTAL", geomean_percent(rows), 1.0))
  labels = [name for name, _, _ in rows]
  values = [percent for _, percent, _ in rows]
  colors = ["#4a7ebb" if value < 0 else "#b65b4b" for value in values]

  plt.rcParams.update({
    "font.family": "serif",
    "font.size": 7,
    "axes.titlesize": 11,
    "axes.labelsize": 8,
  })
  fig, ax = plt.subplots(figsize=(7.2, 3.9))
  ax.bar(labels, values, color=colors, width=0.78)
  ax.axhline(0, color="black", linewidth=0.8)
  ax.set_title(f"{arch}: Hawk Runtime Change Relative to Chez")
  ax.set_ylabel("Runtime change (%)")
  ax.set_xlabel("Benchmark")
  ax.grid(axis="y", color="#dddddd", linewidth=0.5)
  ax.set_axisbelow(True)
  ax.tick_params(axis="x", labelrotation=90, labelsize=4)
  ax.tick_params(axis="y", labelsize=7)
  for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
  fig.tight_layout()
  fig.savefig(GENERATED / f"benchmark_percent_{arch}.pdf")
  plt.close(fig)


def build_pdf(review):
  out = BUILD / "hawk-paper.pdf"
  tex = BUILD / "hawk-paper.tex"
  BUILD.mkdir(parents=True, exist_ok=True)
  env = os.environ.copy()
  tex_path = str(HERE / "tex") + os.pathsep
  env["TEXINPUTS"] = tex_path + env.get("TEXINPUTS", "")
  env["BSTINPUTS"] = tex_path + env.get("BSTINPUTS", "")
  env["BIBINPUTS"] = str(HERE) + os.pathsep + env.get("BIBINPUTS", "")
  class_options = ["sigplan"]
  if review:
    class_options += ["anonymous", "review"]
  cmd = [
    "pandoc",
    str(PAPER.relative_to(HERE)),
    "--from", "markdown+raw_tex",
    "--standalone",
    "--number-sections",
    "--shift-heading-level-by=-1",
    "--natbib",
    "-V", "documentclass=acmart",
    "-V", "biblio-style=ACM-Reference-Format",
    "-V", "indent=true",
  ]
  for option in class_options:
    cmd.extend(["-V", f"classoption={option}"])
  cmd.extend(["-o", str(tex.relative_to(HERE))])
  subprocess.run(cmd, check=True, cwd=HERE, env=env)
  text = tex.read_text(encoding="utf-8")
  match = re.search(r"\n\\maketitle\n+(\\begin\{abstract\}.*?\\end\{abstract\}\n)", text, re.S)
  if match:
    text = text[:match.start()] + "\n" + match.group(1) + "\\maketitle\n" + text[match.end():]
  def table(match):
    spec, body = match.group(1), match.group(2)
    body = re.sub(r"\\endhead\n\\bottomrule\\noalign\{\}\n\\endlastfoot\n", "", body)
    body = body.replace("\\endhead\n", "").replace("\\endlastfoot\n", "").rstrip()
    body += "\n\\bottomrule\\noalign{}"
    return f"\\begin{{center}}\n\\begin{{tabular}}{{{spec}}}\n{body}\n\\end{{tabular}}\n\\end{{center}}"
  text = re.sub(r"\\begin\{longtable\}\[\]\{(.*?)\}\n(.*?)\\end\{longtable\}", table, text, flags=re.S)
  tex.write_text(text, encoding="utf-8")
  stem = str(tex.relative_to(HERE).with_suffix(""))
  latex = ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "-output-directory", "build", str(tex.relative_to(HERE))]
  subprocess.run(latex, check=True, cwd=HERE, env=env)
  subprocess.run(["bibtex", stem], check=True, cwd=HERE, env=env)
  subprocess.run(latex, check=True, cwd=HERE, env=env)
  subprocess.run(latex, check=True, cwd=HERE, env=env)
  return out


def parse_args():
  parser = argparse.ArgumentParser(description="Build the Hawk paper PDF.")
  parser.add_argument(
    "--mode",
    choices=("review", "camera-ready"),
    default="review",
    help="review uses acmart anonymous+review options; camera-ready omits them",
  )
  parser.add_argument(
    "--review",
    action="store_const",
    const="review",
    dest="mode",
    help="build with anonymous review options",
  )
  parser.add_argument(
    "--camera-ready",
    action="store_const",
    const="camera-ready",
    dest="mode",
    help="build without anonymous review options",
  )
  return parser.parse_args()


def main():
  args = parse_args()
  os.environ.setdefault("MPLCONFIGDIR", str(BUILD / "matplotlib"))
  rows_by_arch = comparison_rows_by_arch(parse_benchmarks())
  if not rows_by_arch:
    print("no matched Hawk/Chez benchmark results found", file=sys.stderr)
    return 1
  for arch, rows in rows_by_arch.items():
    write_chart(arch, rows)
  out = build_pdf(args.mode == "review")
  print(f"wrote {out.relative_to(ROOT)} ({args.mode})")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
