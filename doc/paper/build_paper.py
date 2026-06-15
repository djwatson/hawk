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

# Patched trac.pygstyle: Name.Builtin (nb) uses same bold-red as Name.Function (nf)
TRAC_PYGSTYLE_PATCHED = r"""
\makeatletter
\def\PYG@reset{\let\PYG@it=\relax \let\PYG@bf=\relax%
    \let\PYG@ul=\relax \let\PYG@tc=\relax%
    \let\PYG@bc=\relax \let\PYG@ff=\relax}
\def\PYG@tok#1{\csname PYG@tok@#1\endcsname}
\def\PYG@toks#1+{\ifx\relax#1\empty\else%
    \PYG@tok{#1}\expandafter\PYG@toks\fi}
\def\PYG@do#1{\PYG@bc{\PYG@tc{\PYG@ul{%
    \PYG@it{\PYG@bf{\PYG@ff{#1}}}}}}}
\def\PYG#1#2{\PYG@reset\PYG@toks#1+\relax+\PYG@do{#2}}

\@namedef{PYG@tok@w}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.73,0.73}{##1}}}
\@namedef{PYG@tok@c}{\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.53}{##1}}}
\@namedef{PYG@tok@cp}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.60}{##1}}}
\@namedef{PYG@tok@cs}{\let\PYG@bf=\textbf\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.60}{##1}}}
\@namedef{PYG@tok@o}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@s}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sr}{\def\PYG@tc##1{\textcolor[rgb]{0.50,0.50,0.00}{##1}}}
\@namedef{PYG@tok@m}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@k}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@kt}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.27,0.33,0.53}{##1}}}
\@namedef{PYG@tok@nb}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.60,0.00,0.00}{##1}}}
\@namedef{PYG@tok@nf}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.60,0.00,0.00}{##1}}}
\@namedef{PYG@tok@nc}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.27,0.33,0.53}{##1}}}
\@namedef{PYG@tok@ne}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.60,0.00,0.00}{##1}}}
\@namedef{PYG@tok@nn}{\def\PYG@tc##1{\textcolor[rgb]{0.33,0.33,0.33}{##1}}}
\@namedef{PYG@tok@nv}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@no}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@nt}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.00,0.50}{##1}}}
\@namedef{PYG@tok@na}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@ni}{\def\PYG@tc##1{\textcolor[rgb]{0.50,0.00,0.50}{##1}}}
\@namedef{PYG@tok@gh}{\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.60}{##1}}}
\@namedef{PYG@tok@gu}{\def\PYG@tc##1{\textcolor[rgb]{0.67,0.67,0.67}{##1}}}
\@namedef{PYG@tok@gd}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.00,0.00}{##1}}\def\PYG@bc##1{{\setlength{\fboxsep}{0pt}\colorbox[rgb]{1.00,0.87,0.87}{\strut ##1}}}}
\@namedef{PYG@tok@gi}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.00,0.00}{##1}}\def\PYG@bc##1{{\setlength{\fboxsep}{0pt}\colorbox[rgb]{0.87,1.00,0.87}{\strut ##1}}}}
\@namedef{PYG@tok@gr}{\def\PYG@tc##1{\textcolor[rgb]{0.67,0.00,0.00}{##1}}}
\@namedef{PYG@tok@ge}{\let\PYG@it=\textit}
\@namedef{PYG@tok@gs}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@ges}{\let\PYG@bf=\textbf\let\PYG@it=\textit}
\@namedef{PYG@tok@gp}{\def\PYG@tc##1{\textcolor[rgb]{0.33,0.33,0.33}{##1}}}
\@namedef{PYG@tok@go}{\def\PYG@tc##1{\textcolor[rgb]{0.53,0.53,0.53}{##1}}}
\@namedef{PYG@tok@gt}{\def\PYG@tc##1{\textcolor[rgb]{0.67,0.00,0.00}{##1}}}
\@namedef{PYG@tok@err}{\def\PYG@tc##1{\textcolor[rgb]{0.65,0.09,0.09}{##1}}\def\PYG@bc##1{{\setlength{\fboxsep}{0pt}\colorbox[rgb]{0.89,0.82,0.82}{\strut ##1}}}}
\@namedef{PYG@tok@kc}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@kd}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@kn}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@kp}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@kr}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@bp}{\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.60}{##1}}}
\@namedef{PYG@tok@fm}{\let\PYG@bf=\textbf\def\PYG@tc##1{\textcolor[rgb]{0.60,0.00,0.00}{##1}}}
\@namedef{PYG@tok@vc}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@vg}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@vi}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@vm}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.50,0.50}{##1}}}
\@namedef{PYG@tok@sa}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sb}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sc}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@dl}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sd}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@s2}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@se}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sh}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@si}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@sx}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@s1}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@ss}{\def\PYG@tc##1{\textcolor[rgb]{0.73,0.53,0.27}{##1}}}
\@namedef{PYG@tok@mb}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@mf}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@mh}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@mi}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@il}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@mo}{\def\PYG@tc##1{\textcolor[rgb]{0.00,0.60,0.60}{##1}}}
\@namedef{PYG@tok@ow}{\let\PYG@bf=\textbf}
\@namedef{PYG@tok@ch}{\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.53}{##1}}}
\@namedef{PYG@tok@cm}{\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.53}{##1}}}
\@namedef{PYG@tok@cpf}{\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.53}{##1}}}
\@namedef{PYG@tok@c1}{\let\PYG@it=\textit\def\PYG@tc##1{\textcolor[rgb]{0.60,0.60,0.53}{##1}}}
\def\PYGZbs{\char`\\}
\def\PYGZus{\char`\_}
\def\PYGZob{\char`\{}
\def\PYGZcb{\char`\}}
\def\PYGZca{\char`\^}
\def\PYGZam{\char`\&}
\def\PYGZlt{\char`\<}
\def\PYGZgt{\char`\>}
\def\PYGZsh{\char`\#}
\def\PYGZpc{\char`\%}
\def\PYGZdl{\char`\$}
\def\PYGZhy{\char`\-}
\def\PYGZsq{\char`\'}
\def\PYGZdq{\char`\"}
\def\PYGZti{\char`\~}
\def\PYGZat{@}
\def\PYGZlb{[}
\def\PYGZrb{]}
\makeatother
"""
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


def build_pdf(review, no_acm=False):
  out = BUILD / "hawk-paper.pdf"
  tex = BUILD / "hawk-paper.tex"
  BUILD.mkdir(parents=True, exist_ok=True)
  # Pre-create pygstyle so minted doesn't generate it: make Name.Builtin
  # (used by pygments for scheme builtins like list?, pair?, cdr, etc.)
  # use the same color as Name.Function (bold red) instead of grey.
  (BUILD / "_minted-hawk-paper").mkdir(parents=True, exist_ok=True)
  style = (BUILD / "_minted-hawk-paper" / "trac.pygstyle")
  if not style.exists():
    style.write_text(TRAC_PYGSTYLE_PATCHED, encoding="utf-8")
  env = os.environ.copy()
  tex_path = str(HERE / "tex") + os.pathsep
  env["TEXINPUTS"] = tex_path + env.get("TEXINPUTS", "")
  env["BSTINPUTS"] = tex_path + env.get("BSTINPUTS", "")
  env["BIBINPUTS"] = str(HERE) + os.pathsep + env.get("BIBINPUTS", "")
  class_options = ["sigplan"]
  if review:
    class_options += ["anonymous", "review"]
  if no_acm:
    class_options += ["nonacm"]

  paper_text = PAPER.read_text(encoding="utf-8")
  if no_acm:
    paper_text = paper_text.replace(
      "header-includes: |",
      "header-includes: |\n"
      "  \\settopmatter{printccs=false}\n"
      "  \\setcopyright{none}\n"
    )

  paper_input = BUILD / "paper.md"
  paper_input.write_text(paper_text, encoding="utf-8")
  cmd = [
    "pandoc",
    str(paper_input.relative_to(HERE)),
    "--from", "markdown+raw_tex",
    "--standalone",
    "--number-sections",
    "--shift-heading-level-by=-1",
    "--natbib",
    "--lua-filter", str((HERE / "minted.lua").relative_to(HERE)),
    "-V", "documentclass=acmart",
    "-V", "biblio-style=ACM-Reference-Format",
    "-V", "indent=true",
  ]
  for option in class_options:
    cmd += ["-V", f"classoption={option}"]
  cmd += ["-o", str(tex.relative_to(HERE))]
  subprocess.run(cmd, check=True, cwd=HERE, env=env)
  text = tex.read_text(encoding="utf-8")
  match = re.search(r"\n\\maketitle\n+(\\begin\{abstract\}.*?\\end\{abstract\}\n)", text, re.S)
  if match:
    text = text[:match.start()] + "\n" + match.group(1) + "\\maketitle\n" + text[match.end():]
  if no_acm:
    text = text.replace("\\date{\\today}", "\\date{}")
  def table(match):
    spec, body = match.group(1), match.group(2)
    body = re.sub(r"\\endhead\n\\bottomrule\\noalign\{\}\n\\endlastfoot\n", "", body)
    body = body.replace("\\endhead\n", "").replace("\\endlastfoot\n", "").rstrip()
    body += "\n\\bottomrule\\noalign{}"
    return f"\\begin{{center}}\n\\begin{{tabular}}{{{spec}}}\n{body}\n\\end{{tabular}}\n\\end{{center}}"
  text = re.sub(r"\\begin\{longtable\}\[\]\{(.*?)\}\n(.*?)\\end\{longtable\}", table, text, flags=re.S)
  tex.write_text(text, encoding="utf-8")
  stem = str(tex.relative_to(HERE).with_suffix(""))
  latex = ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "-shell-escape", "-output-directory", "build", str(tex.relative_to(HERE))]
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
    default="camera-ready",
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
  parser.add_argument(
    "--acm",
    action="store_false",
    dest="no_acm",
    help="include ACM boilerplate (copyright, reference format, conference header)",
  )
  parser.set_defaults(no_acm=True)
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
  out = build_pdf(review=args.mode == "review", no_acm=args.no_acm)
  print(f"wrote {out.relative_to(ROOT)} ({args.mode})")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
