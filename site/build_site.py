#!/usr/bin/env python3

import html
import http.server
import json
import math
import os
import re
import shutil
import socketserver
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
CONTENT = SITE / "content"
ASSETS = SITE / "assets"
OUT = SITE / "_site"
GENERATED = OUT / "generated"
BASE = os.environ.get("SITE_BASE", "").rstrip("/")

NAV = [
  ("Intro", "/"),
  ("Docs", "/docs/"),
  ("Benchmarks", "/benchmarks/"),
  ("Code", "/code/"),
  # ("Releases", "/releases/"),
  # ("Blog", "/blog/"),
]


def read(path):
  return path.read_text(encoding="utf-8")


def write(path, text):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(text, encoding="utf-8")


def copy(src, dst):
  dst.parent.mkdir(parents=True, exist_ok=True)
  shutil.copyfile(src, dst)


def escape(s):
  return html.escape(str(s), quote=True)


def href(path):
  if re.match(r"^(https?:|#)", path):
    return path
  return f"{BASE}{path if path.startswith('/') else '/' + path}"


def slug(s):
  return re.sub(r"^-|-$", "", re.sub(r"[^a-z0-9]+", "-", s.lower()))


def parse_frontmatter(text):
  if not text.startswith("---\n"):
    return {}, text
  end = text.find("\n---\n", 4)
  if end < 0:
    return {}, text
  meta = {}
  for line in text[4:end].splitlines():
    match = re.match(r"^([^:]+):\s*(.*)$", line)
    if match:
      meta[match.group(1).strip()] = match.group(2).strip().strip("\"'")
  return meta, text[end + 5:]


def inline_md(s):
  spans = []

  def code_span(match):
    spans.append(f"<code>{escape(match.group(1))}</code>")
    return f"\0{len(spans) - 1}\0"

  s = re.sub(r"`([^`]+)`", code_span, s)
  s = escape(s)
  s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
  s = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)
  s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", lambda m: f'<a href="{href(m.group(2))}">{m.group(1)}</a>', s)
  return re.sub(r"\0(\d+)\0", lambda m: spans[int(m.group(1))], s)


def markdown(text):
  lines = text.replace("\r\n", "\n").split("\n")
  out = []
  para = []
  list_open = False
  in_code = False
  code_lang = ""
  code_lines = []

  def flush_para():
    nonlocal para
    if para:
      out.append(f"<p>{inline_md(' '.join(para))}</p>")
      para = []

  def close_list():
    nonlocal list_open
    if list_open:
      out.append("</ul>")
      list_open = False

  for line in lines:
    fence = re.match(r"^```(\w*)\s*$", line)
    if fence and not in_code:
      flush_para()
      close_list()
      in_code = True
      code_lang = fence.group(1)
      code_lines = []
      continue
    if fence and in_code:
      klass = f' class="language-{code_lang}"' if code_lang else ""
      out.append(f"<pre><code{klass}>{escape(chr(10).join(code_lines))}</code></pre>")
      in_code = False
      continue
    if in_code:
      code_lines.append(line)
      continue

    if re.match(r"^\s*<[^>]+>", line):
      flush_para()
      close_list()
      out.append(line)
      continue

    heading = re.match(r"^(#{1,4})\s+(.+)$", line)
    if heading:
      flush_para()
      close_list()
      level = len(heading.group(1))
      title = heading.group(2)
      out.append(f'<h{level} id="{slug(title.replace("`", ""))}">{inline_md(title)}</h{level}>')
      continue

    item = re.match(r"^-\s+(.+)$", line)
    if item:
      flush_para()
      if not list_open:
        out.append("<ul>")
        list_open = True
      out.append(f"<li>{inline_md(item.group(1))}</li>")
      continue

    if not line.strip():
      flush_para()
      close_list()
      continue
    para.append(line.strip())

  flush_para()
  close_list()
  return "\n".join(out) + "\n"


def parse_benchmarks():
  bench_dir = ROOT / "doc" / "bench"
  data = {}
  warnings = []
  if not bench_dir.exists():
    return data, warnings

  for arch_dir in sorted(p for p in bench_dir.iterdir() if p.is_dir()):
    arch = arch_dir.name
    data[arch] = {}
    for result_file in sorted(p for p in arch_dir.iterdir() if p.is_file()):
      for line in read(result_file).splitlines():
        match = re.search(r"\+!CSVLINE!\+([^,]+),([^,]+),([0-9.]+)", line)
        if not match:
          continue
        implementation, invocation, seconds = match.group(1), match.group(2), float(match.group(3))
        name, sep, args = invocation.partition(":")
        key = f"{name}:{args}" if sep else name
        data[arch].setdefault(key, {"name": name, "args": args, "results": {}})
        # Later rows overwrite earlier rows, so repeated runs keep the final result.
        data[arch][key]["results"][implementation] = seconds

  for arch, benches in data.items():
    impls = {impl for bench in benches.values() for impl in bench["results"]}
    for bench in benches.values():
      for impl in impls:
        if impl not in bench["results"]:
          warnings.append(f"{arch}: {bench['name']}:{bench['args']} missing {impl}")
  return data, warnings


def comparison_rows_by_arch(data):
  rows_by_arch = {}
  for arch, benches in sorted(data.items()):
    rows = []
    for invocation, bench in sorted(benches.items()):
      hawk = next((v for k, v in bench["results"].items() if k.lower() == "hawk"), None)
      chez = next((v for k, v in bench["results"].items() if k.lower().startswith("chez")), None)
      if not hawk or not chez:
        continue
      percent = (hawk / chez - 1.0) * 100.0
      name, _, args = invocation.partition(":")
      rows.append((name, args, percent, hawk, chez))
    rows_by_arch[arch] = rows
  return rows_by_arch


def svg_percent_chart(arch, rows):
  rows = sorted(rows, key=lambda row: row[2])
  height = 420
  left = 92
  right = 24
  top = 40
  bottom = 82
  width = max(1000, left + right + len(rows) * 18)
  chart_h = height - top - bottom
  zero_y = top + chart_h / 2
  max_abs = max([abs(percent) for _, _, percent, _, _ in rows] + [1.0])
  scale = (chart_h / 2 - 16) / max_abs
  bar_slot = max(18, (width - left - right) / max(len(rows), 1))
  bar_w = min(22, bar_slot * 0.72)
  axis_limit = max(20, int(math.ceil(max_abs / 20.0) * 20))
  body = [
    f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(arch)} benchmark runtime change chart" xmlns="http://www.w3.org/2000/svg">',
    '<style>'
    'text{font:14px Georgia,serif;fill:#2c2924}'
    '.small{font-size:12px;fill:#676057}'
    '.title{font-weight:bold;font-size:17px}'
    '.axis{font-size:11px;fill:#5f564f}'
    '.bench{font-size:10px;fill:#676057}'
    '</style>',
    f'<text class="title" x="{left}" y="22">{escape(arch)} Hawk Runtime Change Relative to Chez</text>',
    f'<text class="small" x="{left}" y="38">Negative values mean Hawk is faster. Positive values mean Hawk is slower.</text>',
    f'<line x1="{left}" y1="{zero_y:.1f}" x2="{width - right}" y2="{zero_y:.1f}" stroke="#333" stroke-width="1"/>',
  ]
  for percent in range(-axis_limit, axis_limit + 1, 20):
    y = zero_y - percent * scale
    if top <= y <= height - bottom:
      body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#ddd" stroke-width="1"/>')
      body.append(f'<line x1="{left - 4}" y1="{y:.1f}" x2="{left}" y2="{y:.1f}" stroke="#333" stroke-width="1"/>')
      body.append(f'<text class="axis" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{percent:+d}%</text>')
  for i, (name, args, percent, _, _) in enumerate(rows):
    x = left + i * bar_slot + (bar_slot - bar_w) / 2
    bar_h = abs(percent) * scale
    if percent >= 0:
      y = zero_y - bar_h
      fill = "#b65b4b"
    else:
      y = zero_y
      fill = "#4a7ebb"
    body.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" fill="{fill}" rx="2"/>')
    label_x = x + bar_w / 2
    label_y = height - 62
    label = name
    body.append(
      f'<text class="bench" x="{label_x:.1f}" y="{label_y}" text-anchor="end" transform="rotate(-90 {label_x:.1f} {label_y})">{escape(label)}</text>'
    )
  body.append("</svg>")
  return "\n".join(body) + "\n"


def geomean_ratio(rows):
  ratios = [chez / hawk for _, _, _, hawk, chez in rows if hawk and chez]
  if not ratios:
    return None
  return math.exp(sum(math.log(ratio) for ratio in ratios) / len(ratios))


def benchmark_html(data):
  rows_by_arch = comparison_rows_by_arch(data)
  pieces = []
  for arch in sorted(rows_by_arch, key=lambda name: (name != "x64", name)):
    rows = sorted(rows_by_arch[arch], key=lambda row: row[2])
    ratio = geomean_ratio(rows)
    pieces.append(f'<section class="bench-arch">\n<h2 id="{slug(arch)}">{escape(arch)} Hawk Runtime Change Relative to Chez</h2>')
    text = f"{len(rows)} matched benchmarks comparing Hawk and Chez."
    if ratio:
      text += f" Geometric mean: Hawk is {ratio:.2f}x Chez speed on matched benchmarks."
    pieces.append(f"<p>{text} Lower runtime bars are better.</p>")
    filename = f"generated/benchmark_percent_{arch}.svg"
    write(OUT / filename, svg_percent_chart(arch, rows))
    pieces.append(f'<figure class="chart"><img src="{href(filename)}" alt="{escape(arch)} benchmark runtime change chart"></figure>')
    pieces.append('<table><thead><tr><th>Benchmark</th><th>Hawk</th><th>Chez</th><th>% Change</th></tr></thead><tbody>')
    for name, args, percent, hawk, chez in rows:
      pieces.append(
        f"<tr><td>{escape(name)}</td><td>{hawk:.6f}</td><td>{chez:.6f}</td><td>{percent:+.1f}%</td></tr>"
      )
    pieces.append("</tbody></table>\n</section>")
  return "\n".join(pieces) + "\n"


def layout(page, body, current):
  links = []
  for label, target in NAV:
    active = current == target or (target != "/" and current.startswith(target))
    klass = ' class="active"' if active else ""
    links.append(f'<a{klass} href="{href(target)}">{label}</a>')
  title = f"{page['title']} - Hawk" if page.get("title") else "Hawk"
  return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <link rel="icon" href="{href('/assets/favicon.png')}">
  <link rel="stylesheet" href="{href('/assets/style.css')}">
</head>
<body>
  <header>
    <div class="brand-block">
      <div class="brand"><img src="{href('/assets/noun-hawk.png')}" alt="">Hawk</div>
      <p class="brand-tagline">A scheme that makes code fly</p>
    </div>
    <nav>{"".join(links)}</nav>
  </header>
  <main>
{body}
  </main>
</body>
</html>
"""


def output_path(meta, file):
  permalink = meta.get("permalink", f"/{file.stem}/")
  return OUT / permalink.lstrip("/") / "index.html"


def build():
  shutil.rmtree(OUT, ignore_errors=True)
  copy(ASSETS / "style.css", OUT / "assets" / "style.css")
  copy(ASSETS / "noun-hawk.png", OUT / "assets" / "noun-hawk.png")
  copy(ASSETS / "favicon.png", OUT / "assets" / "favicon.png")

  data, warnings = parse_benchmarks()
  GENERATED.mkdir(parents=True, exist_ok=True)
  write(GENERATED / "benchmarks.json", json.dumps(data, indent=2))

  for file in sorted(CONTENT.glob("*.md")):
    meta, body_md = parse_frontmatter(read(file))
    # Skip the dormant blog and releases pages for now.
    if file.name in {"blog.md", "releases.md"}:
      continue
    body = markdown(body_md)
    if meta.get("benchmarks") == "true":
      body += benchmark_html(data)
    file_out = output_path(meta, file)
    current = "/" + file_out.parent.relative_to(OUT).as_posix().strip(".") + "/"
    current = current.replace("//", "/")
    write(file_out, layout(meta, body, current))

  for warning in warnings:
    print(f"benchmark warning: {warning}", file=sys.stderr)
  print(f"built {OUT.relative_to(ROOT)}")


class SiteHandler(http.server.SimpleHTTPRequestHandler):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, directory=str(OUT), **kwargs)


class ReusableTCPServer(socketserver.TCPServer):
  allow_reuse_address = True


def serve():
  build()
  host = os.environ.get("SITE_HOST", "127.0.0.1")
  port = int(os.environ.get("SITE_PORT", "8080"))
  try:
    with ReusableTCPServer((host, port), SiteHandler) as server:
      print(f"serving http://{host}:{port}", flush=True)
      server.serve_forever()
  except OSError as err:
    print(f"server error: {err}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  serve() if "--serve" in sys.argv else build()
