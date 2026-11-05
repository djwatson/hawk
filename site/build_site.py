#!/usr/bin/env python3

import html
import http.server
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
BASE = os.environ.get("SITE_BASE", "").rstrip("/")

NAV = [
  ("Intro", "/"),
  ("Docs", "/docs/"),
  ("Benchmarks", "https://djwatson.github.io/r7rs-benchmarks/"),
  ("Code", "/code/"),
  ("Releases", "/releases/"),
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

  for file in sorted(CONTENT.glob("*.md")):
    meta, body_md = parse_frontmatter(read(file))
    # Skip the dormant blog page for now.
    if file.name == "blog.md":
      continue
    body = markdown(body_md)
    file_out = output_path(meta, file)
    current = "/" + file_out.parent.relative_to(OUT).as_posix().strip(".") + "/"
    current = current.replace("//", "/")
    write(file_out, layout(meta, body, current))

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
