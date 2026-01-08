#!/usr/bin/env python3
"""
Merge Instruments time-profile export with jit-*.dump to annotated HTML.

Usage:
  python3 tools/jit_instruments_merge.py samples.xml jit-<pid>.dump [--out report.html]
"""

import argparse
import collections
import html
import os
import struct
import sys
import xml.etree.ElementTree as ET

try:
  import capstone
except ModuleNotFoundError:
  capstone = None

HEADER_FMT = "<IIIIIIQQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

RECORD_FMT = "<IIQIIQQQQ"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

MAGIC = 0x4A695444


def read_exact(fp, size):
  data = fp.read(size)
  if len(data) != size:
    raise ValueError(f"Unexpected EOF (wanted {size} bytes, got {len(data)})")
  return data


def parse_header(fp):
  raw = read_exact(fp, HEADER_SIZE)
  magic, version, total_size, elf_mach, pad1, pid, timestamp, flags = struct.unpack(
      HEADER_FMT, raw)
  if magic != MAGIC:
    raise ValueError(f"Bad magic: 0x{magic:08x} (expected 0x{MAGIC:08x})")
  return {
      "magic": magic,
      "version": version,
      "total_size": total_size,
      "elf_mach": elf_mach,
      "pad1": pad1,
      "pid": pid,
      "timestamp": timestamp,
      "flags": flags,
  }


def parse_record(fp):
  header_bytes = fp.read(RECORD_SIZE)
  if not header_bytes:
    return None
  if len(header_bytes) != RECORD_SIZE:
    raise ValueError(
        f"Incomplete record header: expected {RECORD_SIZE} bytes, got {len(header_bytes)}")

  rec_id, total_size, timestamp, pid, tid, vma, code_addr, code_size, code_index = struct.unpack(
      RECORD_FMT, header_bytes)

  remaining = total_size - RECORD_SIZE
  if remaining < 0:
    raise ValueError(f"Record total_size too small: {total_size}")
  name_len = remaining - code_size
  if name_len < 0:
    raise ValueError(
        f"Record sizes inconsistent: name_len {name_len} (total_size {total_size}, code_size {code_size})")

  name_bytes = read_exact(fp, name_len)
  code_bytes = read_exact(fp, code_size)
  name = name_bytes.split(b"\x00", 1)[0].decode(errors="replace")
  return {
      "id": rec_id,
      "total_size": total_size,
      "timestamp": timestamp,
      "pid": pid,
      "tid": tid,
      "vma": vma,
      "code_addr": code_addr,
      "code_size": code_size,
      "code_index": code_index,
      "name": name,
      "code_bytes": code_bytes,
  }


def make_disassembler(elf_mach):
  if capstone is None:
    return None
  if elf_mach == 62:  # EM_X86_64
    return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
  if elf_mach == 183:  # EM_AARCH64
    return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
  return None


def arch_from_elf_mach(elf_mach):
  if elf_mach == 183:
    return "arm64"
  if elf_mach == 62:
    return "x86"
  return "arm64" if "arm64" in os.uname().machine else "x86"


def canonical_addr(addr_str, arch):
  try:
    addr = int(addr_str, 16)
  except (TypeError, ValueError):
    return None
  if arch == "arm64":
    addr &= ~0x3
  elif arch == "x86":
    addr &= ~0x1
  return addr


def resolve_frame_addr(frame, frame_addr, arch):
  addr = frame.attrib.get("addr")
  if addr:
    return canonical_addr(addr, arch)
  ref = frame.attrib.get("ref")
  if ref:
    return frame_addr.get(ref)
  return None


def build_frame_index(root, arch):
  frame_addr = {}
  for frame in root.iter("frame"):
    frame_id = frame.attrib.get("id")
    addr_str = frame.attrib.get("addr")
    addr = canonical_addr(addr_str, arch)
    if frame_id and addr is not None:
      frame_addr[frame_id] = addr
  return frame_addr


def build_backtrace_index(root, frame_addr, arch):
  bt_leaf = {}
  for bt in root.iter("backtrace"):
    if "ref" in bt.attrib:
      leaf = bt_leaf.get(bt.attrib["ref"])
    else:
      leaf = None
      for frame in bt.findall("frame"):
        leaf = resolve_frame_addr(frame, frame_addr, arch)
        if leaf is not None:
          break
    bt_id = bt.attrib.get("id")
    if leaf is not None and bt_id:
      bt_leaf[bt_id] = leaf
  return bt_leaf


def aggregate_leaves(root, frame_addr, bt_leaf, arch):
  counts = collections.Counter()
  for row in root.iter("row"):
    bt = row.find("backtrace")
    if bt is None:
      continue

    if "ref" in bt.attrib:
      leaf = bt_leaf.get(bt.attrib["ref"])
    else:
      leaf = None
      for frame in bt.findall("frame"):
        leaf = resolve_frame_addr(frame, frame_addr, arch)
        if leaf is not None:
          break
      bt_id = bt.attrib.get("id")
      if leaf is not None and bt_id:
        bt_leaf[bt_id] = leaf

    if leaf is not None:
      counts[leaf] += 1
  return counts


def parse_samples_xml(path, arch):
  root = ET.parse(path).getroot()
  frame_addr = build_frame_index(root, arch)
  bt_leaf = build_backtrace_index(root, frame_addr, arch)
  counts = aggregate_leaves(root, frame_addr, bt_leaf, arch)
  total = sum(counts.values())
  return counts, total


def parse_jitdump(path):
  with open(path, "rb") as f:
    header = parse_header(f)
    fns = []
    while True:
      rec = parse_record(f)
      if rec is None:
        break
      if rec["id"] != 0:
        continue
      fns.append({
          "name": rec["name"],
          "start": rec["code_addr"],
          "bytes": rec["code_bytes"],
      })
  return header, fns

def disassemble(dis, code_bytes, start):
  if dis:
    return [{
        "addr": ins.address,
        "mnemonic": ins.mnemonic,
        "op_str": ins.op_str,
    } for ins in dis.disasm(code_bytes, start)]
  return []


def render_fn(out, title, insns, counts, total_samples):
  if not insns:
    return

  def line_hits(ins):
    sz = 4
    return sum(v for a, v in counts.items() if ins["addr"] <= a < ins["addr"] + sz)

  fn_total = sum(line_hits(i) for i in insns)
  pct_fn = (100.0 * fn_total / total_samples) if total_samples else 0.0
  out.write(
      f"<div class='fn'><div class='fname'>{html.escape(title)} — {fn_total} samples ({pct_fn:.2f}%)</div>\n"
  )
  out.write("<table class='instable'>\n")
  max_line = max([line_hits(i) for i in insns] + [0])
  for i in insns:
    hits = line_hits(i)
    r = g = b = 0
    if hits and max_line:
      hot = hits / max_line
      r = int(hot * 255)
      g = int((1.0 - hot) * 40)
      b = int((1.0 - hot) * 40)
    pct = f"{(100.0 * hits / total_samples):.2f}%" if hits and total_samples else ""
    hits_str = "" if hits == 0 else str(hits)
    out.write("<tr style='color:rgb({},{},{})'>".format(r, g, b))
    out.write(f"<td class='hits'>{hits_str}</td>")
    out.write(f"<td class='pct'>{pct}</td>")
    out.write(f"<td class='addr'>0x{i['addr']:x}</td>")
    asm_text = f"{i['mnemonic']} {i['op_str']}".strip()
    out.write(f"<td class='asm'>{html.escape(asm_text)}</td>")
    out.write("</tr>\n")
  out.write("</table></div>\n")


def jit_coverage(counts, fns):
  matched = 0
  for addr, n in counts.items():
    for fn in fns:
      start = fn["start"]
      end = start + len(fn["bytes"])
      if start <= addr < end:
        matched += n
        break
  total = sum(counts.values())
  return matched, total - matched, total


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("samples")
  ap.add_argument("jitdump")
  ap.add_argument("--out", default="report.html")
  args = ap.parse_args()

  try:
    header, fns = parse_jitdump(args.jitdump)
  except ValueError as err:
    print(f"Failed to parse jitdump: {err}", file=sys.stderr)
    sys.exit(1)
  arch = arch_from_elf_mach(header["elf_mach"])
  dis = make_disassembler(header["elf_mach"])
  counts, total_samples = parse_samples_xml(args.samples, arch)
  matched, unmatched, total = jit_coverage(counts, fns)
  pct = (100.0 * matched / total) if total else 0.0

  with open(args.out, "w") as out:
    out.write(
        "<html><head><meta charset='utf-8'><style>"
        "body{font-family:monospace;background:#f8f8f8;color:#111;}"
        ".summary{margin:1em 0;padding:0.5em;background:#eef;border:1px solid #ccd;font-weight:bold;}"
        ".fn{margin:1em 0;padding:0.5em;background:#fff;border:1px solid #ddd;}"
        ".fname{font-weight:bold;margin-bottom:0.25em;}"
        ".instable{border-collapse:collapse;width:100%;}"
        ".instable td{padding:0 12px 0 0;white-space:pre;}"
        ".instable .hits{width:5em;text-align:right;}"
        ".instable .pct{width:5em;text-align:right;}"
        ".instable .addr{width:9em;}"
        ".instable .asm{width:auto;}"
        "</style></head><body>\n"
    )
    out.write(
        f"<div class='summary'>{pct:.2f}% of samples in JIT code "
        f"({matched}/{total}), {unmatched} outside</div>\n"
    )
    for fn in fns:
      insns = disassemble(dis, fn["bytes"], fn["start"])
      render_fn(out, fn["name"], insns, counts, total_samples)
    # Host image reporting disabled.
    out.write("</body></html>\n")
  print(f"Wrote {args.out}")


if __name__ == "__main__":
  main()
