#!/usr/bin/env python3
"""
Parse a tracing JIT output.log and emit a DOT graph.

Edges model the observed sequence:
  Try side trace <P> <EXIT>
    -> Record start side <S>
    -> Link to trace <T> (snap exit K)?

Nodes that ever appear as a head trace are marked as roots (doublecircle).

Usage:
  python parse_output.py [path/to/output.log] > traces.dot
"""

import re
import sys
from typing import Iterable, List, Optional, Set, Tuple


def parse_lines(lines: Iterable[str]):
    roots: Set[int] = set()
    parent_edges: List[Tuple[int, int, int]] = []  # parent, exit, side
    link_edges: List[Tuple[int, int, Optional[int]]] = []  # side, target, snap

    # pass 1: roots
    for line in lines:
        m = re.search(r"Arg match head trace (\d+)", line)
        if m:
            roots.add(int(m.group(1)))

    # reset iterator
    if not hasattr(lines, "__iter__") or hasattr(lines, "__next__"):
        raise RuntimeError("lines must be re-iterable")

    parent = None
    exitnum = None
    current_side = None

    for line in lines:
        m = re.search(r"Try side trace (\d+) (\d+)", line)
        if m:
            parent = int(m.group(1))
            exitnum = int(m.group(2))
            continue

        m = re.search(r"Record start side (\d+)", line)
        if m:
            side = int(m.group(1))
            if parent is not None and exitnum is not None:
                parent_edges.append((parent, exitnum, side))
            current_side = side
            parent = None
            exitnum = None
            continue

        m = re.search(r"Link to trace (\d+)(?: \(snap exit (\d+)\))?", line)
        if m and current_side is not None:
            target = int(m.group(1))
            snap = int(m.group(2)) if m.group(2) else None
            link_edges.append((current_side, target, snap))
            current_side = None
            continue

        # regular record starts reset current_side context
        m = re.search(r"Record start (?:0x[0-9a-f]+ )?(\d+) ", line)
        if m:
            current_side = int(m.group(1))

    return roots, parent_edges, link_edges


def emit_dot(roots: Set[int], parent_edges, link_edges):
    nodes: Set[int] = set()
    for a, _, c in parent_edges:
        nodes.update([a, c])
    for a, c, _ in link_edges:
        nodes.update([a, c])

    print("digraph traces {")
    print("  rankdir=LR;")
    for n in sorted(nodes):
        shape = "doublecircle" if n in roots else "circle"
        print(f'  t{n} [label="trace {n}", shape={shape}];')
    for parent, exitnum, side in parent_edges:
        print(f'  t{parent} -> t{side} [label="exit {exitnum}"];')
    for side, target, snap in link_edges:
        label = f"snap {snap}" if snap is not None else "link"
        print(f'  t{side} -> t{target} [style=dashed,label="{label}"];')
    print("}")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output.log"
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # need lines twice; make list
    roots, parent_edges, link_edges = parse_lines(lines)
    emit_dot(roots, parent_edges, link_edges)


if __name__ == "__main__":
    main()
