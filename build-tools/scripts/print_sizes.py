#!/usr/bin/env python3
"""
Print section sizes and the libload RAM-reserve contract from a linker
map file. The map path is passed via the MAPFILE env var (defaults to
bin/DEMO.map).

Sizes printed:
  text   — code
  rodata — read-only data (constants, string literals)
  data   — initialized RAM (copied from program image at startup)
  bss    — zero-initialized RAM (zeroed at startup)

The "runtime RAM reserve" line is what a libload consumer must reserve
when placing this library at a chosen BSSHEAP_LOW. It is data + bss
(both live in the BSSHEAP region; .data is copied there from the
program image, .bss is just zeroed).
"""
import os
import re
import sys

mapfile = os.environ.get("MAPFILE", "bin/DEMO.map")
try:
    text = open(mapfile).read()
except OSError as e:
    print(f"error: cannot read {mapfile}: {e}", file=sys.stderr)
    sys.exit(1)


def section_size(name):
    """Find the line '.<name>  <addr> <size>' and return size as int."""
    m = re.search(r"^\." + re.escape(name) + r"\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)",
                  text, re.M)
    return int(m.group(1), 16) if m else None


sections = [
    ("text",   section_size("text")),
    ("rodata", section_size("rodata")),
    ("data",   section_size("data")),
    ("bss",    section_size("bss")),
]

for name, val in sections:
    if val is not None:
        print(f"  {name:<10} {val:>10} bytes")

d = section_size("data")
b = section_size("bss")
if d is not None and b is not None:
    print()
    print("  Runtime RAM reserve = data + bss:")
    print(f"    {d} + {b} = {d + b} bytes")
