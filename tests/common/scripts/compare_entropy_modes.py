#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

KEYS = [
    "p1",
    "bias",
    "transition_rate",
    "max_run",
    "monobit_z",
    "runs_z",
]


def load_report(path: Path):
    data = json.loads(path.read_text())
    cols = data.get("columns", [])
    by_bit = {int(c["bit"]): c for c in cols}
    return by_bit


def fmt(v):
    if isinstance(v, int):
        return str(v)
    return f"{v:.6f}"


def main():
    ap = argparse.ArgumentParser(description="Compare entropy bit-column reports across capture modes")
    ap.add_argument("raw", type=Path, help="JSON report for raw read mode")
    ap.add_argument("xor3", type=Path, help="JSON report for xor3 mode")
    ap.add_argument("xor7", type=Path, help="JSON report for xor7 mode")
    args = ap.parse_args()

    reports = {
        "raw": load_report(args.raw),
        "xor3": load_report(args.xor3),
        "xor7": load_report(args.xor7),
    }

    for bit in range(8):
        print(f"\nbit {bit}")
        print("metric            raw         xor3        xor7        d(xor3-raw)   d(xor7-raw)")
        print("-" * 88)
        for k in KEYS:
            r = reports["raw"][bit][k]
            x3 = reports["xor3"][bit][k]
            x7 = reports["xor7"][bit][k]
            d3 = x3 - r
            d7 = x7 - r
            print(f"{k:16} {fmt(r):>11} {fmt(x3):>11} {fmt(x7):>11} {fmt(d3):>13} {fmt(d7):>13}")


if __name__ == "__main__":
    main()
