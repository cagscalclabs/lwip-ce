#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import subprocess
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List


CLASSES = ("best", "worst", "random", "edge")


def parse_kv(fields: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for field in fields:
        if "=" not in field:
            continue
        k, v = field.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def parse_percent(value: str) -> str:
    v = value.strip()
    if v.endswith("%"):
        v = v[:-1]
    return v


def convert_8xv_to_bin(input_path: Path, convbin: str, out_bin: Path) -> None:
    cmd = [convbin, "-i", str(input_path), "-o", str(out_bin), "-j", "8x", "-k", "bin"]
    subprocess.run(cmd, check=True)


def load_text_from_input(input_path: Path, convbin: str) -> str:
    suffix = input_path.suffix.lower()
    if suffix == ".8xv":
        with tempfile.TemporaryDirectory(prefix="timing_appvar_") as td:
            out_bin = Path(td) / "TLSTMLOG.bin"
            convert_8xv_to_bin(input_path, convbin, out_bin)
            raw = out_bin.read_bytes()
    elif suffix == ".bin":
        raw = input_path.read_bytes()
    else:
        return input_path.read_text(encoding="utf-8", errors="replace")

    return raw.replace(b"\x00", b"").replace(b"\r", b"").decode("utf-8", errors="replace")


def parse_timing_lines(text: str) -> OrderedDict[str, Dict[str, object]]:
    rows: OrderedDict[str, Dict[str, object]] = OrderedDict()

    def get_row(prim: str) -> Dict[str, object]:
        if prim not in rows:
            rows[prim] = {
                "sigma": "",
                "c6": "",
                "c4": "",
                "max_delta_c6": "",
                "max_delta_c4": "",
                "pass_c6": "",
                "pass_c4": "",
                "median_base": "",
                "class_median": {},
                "median_dev": {},
                "over_c6": {},
                "over_c4": {},
            }
        return rows[prim]

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("primitive="):
            prim = line.split(",", 1)[0].split("=", 1)[1].strip()
            if prim:
                get_row(prim)
            continue
        fields = [f.strip() for f in line.split(",")]
        kind = fields[0] if fields else ""
        if kind not in {"robust", "robust4", "class", "class4"}:
            continue
        if len(fields) < 2:
            continue
        prim = fields[1]
        row = get_row(prim)

        if kind in {"robust", "robust4"}:
            kv = parse_kv(fields[2:])
            if row["sigma"] == "":
                row["sigma"] = kv.get("sigma", "")
            if row["median_base"] == "":
                row["median_base"] = kv.get("median", "")

            if kind == "robust":
                row["c6"] = kv.get("c", "6")
                row["max_delta_c6"] = kv.get("accept", "")
                row["pass_c6"] = "PASS" if kv.get("dpass", "") == "1" else "FAIL"
            else:
                row["c4"] = kv.get("c", "4")
                row["max_delta_c4"] = kv.get("accept", "")
                row["pass_c4"] = "PASS" if kv.get("dpass", "") == "1" else "FAIL"

        elif kind in {"class", "class4"} and len(fields) >= 3:
            cls = fields[2]
            if cls not in CLASSES:
                continue
            kv = parse_kv(fields[3:])
            median_s = kv.get("median", "")
            if median_s:
                try:
                    row["class_median"][cls] = int(median_s)
                except ValueError:
                    pass
            over_s = parse_percent(kv.get("over", ""))
            if kind == "class":
                row["over_c6"][cls] = over_s
            else:
                row["over_c4"][cls] = over_s

    # derive per-class median deviations
    for row in rows.values():
        try:
            base = int(str(row["median_base"]))
        except ValueError:
            continue
        for cls in CLASSES:
            if cls in row["class_median"]:
                row["median_dev"][cls] = str(int(row["class_median"][cls]) - base)

    return rows


def write_csv(output_path: Path, rows: OrderedDict[str, Dict[str, object]]) -> None:
    fieldnames = [
        "primitive",
        "sigma",
        "c6",
        "c4",
        "max_delta_c6",
        "max_delta_c4",
        "pass_c6",
        "pass_c4",
        "median_base",
        "median_dev_best",
        "median_dev_worst",
        "median_dev_random",
        "median_dev_edge",
        "over_best_c6_pct",
        "over_worst_c6_pct",
        "over_random_c6_pct",
        "over_edge_c6_pct",
        "over_best_c4_pct",
        "over_worst_c4_pct",
        "over_random_c4_pct",
        "over_edge_c4_pct",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for prim, row in rows.items():
            out = {
                "primitive": prim,
                "sigma": row["sigma"],
                "c6": row["c6"] or "6",
                "c4": row["c4"] or "4",
                "max_delta_c6": row["max_delta_c6"],
                "max_delta_c4": row["max_delta_c4"],
                "pass_c6": row["pass_c6"],
                "pass_c4": row["pass_c4"],
                "median_base": row["median_base"],
                "median_dev_best": row["median_dev"].get("best", ""),
                "median_dev_worst": row["median_dev"].get("worst", ""),
                "median_dev_random": row["median_dev"].get("random", ""),
                "median_dev_edge": row["median_dev"].get("edge", ""),
                "over_best_c6_pct": row["over_c6"].get("best", ""),
                "over_worst_c6_pct": row["over_c6"].get("worst", ""),
                "over_random_c6_pct": row["over_c6"].get("random", ""),
                "over_edge_c6_pct": row["over_c6"].get("edge", ""),
                "over_best_c4_pct": row["over_c4"].get("best", ""),
                "over_worst_c4_pct": row["over_c4"].get("worst", ""),
                "over_random_c4_pct": row["over_c4"].get("random", ""),
                "over_edge_c4_pct": row["over_c4"].get("edge", ""),
            }
            writer.writerow(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Parse TLSTMLOG timing output (8xv/bin/txt) into a per-primitive CSV "
            "with c=6 and c=4 summary fields."
        )
    )
    parser.add_argument("input", type=Path, help="Path to TLSTMLOG.8xv, TLSTMLOG.bin, or TLSTMLOG.txt")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output CSV path (default: <input stem>.csv next to input)",
    )
    parser.add_argument(
        "--convbin",
        default="convbin",
        help="convbin executable path/name (used when input is .8xv)",
    )
    args = parser.parse_args()

    input_path: Path = args.input
    if not input_path.exists():
        raise SystemExit(f"input file not found: {input_path}")

    output_path = args.output or input_path.with_suffix(".csv")
    text = load_text_from_input(input_path, args.convbin)
    rows = parse_timing_lines(text)
    if not rows:
        raise SystemExit("no parseable timing lines found (expected robust/class/robust4/class4)")

    write_csv(output_path, rows)
    print(f"wrote {len(rows)} primitive rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
