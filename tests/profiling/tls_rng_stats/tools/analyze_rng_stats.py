#!/usr/bin/env python3
"""Analyze RNGSTATS raw-tap profiles and estimate binary marginal entropy."""

from __future__ import annotations

import argparse
import csv
import json
import math
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any


Z_99 = 2.576
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
STATISTICS_DIR = REPOSITORY_ROOT / "statistics" / "rng"


def load_text(path: Path, convbin: str) -> str:
    if path.suffix.lower() != ".8xv":
        return path.read_text(encoding="ascii", errors="replace").replace("\x00", "")

    with tempfile.TemporaryDirectory(prefix="rng_stats_") as temp_dir:
        raw_path = Path(temp_dir) / "RNGSTATS.bin"
        subprocess.run(
            [convbin, "-i", str(path), "-o", str(raw_path), "-j", "8x", "-k", "bin"],
            check=True,
        )
        return raw_path.read_bytes().decode("ascii", errors="replace").replace("\x00", "")


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in line.strip().split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def parse_runs(text: str) -> list[dict[str, int | str]]:
    runs: list[dict[str, int | str]] = []
    for line in text.splitlines():
        if not line.startswith("run="):
            continue
        fields = parse_fields(line)
        required = {"run", "source", "mask", "samples", "ones", "zeros"}
        if not required.issubset(fields):
            raise ValueError(f"incomplete run row: {line}")

        row: dict[str, int | str] = {
            "run": int(fields["run"]),
            "source": fields["source"],
            "mask": fields["mask"],
        }
        for key, value in fields.items():
            if key not in {"run", "source", "mask"}:
                row[key] = int(value)
        runs.append(row)

    if not runs:
        raise ValueError("no rng_stats run rows found")
    return runs


def estimate(ones: int, zeros: int) -> dict[str, float | int]:
    samples = ones + zeros
    if samples < 2:
        raise ValueError("entropy estimate needs at least two observations")

    p1 = ones / samples
    p_max = max(ones, zeros) / samples
    # SP 800-90B's MCV-style 99% upper-confidence adjustment. This only
    # estimates binary marginal min-entropy; it does not model dependence.
    p_max_upper_99 = min(
        1.0,
        p_max + Z_99 * math.sqrt((p_max * (1.0 - p_max)) / (samples - 1)),
    )
    h_plugin = -math.log2(p_max)
    h_lower_99 = -math.log2(p_max_upper_99)
    return {
        "samples": samples,
        "p1": p1,
        "p_max": p_max,
        "p_max_upper_99": p_max_upper_99,
        "h_mcv_plugin_bits_per_raw_bit": h_plugin,
        "h_mcv_lower_99_bits_per_raw_bit": h_lower_99,
    }


def analyze(runs: list[dict[str, int | str]]) -> dict[str, Any]:
    analyzed_runs: list[dict[str, Any]] = []
    total_ones = 0
    total_zeros = 0

    for row in runs:
        ones = int(row["ones"])
        zeros = int(row["zeros"])
        if int(row["samples"]) != ones + zeros:
            raise ValueError(f"run {row['run']} sample count does not match ones + zeros")
        total_ones += ones
        total_zeros += zeros
        analyzed_runs.append({**row, **estimate(ones, zeros)})

    aggregate = estimate(total_ones, total_zeros)
    worst_window_h = min(
        float(row["h_mcv_lower_99_bits_per_raw_bit"]) for row in analyzed_runs
    )
    sources = sorted({f"{row['source']}/{row['mask']}" for row in analyzed_runs})
    if len(sources) != 1:
        raise ValueError(
            "profile contains multiple source/mask pairs; analyze each tap separately"
        )

    return {
        "estimator": "binary marginal most-common-value estimate",
        "confidence": "99% normal upper bound (z=2.576)",
        "scope_warning": (
            "This is a marginal estimate, not a complete SP 800-90B non-IID "
            "entropy assessment; serial dependence can reduce actual min-entropy."
        ),
        "sources": sources,
        "aggregate": aggregate,
        "worst_window_h_mcv_lower_99_bits_per_raw_bit": worst_window_h,
        "conservative_working_h_bits_per_raw_bit": min(
            worst_window_h,
            float(aggregate["h_mcv_lower_99_bits_per_raw_bit"]),
        ),
        "runs": analyzed_runs,
    }


def write_csv(path: Path, report: dict[str, Any]) -> None:
    fields = [
        "model",
        "run",
        "source",
        "mask",
        "samples",
        "ones",
        "zeros",
        "p1",
        "p_max",
        "p_max_upper_99",
        "h_mcv_plugin_bits_per_raw_bit",
        "h_mcv_lower_99_bits_per_raw_bit",
        "transitions",
        "longest",
        "longest0",
        "longest1",
    ]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({"model": report["model"], **row} for row in report["runs"])


def allocate_output_path(output_format: str) -> Path:
    STATISTICS_DIR.mkdir(parents=True, exist_ok=True)
    while True:
        unique_id = secrets.token_hex(6)
        path = STATISTICS_DIR / f"{unique_id}_rngstats.{output_format}"
        if not path.exists():
            return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Estimate marginal min-entropy from an RNGSTATS AppVar/profile"
    )
    parser.add_argument("input", type=Path, help="RNGSTATS.8xv or extracted text/bin")
    parser.add_argument("--convbin", default="convbin")
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="output format written to statistics/rng (default: json)",
    )
    parser.add_argument(
        "--model",
        default="uncategorized",
        help="calculator hardware model/revision recorded in the report",
    )
    args = parser.parse_args()

    report = analyze(parse_runs(load_text(args.input, args.convbin)))
    report["model"] = args.model
    output_path = allocate_output_path(args.format)
    if args.format == "json":
        output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    else:
        write_csv(output_path, report)

    aggregate = report["aggregate"]
    print(f"source(s): {', '.join(report['sources'])}")
    print(f"samples: {aggregate['samples']}")
    print(f"p(1): {aggregate['p1']:.8f}")
    print(f"MCV plug-in H: {aggregate['h_mcv_plugin_bits_per_raw_bit']:.6f} bits/raw bit")
    print(
        "MCV 99% lower H: "
        f"{aggregate['h_mcv_lower_99_bits_per_raw_bit']:.6f} bits/raw bit"
    )
    print(
        "worst-window 99% lower H: "
        f"{report['worst_window_h_mcv_lower_99_bits_per_raw_bit']:.6f} bits/raw bit"
    )
    print(
        "conservative working H: "
        f"{report['conservative_working_h_bits_per_raw_bit']:.6f} bits/raw bit"
    )
    print("warning: " + report["scope_warning"])
    print(f"wrote {output_path.relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
