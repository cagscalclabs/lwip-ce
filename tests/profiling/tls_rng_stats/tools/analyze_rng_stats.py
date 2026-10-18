#!/usr/bin/env python3
"""Analyze RNGSTATS raw-tap profiles for marginal and first-order entropy."""

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
# Bonferroni-adjusted one-sided z for four simultaneous 99% transition bounds.
MARKOV_Z_99 = 2.807033768343811
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


def wilson_upper(successes: int, trials: int) -> float:
    """Return a conservative Wilson upper bound using the profiler's z value."""
    if trials <= 0:
        return 1.0
    p = successes / trials
    z2 = MARKOV_Z_99 * MARKOV_Z_99
    denominator = 1.0 + z2 / trials
    center = p + z2 / (2.0 * trials)
    radius = MARKOV_Z_99 * math.sqrt(
        (p * (1.0 - p) + z2 / (4.0 * trials)) / trials
    )
    return min(1.0, (center + radius) / denominator)


def transition_candidates(row: dict[str, int | str]) -> list[dict[str, int]]:
    """Get exact v2 pair counts or all endpoint-consistent v1 reconstructions."""
    samples = int(row["samples"])
    ones = int(row["ones"])
    zeros = int(row["zeros"])
    transitions = int(row.get("transitions", -1))
    keys = ("n00", "n01", "n10", "n11")

    if all(key in row for key in keys):
        counts = {key: int(row[key]) for key in keys}
        if any(value < 0 for value in counts.values()):
            raise ValueError(f"run {row['run']} has a negative transition count")
        if sum(counts.values()) != samples - 1:
            raise ValueError(f"run {row['run']} transition matrix does not contain n - 1 pairs")
        if transitions >= 0 and counts["n01"] + counts["n10"] != transitions:
            raise ValueError(f"run {row['run']} transition count does not match n01 + n10")
        row0 = counts["n00"] + counts["n01"]
        row1 = counts["n10"] + counts["n11"]
        col0 = counts["n00"] + counts["n10"]
        col1 = counts["n01"] + counts["n11"]
        if (
            row0 not in (zeros - 1, zeros)
            or col0 not in (zeros - 1, zeros)
            or row1 not in (ones - 1, ones)
            or col1 not in (ones - 1, ones)
            or abs(counts["n01"] - counts["n10"]) > 1
        ):
            raise ValueError(f"run {row['run']} transition matrix has inconsistent margins")
        return [counts]

    if transitions < 0:
        raise ValueError(f"run {row['run']} has no transition statistics")

    candidates: list[dict[str, int]] = []
    for first in (0, 1):
        for last in (0, 1):
            delta = last - first
            if (transitions + delta) % 2 != 0:
                continue
            n01 = (transitions + delta) // 2
            n10 = transitions - n01
            n00 = zeros - int(last == 0) - n01
            n11 = ones - int(last == 1) - n10
            counts = {"n00": n00, "n01": n01, "n10": n10, "n11": n11}
            if min(counts.values()) < 0 or sum(counts.values()) != samples - 1:
                continue
            if counts not in candidates:
                candidates.append(counts)
    if not candidates:
        raise ValueError(f"run {row['run']} transition totals are inconsistent")
    return candidates


def transition_estimate(
    counts: dict[str, int], ones: int, zeros: int
) -> dict[str, float | int]:
    """Estimate lag-1 dependence and a conservative first-order entropy rate."""
    n00 = counts["n00"]
    n01 = counts["n01"]
    n10 = counts["n10"]
    n11 = counts["n11"]
    pairs = n00 + n01 + n10 + n11
    row0 = n00 + n01
    row1 = n10 + n11
    col0 = n00 + n10
    col1 = n01 + n11
    transitions = n01 + n10
    transition_rate = transitions / pairs if pairs else 0.0
    samples = ones + zeros
    p1 = ones / samples
    iid_transition_rate = 2.0 * p1 * (1.0 - p1)

    phi_denominator = math.sqrt(row0 * row1 * col0 * col1)
    lag1_phi = (
        (n00 * n11 - n01 * n10) / phi_denominator
        if phi_denominator > 0.0
        else 0.0
    )

    runs = transitions + 1
    expected_runs = 1.0 + (2.0 * ones * zeros) / samples
    runs_variance = (
        (2.0 * ones * zeros * (2.0 * ones * zeros - samples))
        / (samples * samples * (samples - 1.0))
    )
    runs_z = (
        (runs - expected_runs) / math.sqrt(runs_variance)
        if runs_variance > 0.0
        else 0.0
    )

    p00 = n00 / row0 if row0 else 1.0
    p01 = n01 / row0 if row0 else 1.0
    p10 = n10 / row1 if row1 else 1.0
    p11 = n11 / row1 if row1 else 1.0
    max_cycle_probability = max(p00, p11, math.sqrt(p01 * p10))

    p00_upper = wilson_upper(n00, row0)
    p01_upper = wilson_upper(n01, row0)
    p10_upper = wilson_upper(n10, row1)
    p11_upper = wilson_upper(n11, row1)
    max_cycle_probability_upper = max(
        p00_upper,
        p11_upper,
        math.sqrt(p01_upper * p10_upper),
    )

    return {
        **counts,
        "pair_count": pairs,
        "transitions": transitions,
        "transition_rate": transition_rate,
        "iid_expected_transition_rate": iid_transition_rate,
        "lag1_phi": lag1_phi,
        "runs": runs,
        "runs_expected": expected_runs,
        "runs_variance": runs_variance,
        "runs_z": runs_z,
        "p00": p00,
        "p01": p01,
        "p10": p10,
        "p11": p11,
        "max_cycle_probability": max_cycle_probability,
        "max_cycle_probability_upper_99": max_cycle_probability_upper,
        "h_markov_plugin_bits_per_raw_bit": -math.log2(max_cycle_probability),
        "h_markov_lower_99_bits_per_raw_bit": -math.log2(
            max_cycle_probability_upper
        ),
    }


def analyze_run(row: dict[str, int | str]) -> dict[str, Any]:
    ones = int(row["ones"])
    zeros = int(row["zeros"])
    if int(row["samples"]) != ones + zeros:
        raise ValueError(f"run {row['run']} sample count does not match ones + zeros")

    candidates = [
        transition_estimate(counts, ones, zeros)
        for counts in transition_candidates(row)
    ]
    transition = min(
        candidates,
        key=lambda item: float(item["h_markov_lower_99_bits_per_raw_bit"]),
    )
    mcv = estimate(ones, zeros)
    stored_source = str(row.get("transition_counts_source", ""))
    if stored_source not in {"recorded", "reconstructed_conservatively"}:
        stored_source = (
            "recorded"
            if all(key in row for key in ("n00", "n01", "n10", "n11"))
            else "reconstructed_conservatively"
        )
    return {
        **row,
        **mcv,
        **transition,
        "transition_counts_source": stored_source,
        "first_order_dependency_factor": (
            min(
                1.0,
                float(transition["h_markov_lower_99_bits_per_raw_bit"])
                / float(mcv["h_mcv_lower_99_bits_per_raw_bit"]),
            )
            if float(mcv["h_mcv_lower_99_bits_per_raw_bit"]) > 0.0
            else 0.0
        ),
    }


def analyze(runs: list[dict[str, int | str]]) -> dict[str, Any]:
    analyzed_runs: list[dict[str, Any]] = []
    total_ones = 0
    total_zeros = 0

    for row in runs:
        analyzed = analyze_run(row)
        ones = int(analyzed["ones"])
        zeros = int(analyzed["zeros"])
        total_ones += ones
        total_zeros += zeros
        analyzed_runs.append(analyzed)

    aggregate_counts = {
        key: sum(int(row[key]) for row in analyzed_runs)
        for key in ("n00", "n01", "n10", "n11")
    }
    aggregate_mcv = estimate(total_ones, total_zeros)
    aggregate_transition = transition_estimate(
        aggregate_counts, total_ones, total_zeros
    )
    aggregate_runs_delta = sum(
        float(row["runs"]) - float(row["runs_expected"])
        for row in analyzed_runs
    )
    aggregate_runs_variance = sum(
        float(row["runs_variance"]) for row in analyzed_runs
    )
    aggregate_transition["runs"] = sum(int(row["runs"]) for row in analyzed_runs)
    aggregate_transition["runs_expected"] = sum(
        float(row["runs_expected"]) for row in analyzed_runs
    )
    aggregate_transition["runs_variance"] = aggregate_runs_variance
    aggregate_transition["runs_z"] = (
        aggregate_runs_delta / math.sqrt(aggregate_runs_variance)
        if aggregate_runs_variance > 0.0
        else 0.0
    )
    aggregate = {**aggregate_mcv, **aggregate_transition}
    transition_counts_source = (
        "recorded"
        if all(
            row["transition_counts_source"] == "recorded"
            for row in analyzed_runs
        )
        else "includes_conservative_legacy_reconstruction"
    )
    aggregate["transition_counts_source"] = transition_counts_source
    worst_window_mcv_h = min(
        float(row["h_mcv_lower_99_bits_per_raw_bit"]) for row in analyzed_runs
    )
    worst_window_markov_h = min(
        float(row["h_markov_lower_99_bits_per_raw_bit"]) for row in analyzed_runs
    )
    mcv_working_h = min(
        worst_window_mcv_h,
        float(aggregate["h_mcv_lower_99_bits_per_raw_bit"]),
    )
    markov_working_h = min(
        worst_window_markov_h,
        float(aggregate["h_markov_lower_99_bits_per_raw_bit"]),
    )
    working_h = min(mcv_working_h, markov_working_h)
    sources = sorted({f"{row['source']}/{row['mask']}" for row in analyzed_runs})
    if len(sources) != 1:
        raise ValueError(
            "profile contains multiple source/mask pairs; analyze each tap separately"
        )

    return {
        "estimator": "binary marginal MCV and coarse first-order Markov estimates",
        "confidence": (
            "99% upper bounds (MCV normal z=2.576; Markov simultaneous "
            "Wilson with Bonferroni-adjusted z=2.807034)"
        ),
        "scope_warning": (
            "The Markov result is a coarse first-order dependence bound, not a "
            "complete SP 800-90B non-IID entropy assessment; longer-range "
            "dependence can reduce actual min-entropy."
        ),
        "transition_counts_provenance": transition_counts_source,
        "transition_counts_note": (
            "Version 1 reports did not record endpoint bits. Their stored "
            "transition matrices are the endpoint-consistent candidates that "
            "produce the lowest first-order 99% lower estimate."
            if transition_counts_source != "recorded"
            else "Transition matrices were recorded directly by the version 2 profiler."
        ),
        "sources": sources,
        "aggregate": aggregate,
        "worst_window_h_mcv_lower_99_bits_per_raw_bit": worst_window_mcv_h,
        "worst_window_h_markov_lower_99_bits_per_raw_bit": worst_window_markov_h,
        "marginal_working_h_bits_per_raw_bit": mcv_working_h,
        "first_order_working_h_bits_per_raw_bit": markov_working_h,
        "first_order_dependency_factor": (
            min(1.0, working_h / mcv_working_h) if mcv_working_h > 0.0 else 0.0
        ),
        "conservative_working_h_bits_per_raw_bit": working_h,
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
        "n00",
        "n01",
        "n10",
        "n11",
        "transition_counts_source",
        "transition_rate",
        "iid_expected_transition_rate",
        "lag1_phi",
        "runs_z",
        "h_markov_plugin_bits_per_raw_bit",
        "h_markov_lower_99_bits_per_raw_bit",
        "first_order_dependency_factor",
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


def reanalyze_json(path: Path) -> dict[str, Any]:
    """Recompute a report from its raw run counts, preserving report metadata."""
    original = json.loads(path.read_text(encoding="utf-8"))
    runs = original.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError(f"{path} has no run rows")
    # Existing top-level metadata (notably the hardware model) survives, while
    # every analyzer-owned result is replaced by the current computation.
    return {**original, **analyze(runs)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Estimate marginal and first-order min-entropy from RNGSTATS"
    )
    parser.add_argument(
        "input", type=Path,
        help="RNGSTATS.8xv, extracted text/bin, or an analyzer JSON report",
    )
    parser.add_argument("--convbin", default="convbin")
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="output format written to statistics/rng (default: json)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="calculator hardware model/revision recorded in the report",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="recompute and replace an existing JSON report",
    )
    args = parser.parse_args()

    is_json_input = args.input.suffix.lower() == ".json"
    if args.in_place and not is_json_input:
        parser.error("--in-place requires an existing JSON report")
    if args.in_place and args.format != "json":
        parser.error("--in-place cannot be combined with --format csv")

    if is_json_input:
        report = reanalyze_json(args.input)
    else:
        report = analyze(parse_runs(load_text(args.input, args.convbin)))
    if args.model is not None:
        report["model"] = args.model
    elif "model" not in report:
        report["model"] = "uncategorized"

    output_path = args.input if args.in_place else allocate_output_path(args.format)
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
    print(f"lag-1 phi: {aggregate['lag1_phi']:.6f}")
    print(
        "Markov 99% lower H: "
        f"{aggregate['h_markov_lower_99_bits_per_raw_bit']:.6f} bits/raw bit"
    )
    print(
        "first-order dependency factor: "
        f"{report['first_order_dependency_factor']:.6f}"
    )
    print(
        "conservative working H: "
        f"{report['conservative_working_h_bits_per_raw_bit']:.6f} bits/raw bit"
    )
    print("warning: " + report["scope_warning"])
    print(f"wrote {output_path.resolve().relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
