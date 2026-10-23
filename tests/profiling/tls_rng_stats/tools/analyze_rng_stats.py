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
PROFILED_LAGS = range(1, 5)
HEALTH_ALL_PASS = 0x7F
# Startup qualification match bounds in random.s, over 952 samples.
STARTUP_LAG_MATCH_BOUNDS = {
    1: (136, 815),
    2: (136, 814),
    3: (135, 814),
    4: (135, 813),
}
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
    profiler_version = 1
    for line in text.splitlines():
        if line.startswith("rng_stats,"):
            header = parse_fields(line)
            profiler_version = int(header.get("version", "1"))
            continue
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

    by_run = {int(row["run"]): row for row in runs}
    if len(by_run) != len(runs):
        raise ValueError("duplicate rng_stats run number")
    health_rows: set[int] = set()
    lag_health_rows: set[int] = set()
    for line in text.splitlines():
        if line.startswith("health_run="):
            fields = parse_fields(line)
            run = int(fields.pop("health_run"))
            if run not in by_run or run in health_rows:
                raise ValueError(f"invalid or duplicate health row for run {run}")
            health_rows.add(run)
            for key, value in fields.items():
                canonical = {
                    "evaluated": "health_tests_evaluated",
                    "passed": "health_tests_passed",
                }.get(key, key)
                by_run[run][canonical] = (
                    int(value, 16) if key in {"evaluated", "passed"} else int(value)
                )
        elif line.startswith("lag_health_run="):
            fields = parse_fields(line)
            run = int(fields.pop("lag_health_run"))
            if run not in by_run or run in lag_health_rows:
                raise ValueError(f"invalid or duplicate lag-health row for run {run}")
            lag_health_rows.add(run)
            for key, value in fields.items():
                by_run[run][f"window_{key}"] = int(value)

    if profiler_version >= 4:
        expected = set(by_run)
        if health_rows != expected or lag_health_rows != expected:
            raise ValueError("version 4 capture is missing health detail rows")
    for row in runs:
        row["profiler_version"] = profiler_version
    return runs


def health_diagnostics(row: dict[str, Any]) -> dict[str, Any]:
    """Validate and summarize version 4 production-window diagnostics."""
    if "health_tests_evaluated" not in row:
        return {
            "health_diagnostics_available": False,
            "health_tests_all_evaluated": None,
            "health_tests_all_passed": None,
            "health_failure_total": None,
        }

    evaluated = int(row["health_tests_evaluated"])
    passed = int(row["health_tests_passed"])
    if evaluated & ~HEALTH_ALL_PASS or passed & ~evaluated:
        raise ValueError(f"run {row['run']} has an invalid health-test mask")

    count_fields = [
        "rct_failures",
        "apt_windows",
        "apt_failures",
        "startup_marginal_failures",
        "distribution_windows",
        "distribution_failures",
        *(f"window_lag{lag}_failures" for lag in PROFILED_LAGS),
    ]
    if any(int(row.get(field, -1)) < 0 for field in count_fields):
        raise ValueError(f"run {row['run']} has incomplete health-test counts")
    samples = int(row["samples"])
    apt_windows = int(row["apt_windows"])
    distribution_windows = int(row["distribution_windows"])
    if apt_windows != samples // 952 or distribution_windows != samples // 1024:
        raise ValueError(f"run {row['run']} has inconsistent health window counts")
    expected_evaluated = 0x01
    if apt_windows:
        expected_evaluated |= 0x3E
        if not (
            0 <= int(row["apt_min_ones"]) <= int(row["apt_max_ones"]) <= 952
        ):
            raise ValueError(f"run {row['run']} has invalid APT extrema")
        for lag in PROFILED_LAGS:
            minimum = int(row[f"window_lag{lag}_min"])
            maximum = int(row[f"window_lag{lag}_max"])
            if not 0 <= minimum <= maximum <= 952 - lag:
                raise ValueError(f"run {row['run']} has invalid lag-{lag} extrema")
    if apt_windows and distribution_windows:
        expected_evaluated |= 0x40
    if distribution_windows and not (
        0
        <= int(row["distribution_min_ones"])
        <= int(row["distribution_max_ones"])
        <= 1024
        and 0
        <= int(row["distribution_min_disagreements"])
        <= int(row["distribution_max_disagreements"])
        <= 512
    ):
        raise ValueError(f"run {row['run']} has invalid distribution extrema")
    if evaluated != expected_evaluated:
        raise ValueError(f"run {row['run']} has an inconsistent evaluated mask")

    bounded_failures = {
        "apt_failures": apt_windows,
        "startup_marginal_failures": apt_windows,
        "distribution_failures": distribution_windows,
        **{f"window_lag{lag}_failures": apt_windows for lag in PROFILED_LAGS},
    }
    if any(int(row[field]) > maximum for field, maximum in bounded_failures.items()):
        raise ValueError(f"run {row['run']} has a failure count above its windows")

    expected_passed = evaluated
    if int(row["rct_failures"]):
        expected_passed &= ~0x01
    if int(row["apt_failures"]):
        expected_passed &= ~0x02
    for lag in PROFILED_LAGS:
        if int(row[f"window_lag{lag}_failures"]):
            expected_passed &= ~(1 << (lag + 1))
    if int(row["startup_marginal_failures"]) or int(row["distribution_failures"]):
        expected_passed &= ~0x40
    if passed != expected_passed:
        raise ValueError(f"run {row['run']} has an inconsistent passed mask")

    failure_fields = [
        "rct_failures",
        "apt_failures",
        "startup_marginal_failures",
        "distribution_failures",
        *(f"window_lag{lag}_failures" for lag in PROFILED_LAGS),
    ]
    return {
        "health_diagnostics_available": True,
        "health_tests_all_evaluated": evaluated == HEALTH_ALL_PASS,
        "health_tests_all_passed": passed == evaluated,
        "health_failure_total": sum(int(row[field]) for field in failure_fields),
    }


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


def lag_diagnostics(
    row: dict[str, Any], pair_counts: dict[int, int] | None = None
) -> dict[str, Any]:
    """Describe lag-1..4 behavior without treating it as entropy credit."""
    samples = int(row["samples"])
    p1 = int(row["ones"]) / samples
    iid_mismatch_rate = 2.0 * p1 * (1.0 - p1)
    result: dict[str, Any] = {}
    available: list[int] = []
    correlations: list[float] = []

    for lag in PROFILED_LAGS:
        key = f"lag{lag}_mismatches"
        raw_count = row.get(key)
        if raw_count is None and lag == 1 and "transitions" in row:
            raw_count = row["transitions"]
        if raw_count is None:
            result[key] = None
            result[f"lag{lag}_mismatch_rate"] = None
            result[f"lag{lag}_correlation_heuristic"] = None
            result[f"lag{lag}_projected_startup_pass"] = None
            continue

        count = int(raw_count)
        if lag == 1 and "transitions" in row and count != int(row["transitions"]):
            raise ValueError(
                f"run {row.get('run', 'aggregate')} lag-1 count does not match transitions"
            )
        pairs = pair_counts[lag] if pair_counts is not None else samples - lag
        if count < 0 or count > pairs:
            raise ValueError(f"run {row.get('run', 'aggregate')} has invalid lag-{lag} count")
        rate = count / pairs
        correlation = (
            max(-1.0, min(1.0, 1.0 - rate / iid_mismatch_rate))
            if iid_mismatch_rate > 0.0
            else 0.0
        )
        match_low, match_high = STARTUP_LAG_MATCH_BOUNDS[lag]
        startup_pairs = 952 - lag
        mismatch_low = startup_pairs - match_high
        mismatch_high = startup_pairs - match_low

        result[key] = count
        result[f"lag{lag}_mismatch_rate"] = rate
        result[f"lag{lag}_correlation_heuristic"] = correlation
        result[f"lag{lag}_projected_startup_pass"] = (
            mismatch_low / startup_pairs <= rate <= mismatch_high / startup_pairs
        )
        available.append(lag)
        correlations.append(correlation)

    result["profiled_lags_available"] = available
    result["max_abs_lag_correlation_heuristic"] = (
        max(abs(value) for value in correlations) if correlations else None
    )
    result["projected_startup_lag_screen_pass"] = (
        all(bool(result[f"lag{lag}_projected_startup_pass"]) for lag in available)
        if available
        else None
    )
    return result


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
    lags = lag_diagnostics(row)
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
        **lags,
        **health_diagnostics(row),
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
    aggregate_lag_counts: dict[str, int] = {}
    aggregate_lag_pairs: dict[int, int] = {}
    for lag in PROFILED_LAGS:
        key = f"lag{lag}_mismatches"
        values = [row[key] for row in analyzed_runs]
        if all(value is not None for value in values):
            aggregate_lag_counts[key] = sum(int(value) for value in values)
            aggregate_lag_pairs[lag] = sum(int(row["samples"]) - lag for row in analyzed_runs)
    aggregate.update(
        lag_diagnostics(
            {
                **aggregate_lag_counts,
                "samples": total_ones + total_zeros,
                "ones": total_ones,
                "transitions": aggregate_transition["transitions"],
            },
            aggregate_lag_pairs,
        )
    )
    health_runs = [
        row for row in analyzed_runs if row["health_diagnostics_available"]
    ]
    aggregate["health_profile_runs"] = len(health_runs)
    if health_runs:
        evaluated = HEALTH_ALL_PASS
        passed = HEALTH_ALL_PASS
        for row in health_runs:
            evaluated &= int(row["health_tests_evaluated"])
            passed &= int(row["health_tests_passed"])
        aggregate.update(
            {
                "health_tests_evaluated": evaluated,
                "health_tests_passed": passed & evaluated,
                "rct_failures": sum(int(row["rct_failures"]) for row in health_runs),
                "apt_windows": sum(int(row["apt_windows"]) for row in health_runs),
                "apt_failures": sum(int(row["apt_failures"]) for row in health_runs),
                "startup_marginal_failures": sum(
                    int(row["startup_marginal_failures"]) for row in health_runs
                ),
                "distribution_windows": sum(
                    int(row["distribution_windows"]) for row in health_runs
                ),
                "distribution_failures": sum(
                    int(row["distribution_failures"]) for row in health_runs
                ),
            }
        )
        for lag in PROFILED_LAGS:
            aggregate[f"window_lag{lag}_failures"] = sum(
                int(row[f"window_lag{lag}_failures"]) for row in health_runs
            )
    else:
        aggregate["health_tests_evaluated"] = None
        aggregate["health_tests_passed"] = None
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
            "dependence can reduce actual min-entropy. Lag-2 through lag-4 "
            "results are diagnostics only and do not increase entropy credit."
        ),
        "lag_diagnostics_note": (
            "Lag-1 through lag-4 mismatch rates mirror the startup qualification "
            "range. Correlation values use the stationary-binary approximation "
            "1-q_k/(2*p0*p1); projected startup results compare reported rates "
            "with the qualification bounds and are not per-window health tests."
        ),
        "transition_counts_provenance": transition_counts_source,
        "transition_counts_note": (
            "Version 1 reports did not record endpoint bits. Their stored "
            "transition matrices are the endpoint-consistent candidates that "
            "produce the lowest first-order 99% lower estimate."
            if transition_counts_source != "recorded"
            else "Transition matrices were recorded directly by the version 2-or-newer profiler."
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
        "lag1_mismatches",
        "lag1_mismatch_rate",
        "lag1_correlation_heuristic",
        "lag2_mismatches",
        "lag2_mismatch_rate",
        "lag2_correlation_heuristic",
        "lag3_mismatches",
        "lag3_mismatch_rate",
        "lag3_correlation_heuristic",
        "lag4_mismatches",
        "lag4_mismatch_rate",
        "lag4_correlation_heuristic",
        "max_abs_lag_correlation_heuristic",
        "projected_startup_lag_screen_pass",
        "runs_z",
        "h_markov_plugin_bits_per_raw_bit",
        "h_markov_lower_99_bits_per_raw_bit",
        "first_order_dependency_factor",
        "longest",
        "longest0",
        "longest1",
        "profiler_version",
        "health_tests_evaluated",
        "health_tests_passed",
        "health_tests_all_evaluated",
        "health_tests_all_passed",
        "rct_failures",
        "apt_windows",
        "apt_failures",
        "apt_min_ones",
        "apt_max_ones",
        "startup_marginal_failures",
        "window_lag1_failures",
        "window_lag1_min",
        "window_lag1_max",
        "window_lag2_failures",
        "window_lag2_min",
        "window_lag2_max",
        "window_lag3_failures",
        "window_lag3_min",
        "window_lag3_max",
        "window_lag4_failures",
        "window_lag4_min",
        "window_lag4_max",
        "distribution_windows",
        "distribution_failures",
        "distribution_min_ones",
        "distribution_max_ones",
        "distribution_min_disagreements",
        "distribution_max_disagreements",
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
    for lag in PROFILED_LAGS:
        value = aggregate[f"lag{lag}_correlation_heuristic"]
        if value is not None:
            print(f"lag-{lag} correlation heuristic: {value:.6f}")
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
