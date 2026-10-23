#!/usr/bin/env python3
"""Build human- and machine-readable summaries of checked-in RNG profiles."""

from __future__ import annotations

import argparse
import csv
import html
import importlib.util
import json
import math
import statistics
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
ANALYZER_PATH = SCRIPT_DIR / "analyze_rng_stats.py"

ANALYZER_SPEC = importlib.util.spec_from_file_location(
    "lwip_ce_analyze_rng_stats", ANALYZER_PATH
)
if ANALYZER_SPEC is None or ANALYZER_SPEC.loader is None:
    raise RuntimeError(f"cannot load RNG analyzer from {ANALYZER_PATH}")
ANALYZER = importlib.util.module_from_spec(ANALYZER_SPEC)
ANALYZER_SPEC.loader.exec_module(ANALYZER)


def load_profiles(stats_dir: Path) -> list[dict[str, Any]]:
    """Load profiles and recompute every analyzer-owned field from raw counts."""
    profiles: list[dict[str, Any]] = []
    for path in sorted(stats_dir.glob("*_rngstats.json")):
        stored = json.loads(path.read_text(encoding="utf-8"))
        runs = stored.get("runs")
        if not isinstance(runs, list) or not runs:
            raise ValueError(f"{path}: no RNG run rows")
        report = ANALYZER.analyze(runs)
        profiles.append(
            {
                "source_file": path.name,
                "model": str(
                    stored.get("model", stored.get("device_model", "uncategorized"))
                ),
                **report,
            }
        )
    if not profiles:
        raise ValueError(f"no *_rngstats.json profiles found in {stats_dir}")
    return profiles


def summarize_scope(name: str, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    runs = [row for profile in profiles for row in profile["runs"]]
    total_ones = sum(int(row["ones"]) for row in runs)
    total_zeros = sum(int(row["zeros"]) for row in runs)
    marginal_aggregate = ANALYZER.estimate(total_ones, total_zeros)
    transition_counts = {
        key: sum(int(row[key]) for row in runs)
        for key in ("n00", "n01", "n10", "n11")
    }
    markov_aggregate = ANALYZER.transition_estimate(
        transition_counts, total_ones, total_zeros
    )

    marginal_h = min(
        float(marginal_aggregate["h_mcv_lower_99_bits_per_raw_bit"]),
        *(float(row["h_mcv_lower_99_bits_per_raw_bit"]) for row in runs),
    )
    markov_h = min(
        float(markov_aggregate["h_markov_lower_99_bits_per_raw_bit"]),
        *(float(profile["first_order_working_h_bits_per_raw_bit"])
          for profile in profiles),
        *(float(row["h_markov_lower_99_bits_per_raw_bit"]) for row in runs),
    )
    conservative_h = min(marginal_h, markov_h)
    worst_rho_row = max(runs, key=lambda row: abs(float(row["lag1_phi"])))
    worst_rho = float(worst_rho_row["lag1_phi"])
    worst_lag_correlations: dict[str, float | None] = {}
    for lag in ANALYZER.PROFILED_LAGS:
        key = f"lag{lag}_correlation_heuristic"
        values = [float(row[key]) for row in runs if row.get(key) is not None]
        worst_lag_correlations[str(lag)] = (
            max(values, key=abs) if values else None
        )
    lag_screen_runs = [
        row for row in runs if row.get("profiled_lags_available") == [1, 2, 3, 4]
    ]
    lag_screen_failures = sum(
        not bool(row["projected_startup_lag_screen_pass"])
        for row in lag_screen_runs
    )
    health_runs = [row for row in runs if row["health_diagnostics_available"]]
    health_evaluated_mask = ANALYZER.HEALTH_ALL_PASS
    health_passed_mask = ANALYZER.HEALTH_ALL_PASS
    for row in health_runs:
        health_evaluated_mask &= int(row["health_tests_evaluated"])
        health_passed_mask &= int(row["health_tests_passed"])

    distributions = {
        "marginal_h": [
            float(row["h_mcv_lower_99_bits_per_raw_bit"]) for row in runs
        ],
        "lag1_phi": [float(row["lag1_phi"]) for row in runs],
        "max_abs_lag_correlation": [
            float(row["max_abs_lag_correlation_heuristic"])
            for row in runs
            if row.get("max_abs_lag_correlation_heuristic") is not None
        ],
        "conservative_h": [
            min(
                float(row["h_mcv_lower_99_bits_per_raw_bit"]),
                float(row["h_markov_lower_99_bits_per_raw_bit"]),
            )
            for row in runs
        ],
    }
    return {
        "scope": name,
        "profiles": len(profiles),
        "windows": len(runs),
        "samples": total_ones + total_zeros,
        "marginal_h_lower_99_bits_per_raw_bit": marginal_h,
        "worst_window_lag1_phi": worst_rho,
        "max_abs_lag1_phi": abs(worst_rho),
        "worst_lag_correlations": worst_lag_correlations,
        **{
            f"worst_lag{lag}_correlation_heuristic": value
            for lag, value in worst_lag_correlations.items()
        },
        "projected_lag_screen_windows": len(lag_screen_runs),
        "projected_lag_screen_failures": lag_screen_failures,
        "health_profile_windows": len(health_runs),
        "health_tests_evaluated_mask": (
            health_evaluated_mask if health_runs else None
        ),
        "health_tests_passed_mask": (
            health_passed_mask & health_evaluated_mask if health_runs else None
        ),
        "rct_failures": sum(int(row["rct_failures"]) for row in health_runs),
        "apt_windows": sum(int(row["apt_windows"]) for row in health_runs),
        "apt_failures": sum(int(row["apt_failures"]) for row in health_runs),
        "startup_marginal_failures": sum(
            int(row["startup_marginal_failures"]) for row in health_runs
        ),
        **{
            f"window_lag{lag}_failures": sum(
                int(row[f"window_lag{lag}_failures"]) for row in health_runs
            )
            for lag in ANALYZER.PROFILED_LAGS
        },
        "distribution_windows": sum(
            int(row["distribution_windows"]) for row in health_runs
        ),
        "distribution_failures": sum(
            int(row["distribution_failures"]) for row in health_runs
        ),
        "markov_h_lower_99_bits_per_raw_bit": markov_h,
        "first_order_dependency_factor": (
            min(1.0, conservative_h / marginal_h) if marginal_h > 0.0 else 0.0
        ),
        "conservative_h_bits_per_raw_bit": conservative_h,
        "distributions": distributions,
    }


def build_report(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        grouped.setdefault(str(profile["model"]), []).append(profile)
    scopes = [summarize_scope("All models", profiles)]
    scopes.extend(
        summarize_scope(model, grouped[model])
        for model in sorted(grouped, key=str.casefold)
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
        "source_files": [str(profile["source_file"]) for profile in profiles],
        "scopes": scopes,
    }


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def summary_table(scopes: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Scope | Profiles | Windows | Samples | Marginal H₉₉ | Worst ρ₁…₄ (heuristic) | Projected lag-screen failures | Markov H₉₉ | Dependency factor | Conservative H |",
        "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for scope in scopes:
        lag_values = scope["worst_lag_correlations"]
        lag_summary = ", ".join(
            f"ρ{lag}={float(value):+.4f}" if value is not None else f"ρ{lag}=n/a"
            for lag, value in lag_values.items()
        )
        lines.append(
            f"| {markdown_escape(str(scope['scope']))} "
            f"| {int(scope['profiles'])} | {int(scope['windows'])} "
            f"| {int(scope['samples']):,} "
            f"| {float(scope['marginal_h_lower_99_bits_per_raw_bit']):.6f} "
            f"| {lag_summary} "
            f"| {int(scope['projected_lag_screen_failures'])}/{int(scope['projected_lag_screen_windows'])} "
            f"| {float(scope['markov_h_lower_99_bits_per_raw_bit']):.6f} "
            f"| {float(scope['first_order_dependency_factor']):.6f} "
            f"| {float(scope['conservative_h_bits_per_raw_bit']):.6f} |"
        )
    return lines


def write_markdown(path: Path, report: dict[str, Any], image_url: str) -> None:
    scopes = report["scopes"]
    lines = [
        "# RNG entropy statistics",
        "",
        (
            f"Processed **{len(report['source_files'])} profiles** and "
            f"**{int(scopes[0]['windows'])} test windows**. Entropy values are "
            "bits per raw bit."
        ),
        "",
        f"![RNG entropy and lag-1 through lag-4 correlation distributions]({image_url})",
        "",
        (
            "> Smoothed distributions are descriptive rather than fitted normal "
            "curves. Every circle is an individual test window."
        ),
        "",
        "## Aggregate",
        "",
        *summary_table(scopes[:1]),
        "",
        "## Per model",
        "",
        *summary_table(scopes[1:]),
        "",
        "## Production health-test diagnostics",
        "",
        "| Scope | Version 4 runs | Evaluated mask | Passed mask | RCT failures | APT failures/windows | Startup marginal failures | Lag 1/2/3/4 failures | Distribution failures/windows |",
        "|---|---:|---:|---:|---:|---:|---:|---|---:|",
        *[
            f"| {markdown_escape(str(scope['scope']))} "
            f"| {int(scope['health_profile_windows'])} "
            f"| {('0x%02X' % int(scope['health_tests_evaluated_mask'])) if scope['health_tests_evaluated_mask'] is not None else 'n/a'} "
            f"| {('0x%02X' % int(scope['health_tests_passed_mask'])) if scope['health_tests_passed_mask'] is not None else 'n/a'} "
            f"| {int(scope['rct_failures'])} "
            f"| {int(scope['apt_failures'])}/{int(scope['apt_windows'])} "
            f"| {int(scope['startup_marginal_failures'])} "
            f"| {int(scope['window_lag1_failures'])}/"
            f"{int(scope['window_lag2_failures'])}/"
            f"{int(scope['window_lag3_failures'])}/"
            f"{int(scope['window_lag4_failures'])} "
            f"| {int(scope['distribution_failures'])}/"
            f"{int(scope['distribution_windows'])} |"
            for scope in scopes
        ],
        "",
        "## Interpretation",
        "",
        "- **Marginal H₉₉** is the lower 99% MCV estimate, conservatively taking the poorer of the pooled and worst-window results.",
        "- **Worst ρ₁…₄** uses the stationary-binary correlation heuristic `1-qₖ/(2p₀p₁)`; these values diagnose periodicity and do not add entropy credit.",
        "- **Projected lag-screen failures** compares each version 3-or-newer run's aggregate lag rates with the startup bounds; version 4 health diagnostics separately count exact non-overlapping 952-sample windows.",
        "- **Conservative H** is the lower of the marginal and first-order Markov estimates.",
        "- The aggregate headline is a worst-supported bound across the dataset, not an average calculator.",
        "",
        f"> ⚠️ {report['scope_warning']}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(path: Path, report: dict[str, Any]) -> None:
    fields = [
        "scope",
        "profiles",
        "windows",
        "samples",
        "marginal_h_lower_99_bits_per_raw_bit",
        "worst_window_lag1_phi",
        "max_abs_lag1_phi",
        "worst_lag1_correlation_heuristic",
        "worst_lag2_correlation_heuristic",
        "worst_lag3_correlation_heuristic",
        "worst_lag4_correlation_heuristic",
        "projected_lag_screen_windows",
        "projected_lag_screen_failures",
        "health_profile_windows",
        "health_tests_evaluated_mask",
        "health_tests_passed_mask",
        "rct_failures",
        "apt_windows",
        "apt_failures",
        "startup_marginal_failures",
        "window_lag1_failures",
        "window_lag2_failures",
        "window_lag3_failures",
        "window_lag4_failures",
        "distribution_windows",
        "distribution_failures",
        "markov_h_lower_99_bits_per_raw_bit",
        "first_order_dependency_factor",
        "conservative_h_bits_per_raw_bit",
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for scope in report["scopes"]:
            writer.writerow({key: scope[key] for key in fields})


def nice_correlation_limit(scopes: list[dict[str, Any]]) -> float:
    observed = max(
        abs(value)
        for scope in scopes
        for value in scope["distributions"]["max_abs_lag_correlation"]
    )
    return min(1.0, max(0.05, math.ceil(observed * 20.0) / 20.0))


def kde(values: list[float], points: list[float], axis_span: float) -> list[float]:
    if len(values) < 2 or max(values) == min(values):
        return [0.0 for _ in points]
    deviation = statistics.stdev(values)
    bandwidth = max(axis_span * 0.0125, 1.06 * deviation * len(values) ** -0.2)
    scale = bandwidth * math.sqrt(2.0 * math.pi) * len(values)
    return [
        sum(math.exp(-0.5 * ((point - value) / bandwidth) ** 2) for value in values)
        / scale
        for point in points
    ]


def svg_text(x: float, y: float, value: str, **attrs: str) -> str:
    attributes = " ".join(f'{key.replace("_", "-")}="{html.escape(val)}"' for key, val in attrs.items())
    return f'<text x="{x:.1f}" y="{y:.1f}" {attributes}>{html.escape(value)}</text>'


def write_svg(path: Path, report: dict[str, Any], paper_chart: bool = False) -> None:
    scopes = report["scopes"]
    width = 1500
    left = 250
    right = 35
    gap = 35
    top = 70 if paper_chart else 120
    row_height = 92
    bottom = 55 if paper_chart else 85
    panel_width = (width - left - right - 2 * gap) / 3
    height = top + row_height * len(scopes) + bottom
    rho_limit = nice_correlation_limit(scopes)
    panels = [
        ("marginal_h", "Marginal H₉₉", 0.0, 1.0, "#0969da"),
        ("max_abs_lag_correlation", "Max |lag correlation|, k=1…4", 0.0, rho_limit, "#8250df"),
        ("conservative_h", "Conservative H", 0.0, 1.0, "#1a7f37"),
    ]

    out: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}">'
        ),
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<g font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" fill="#24292f">',
    ]
    if not paper_chart:
        out.extend(
            [
                svg_text(24, 36, "RNG entropy statistics", font_size="24", font_weight="600"),
                svg_text(
                    24,
                    62,
                    "Smoothed window distributions with every measured window overlaid",
                    font_size="14",
                    fill="#57606a",
                ),
            ]
        )

    for row_index in range(len(scopes)):
        if row_index % 2 == 0:
            center_y = top + row_index * row_height + row_height / 2
            out.append(
                f'<rect x="10" y="{center_y - row_height / 2:.1f}" width="{width - 20}" height="{row_height:.1f}" rx="6" fill="#f6f8fa"/>'
            )

    for panel_index, (key, title, axis_min, axis_max, color) in enumerate(panels):
        panel_x = left + panel_index * (panel_width + gap)
        out.append(svg_text(panel_x + panel_width / 2, top - 28, title, text_anchor="middle", font_size="17", font_weight="600"))
        ticks = [axis_min + (axis_max - axis_min) * index / 4 for index in range(5)]
        for tick in ticks:
            x = panel_x + (tick - axis_min) / (axis_max - axis_min) * panel_width
            out.append(
                f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{top + row_height * len(scopes)}" stroke="#d8dee4" stroke-width="1"/>'
            )
            label = f"{tick:.2f}"
            tick_y = height - (48 if not paper_chart else 20)
            out.append(svg_text(x, tick_y, label, text_anchor="middle", font_size="12", fill="#57606a"))

        for row_index, scope in enumerate(scopes):
            center_y = top + row_index * row_height + row_height / 2
            values = [float(value) for value in scope["distributions"][key]]
            point_values = [axis_min + (axis_max - axis_min) * index / 120 for index in range(121)]
            densities = kde(values, point_values, axis_max - axis_min)
            max_density = max(densities, default=0.0)
            if max_density > 0.0:
                upper: list[str] = []
                lower: list[str] = []
                for value, density in zip(point_values, densities):
                    x = panel_x + (value - axis_min) / (axis_max - axis_min) * panel_width
                    amplitude = 25.0 * density / max_density
                    upper.append(f"{x:.1f},{center_y - amplitude:.1f}")
                    lower.append(f"{x:.1f},{center_y + amplitude:.1f}")
                polygon = " ".join(upper + list(reversed(lower)))
                out.append(f'<polygon points="{polygon}" fill="{color}" fill-opacity="0.20" stroke="{color}" stroke-width="1.5"/>')
            else:
                out.append(
                    f'<line x1="{panel_x:.1f}" y1="{center_y:.1f}" x2="{panel_x + panel_width:.1f}" y2="{center_y:.1f}" stroke="#d8dee4"/>'
                )
            for value_index, value in enumerate(sorted(values)):
                x = panel_x + (value - axis_min) / (axis_max - axis_min) * panel_width
                jitter = ((value_index % 5) - 2) * 3.0
                out.append(
                    f'<circle cx="{x:.1f}" cy="{center_y + jitter:.1f}" r="3.5" fill="{color}" stroke="#ffffff" stroke-width="1"/>'
                )

    for row_index, scope in enumerate(scopes):
        center_y = top + row_index * row_height + row_height / 2
        out.append(svg_text(24, center_y - 2, str(scope["scope"]), font_size="15", font_weight="600"))
        out.append(svg_text(24, center_y + 19, f"{scope['profiles']} profiles · {scope['windows']} windows", font_size="12", fill="#57606a"))

    if not paper_chart:
        out.append(
            svg_text(
                width / 2,
                height - 15,
                "Density shapes are descriptive, not fitted normal distributions; circles are individual test windows.",
                text_anchor="middle",
                font_size="12",
                fill="#57606a",
            )
        )
    out.extend(["</g>", "</svg>"])
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--image-url",
        default="rng-distributions.svg",
        help="image URL embedded in the generated Markdown summary",
    )
    parser.add_argument(
        "--paper-chart",
        action="store_true",
        help="omit the standalone heading and explanatory footer",
    )
    args = parser.parse_args()

    profiles = load_profiles(args.stats_dir)
    report = build_report(profiles)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "rng-statistics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(args.output_dir / "rng-statistics.csv", report)
    write_svg(
        args.output_dir / "rng-distributions.svg",
        report,
        paper_chart=args.paper_chart,
    )
    write_markdown(args.output_dir / "rng-statistics.md", report, args.image_url)
    print(
        f"wrote RNG report for {len(profiles)} profiles and "
        f"{report['scopes'][0]['windows']} windows to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
