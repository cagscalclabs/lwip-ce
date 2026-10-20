#!/usr/bin/env python3
"""Build human- and machine-readable summaries of checked-in timing profiles."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


PRIMITIVES = (
    "BYTES",
    "SHA256",
    "HMAC",
    "HKDF",
    "PBKDF2",
    "AESGCM-E",
    "AESGCM-DV",
    "AESCBC-E",
    "AESCBC-D",
    "AESCCM-E",
    "AESCCM-D",
    "X25519",
)
CLASSES = {"best", "worst", "random", "edge"}
CONFIGURATION = {"c": 6, "c_rig": 4, "sigma_scale": 14826}


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def require_number(value: Any, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    number = float(value)
    if number < minimum:
        raise ValueError(f"{label} must be >= {minimum}")
    return number


def validate_classes(value: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != CLASSES:
        raise ValueError(f"{label} must contain exactly {sorted(CLASSES)}")
    normalized: dict[str, dict[str, Any]] = {}
    for name, row in value.items():
        if not isinstance(row, dict):
            raise ValueError(f"{label}.{name} must be an object")
        trend = row.get("trend")
        if trend not in {"+", "-", "="}:
            raise ValueError(f"{label}.{name}.trend is invalid")
        over_percent = require_number(
            row.get("over_percent"), f"{label}.{name}.over_percent"
        )
        if over_percent > 100.0:
            raise ValueError(f"{label}.{name}.over_percent must be <= 100")
        normalized[name] = {
            "mean": require_int(row.get("mean"), f"{label}.{name}.mean"),
            "median": require_int(row.get("median"), f"{label}.{name}.median"),
            "trend": trend,
            "over_percent": over_percent,
        }
    return normalized


def validate_threshold(value: Any, label: str, expected_c: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    differential_pass = value.get("differential_pass")
    if not isinstance(differential_pass, bool):
        raise ValueError(f"{label}.differential_pass must be boolean")
    c_value = require_int(value.get("c"), f"{label}.c", 1)
    if c_value != expected_c:
        raise ValueError(f"{label}.c must be {expected_c}")
    return {
        "median": require_int(value.get("median"), f"{label}.median"),
        "mad": require_int(value.get("mad"), f"{label}.mad"),
        "sigma": require_number(value.get("sigma"), f"{label}.sigma"),
        "c": c_value,
        "accept": require_int(value.get("accept"), f"{label}.accept"),
        "differential_pass": differential_pass,
    }


def validate_profile(path: Path, stored: Any) -> dict[str, Any]:
    if not isinstance(stored, dict):
        raise ValueError(f"{path}: root must be an object")
    if stored.get("capture_format") != "cagscalclabs-ctstats-v1":
        raise ValueError(f"{path}: unsupported capture_format")
    model = stored.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValueError(f"{path}: model must be a non-empty string")
    if stored.get("configuration") != CONFIGURATION:
        raise ValueError(f"{path}: unsupported timing configuration")
    rows = stored.get("primitives")
    if not isinstance(rows, list) or len(rows) != len(PRIMITIVES):
        raise ValueError(f"{path}: expected {len(PRIMITIVES)} primitives")

    primitives: list[dict[str, Any]] = []
    for expected_name, row in zip(PRIMITIVES, rows):
        label = f"{path}:{expected_name}"
        if not isinstance(row, dict) or row.get("name") != expected_name:
            raise ValueError(f"{label}: primitive order or name is invalid")
        samples = require_int(row.get("samples"), f"{label}.samples", 1)
        primitives.append(
            {
                "name": expected_name,
                "reps": require_int(row.get("reps"), f"{label}.reps", 1),
                "samples": samples,
                "robust": validate_threshold(row.get("robust"), f"{label}.robust", 6),
                "rigorous": validate_threshold(
                    row.get("rigorous"), f"{label}.rigorous", 4
                ),
                "classes": validate_classes(row.get("classes"), f"{label}.classes"),
                "rigorous_classes": validate_classes(
                    row.get("rigorous_classes"), f"{label}.rigorous_classes"
                ),
            }
        )

    standard_passes = sum(row["robust"]["differential_pass"] for row in primitives)
    rigorous_passes = sum(row["rigorous"]["differential_pass"] for row in primitives)
    expected_summary = {
        "primitives": len(PRIMITIVES),
        "samples_per_class": primitives[0]["samples"],
        "standard_passes": standard_passes,
        "standard_failures": len(PRIMITIVES) - standard_passes,
        "rigorous_passes": rigorous_passes,
        "rigorous_failures": len(PRIMITIVES) - rigorous_passes,
    }
    if any(row["samples"] != expected_summary["samples_per_class"] for row in primitives):
        raise ValueError(f"{path}: samples_per_class differs between primitives")
    if stored.get("summary") != expected_summary:
        raise ValueError(f"{path}: stored summary does not match primitive results")

    return {
        "source_file": path.name,
        "model": model.strip(),
        "summary": expected_summary,
        "primitives": primitives,
    }


def load_profiles(stats_dir: Path) -> list[dict[str, Any]]:
    profiles = []
    for path in sorted(stats_dir.glob("*_ctstats.json")):
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"{path}: cannot read JSON: {error}") from error
        profiles.append(validate_profile(path, stored))
    if not profiles:
        raise ValueError(f"no *_ctstats.json profiles found in {stats_dir}")
    return profiles


def summarize_scope(name: str, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    evaluations = len(profiles) * len(PRIMITIVES)
    standard_passes = sum(row["summary"]["standard_passes"] for row in profiles)
    rigorous_passes = sum(row["summary"]["rigorous_passes"] for row in profiles)
    return {
        "scope": name,
        "profiles": len(profiles),
        "primitive_evaluations": evaluations,
        "standard_passes": standard_passes,
        "standard_failures": evaluations - standard_passes,
        "standard_pass_rate": standard_passes / evaluations,
        "rigorous_passes": rigorous_passes,
        "rigorous_failures": evaluations - rigorous_passes,
        "rigorous_pass_rate": rigorous_passes / evaluations,
    }


def summarize_primitive(name: str, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [profile["primitives"][PRIMITIVES.index(name)] for profile in profiles]
    standard_passes = sum(row["robust"]["differential_pass"] for row in rows)
    rigorous_passes = sum(row["rigorous"]["differential_pass"] for row in rows)
    return {
        "primitive": name,
        "profiles": len(rows),
        "standard_passes": standard_passes,
        "standard_failures": len(rows) - standard_passes,
        "rigorous_passes": rigorous_passes,
        "rigorous_failures": len(rows) - rigorous_passes,
        "worst_standard_over_percent": max(
            item["over_percent"] for row in rows for item in row["classes"].values()
        ),
        "worst_rigorous_over_percent": max(
            item["over_percent"]
            for row in rows
            for item in row["rigorous_classes"].values()
        ),
    }


def build_report(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        grouped.setdefault(profile["model"], []).append(profile)
    return {
        "capture_format": "cagscalclabs-ctstats-summary-v1",
        "configuration": CONFIGURATION,
        "source_files": [profile["source_file"] for profile in profiles],
        "scopes": [summarize_scope("All models", profiles)]
        + [
            summarize_scope(model, grouped[model])
            for model in sorted(grouped, key=str.casefold)
        ],
        "primitives": [summarize_primitive(name, profiles) for name in PRIMITIVES],
    }


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def ratio(passes: int, failures: int) -> str:
    return f"{passes}/{passes + failures}"


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# TLS timing statistics",
        "",
        f"Processed **{len(report['source_files'])} hardware profiles**.",
        "",
        (
            "> The standard result uses c=6. The more sensitive rigorous result uses "
            "c=4. Pass counts reproduce each profiler's differential-pass decision."
        ),
        "",
        "## Aggregate",
        "",
        "| Scope | Profiles | Evaluations | Standard pass | Standard failures | Rigorous pass | Rigorous failures |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for scope in report["scopes"][:1]:
        lines.append(
            f"| {markdown_escape(scope['scope'])} | {scope['profiles']} "
            f"| {scope['primitive_evaluations']} "
            f"| {ratio(scope['standard_passes'], scope['standard_failures'])} "
            f"| {scope['standard_failures']} "
            f"| {ratio(scope['rigorous_passes'], scope['rigorous_failures'])} "
            f"| {scope['rigorous_failures']} |"
        )

    lines.extend(
        [
            "",
            "## Per model",
            "",
            "| Model | Profiles | Evaluations | Standard pass | Standard failures | Rigorous pass | Rigorous failures |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for scope in report["scopes"][1:]:
        lines.append(
            f"| {markdown_escape(scope['scope'])} | {scope['profiles']} "
            f"| {scope['primitive_evaluations']} "
            f"| {ratio(scope['standard_passes'], scope['standard_failures'])} "
            f"| {scope['standard_failures']} "
            f"| {ratio(scope['rigorous_passes'], scope['rigorous_failures'])} "
            f"| {scope['rigorous_failures']} |"
        )

    lines.extend(
        [
            "",
            "## Per primitive",
            "",
            "| Primitive | Profiles | Standard pass | Rigorous pass | Worst standard over | Worst rigorous over |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for primitive in report["primitives"]:
        lines.append(
            f"| {primitive['primitive']} | {primitive['profiles']} "
            f"| {ratio(primitive['standard_passes'], primitive['standard_failures'])} "
            f"| {ratio(primitive['rigorous_passes'], primitive['rigorous_failures'])} "
            f"| {primitive['worst_standard_over_percent']:.2f}% "
            f"| {primitive['worst_rigorous_over_percent']:.2f}% |"
        )

    lines.extend(
        [
            "",
            "> A passing hardware profile is evidence about the measured inputs and device, not proof that every implementation path is constant-time.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(path: Path, report: dict[str, Any]) -> None:
    fields = [
        "primitive",
        "profiles",
        "standard_passes",
        "standard_failures",
        "rigorous_passes",
        "rigorous_failures",
        "worst_standard_over_percent",
        "worst_rigorous_over_percent",
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report["primitives"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    profiles = load_profiles(args.stats_dir)
    report = build_report(profiles)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "timing-statistics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(args.output_dir / "timing-statistics.csv", report)
    write_markdown(args.output_dir / "timing-statistics.md", report)
    print(
        f"wrote timing report for {len(profiles)} profiles and "
        f"{len(profiles) * len(PRIMITIVES)} primitive evaluations to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
