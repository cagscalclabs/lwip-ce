#!/usr/bin/env python3
"""
Host-side timing gate: reads checked-in statistics/timing/*_ctstats.json files
and enforces the c=6 over-percent threshold without running on an emulator.

Exit codes:
  0  All primitives pass (max c=6 over% < 75% across all profiles/classes).
     Warnings are printed for primitives where max c=6 over% > 50% or any
     profile's c=4 (rigorous) differential_pass is False, but these do not
     fail the workflow.
  1  One or more primitives exceed the 75% c=6 over-percent limit.
  2  No *_ctstats.json files found, or a file cannot be parsed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Thresholds
FAIL_THRESHOLD = 75.0   # c=6 over% at which a primitive fails the gate
WARN_THRESHOLD = 50.0   # c=6 over% at which a warning icon is shown

CLASSES = ("best", "worst", "random", "edge")

# Bar chart dimensions (characters)
BAR_WIDTH = 40


def bar(value: float, maximum: float = 100.0, width: int = BAR_WIDTH) -> str:
    filled = int(round(value / maximum * width))
    filled = max(0, min(filled, width))
    return "█" * filled + "░" * (width - filled)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[3]
    stats_dir = repo_root / "statistics" / "timing"

    profiles_raw = sorted(stats_dir.glob("*_ctstats.json"))
    if not profiles_raw:
        print(f"ERROR: no *_ctstats.json files found in {stats_dir}", file=sys.stderr)
        return 2

    # Load all profiles
    profiles: list[dict] = []
    for path in profiles_raw:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        profiles.append({"file": path.name, "data": data})

    print(f"Loaded {len(profiles)} profile(s) from {stats_dir}\n")

    # Union of primitive names across all profiles, preserving first-seen order.
    # Profiles recorded before or after a primitive was added will simply have
    # fewer data points for that primitive — that is expected during transitions.
    seen: set[str] = set()
    primitive_names: list[str] = []
    for profile in profiles:
        for prim_row in profile["data"]["primitives"]:
            name = prim_row["name"]
            if name not in seen:
                seen.add(name)
                primitive_names.append(name)

    # Warn about primitives that are not present in every profile so the
    # operator knows the gate has less coverage for those entries.
    profile_sets = [
        {prim_row["name"] for prim_row in p["data"]["primitives"]}
        for p in profiles
    ]
    all_names = set(primitive_names)
    partial: list[str] = [
        name for name in primitive_names
        if not all(name in ps for ps in profile_sets)
    ]
    if partial:
        print(
            f"NOTE: {len(partial)} primitive(s) appear in only some profiles "
            f"(transition in progress): {', '.join(partial)}"
        )
        print()

    # {prim: {class: [over% per profile that contains this primitive]}}
    c6_by_class: dict[str, dict[str, list[float]]] = {
        name: {cls: [] for cls in CLASSES} for name in primitive_names
    }
    c4_by_class: dict[str, dict[str, list[float]]] = {
        name: {cls: [] for cls in CLASSES} for name in primitive_names
    }
    c4_any_fail: dict[str, bool] = {name: False for name in primitive_names}

    for profile in profiles:
        for prim_row in profile["data"]["primitives"]:
            name = prim_row["name"]
            if name not in all_names:
                continue
            for cls in CLASSES:
                c6_by_class[name][cls].append(
                    prim_row["classes"][cls]["over_percent"]
                )
                c4_by_class[name][cls].append(
                    prim_row["rigorous_classes"][cls]["over_percent"]
                )
            if not prim_row["rigorous"]["differential_pass"]:
                c4_any_fail[name] = True

    # Evaluate each primitive
    failing: list[str] = []
    warning_over50: list[str] = []
    warning_c4: list[str] = []

    print("=" * 72)
    print(f"{'Primitive':<14} {'Max c6 over%':>13} {'Max c4 over%':>13}  Status")
    print("=" * 72)

    for name in primitive_names:
        max_c6 = max(
            v for cls_vals in c6_by_class[name].values() for v in cls_vals
        )
        max_c4 = max(
            v for cls_vals in c4_by_class[name].values() for v in cls_vals
        )

        if max_c6 >= FAIL_THRESHOLD:
            status = "❌ FAIL"
            failing.append(name)
        elif max_c6 > WARN_THRESHOLD:
            status = "⚠️  WARN (c6 >50%)"
            warning_over50.append(name)
        elif c4_any_fail[name]:
            status = "⚠️  WARN (c4 fail)"
            warning_c4.append(name)
        else:
            status = "✅ pass"

        print(f"  {name:<12} {max_c6:>12.2f}%  {max_c4:>12.2f}%  {status}")

    print("=" * 72)
    print()

    # Per-primitive chart: worst c=6 over% per class, averaged across profiles
    print("Chart: average c=6 over% per class (each bar = 0–100%)")
    print()
    for name in primitive_names:
        # worst class average (guard against a primitive with zero samples)
        class_avgs = {
            cls: (
                sum(c6_by_class[name][cls]) / len(c6_by_class[name][cls])
                if c6_by_class[name][cls] else 0.0
            )
            for cls in CLASSES
        }
        max_avg = max(class_avgs.values())
        flag = ""
        if name in failing:
            flag = " ❌"
        elif name in warning_over50 or name in warning_c4:
            flag = " ⚠️"
        n_profiles = len(c6_by_class[name][CLASSES[0]])
        coverage = f" ({n_profiles}/{len(profiles)} profiles)" if name in partial else ""
        print(f"  {name}{flag}{coverage}")
        for cls in CLASSES:
            avg = class_avgs[cls]
            print(f"    {cls:<8} [{bar(avg)}] {avg:.1f}%")
        print()

    # Summary
    total = len(primitive_names)
    n_fail = len(failing)
    n_warn = len(warning_over50) + len(warning_c4)
    n_pass = total - n_fail - len(warning_over50) - len(warning_c4)

    print("=" * 72)
    print(f"Result: {total} primitives — {n_pass} pass, {n_warn} warn, {n_fail} fail")
    if warning_c4:
        print(f"  c=4 (rigorous) warnings: {', '.join(warning_c4)}")
    if warning_over50:
        print(f"  c=6 >50% warnings:       {', '.join(warning_over50)}")
    if failing:
        print(f"  FAILING (c=6 ≥75%):      {', '.join(failing)}")
    print("=" * 72)

    return 1 if failing else 0


if __name__ == "__main__":
    raise SystemExit(main())
