#!/usr/bin/env python3
"""Regression tests for the checked-in timing statistics summarizer."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SUMMARIZER_PATH = (
    ROOT / "tests/profiling/tls_timing/tools/summarize_timing_stats.py"
)
SPEC = importlib.util.spec_from_file_location("summarize_timing_stats", SUMMARIZER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load timing summarizer from {SUMMARIZER_PATH}")
SUMMARIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARIZER)
COUNT = len(SUMMARIZER.PRIMITIVES)


def fixture(model: str = "TI-84 Plus CE / M", failure: str = "BYTES") -> dict:
    primitives = []
    for index, name in enumerate(SUMMARIZER.PRIMITIVES):
        standard_pass = name != failure
        classes = {
            class_name: {
                "mean": 1001 + index,
                "median": 1000 + index,
                "trend": "=",
                "over_percent": float(index),
            }
            for class_name in SUMMARIZER.CLASSES
        }
        rigorous_classes = {
            class_name: {**row, "over_percent": row["over_percent"] + 0.5}
            for class_name, row in classes.items()
        }
        primitives.append(
            {
                "name": name,
                "reps": 16,
                "samples": 32,
                "robust": {
                    "median": 1000,
                    "mad": 2,
                    "sigma": 2.9652,
                    "c": 6,
                    "accept": 18,
                    "differential_pass": standard_pass,
                },
                "rigorous": {
                    "median": 1000,
                    "mad": 2,
                    "sigma": 2.9652,
                    "c": 4,
                    "accept": 12,
                    "differential_pass": True,
                },
                "classes": classes,
                "rigorous_classes": rigorous_classes,
            }
        )
    return {
        "capture_format": "cagscalclabs-ctstats-v1",
        "model": model,
        "profiler": "lwIP-CE tests/profiling/tls_timing",
        "configuration": dict(SUMMARIZER.CONFIGURATION),
        "summary": {
            "primitives": COUNT,
            "samples_per_class": 32,
            "standard_passes": COUNT - 1,
            "standard_failures": 1,
            "rigorous_passes": COUNT,
            "rigorous_failures": 0,
        },
        "primitives": primitives,
    }


class TimingStatisticsTests(unittest.TestCase):
    def test_cli_writes_json_csv_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stats_dir = root / "statistics" / "timing"
            output_dir = root / "build"
            stats_dir.mkdir(parents=True)
            (stats_dir / "capture_ctstats.json").write_text(
                json.dumps(fixture()), encoding="utf-8"
            )

            subprocess.run(
                [
                    sys.executable,
                    str(SUMMARIZER_PATH),
                    "--stats-dir",
                    str(stats_dir),
                    "--output-dir",
                    str(output_dir),
                ],
                check=True,
            )

            report = json.loads(
                (output_dir / "timing-statistics.json").read_text(encoding="utf-8")
            )
            markdown = (output_dir / "timing-statistics.md").read_text(
                encoding="utf-8"
            )
            self.assertEqual(report["scopes"][0]["standard_failures"], 1)
            self.assertTrue((output_dir / "timing-statistics.csv").is_file())
            self.assertIn("# TLS timing statistics", markdown)
            self.assertIn("| BYTES | 1 | 0/1 | 1/1 |", markdown)

    def test_loads_and_aggregates_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stats_dir = Path(temporary)
            (stats_dir / "first_ctstats.json").write_text(
                json.dumps(fixture()), encoding="utf-8"
            )
            (stats_dir / "second_ctstats.json").write_text(
                json.dumps(fixture(model="TI-84 Plus CE / L", failure="SHA256")),
                encoding="utf-8",
            )

            report = SUMMARIZER.build_report(SUMMARIZER.load_profiles(stats_dir))

        self.assertEqual(report["capture_format"], "cagscalclabs-ctstats-summary-v1")
        self.assertEqual(report["scopes"][0]["profiles"], 2)
        self.assertEqual(report["scopes"][0]["primitive_evaluations"], 2 * COUNT)
        self.assertEqual(report["scopes"][0]["standard_passes"], 2 * COUNT - 2)
        self.assertEqual(report["scopes"][0]["rigorous_passes"], 2 * COUNT)
        self.assertEqual([row["scope"] for row in report["scopes"][1:]], [
            "TI-84 Plus CE / L",
            "TI-84 Plus CE / M",
        ])
        self.assertEqual(report["primitives"][0]["standard_failures"], 1)
        self.assertEqual(report["primitives"][1]["standard_failures"], 1)

    def test_rejects_inconsistent_stored_summary(self) -> None:
        profile = fixture()
        profile["summary"]["standard_passes"] = COUNT
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad_ctstats.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stored summary"):
                SUMMARIZER.load_profiles(path.parent)


if __name__ == "__main__":
    unittest.main()
