#!/usr/bin/env python3
"""Tests for the live ACVP job-summary adapter."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("summary.py")
SPEC = importlib.util.spec_from_file_location("acvp_live_summary", SCRIPT)
assert SPEC and SPEC.loader
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def test_groups_vector_sets_and_reports_partial_failure(self):
        vectors = [
            {"acvVersion": "1.0"},
            {"vsId": 11, "algorithm": "SHA2-256"},
            {"vsId": 12, "algorithm": "SHA2-256"},
            {"vsId": 13, "algorithm": "ACVP-AES-GCM"},
        ]
        responses = [
            {"acvVersion": "1.0"},
            {"vsId": 11, "testGroups": []},
            {"vsId": 13, "testGroups": []},
        ]
        results = summary.build_results(
            vectors, responses, None, "failure", "skipped", "skipped"
        )
        self.assertEqual([item["module"] for item in results],
                         ["SHA2-256", "ACVP-AES-GCM"])
        sha_units = results[0]["units"]
        self.assertEqual(sha_units[0]["tests"][0]["status"], "pass")
        self.assertEqual(sha_units[1]["tests"][0]["status"], "fail")
        self.assertEqual(results[0]["status"], "fail")

    def test_applies_successful_nist_grade_to_every_vector_set(self):
        vectors = [{"vsId": 21, "algorithm": "ECDSA", "mode": "sigVer"}]
        responses = [{"vsId": 21, "testGroups": []}]
        results = summary.build_results(
            vectors, responses, {"passed": True},
            "success", "success", "success",
        )
        self.assertEqual(results[0]["module"], "ECDSA sigVer")
        self.assertEqual(results[0]["status"], "pass")
        self.assertTrue(all(
            test["status"] == "pass"
            for test in results[0]["units"][0]["tests"]
        ))

    def test_missing_vectors_produces_workflow_fallback(self):
        results = summary.build_results(
            None, None, None, "failure", "skipped", "skipped"
        )
        self.assertEqual(results[0]["module"], "ACVP LIVE")
        self.assertEqual(results[0]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
