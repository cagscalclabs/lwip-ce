#!/usr/bin/env python3
"""Tests for the live ACVP job-summary renderer."""

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
    def test_renders_one_nist_graded_row_per_vector_set(self):
        vectors = [
            {"acvVersion": "1.0"},
            {"vsId": 11, "algorithm": "SHA2-256"},
            {"vsId": 12, "algorithm": "ECDSA", "mode": "sigVer"},
        ]
        text = summary.build_summary(
            vectors,
            {"passed": True, "test_session_id": 42},
            "demo.acvts.nist.gov",
        )

        self.assertIn("**Test session:** `42`", text)
        self.assertIn("| 11 | SHA2-256 | ✅ Pass |", text)
        self.assertIn("| 12 | ECDSA sigVer | ✅ Pass |", text)
        self.assertNotIn("Calculator response", text)
        self.assertNotIn("Unit", text)

    def test_failed_nist_grade_is_visible(self):
        text = summary.build_summary(
            [{"vsId": 21, "algorithm": "ACVP-AES-GCM"}],
            {"passed": False},
            "demo.acvts.nist.gov",
        )
        self.assertIn("| 21 | ACVP-AES-GCM | ❌ Fail |", text)

    def test_missing_vectors_and_grade_have_clear_fallback(self):
        text = summary.build_summary(None, None, "demo.acvts.nist.gov")
        self.assertIn("| — | No vector sets available | ⚪ Not graded |", text)


if __name__ == "__main__":
    unittest.main()
