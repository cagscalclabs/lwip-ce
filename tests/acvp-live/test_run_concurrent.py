#!/usr/bin/env python3 -I
"""Unit tests for concurrent live ACVP vector partitioning and assembly."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "run_acvp_live_tests.py"
SCRIPTS = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("run_acvp_live_tests", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)


HEADER = {"acvVersion": "1.0"}
VECTORS = [
    {"vsId": 10, "algorithm": "SHA2-256", "testGroups": []},
    {"vsId": 11, "algorithm": "ACVP-AES-GCM", "testGroups": []},
    {"vsId": 12, "algorithm": "PBKDF", "testGroups": []},
]


class TestConcurrentAssembly(unittest.TestCase):
    def test_partition_and_merge_preserve_nist_order(self):
        header, units = module.make_units([HEADER, *VECTORS])
        self.assertEqual([unit.vsid for unit in units], [10, 11, 12])
        self.assertEqual([unit.algorithm for unit in units],
                         ["SHA2-256", "ACVP-AES-GCM", "PBKDF"])
        responses = {
            12: {"vsId": 12, "testGroups": [{"tgId": 3}]},
            10: {"vsId": 10, "testGroups": [{"tgId": 1}]},
            11: {"vsId": 11, "testGroups": [{"tgId": 2}]},
        }
        combined = module.combine_responses(header, units, responses)
        self.assertEqual(combined[0], HEADER)
        self.assertEqual([item["vsId"] for item in combined[1:]], [10, 11, 12])

    def test_missing_response_is_rejected(self):
        header, units = module.make_units([HEADER, *VECTORS])
        with self.assertRaisesRegex(RuntimeError, r"missing=\[11, 12\]"):
            module.combine_responses(header, units,
                                     {10: {"vsId": 10, "testGroups": []}})

    def test_duplicate_prompt_vsid_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate vsIds"):
            module.make_units([HEADER, VECTORS[0], dict(VECTORS[0])])

    def test_worker_response_accepts_acvp_response_without_algorithm_field(self):
        _, units = module.make_units([HEADER, *VECTORS])
        with tempfile.TemporaryDirectory(prefix="acvp_live_response_") as directory:
            response = Path(directory) / "combined.json"
            response.write_text(json.dumps([
                HEADER, {"vsId": 10, "testGroups": [{"tgId": 1}]},
            ]))
            parsed = module.response_for_unit(response, units[0])
        self.assertEqual(parsed["vsId"], 10)

    def test_worker_response_rejects_wrong_vsid(self):
        _, units = module.make_units([HEADER, *VECTORS])
        with tempfile.TemporaryDirectory(prefix="acvp_live_response_") as directory:
            response = Path(directory) / "combined.json"
            response.write_text(json.dumps([
                HEADER, {"vsId": 99, "testGroups": []},
            ]))
            with self.assertRaisesRegex(RuntimeError, r"expected 10, found \[99\]"):
                module.response_for_unit(response, units[0])

    def test_workers_are_capped_by_cpu_and_unit_count(self):
        self.assertEqual(module.worker_count(16, cpu_count=4), 4)
        self.assertEqual(module.worker_count(2, cpu_count=8), 2)
        self.assertEqual(module.worker_count(16, requested=3, cpu_count=8), 3)
        self.assertEqual(module.worker_count(16, requested=8, cpu_count=2), 2)

    def test_streamed_worker_output_is_saved(self):
        with tempfile.TemporaryDirectory(prefix="acvp_live_stream_") as directory:
            log = Path(directory) / "host.log"
            status = module.run_streamed(
                [sys.executable, "-I", "-c", "print('worker output')"],
                log, "test", 5,
            )
            self.assertEqual(status, 0)
            self.assertEqual(log.read_text(), "worker output\n")

    def test_main_dispatches_every_vector_and_writes_ordered_response(self):
        with tempfile.TemporaryDirectory(prefix="acvp_live_concurrent_") as directory:
            root = Path(directory)
            image = root / "state.ce"
            autotester = root / "autotester"
            binary = root / "ACVPRUN.8xp"
            runner = root / "run.py"
            vectors = root / "vectors.json"
            response = root / "response.json"
            artifacts = root / "units"
            for path in (image, autotester, binary, runner):
                path.write_bytes(b"test")
            vectors.write_text(json.dumps([HEADER, *VECTORS]))

            def fake_worker(args, unit, namespace):
                return 0, {"vsId": unit.vsid,
                           "testGroups": [{"tgId": unit.index + 1}]}

            argv = [
                str(SCRIPT), "--runner", str(runner),
                "--autotester", str(autotester), "--usb", "usb|test",
                "--binary", str(binary), "--vectors", str(vectors),
                "--response", str(response), "--artifacts-dir", str(artifacts),
                "--max-workers", "2",
            ]
            with (mock.patch.dict(os.environ, {"AUTOTESTER_IMAGE": str(image)}),
                  mock.patch.object(sys, "argv", argv),
                  mock.patch.object(module.os, "geteuid", return_value=0),
                  mock.patch.object(module, "setup_namespace"),
                  mock.patch.object(module, "cleanup_namespace"),
                  mock.patch.object(module, "run_worker", side_effect=fake_worker)):
                status = module.main()

            self.assertEqual(status, 0)
            combined = json.loads(response.read_text())
            self.assertEqual(combined[0], HEADER)
            self.assertEqual([item["vsId"] for item in combined[1:]], [10, 11, 12])


if __name__ == "__main__":
    unittest.main(verbosity=2)
