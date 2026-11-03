#!/usr/bin/env python3 -I
"""Offline-format tests for the libacvp fetch/process/upload bridge."""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acvp_offline as offline


@contextlib.contextmanager
def temporary_layout():
    with tempfile.TemporaryDirectory(prefix="acvp_offline_") as directory:
        root = Path(directory)
        replacements = {
            "HERE": root,
            "LIBACVP_DIR": root / "libacvp",
            "ACVP_APP": root / "libacvp" / "app" / "acvp_app",
            "VECTORS_DIR": root / "vectors",
            "RESPONSES_DIR": root / "responses",
            "SESSION_FILE": root / "session.json",
            "UPLOAD_CONTEXT_FILE": root / "upload_context.json",
            "CAPABILITIES_FILE": root / "capabilities.json",
            "RESULTS_FILE": root / "results.json",
            "RESULTS_LOG": root / "results.log",
        }
        with contextlib.ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(mock.patch.object(offline, name, value))
            yield root


CONTEXT = {
    "jwt": "test-only-token",
    "url": "/acvp/v1/testSessions/42",
    "isSample": False,
    "vectorSetUrls": ["/acvp/v1/testSessions/42/vectorSets/7"],
}
VECTOR = {
    "vsId": 7,
    "algorithm": "SHA2-256",
    "revision": "1.0",
    "testGroups": [],
}
RESPONSE = {"vsId": 7, "testGroups": []}


class TestOfflineEnvelope(unittest.TestCase):
    def test_fetch_envelope_is_separated_and_restored_for_upload(self):
        with temporary_layout() as root:
            request = root / "request.json"
            request.write_text(json.dumps([CONTEXT, VECTOR]))

            paths = offline.write_vector_files(request)

            self.assertEqual([path.name for path in paths], ["7.json"])
            self.assertFalse((offline.VECTORS_DIR / "unknown.json").exists())
            vectors = json.loads((offline.VECTORS_DIR / "combined.json").read_text())
            self.assertEqual(vectors, [{"acvVersion": "1.0"}, VECTOR])
            self.assertEqual(json.loads(offline.UPLOAD_CONTEXT_FILE.read_text()), CONTEXT)
            self.assertEqual(offline.UPLOAD_CONTEXT_FILE.stat().st_mode & 0o777, 0o600)

            offline.RESPONSES_DIR.mkdir()
            (offline.RESPONSES_DIR / "combined.json").write_text(json.dumps([
                {"acvVersion": "1.0"}, RESPONSE,
            ]))
            upload = offline.collect_responses()

            self.assertEqual(json.loads(upload.read_text()), [CONTEXT, RESPONSE])
            self.assertEqual(json.loads((offline.RESPONSES_DIR / "7.json").read_text()),
                             RESPONSE)
            self.assertEqual(upload.stat().st_mode & 0o777, 0o600)

    def test_missing_session_metadata_is_rejected(self):
        with temporary_layout() as root:
            request = root / "request.json"
            request.write_text(json.dumps([{"acvVersion": "1.0"}, VECTOR]))
            with self.assertRaisesRegex(RuntimeError, "session metadata"):
                offline.write_vector_files(request)

    def test_incomplete_response_set_is_rejected(self):
        with temporary_layout():
            context = dict(CONTEXT)
            context["vectorSetUrls"] = [
                "/acvp/v1/testSessions/42/vectorSets/7",
                "/acvp/v1/testSessions/42/vectorSets/8",
            ]
            offline.RESPONSES_DIR.mkdir()
            offline._secure_write(offline.UPLOAD_CONTEXT_FILE, context)
            (offline.RESPONSES_DIR / "combined.json").write_text(json.dumps([
                {"acvVersion": "1.0"}, RESPONSE,
            ]))

            with self.assertRaisesRegex(RuntimeError, "missing vsId.*8"):
                offline.collect_responses()


class TestResultCommand(unittest.TestCase):
    def test_get_results_uses_session_as_required_argument(self):
        with temporary_layout() as root:
            offline.LIBACVP_DIR.mkdir()
            offline.SESSION_FILE.write_text("[]")
            completed = subprocess.CompletedProcess(
                [], 0, stdout="[ACVP]: Passed all vectors in test session!\n",
            )
            with (mock.patch.object(offline, "build_libacvp"),
                  mock.patch.object(offline, "validate_credentials"),
                  mock.patch.object(offline, "acvp_env", return_value={}),
                  mock.patch.object(offline.subprocess, "run", return_value=completed) as run):
                status = offline.cmd_get_results(argparse.Namespace(session=None))

            self.assertEqual(status, 0)
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["--get_results", str(offline.SESSION_FILE)])
            self.assertNotIn("--session", command)
            self.assertTrue(json.loads(offline.RESULTS_FILE.read_text())["passed"])


class TestSubmitCommand(unittest.TestCase):
    def test_upload_uses_saved_session_envelope_without_registration(self):
        with temporary_layout():
            offline.LIBACVP_DIR.mkdir()
            offline.SESSION_FILE.write_text("[]")
            combined = offline.HERE / "combined_responses.json"
            offline._secure_write(combined, [CONTEXT, RESPONSE])
            completed = subprocess.CompletedProcess([], 0)
            with (mock.patch.object(offline, "build_libacvp"),
                  mock.patch.object(offline, "validate_credentials"),
                  mock.patch.object(offline, "acvp_env", return_value={}),
                  mock.patch.object(offline, "collect_responses", return_value=combined),
                  mock.patch.object(offline.subprocess, "run", return_value=completed) as run):
                status = offline.cmd_submit(argparse.Namespace(session=None))

            self.assertEqual(status, 0)
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["--disable_fips", "--vector_upload"])
            self.assertEqual(command[3], str(combined))
            self.assertNotIn("--manual_registration", command)


if __name__ == "__main__":
    unittest.main(verbosity=2)
