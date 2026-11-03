#!/usr/bin/env python3 -I
"""Local stub tests for run.py — no NIST, no CEmu, no calculator required.

Architecture
------------
In the real system:
  - run_cemu() starts a TCP LISTENER (the host) on DEFAULT_PORT.
  - The autotester launches ACVPRUN (the calc), which CONNECTS to that listener.
  - ACVPRUN acts as a TCP client: it sends ACR1 responses to ACV1 requests.

Stub approach:
  - We patch run_mod.DEFAULT_PORT to a free port per test.
  - We patch run_mod.subprocess.run so the "autotester" subprocess is replaced
    by a Python script (stub_calc.py) that connects to the host listener and
    acts as a reference calculator: it reads ACV1 frames, dispatches through
    reference_backend(), and sends ACR1 responses.
  - This exercises the full threading path in run_cemu() without any real
    hardware, CEmu, or NIST traffic.
  - Control() tries to bind UDP 7000 — we patch it to a no-op to avoid
    port conflicts across parallel test runs.

Run:
  cd tests/acvp-live
  python3 test_run_local.py
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "validation" / "acvp"))
from acvp_client import (  # noqa: E402
    HEADER,
    MAGIC_REQUEST,
    MAGIC_RESPONSE,
    OP_STOP,
    AcvpError,
    reference_backend,
)

# Import run.py as a module (it is not a package, so patch sys.path first)
sys.path.insert(0, str(HERE))
import run as run_mod  # noqa: E402


# ── Helpers ────────────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AcvpError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


# ── Stub calculator (replaces ACVPRUN / autotester) ───────────────────────────

def _write_stub_calc(path: Path, port: int) -> None:
    """Write a stub calculator that connects to the host ACVP listener on `port`."""
    acvp_client_dir = str(HERE.parent / "validation" / "acvp")
    # Build the script without .format() to avoid escaping every f-string brace.
    lines = [
        "import socket, sys, time",
        f"sys.path.insert(0, {acvp_client_dir!r})",
        "from acvp_client import HEADER, MAGIC_REQUEST, MAGIC_RESPONSE, OP_STOP, reference_backend",
        f"PORT = {port}",
        "def recv_exact(s, n):",
        "    buf = bytearray()",
        "    while len(buf) < n:",
        "        chunk = s.recv(n - len(buf))",
        "        if not chunk: raise RuntimeError('connection closed')",
        "        buf.extend(chunk)",
        "    return bytes(buf)",
        "for attempt in range(30):",
        "    try:",
        "        sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)",
        "        break",
        "    except OSError:",
        "        time.sleep(0.05)",
        "else:",
        "    print(f'stub_calc: could not connect to 127.0.0.1:{PORT}', file=sys.stderr)",
        "    sys.exit(1)",
        "with sock:",
        "    sock.settimeout(30)",
        "    while True:",
        "        raw = recv_exact(sock, HEADER.size)",
        "        magic, op, rsv, req_id, length = HEADER.unpack(raw)",
        "        if magic != MAGIC_REQUEST:",
        "            print(f'stub_calc: bad magic {magic!r}', file=sys.stderr)",
        "            sys.exit(1)",
        "        payload = recv_exact(sock, length)",
        "        if op == OP_STOP:",
        "            sock.sendall(HEADER.pack(MAGIC_RESPONSE, 0, 0, req_id, 0))",
        "            break",
        "        try:",
        "            result = reference_backend(op, payload)",
        "            sock.sendall(HEADER.pack(MAGIC_RESPONSE, 0, 0, req_id, len(result)) + result)",
        "        except Exception as exc:",
        "            print(f'stub_calc: op {op} error: {exc}', file=sys.stderr)",
        "            sock.sendall(HEADER.pack(MAGIC_RESPONSE, 1, 0, req_id, 0))",
        "sys.exit(0)",
    ]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)


# ── Context managers ───────────────────────────────────────────────────────────

import contextlib


@contextlib.contextmanager
def _patch_port(port: int):
    old = run_mod.DEFAULT_PORT
    run_mod.DEFAULT_PORT = port
    try:
        yield
    finally:
        run_mod.DEFAULT_PORT = old


@contextlib.contextmanager
def _patch_control():
    """Replace Control() with a no-op so UDP port 7000 is not contested."""
    orig = run_mod.Control
    class NoOpControl:
        def close(self):
            pass
    run_mod.Control = NoOpControl  # type: ignore[assignment]
    try:
        yield
    finally:
        run_mod.Control = orig  # type: ignore[assignment]


@contextlib.contextmanager
def _patch_subprocess(stub_calc: Path):
    """Replace subprocess.run so the autotester is our stub calculator."""
    orig = run_mod.subprocess.run

    def patched(cmd, **kwargs):
        # Strip keys that CompletedProcess doesn't understand and run the stub
        safe_kwargs = {k: v for k, v in kwargs.items()
                       if k in ("cwd", "timeout", "env", "capture_output",
                                "stdout", "stderr", "stdin", "check")}
        result = orig([sys.executable, "-I", str(stub_calc)], **safe_kwargs)
        log = b"SUITE acvp\nPASS stub calculator\nDONE pass 1 fail 0\n"
        appvar = bytearray(0x4A)
        appvar[0x48:0x4A] = len(log).to_bytes(2, "little")
        (Path(kwargs["cwd"]) / "NETLOG.8xv").write_bytes(appvar + log)
        return result

    run_mod.subprocess.run = patched  # type: ignore[assignment]
    try:
        yield
    finally:
        run_mod.subprocess.run = orig  # type: ignore[assignment]


# ── Base test case ─────────────────────────────────────────────────────────────

class RunCemuTestBase(unittest.TestCase):
    """Base class: writes combined.json, patches run_cemu, verifies results."""

    def _run(self, vectors: list) -> tuple[int, Path]:
        port = _find_free_port()
        tmp = Path(tempfile.mkdtemp(prefix="acvp_stub_"))

        vectors_dir = tmp / "vectors"
        responses_dir = tmp / "responses"
        vectors_dir.mkdir()
        responses_dir.mkdir()

        # Write combined.json with an ACVP header
        combined = [{"acvVersion": "1.0"}, *vectors]
        (vectors_dir / "combined.json").write_text(json.dumps(combined, indent=2) + "\n")

        # Write stub calc that speaks ACV1/ACR1 on this port
        stub_calc = tmp / "stub_calc.py"
        _write_stub_calc(stub_calc, port)

        args = argparse.Namespace(
            vectors=vectors_dir,
            responses=responses_dir,
            timeout=30,
            cemu=True,
            autotester="/nonexistent/autotester",  # patched away
            usb="usb|plug",
            binary=Path("/nonexistent/ACVPRUN.8xp"),
            work_dir=tmp / "cemu_work",
        )

        with _patch_port(port), _patch_control(), _patch_subprocess(stub_calc):
            rc = run_mod.run_cemu(args)

        return rc, responses_dir / "combined.json"


# ── Individual tests ───────────────────────────────────────────────────────────

HEADER_VS = {"acvVersion": "1.0"}

SHA256_VS = {
    "vsId": 1001,
    "algorithm": "SHA2-256",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "tests": [
                {"tcId": 1, "len": 0, "msg": "00"},
                {"tcId": 2, "len": 8, "msg": "61"},
                {"tcId": 3, "len": 24, "msg": "616263"},
            ],
        },
    ],
}

SHA256_MCT_VS = {
    "vsId": 1002,
    "algorithm": "SHA2-256",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "standard",
            "tests": [
                {
                    "tcId": 10,
                    "len": 256,
                    "msg": "6d2d5a4b3f81c9e70a2b4d6f8c1e3a5b7d9f0e2c4a6b8d0f2e4c6a8b0d2e4f60",
                },
            ],
        },
    ],
}

HMAC256_VS = {
    "vsId": 1003,
    "algorithm": "HMAC-SHA2-256",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "keyLen": 256,
            "macLen": 256,
            "tests": [
                {
                    "tcId": 1,
                    "len": 128,
                    "msg": "00112233445566778899aabbccddeeff",
                    "key": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                },
            ],
        },
    ],
}

AES_CBC_VS = {
    "vsId": 1004,
    "algorithm": "ACVP-AES-CBC",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "payloadLen": 128,
            "tests": [
                {
                    "tcId": 1,
                    "key": "2b7e151628aed2a6abf7158809cf4f3c",
                    "iv": "000102030405060708090a0b0c0d0e0f",
                    "pt": "6bc1bee22e409f96e93d7e117393172a",
                },
            ],
        },
        {
            "tgId": 2,
            "testType": "AFT",
            "direction": "decrypt",
            "keyLen": 128,
            "payloadLen": 128,
            "tests": [
                {
                    "tcId": 2,
                    "key": "2b7e151628aed2a6abf7158809cf4f3c",
                    "iv": "000102030405060708090a0b0c0d0e0f",
                    "ct": "7649abac8119b246cee98e9b12e9197d",
                },
            ],
        },
    ],
}

PBKDF_VS = {
    "vsId": 1005,
    "algorithm": "PBKDF",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "hmacAlg": "SHA2-256",
            "tests": [
                {
                    "tcId": 1,
                    "iterationCount": 1,
                    "keyLen": 128,
                    "password": "password",
                    "salt": "73616c74",  # "salt" in hex, 4 bytes = 32 bits — too short for NIST but fine for local test
                },
            ],
        },
    ],
}

HKDF_VS = {
    "vsId": 1006,
    "algorithm": "KDA",
    "mode": "HKDF",
    "revision": "Sp800-56Cr1",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "kdfConfiguration": {
                "hmacAlg": "SHA2-256",
                "fixedInfoEncoding": "concatenation",
                "fixedInfoPattern": "uPartyInfo||vPartyInfo||l",
                "l": 256,
            },
            "tests": [
                {
                    "tcId": 1,
                    "kdfParameter": {
                        "z": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                        "salt": "000102030405060708090a0b0c0d0e0f",
                        "l": 256,
                    },
                    "fixedInfoPartyU": {
                        "partyId": "416c696365",
                        "ephemeralData": "",
                    },
                    "fixedInfoPartyV": {
                        "partyId": "426f62",
                        "ephemeralData": "",
                    },
                },
            ],
        },
    ],
}

AES_GCM_VS = {
    "vsId": 1007,
    "algorithm": "ACVP-AES-GCM",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "ivLen": 96,
            "tagLen": 128,
            "payloadLen": 128,
            "aadLen": 0,
            "ivGen": "external",
            "ivGenMode": "8.2.2",
            "tests": [
                {
                    "tcId": 1,
                    "key": "feffe9928665731c6d6a8f9467308308",
                    "iv": "cafebabefacedbaddecaf888",
                    "pt": "d9313225f88406e5a55909c5aff5269a",
                    "aad": "",
                    "ivLen": 96,
                    "keyLen": 128,
                    "tagLen": 128,
                    "payloadLen": 128,
                    "aadLen": 0,
                },
            ],
        },
    ],
}

AES_CCM_VS = {
    "vsId": 1008,
    "algorithm": "ACVP-AES-CCM",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "ivLen": 56,
            "tagLen": 32,
            "payloadLen": 0,
            "aadLen": 0,
            "tests": [
                {
                    "tcId": 1,
                    "key": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
                    "iv": "acde4800000001",  # 7 bytes = 56 bits
                    "pt": "",
                    "aad": "",
                    "ivLen": 56,
                    "keyLen": 128,
                    "tagLen": 32,
                    "payloadLen": 0,
                    "aadLen": 0,
                },
            ],
        },
    ],
}


class TestRunCemuSingleAlgorithm(RunCemuTestBase):
    """Each test exercises one algorithm vector set through the full run_cemu path."""

    def test_sha256_aft(self):
        rc, rsp = self._run([SHA256_VS])
        self.assertEqual(rc, 0, "run_cemu should return 0")
        self.assertTrue(rsp.exists(), "responses/combined.json must exist")
        data = json.loads(rsp.read_text())
        # data is [header, response_vs]
        vs_rsp = data[1] if isinstance(data, list) else data
        self.assertEqual(vs_rsp["vsId"], 1001)
        tgs = vs_rsp["testGroups"]
        self.assertEqual(len(tgs), 1)
        tests = tgs[0]["tests"]
        self.assertEqual(len(tests), 3)
        # Verify SHA-256 of empty string
        self.assertEqual(tests[0]["md"],
                         "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        # SHA-256("a")
        self.assertEqual(tests[1]["md"],
                         "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB")
        # SHA-256("abc")
        self.assertEqual(tests[2]["md"],
                         "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")

    def test_sha256_mct(self):
        rc, rsp = self._run([SHA256_MCT_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        tg = vs_rsp["testGroups"][0]
        test = tg["tests"][0]
        self.assertIn("resultsArray", test)
        self.assertEqual(len(test["resultsArray"]), 100)
        for item in test["resultsArray"]:
            self.assertIn("md", item)
            self.assertEqual(len(bytes.fromhex(item["md"])), 32)

    def test_hmac_sha256(self):
        rc, rsp = self._run([HMAC256_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        test = vs_rsp["testGroups"][0]["tests"][0]
        self.assertIn("mac", test)
        self.assertEqual(len(bytes.fromhex(test["mac"])), 32)

    def test_aes_cbc(self):
        rc, rsp = self._run([AES_CBC_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        tgs = vs_rsp["testGroups"]
        # NIST AES-128-CBC known-answer: encrypt
        enc_test = tgs[0]["tests"][0]
        self.assertIn("ct", enc_test)
        self.assertEqual(enc_test["ct"].upper(), "7649ABAC8119B246CEE98E9B12E9197D")
        # decrypt should round-trip
        dec_test = tgs[1]["tests"][0]
        self.assertIn("pt", dec_test)
        self.assertEqual(dec_test["pt"].upper(), "6BC1BEE22E409F96E93D7E117393172A")

    def test_aes_gcm(self):
        rc, rsp = self._run([AES_GCM_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        test = vs_rsp["testGroups"][0]["tests"][0]
        self.assertIn("ct", test)
        self.assertIn("tag", test)

    def test_aes_ccm(self):
        rc, rsp = self._run([AES_CCM_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        test = vs_rsp["testGroups"][0]["tests"][0]
        # CCM encrypt merges ct+tag into ct field
        self.assertIn("ct", test)

    def test_pbkdf(self):
        rc, rsp = self._run([PBKDF_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        test = vs_rsp["testGroups"][0]["tests"][0]
        self.assertIn("derivedKey", test)
        self.assertEqual(len(bytes.fromhex(test["derivedKey"])), 16)

    def test_hkdf(self):
        rc, rsp = self._run([HKDF_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        vs_rsp = data[1] if isinstance(data, list) else data
        test = vs_rsp["testGroups"][0]["tests"][0]
        self.assertIn("dkm", test)
        self.assertEqual(len(bytes.fromhex(test["dkm"])), 32)


class TestRunCemuCombinedMultipleAlgorithms(RunCemuTestBase):
    """Multiple vector sets in one combined.json — as NIST sends in practice."""

    def test_combined_sha_hmac_aes(self):
        rc, rsp = self._run([SHA256_VS, HMAC256_VS, AES_CBC_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        # [header, rsp1, rsp2, rsp3]
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 4)  # header + 3 responses
        self.assertEqual(data[1]["vsId"], 1001)
        self.assertEqual(data[2]["vsId"], 1003)
        self.assertEqual(data[3]["vsId"], 1004)

    def test_combined_all_stub_algorithms(self):
        all_vs = [
            SHA256_VS, SHA256_MCT_VS, HMAC256_VS,
            AES_CBC_VS, AES_GCM_VS, AES_CCM_VS,
            PBKDF_VS, HKDF_VS,
        ]
        rc, rsp = self._run(all_vs)
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())
        data = json.loads(rsp.read_text())
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), len(all_vs) + 1)  # +1 for header


class TestRunCemuThreadingAndBugRegression(RunCemuTestBase):
    """Regression tests for the threading/join timeout issue."""

    def test_thread_join_completes(self):
        """Verify run_cemu does not report 'ACVP host did not complete'."""
        import io
        from contextlib import redirect_stderr

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc, rsp = self._run([SHA256_VS])
        stderr_output = buf.getvalue()
        self.assertNotIn("ACVP host did not complete", stderr_output,
                         f"threading regression: {stderr_output}")
        self.assertEqual(rc, 0)

    def test_response_file_written_before_autotester_exits(self):
        """The response file must exist and be valid JSON when run_cemu returns 0."""
        rc, rsp = self._run([SHA256_VS, HMAC256_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists(), "response file must be written")
        # Must be valid JSON
        data = json.loads(rsp.read_text())
        self.assertIsInstance(data, list)

    def test_empty_aad_and_pt_strings(self):
        """GCM/CCM with empty plaintext/AAD (common in NIST sets) must not error."""
        rc, rsp = self._run([AES_GCM_VS, AES_CCM_VS])
        self.assertEqual(rc, 0)
        self.assertTrue(rsp.exists())

    def test_missing_combined_json_returns_1(self):
        """run_cemu should return 1 if vectors/combined.json does not exist."""
        tmp = Path(tempfile.mkdtemp(prefix="acvp_stub_"))
        vectors_dir = tmp / "vectors"
        responses_dir = tmp / "responses"
        vectors_dir.mkdir()
        # Do NOT create combined.json
        args = argparse.Namespace(
            vectors=vectors_dir,
            responses=responses_dir,
            timeout=30,
            cemu=True,
            autotester="/nonexistent/autotester",
            usb="usb|plug",
            binary=Path("/nonexistent/ACVPRUN.8xp"),
            work_dir=tmp / "cemu_work",
        )
        with _patch_control():
            rc = run_mod.run_cemu(args)
        self.assertEqual(rc, 1)

    def test_calculator_never_connects_reports_root_cause(self):
        """A launcher false-positive must not be masked by listener EINVAL."""
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        port = _find_free_port()
        tmp = Path(tempfile.mkdtemp(prefix="acvp_stub_"))
        vectors_dir = tmp / "vectors"
        vectors_dir.mkdir()
        (vectors_dir / "combined.json").write_text(json.dumps([
            {"acvVersion": "1.0"}, SHA256_VS,
        ]))
        args = argparse.Namespace(
            vectors=vectors_dir,
            responses=tmp / "responses",
            timeout=2,
            cemu=True,
            autotester="/nonexistent/autotester",
            usb="usb|plug",
            binary=Path("/nonexistent/ACVPRUN.8xp"),
            work_dir=tmp / "cemu_work",
        )
        stderr = io.StringIO()
        completed = subprocess.CompletedProcess([], 0)
        with (_patch_port(port), _patch_control(),
              mock.patch.object(run_mod.subprocess, "run", return_value=completed),
              redirect_stderr(stderr)):
            rc = run_mod.run_cemu(args)

        self.assertEqual(rc, 1)
        self.assertIn("calculator never connected", stderr.getvalue())
        self.assertNotIn("Invalid argument", stderr.getvalue())

    def test_server_error_propagates(self):
        """If the fake server rejects an op, run_cemu should return non-zero or raise."""
        # Send a vector set with an unsupported algorithm — process_file will
        # raise AcvpError before any socket ops, so run_cemu returns 1.
        bad_vs = {
            "vsId": 9999,
            "algorithm": "SHA3-256",  # not implemented
            "revision": "1.0",
            "testGroups": [],
        }
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc, rsp = self._run([bad_vs])
        # Should either return 1 or print an error
        self.assertNotEqual(rc, 0, "unsupported algorithm must not succeed")


class TestProcessFileDirectly(unittest.TestCase):
    """Unit-test process_file in isolation using reference_backend (no sockets)."""

    def _process(self, vectors: list) -> list:
        """Returns [header, rsp1, rsp2, ...] matching process_document output."""
        from acvp_client import process_document
        doc = [{"acvVersion": "1.0"}, *vectors]
        result = process_document(doc, reference_backend)
        # With a header, process_document returns [header, rsp1, ...]
        assert isinstance(result, list) and result[0].get("acvVersion"), \
            f"unexpected structure: {result!r:.200}"
        return result

    def test_sha256_known_answers(self):
        result = self._process([SHA256_VS])
        # result[0] = header, result[1] = response vs
        rsp = result[1]
        tests = rsp["testGroups"][0]["tests"]
        self.assertEqual(tests[0]["md"],
                         "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        self.assertEqual(tests[1]["md"],
                         "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB")
        # SHA-256("abc")
        self.assertEqual(tests[2]["md"],
                         "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")

    def test_aes_cbc_known_answer(self):
        result = self._process([AES_CBC_VS])
        rsp = result[1]
        enc = rsp["testGroups"][0]["tests"][0]
        self.assertEqual(enc["ct"].upper(), "7649ABAC8119B246CEE98E9B12E9197D")
        dec = rsp["testGroups"][1]["tests"][0]
        self.assertEqual(dec["pt"].upper(), "6BC1BEE22E409F96E93D7E117393172A")

    def test_pbkdf_known_answer(self):
        """PBKDF2-SHA256 output: stable across calls and correct length."""
        import hashlib
        # Verify independently against Python's reference implementation
        salt = bytes.fromhex("73616c74")  # b"salt"
        expected = hashlib.pbkdf2_hmac("sha256", b"password", salt, 1, 16).hex().upper()
        result = self._process([PBKDF_VS])
        rsp = result[1]
        dk = rsp["testGroups"][0]["tests"][0]["derivedKey"]
        self.assertEqual(dk.upper(), expected)

    def test_hkdf_known_answer(self):
        """Deterministic HKDF output: correct length and stable across calls."""
        result = self._process([HKDF_VS])
        rsp = result[1]
        dkm = rsp["testGroups"][0]["tests"][0]["dkm"]
        # 32 bytes = 256 bits (l=256 in the stub vector)
        self.assertEqual(len(bytes.fromhex(dkm)), 32)
        # Stable: calling again must produce the same output
        result2 = self._process([HKDF_VS])
        dkm2 = result2[1]["testGroups"][0]["tests"][0]["dkm"]
        self.assertEqual(dkm, dkm2)

    def test_multi_algorithm_order_preserved(self):
        """Responses must preserve input vsId order."""
        vs_list = [SHA256_VS, HMAC256_VS, AES_CBC_VS, PBKDF_VS]
        result = self._process(vs_list)
        self.assertIsInstance(result, list)
        # result[0] = header; result[1..n] = responses
        for i, vs in enumerate(vs_list):
            self.assertEqual(result[i + 1]["vsId"], vs["vsId"])


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
