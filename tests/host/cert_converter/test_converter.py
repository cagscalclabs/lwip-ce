#!/usr/bin/env python3
"""Regression tests for the user-facing certificate AppVar converter."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
CONVERTER = REPO_ROOT / "tools" / "lwip-cert-converter"
OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "OpenSSL is required")
class ConverterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_tmp = tempfile.TemporaryDirectory(prefix="lwip-cert-test-")
        cls.fixture = Path(cls.fixture_tmp.name)
        cls._make_identity()
        cls._make_fake_convbin()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_tmp.cleanup()

    @classmethod
    def _openssl(cls, *args: str) -> None:
        subprocess.run(
            [OPENSSL, *args],
            cwd=cls.fixture,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    @classmethod
    def _make_identity(cls) -> None:
        cls._openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
            "-subj",
            "/CN=lwIP converter test root",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        cls._openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=lwIP converter test leaf",
        )
        (cls.fixture / "leaf.ext").write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth,clientAuth\n",
            encoding="ascii",
        )
        cls._openssl(
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        )
        cls._openssl(
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "wrong.key",
        )
        cls._openssl(
            "ec",
            "-in",
            "leaf.key",
            "-aes256",
            "-passout",
            "pass:test-only",
            "-out",
            "legacy-encrypted.key",
        )
        cls._openssl(
            "pkcs8",
            "-topk8",
            "-in",
            "leaf.key",
            "-v2",
            "aes-256-cbc",
            "-v2prf",
            "hmacWithSHA256",
            "-passout",
            "pass:test-only",
            "-out",
            "supported-encrypted.key",
        )

    @classmethod
    def _make_fake_convbin(cls) -> None:
        fake = cls.fixture / "convbin"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, shutil, sys\n"
            "args = sys.argv[1:]\n"
            "source = pathlib.Path(args[args.index('-i') + 1])\n"
            "output = pathlib.Path(args[args.index('-o') + 1])\n"
            "shutil.copyfile(source, output)\n",
            encoding="ascii",
        )
        fake.chmod(0o755)

    def run_converter(
        self,
        *args: str,
        output_dir: Path,
        convbin: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["OPENSSL"] = OPENSSL
        env["CONVBIN"] = str(convbin or self.fixture / "convbin")
        return subprocess.run(
            [sys.executable, str(CONVERTER), *args],
            cwd=output_dir,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def common_args(self, fullchain: Path) -> list[str]:
        return [
            "--pkey",
            str(self.fixture / "leaf.key"),
            "--fullchain",
            str(fullchain),
            "--pkey_name",
            "TLSKEY",
            "--chain_name",
            "TLSCHAIN",
        ]

    def test_help_documents_required_interface(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CONVERTER), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in (
            "--pkey",
            "--fullchain",
            "--cert",
            "--pkey_name",
            "--chain_name",
            "--algorithm",
        ):
            self.assertIn(option, result.stdout)

    def test_unsupported_algorithm_is_rejected_by_lwip_gate(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            result = self.run_converter(
                *self.common_args(self.fixture / "root.pem"),
                "--algorithm",
                "chacha20-poly1305",
                output_dir=output,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("algorithm unsupported", result.stderr)

    def test_fullchain_and_duplicate_leaf_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            fullchain = output / "fullchain.pem"
            fullchain.write_bytes(
                (self.fixture / "leaf.pem").read_bytes()
                + (self.fixture / "root.pem").read_bytes()
            )
            result = self.run_converter(
                *self.common_args(fullchain),
                "--cert",
                str(self.fixture / "leaf.pem"),
                output_dir=output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["TLSKEY.8xv", "TLSCHAIN.8xv"])
            self.assertIn(b"PRIVATE KEY", (output / "TLSKEY.8xv").read_bytes())
            self.assertEqual(
                (output / "TLSCHAIN.8xv").read_bytes().count(b"BEGIN CERTIFICATE"),
                2,
            )

    def test_cert_supplies_leaf_for_leafless_chain(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            result = self.run_converter(
                *self.common_args(self.fixture / "root.pem"),
                "--cert",
                str(self.fixture / "leaf.pem"),
                output_dir=output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (output / "TLSCHAIN.8xv").read_bytes().count(b"BEGIN CERTIFICATE"),
                2,
            )

    def test_non_self_signed_leaf_alone_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            result = self.run_converter(
                *self.common_args(self.fixture / "leaf.pem"),
                output_dir=output,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("only a non-self-signed leaf", result.stderr)

    def test_private_key_must_match_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            fullchain = output / "fullchain.pem"
            fullchain.write_bytes(
                (self.fixture / "leaf.pem").read_bytes()
                + (self.fixture / "root.pem").read_bytes()
            )
            args = self.common_args(fullchain)
            args[1] = str(self.fixture / "wrong.key")
            result = self.run_converter(*args, output_dir=output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("does not match", result.stderr)

    def test_appvar_names_follow_device_limits(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            result = self.run_converter(
                *self.common_args(self.fixture / "root.pem")[:-4],
                "--pkey_name",
                "9BAD",
                "--chain_name",
                "TLSCHAIN",
                output_dir=output,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("start with a letter", result.stderr)

    def test_unsupported_key_encryption_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            args = self.common_args(self.fixture / "root.pem")
            args[1] = str(self.fixture / "legacy-encrypted.key")
            result = self.run_converter(*args, output_dir=output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsupported encryption algorithm", result.stderr)
            self.assertIn("confirmation requires an interactive terminal", result.stderr)

    def test_supported_key_encryption_is_identified(self) -> None:
        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            args = self.common_args(self.fixture / "root.pem")
            args[1] = str(self.fixture / "supported-encrypted.key")
            result = self.run_converter(*args, output_dir=output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("aes-256-cbc private-key password", result.stderr)
            self.assertNotIn("unsupported encryption algorithm", result.stderr)

    def test_real_convbin_creates_ti_appvars_when_available(self) -> None:
        candidates = [shutil.which("convbin")]
        if os.environ.get("CEDEV"):
            candidates.append(str(Path(os.environ["CEDEV"]) / "bin" / "convbin"))
        candidates.append(str(REPO_ROOT.parents[1] / "bin" / "convbin"))
        convbin = next(
            (Path(candidate) for candidate in candidates if candidate and Path(candidate).is_file()),
            None,
        )
        if convbin is None:
            self.skipTest("convbin is not installed")

        with tempfile.TemporaryDirectory() as raw_output:
            output = Path(raw_output)
            fullchain = output / "fullchain.pem"
            fullchain.write_bytes(
                (self.fixture / "leaf.pem").read_bytes()
                + (self.fixture / "root.pem").read_bytes()
            )
            result = self.run_converter(
                *self.common_args(fullchain),
                output_dir=output,
                convbin=convbin,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output / "TLSKEY.8xv").read_bytes().startswith(b"**TI83F*"))
            self.assertTrue((output / "TLSCHAIN.8xv").read_bytes().startswith(b"**TI83F*"))


if __name__ == "__main__":
    unittest.main()
