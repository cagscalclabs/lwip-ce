#!/usr/bin/env python3
"""Build a v3 lwIPCERT containing the runner-local CA.

The store is test-only, but its envelope is signed by the production
TRUSTSTORE_SIGNER supplied by GitHub Actions.  The production library can
therefore validate the normal format and signature path without embedding a
test verification key or adding the test CA to the distributed truststore.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import re
import shutil
import struct
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

VERSION = 3
INDEX_KEY_LEN = 32
ENTRY_PREFIX_LEN = 77
RSA_PKCS1_SHA256 = 1


def run(args: list[str], input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(args, input=input_bytes, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed: {' '.join(args)}\n"
            f"{result.stderr.decode('utf-8', 'replace')}"
        )
    return result.stdout


def der_tlv(blob: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(blob):
        raise ValueError("truncated DER")
    tag = blob[offset]
    first = blob[offset + 1]
    pos = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if not count or count > 4 or pos + count > len(blob):
            raise ValueError("invalid DER length")
        length = int.from_bytes(blob[pos : pos + count], "big")
        pos += count
    else:
        length = first
    end = pos + length
    if end > len(blob):
        raise ValueError("truncated DER value")
    return tag, pos, end


def subject_digest(cert: Path) -> bytes:
    der = run(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    tag, cert_body, cert_end = der_tlv(der, 0)
    if tag != 0x30 or cert_end != len(der):
        raise ValueError("invalid Certificate DER")
    tag, tbs_body, _ = der_tlv(der, cert_body)
    if tag != 0x30:
        raise ValueError("missing TBSCertificate")
    pos = tbs_body
    tag, _, end = der_tlv(der, pos)
    if tag == 0xA0:
        pos = end
    for _ in range(4):  # serial, signature, issuer, validity
        _, _, pos = der_tlv(der, pos)
    start = pos
    tag, _, end = der_tlv(der, start)
    if tag != 0x30:
        raise ValueError("missing Subject Name")
    return hashlib.sha256(der[start:end]).digest()


def certificate_metadata(cert: Path) -> tuple[bytes, int, int, bytes]:
    text = run([
        "openssl", "x509", "-in", str(cert), "-noout", "-dates", "-text",
    ]).decode("utf-8", "replace")
    dates: dict[str, int] = {}
    for label in ("notBefore", "notAfter"):
        match = re.search(rf"^{label}=(.+)$", text, re.MULTILINE)
        if not match:
            raise ValueError(f"certificate lacks {label}")
        value = " ".join(match.group(1).split())
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        dates[label] = calendar.timegm(dt.timetuple())

    ski_match = re.search(
        r"X509v3 Subject Key Identifier:\s*\n\s*"
        r"((?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2})",
        text,
    )
    if not ski_match:
        raise ValueError("certificate lacks SubjectKeyIdentifier")
    ski_raw = bytes.fromhex(ski_match.group(1).replace(":", ""))
    if not ski_raw or len(ski_raw) > INDEX_KEY_LEN:
        raise ValueError("invalid SubjectKeyIdentifier")
    ski = ski_raw.ljust(INDEX_KEY_LEN, b"\0")

    modulus_text = run([
        "openssl", "x509", "-in", str(cert), "-noout", "-modulus",
    ]).decode("ascii").strip()
    if not modulus_text.startswith("Modulus="):
        raise ValueError("test CA must use RSA")
    modulus_hex = modulus_text.removeprefix("Modulus=")
    if len(modulus_hex) == 514 and modulus_hex.startswith("00"):
        modulus_hex = modulus_hex[2:]
    modulus = bytes.fromhex(modulus_hex)
    if len(modulus) != 256:
        raise ValueError("test CA must use a 2048-bit RSA key")
    key = struct.pack("<I", 65537)[:3] + modulus
    return ski, dates["notBefore"], dates["notAfter"], key


def build_store(cert: Path, signer: Path, output: Path, convbin: Path) -> None:
    subject = subject_digest(cert)
    ski, not_before, not_after, key = certificate_metadata(cert)
    entry_len = ENTRY_PREFIX_LEN + len(key)
    entry = b"".join([
        struct.pack("<I", entry_len),
        subject,
        ski,
        struct.pack("<II", not_before, not_after),
        bytes([RSA_PKCS1_SHA256]),
        key,
    ])
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        ski_index = ski + struct.pack("<H", 0)
        subject_index = subject + struct.pack("<H", 0)
        payload = b"".join([
            struct.pack("<HIH", VERSION, int(time.time()), 1),
            ski_index,
            subject_index,
            entry,
        ])
        if 256 + len(payload) > 0xFFFF:
            raise ValueError("test truststore exceeds AppVar size")

        data = tmp / "lwIPCERT.data"
        signature = tmp / "lwIPCERT.sig"
        blob = tmp / "lwIPCERT.bin"
        data.write_bytes(payload)
        run([
            "openssl", "dgst", "-sha256",
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:-1",
            "-sigopt", "rsa_mgf1_md:sha256",
            "-sign", str(signer), "-out", str(signature), str(data),
        ])
        sig = signature.read_bytes()
        if len(sig) != 256:
            raise ValueError("TRUSTSTORE_SIGNER must be a 2048-bit RSA key")
        blob.write_bytes(sig + payload)
        output.parent.mkdir(parents=True, exist_ok=True)
        run([
            str(convbin), "-i", str(blob), "-o", str(output),
            "-j", "bin", "-k", "8xv", "-n", "lwIPCERT", "-r",
        ])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--signer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    found_convbin = shutil.which("convbin")
    parser.add_argument("--convbin", type=Path,
                        default=Path(found_convbin) if found_convbin else None,
                        help="convbin executable (defaults to the copy on PATH)")
    args = parser.parse_args()
    if args.convbin is None:
        parser.error("convbin was not found on PATH; pass --convbin /absolute/path/to/convbin")
    if not args.convbin.is_file():
        parser.error(f"convbin executable does not exist: {args.convbin}")
    build_store(args.certificate, args.signer, args.output, args.convbin)
    print(f"generated signed v{VERSION} test truststore: {args.output}")


if __name__ == "__main__":
    main()
