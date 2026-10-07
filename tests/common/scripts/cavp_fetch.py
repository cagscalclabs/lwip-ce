#!/usr/bin/env python3
"""Fetch NIST CAVP archives, sample N vectors per primitive, add generated
vectors where CAVP coverage is unavailable, and emit:

  - vectors/CAVP00..15.8xv Calc-side input AppVars (binary, packed).
  - vectors/expected.json  The host-side grading source (test_id -> expected).

This script is the single source of truth for the CAVP test inputs.
The CAVPxx.8xv files are ignored and expected.json is a tracked readable
snapshot; both are regenerated together on every CI run.

CAVP archives covered:
  AES-GCM encrypt/decrypt gcm{EncryptExtIV,Decrypt}{128,192,256}.rsp
  AES-CBC encrypt/decrypt CBC KAT + MMT response files (128/192/256)
  AES-CCM encrypt/decrypt VADT/VNT/VPT/VTT + DVPT (128/192/256)
  SHA-256 short/long/MCT  SHA256{ShortMsg,LongMsg,Monte}.rsp
  HMAC-SHA-256            HMAC.rsp [L=32] from hmactestvectors.zip

Not from CAVP (no compatible archive):
  RSA-2048-PSS-SHA-256    fresh-per-run keygen + sign (see notes below)
  HKDF-SHA-256            RFC 5869 §A.1-A.3 plus generated vectors
  PBKDF2-HMAC-SHA-256     generated ACVP-shaped vectors (small iterations)
  X25519                  RFC 7748 §6.1 + §5.2 plus generated vectors

RSA-PSS notes:
  Calc-side `tls_rsa_decrypt_signature` hardcodes e=65537 and ignores
  the exponent in the wire format. NIST's SigVerPSS_186-3.rsp ships
  every vector with a randomly-generated `e`, so none of its 90 vectors
  are compatible with a fixed-e=65537 verifier. Instead, we generate a
  fresh RSA-2048 keypair each run via python3-cryptography, sign random
  messages with PKCS#1 v2.1 PSS (SHA-256, salt=32), and inject negatives
  by tampering with the signature or message. The per-run keygen also
  exercises that the verifier accepts arbitrary valid keys, not just the
  truststore key. Additional API constraint: `powmod_exp_u24` takes a
  uint8_t for modulus size, with 0 encoding 256 bytes — so the generator
  enforces a canonical 256-byte modulus (MSB set, no leading zero).

Random sampling:
  Default 16 per primitive (override with CAVP_FETCH_SAMPLE=N).
  Seed defaults to int(time()) so each run is fresh; CAVP selection and
  non-RSA generated vectors are reproducible with CAVP_FETCH_SEED. RSA
  key generation intentionally still uses the OS CSPRNG.
  RSA-PSS samples are forced to contain >=1 positive and >=1 negative so
  a verifier that always accepts (or always rejects) is caught.

Exit codes:
  0  All good.
  1  Schema sanity-check failed.
  2  Network/download/parse error.
"""

from __future__ import annotations

import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import shutil
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
TESTS_DIR = SCRIPT_DIR.parents[1]
TEST_DIR = Path(os.environ.get("CAVP_TEST_DIR", TESTS_DIR / "profiling" / "tls_cavp")).resolve()
VECTORS_DIR = TEST_DIR / "vectors"
CACHE_DIR = VECTORS_DIR / "cache"
EXPECTED_PATH = VECTORS_DIR / "expected.json"
APPVAR_NAMES = tuple(f"CAVP{i:02d}" for i in range(16))
MAX_CHUNK_BODY = 4096

DEFAULT_SAMPLE_SIZE = 16

# Algorithm IDs — must match src/main.c #defines and parse_cavp_output_appvar.py
ALG_ID = {
    "AES-GCM":                  1,
    "SHA-256":                  2,
    "HMAC-SHA-256":             3,
    "HKDF-SHA-256":             4,
    "DRBG-SHA-256":             5,
    "RSA-PSS-SHA-256-VERIFY":   6,
    "X25519-PUBLICKEY":         7,
    "X25519-SECRET":            8,
    "AES-CBC":                  9,
    "AES-CCM":                 10,
    "PBKDF2-HMAC-SHA256":      11,
    "SHA-256-MCT":             12,
}

# Test ID ranges (sequentially assigned per algorithm)
TID_RANGES = {
    "AES-GCM":                1001,
    "SHA-256":                2001,
    "HMAC-SHA-256":           3001,
    "HKDF-SHA-256":           4001,
    "RSA-PSS-SHA-256-VERIFY": 6001,
    "X25519-PUBLICKEY":       7001,
    "X25519-SECRET":          8001,
    "AES-CBC":               9001,
    "AES-CCM":              10001,
    "PBKDF2-HMAC-SHA256":   11001,
    "SHA-256-MCT":          12001,
}


# ============================================================
# RFC-pinned vectors (HKDF, X25519) — CAVP doesn't publish these
# ============================================================

RFC_VECTORS: list[dict[str, Any]] = [
    {
        "$source": "RFC 5869 §A.1 (test case 1, SHA-256)",
        "algorithm": "HKDF-SHA-256",
        "ikm_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "salt_hex": "000102030405060708090a0b0c",
        "info_hex": "f0f1f2f3f4f5f6f7f8f9",
        "l": 42,
        "expected_okm_hex": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    {
        "$source": "RFC 5869 §A.2 (test case 2, SHA-256, longer)",
        "algorithm": "HKDF-SHA-256",
        "ikm_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        "salt_hex": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "info_hex": "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "l": 82,
        "expected_okm_hex": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    {
        "$source": "RFC 5869 §A.3 (test case 3, SHA-256, empty salt/info)",
        "algorithm": "HKDF-SHA-256",
        "ikm_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "salt_hex": "",
        "info_hex": "",
        "l": 42,
        "expected_okm_hex": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
    {
        "$source": "RFC 7748 §6.1 Alice's keypair",
        "algorithm": "X25519-PUBLICKEY",
        "priv_hex": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "expected_pub_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    },
    {
        "$source": "RFC 7748 §6.1 Bob's keypair",
        "algorithm": "X25519-PUBLICKEY",
        "priv_hex": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "expected_pub_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    },
    {
        "$source": "RFC 7748 §6.1 Alice computes shared with Bob's pub",
        "algorithm": "X25519-SECRET",
        "priv_hex": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "peer_pub_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "expected_shared_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    },
    {
        "$source": "RFC 7748 §6.1 Bob computes shared with Alice's pub (symmetry check)",
        "algorithm": "X25519-SECRET",
        "priv_hex": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "peer_pub_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "expected_shared_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    },
    {
        "$source": "RFC 7748 §5.2 first iteration (k = u = base point scalar mult once)",
        "algorithm": "X25519-SECRET",
        "priv_hex": "0900000000000000000000000000000000000000000000000000000000000000",
        "peer_pub_hex": "0900000000000000000000000000000000000000000000000000000000000000",
        "expected_shared_hex": "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
    },
]


# ============================================================
# CAVP fetcher
# ============================================================

CAVP_SOURCES = {
    "gcm": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip",
        "name": "gcmtestvectors.zip",
    },
    "sha": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip",
        "name": "shabytetestvectors.zip",
    },
    "hmac": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip",
        "name": "hmactestvectors.zip",
    },
    "aes_kat": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip",
        "name": "KAT_AES.zip",
    },
    "aes_mmt": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip",
        "name": "aesmmt.zip",
    },
    "ccm": {
        "url":  "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip",
        "name": "ccmtestvectors.zip",
    },
}


def download_if_missing(key: str) -> Path:
    src = CAVP_SOURCES[key]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    local = CACHE_DIR / src["name"]
    if local.exists() and local.stat().st_size > 0:
        return local
    print(f"  downloading {src['name']} ...", file=sys.stderr)
    try:
        req = urllib.request.Request(src["url"], headers={
            "User-Agent": "lwip-ce-cavp-fetch/1.0 (+https://github.com/cagscalclabs/lwip-ce)",
        })
        with urllib.request.urlopen(req, timeout=60) as resp:
            local.write_bytes(resp.read())
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SystemExit(f"download failed for {src['url']}: {e}")
    if local.stat().st_size < 1000:
        raise SystemExit(f"download too small for {local} ({local.stat().st_size} bytes)")
    return local


def parse_rsp(text: str, anchor: str = "Count") -> list[dict[str, str]]:
    """Parse a NIST CAVP .rsp file into a flat list of test dicts.

    Section parameters in [Key = Value] brackets are merged into every test
    that follows, until the next section. A test begins at a line of the
    form '<anchor> = ...' and ends at the next anchor occurrence or section
    header. The anchor field varies by file:

      Count   — HMAC.rsp, gcmEncrypt*.rsp (most CAVP files)
      Len     — SHA*ShortMsg.rsp, SHA*LongMsg.rsp (one bit-length per test)
      SHAAlg  — SigVerPSS_186-3.rsp (test boundary is the hash algorithm)

    Lines that appear before the first anchor in a section (e.g. RSA's
    'n', 'p', 'q', 'd' lines) are treated as section-scoped — every test
    in that section inherits them.
    """
    tests: list[dict[str, str]] = []
    current_section: dict[str, str] = {}
    current_test: dict[str, str] | None = None

    def flush():
        nonlocal current_test
        if current_test is not None:
            tests.append({**current_section, **current_test})
            current_test = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            inner = line[1:-1].strip()
            if "=" in inner:
                for field in inner.split(","):
                    if "=" not in field:
                        continue
                    k, v = field.split("=", 1)
                    current_section[k.strip()] = v.strip()
            else:
                current_section["Section"] = inner.upper()
            continue
        if line.upper() == "FAIL":
            if current_test is not None:
                current_test["FAIL"] = "true"
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if k == anchor:
            flush()
            current_test = {k: v}
        else:
            if current_test is None:
                current_section[k] = v
            else:
                current_test[k] = v
    flush()
    return tests


# ---------- Per-algorithm extractors ----------

def fetch_aes_gcm() -> list[dict[str, Any]]:
    zip_path = download_if_missing("gcm")
    out = []
    with zipfile.ZipFile(zip_path) as zf:
        for key_bits in (128, 192, 256):
            for operation, filename in (
                ("encrypt", f"gcmEncryptExtIV{key_bits}.rsp"),
                ("decrypt", f"gcmDecrypt{key_bits}.rsp"),
            ):
                text = zf.read(filename).decode("latin-1")
                for t in parse_rsp(text, anchor="Count"):
                    if (t.get("Keylen") != str(key_bits) or
                            t.get("IVlen") != "96" or t.get("Taglen") != "128"):
                        continue
                    if not all(k in t for k in ("Key", "IV", "AAD", "CT", "Tag")):
                        continue
                    accepted = t.get("FAIL") != "true"
                    if operation == "encrypt" and "PT" not in t:
                        continue
                    if operation == "decrypt" and accepted and "PT" not in t:
                        continue
                    data_in = t["PT"] if operation == "encrypt" else t["CT"]
                    expected_data = t["CT"] if operation == "encrypt" else t.get("PT", "")
                    out.append({
                        "algorithm": "AES-GCM",
                        "operation": operation,
                        "source_file": filename,
                        "source_count": (
                            f"Keylen={key_bits},PTlen={t.get('PTlen', '?')},"
                            f"AADlen={t.get('AADlen', '?')},Count={t['Count']}"
                        ),
                        "key_hex": t["Key"].lower(),
                        "iv_hex": t["IV"].lower(),
                        "aad_hex": t["AAD"].lower(),
                        "data_hex": data_in.lower(),
                        "tag_hex": t["Tag"].lower() if operation == "decrypt" else "",
                        "tag_len": 16,
                        "expected_accept": accepted,
                        "expected_data_hex": expected_data.lower() if accepted else "",
                        "expected_tag_hex": t["Tag"].lower() if operation == "encrypt" else "",
                        "key_bits": key_bits,
                    })
    return out


def fetch_sha256() -> list[dict[str, Any]]:
    zip_path = download_if_missing("sha")
    out = []
    with zipfile.ZipFile(zip_path) as zf:
        for variant, filename in (
            ("short", "SHA256ShortMsg.rsp"),
            ("long", "SHA256LongMsg.rsp"),
        ):
            text = zf.read(f"shabytetestvectors/{filename}").decode("latin-1")
            for t in parse_rsp(text, anchor="Len"):
                if "Msg" not in t or "MD" not in t or "Len" not in t:
                    continue
                bit_len = int(t["Len"])
                if bit_len % 8 or (variant == "long" and bit_len > 16384):
                    continue
                msg = t["Msg"].lower() if bit_len > 0 else ""
                out.append({
                    "algorithm": "SHA-256",
                    "variant": variant,
                    "source_file": filename,
                    "source_count": f"Len={bit_len}",
                    "msg_hex": msg,
                    "expected_hex": t["MD"].lower(),
                })
    return out


def fetch_sha256_mct() -> list[dict[str, Any]]:
    zip_path = download_if_missing("sha")
    with zipfile.ZipFile(zip_path) as zf:
        text = zf.read("shabytetestvectors/SHA256Monte.rsp").decode("latin-1")
    seed_match = re.search(r"^Seed\s*=\s*([0-9a-fA-F]+)\s*$", text, re.MULTILINE)
    if not seed_match:
        raise ValueError("SHA256Monte.rsp has no Seed")
    seed = seed_match.group(1).lower()
    out = []
    for t in parse_rsp(text, anchor="COUNT"):
        if "MD" not in t:
            continue
        out.append({
            "algorithm": "SHA-256-MCT",
            "source_file": "SHA256Monte.rsp",
            "source_count": f"COUNT={t['COUNT']}",
            "seed_hex": seed,
            "expected_hex": t["MD"].lower(),
        })
        seed = t["MD"].lower()
    return out


def fetch_aes_cbc() -> list[dict[str, Any]]:
    out = []
    for source_key in ("aes_kat", "aes_mmt"):
        zip_path = download_if_missing(source_key)
        with zipfile.ZipFile(zip_path) as zf:
            for filename in zf.namelist():
                if not re.fullmatch(r"CBC(?:GFSbox|KeySbox|VarKey|VarTxt|MMT)(128|192|256)\.rsp", filename):
                    continue
                text = zf.read(filename).decode("latin-1")
                for t in parse_rsp(text, anchor="COUNT"):
                    operation = t.get("Section", "").lower()
                    if operation not in ("encrypt", "decrypt"):
                        continue
                    if not all(k in t for k in ("KEY", "IV", "PLAINTEXT", "CIPHERTEXT")):
                        continue
                    key_bits = len(t["KEY"]) * 4
                    out.append({
                        "algorithm": "AES-CBC",
                        "operation": operation,
                        "source_file": filename,
                        "source_count": f"{operation},COUNT={t['COUNT']}",
                        "key_hex": t["KEY"].lower(),
                        "iv_hex": t["IV"].lower(),
                        "data_hex": (t["PLAINTEXT"] if operation == "encrypt" else t["CIPHERTEXT"]).lower(),
                        "expected_hex": (t["CIPHERTEXT"] if operation == "encrypt" else t["PLAINTEXT"]).lower(),
                        "key_bits": key_bits,
                        "vector_class": "MMT" if "MMT" in filename else "KAT",
                    })
    return out


def _ccm_bytes(value: str, declared_len: int) -> str:
    return value.lower() if declared_len else ""


def fetch_aes_ccm() -> list[dict[str, Any]]:
    zip_path = download_if_missing("ccm")
    out = []
    with zipfile.ZipFile(zip_path) as zf:
        for filename in zf.namelist():
            match = re.fullmatch(r"(VADT|VNT|VPT|VTT)(128|192|256)\.rsp", filename)
            if not match:
                continue
            text = zf.read(filename).decode("latin-1")
            for t in parse_rsp(text, anchor="Count"):
                if not all(k in t for k in ("Key", "Nonce", "Adata", "Payload", "CT")):
                    continue
                plen, alen, tlen = int(t["Plen"]), int(t["Alen"]), int(t["Tlen"])
                combined = t["CT"].lower()
                if len(combined) != 2 * (plen + tlen):
                    continue
                out.append({
                    "algorithm": "AES-CCM",
                    "operation": "encrypt",
                    "source_file": filename,
                    "source_count": f"Alen={alen},Plen={plen},Nlen={t['Nlen']},Tlen={tlen},Count={t['Count']}",
                    "key_hex": t["Key"].lower(),
                    "nonce_hex": t["Nonce"].lower(),
                    "aad_hex": _ccm_bytes(t["Adata"], alen),
                    "data_hex": _ccm_bytes(t["Payload"], plen),
                    "tag_hex": "",
                    "tag_len": tlen,
                    "expected_accept": True,
                    "expected_data_hex": combined[:2 * plen],
                    "expected_tag_hex": combined[2 * plen:],
                    "key_bits": int(match.group(2)),
                    "nonce_len": len(t["Nonce"]) // 2,
                    "aad_empty": alen == 0,
                    "data_empty": plen == 0,
                })

        for key_bits in (128, 192, 256):
            filename = f"DVPT{key_bits}.rsp"
            text = zf.read(filename).decode("latin-1")
            for t in parse_rsp(text, anchor="Count"):
                if not all(k in t for k in ("Key", "Nonce", "Adata", "CT", "Result")):
                    continue
                plen, alen, tlen = int(t["Plen"]), int(t["Alen"]), int(t["Tlen"])
                combined = t["CT"].lower()
                if len(combined) != 2 * (plen + tlen):
                    continue
                accepted = t["Result"].lower() == "pass"
                out.append({
                    "algorithm": "AES-CCM",
                    "operation": "decrypt",
                    "source_file": filename,
                    "source_count": f"Alen={alen},Plen={plen},Nlen={t['Nlen']},Tlen={tlen},Count={t['Count']}",
                    "key_hex": t["Key"].lower(),
                    "nonce_hex": t["Nonce"].lower(),
                    "aad_hex": _ccm_bytes(t["Adata"], alen),
                    "data_hex": combined[:2 * plen],
                    "tag_hex": combined[2 * plen:],
                    "tag_len": tlen,
                    "expected_accept": accepted,
                    "expected_data_hex": _ccm_bytes(t.get("Payload", ""), plen) if accepted else "",
                    "expected_tag_hex": "",
                    "key_bits": key_bits,
                    "nonce_len": len(t["Nonce"]) // 2,
                    "aad_empty": alen == 0,
                    "data_empty": plen == 0,
                })
    return out


def fetch_hmac_sha256() -> list[dict[str, Any]]:
    zip_path = download_if_missing("hmac")
    with zipfile.ZipFile(zip_path) as zf:
        with zf.open("HMAC.rsp") as f:
            text = f.read().decode("latin-1")
    out = []
    for t in parse_rsp(text, anchor="Count"):
        if t.get("L") != "32" or t.get("Tlen") != "32":
            continue
        if not all(k in t for k in ("Key", "Msg", "Mac")):
            continue
        out.append({
            "algorithm": "HMAC-SHA-256",
            "source_file": "HMAC.rsp",
            "source_count": f"L={t['L']},Count={t['Count']}",
            "key_hex": t["Key"].lower(),
            "msg_hex": t["Msg"].lower(),
            "expected_hex": t["Mac"].lower(),
        })
    return out


def gen_rsa_pss_sha256(rng: random.Random, n_vectors: int) -> list[dict[str, Any]]:
    """Generate a fresh RSA-2048 keypair and sign N random messages with
    PKCS#1 v2.1 PSS (SHA-256, salt=32 bytes).

    Returns roughly equal numbers of positive (valid) and negative
    (tampered) vectors so a verifier that always-accepts or always-rejects
    is caught. Negatives are produced by flipping a single bit in either
    the signature or the message; the verifier has no way to detect that
    flip without running modexp + PSS decode, so both stages get tested.

    Uses python3-cryptography (apt: python3-cryptography). The library's
    PSS signer is the reference for what our calc-side verifier should
    accept; matching its output bit-for-bit is the success criterion.

    The per-run keygen also exercises that the verifier accepts arbitrary
    valid 2048-bit keys, not just the truststore key — i.e., it catches
    code that accidentally hardwires anything beyond e=65537.
    """
    # Lazy import — only the RSA path needs cryptography. The apt package
    # python3-cryptography is the runtime fix for the missing dep.
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
    except ImportError as e:
        raise SystemExit(
            "RSA-PSS vector generation needs python3-cryptography "
            f"(apt install python3-cryptography). Import failed: {e}")

    print("  generating fresh RSA-2048 keypair (e=65537) ...", file=sys.stderr)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.public_key().public_numbers().n
    # API constraint: powmod_exp_u24 takes uint8_t for size, where 0
    # encodes 256. A freshly generated 2048-bit key always has MSB set
    # in its modulus, but assert to fail loud if the library ever lies.
    n_bytes = n.to_bytes(256, "big")
    if (n_bytes[0] & 0x80) == 0:
        raise SystemExit("generated 2048-bit modulus has MSB clear "
                         "(should be impossible)")

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    n_negatives = max(1, n_vectors // 2) if n_vectors >= 2 else 0
    n_positives = n_vectors - n_negatives

    out: list[dict[str, Any]] = []
    for i in range(n_positives):
        msg = rng.randbytes(rng.randint(16, 128))
        sig = key.sign(msg, pss, hashes.SHA256())
        out.append({
            "algorithm": "RSA-PSS-SHA-256-VERIFY",
            "source_file": "generated/cavp_fetch.py",
            "source_count": f"positive[{i}],msg_len={len(msg)}",
            "modulus_hex": n_bytes.hex(),
            "exponent_hex": "010001",
            "salt_len": 32,
            "msg_hex": msg.hex(),
            "sig_hex": sig.hex(),
            "expected_verify": True,
        })

    for i in range(n_negatives):
        msg = rng.randbytes(rng.randint(16, 128))
        sig = bytearray(key.sign(msg, pss, hashes.SHA256()))
        # Tamper either the signature or the message. Sig tampering
        # exercises modexp (different EM); msg tampering exercises PSS
        # decode (modexp ok, but H' != H).
        if rng.random() < 0.5:
            sig[rng.randrange(len(sig))] ^= 1 << rng.randrange(8)
            mode = "sig_flip"
        else:
            msg = bytearray(msg)
            msg[rng.randrange(len(msg))] ^= 1 << rng.randrange(8)
            msg = bytes(msg)
            mode = "msg_flip"
        out.append({
            "algorithm": "RSA-PSS-SHA-256-VERIFY",
            "source_file": "generated/cavp_fetch.py",
            "source_count": f"negative[{i}],{mode},msg_len={len(msg)}",
            "modulus_hex": n_bytes.hex(),
            "exponent_hex": "010001",
            "salt_len": 32,
            "msg_hex": msg.hex(),
            "sig_hex": bytes(sig).hex(),
            "expected_verify": False,
        })

    return out


def gen_hkdf_sha256(rng: random.Random, n_vectors: int) -> list[dict[str, Any]]:
    """Generate deterministic HKDF-SHA-256 vectors."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as e:
        raise SystemExit(
            "HKDF vector generation needs python3-cryptography "
            f"(apt install python3-cryptography). Import failed: {e}")

    out: list[dict[str, Any]] = []
    for i in range(n_vectors):
        ikm = rng.randbytes(rng.randint(1, 96))
        salt = rng.randbytes(rng.randint(0, 64))
        info = rng.randbytes(rng.randint(0, 64))
        length = rng.randint(1, 96)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt if salt else None,
            info=info,
        )
        okm = hkdf.derive(ikm)
        out.append({
            "algorithm": "HKDF-SHA-256",
            "source_file": "generated/cavp_fetch.py",
            "source_count": f"hkdf[{i}],ikm_len={len(ikm)},salt_len={len(salt)},info_len={len(info)},l={length}",
            "ikm_hex": ikm.hex(),
            "salt_hex": salt.hex(),
            "info_hex": info.hex(),
            "l": length,
            "expected_okm_hex": okm.hex(),
        })

    return out


def gen_pbkdf2_sha256(rng: random.Random, n_vectors: int) -> list[dict[str, Any]]:
    """Generate ACVP-shaped PBKDF2-HMAC-SHA-256 vectors.

    The iteration counts are intentionally small: this suite validates the
    primitive's block/XOR/iteration behavior on calculator hardware; it is
    not a password-hardening benchmark.  Larger counts are covered by the
    timing suite without making every CAVP run needlessly slow.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as e:
        raise SystemExit(
            "PBKDF2 vector generation needs python3-cryptography "
            f"(apt install python3-cryptography). Import failed: {e}")

    round_counts = (1, 2, 3, 4, 8, 16, 32)
    key_lengths = (16, 24, 32, 48, 64)
    out: list[dict[str, Any]] = []
    for i in range(n_vectors):
        password = rng.randbytes(rng.randint(1, 48))
        salt = rng.randbytes(rng.randint(8, 32))
        rounds = round_counts[i % len(round_counts)]
        key_len = key_lengths[i % len(key_lengths)]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=salt,
            iterations=rounds,
        )
        derived = kdf.derive(password)
        out.append({
            "algorithm": "PBKDF2-HMAC-SHA256",
            "source_file": "generated/cavp_fetch.py",
            "source_count": (
                f"pbkdf2[{i}],password_len={len(password)},salt_len={len(salt)},"
                f"rounds={rounds},key_len={key_len}"
            ),
            "password_hex": password.hex(),
            "salt_hex": salt.hex(),
            "rounds": rounds,
            "key_len": key_len,
            "expected_hex": derived.hex(),
        })
    return out


def gen_x25519(rng: random.Random, n_vectors: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate deterministic X25519 public-key and shared-secret vectors.

    RFC 7748 provides only a small fixed set. These generated vectors expand
    coverage while preserving reproducibility under CAVP_FETCH_SEED.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as e:
        raise SystemExit(
            "X25519 vector generation needs python3-cryptography "
            f"(apt install python3-cryptography). Import failed: {e}")

    pub_vectors: list[dict[str, Any]] = []
    secret_vectors: list[dict[str, Any]] = []

    for i in range(n_vectors):
        priv_bytes = rng.randbytes(32)
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pub_vectors.append({
            "algorithm": "X25519-PUBLICKEY",
            "source_file": "generated/cavp_fetch.py",
            "source_count": f"publickey[{i}]",
            "priv_hex": priv_bytes.hex(),
            "expected_pub_hex": pub_bytes.hex(),
        })

        peer_priv_bytes = rng.randbytes(32)
        peer_priv = x25519.X25519PrivateKey.from_private_bytes(peer_priv_bytes)
        peer_pub_bytes = peer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        shared_bytes = priv.exchange(peer_priv.public_key())
        secret_vectors.append({
            "algorithm": "X25519-SECRET",
            "source_file": "generated/cavp_fetch.py",
            "source_count": f"secret[{i}]",
            "priv_hex": priv_bytes.hex(),
            "peer_pub_hex": peer_pub_bytes.hex(),
            "expected_shared_hex": shared_bytes.hex(),
        })

    return pub_vectors, secret_vectors


# ============================================================
# Sampling
# ============================================================

def sample_with_seed(candidates: list[dict[str, Any]], n: int,
                     rng: random.Random, algorithm: str) -> list[dict[str, Any]]:
    if len(candidates) <= n:
        return list(candidates)
    return rng.sample(candidates, n)


def sample_stratified(candidates: list[dict[str, Any]], n: int,
                      rng: random.Random,
                      fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Sample while covering parameter classes before filling randomly."""
    if len(candidates) <= n:
        return list(candidates)
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for candidate in candidates:
        key = tuple(candidate.get(field) for field in fields)
        groups.setdefault(key, []).append(candidate)

    group_items = list(groups.items())
    rng.shuffle(group_items)
    if len(group_items) > n:
        group_items = group_items[:n]
    selected = [rng.choice(group) for _, group in group_items]
    selected_ids = {id(v) for v in selected}
    remainder = [v for v in candidates if id(v) not in selected_ids]
    selected.extend(rng.sample(remainder, n - len(selected)))
    rng.shuffle(selected)
    return selected


def sample_ccm(candidates: list[dict[str, Any]], n: int,
               rng: random.Random) -> list[dict[str, Any]]:
    """Cover CCM direction/key/verdict combinations, then parameter values."""
    required_fields = ("operation", "key_bits", "expected_accept")
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for candidate in candidates:
        key = tuple(candidate.get(field) for field in required_fields)
        groups.setdefault(key, []).append(candidate)
    selected = [rng.choice(group) for group in groups.values()]
    if len(selected) > n:
        return sample_stratified(candidates, n, rng, required_fields)

    coverage_fields = ("tag_len", "nonce_len", "aad_empty", "data_empty")
    uncovered = {
        (field, candidate.get(field))
        for field in coverage_fields
        for candidate in candidates
    }
    for candidate in selected:
        for field in coverage_fields:
            uncovered.discard((field, candidate.get(field)))
    selected_ids = {id(v) for v in selected}
    remaining = [v for v in candidates if id(v) not in selected_ids]
    while uncovered and remaining and len(selected) < n:
        rng.shuffle(remaining)
        best = max(
            remaining,
            key=lambda candidate: sum(
                (field, candidate.get(field)) in uncovered
                for field in coverage_fields
            ),
        )
        selected.append(best)
        remaining.remove(best)
        for field in coverage_fields:
            uncovered.discard((field, best.get(field)))
    if len(selected) < n:
        selected.extend(rng.sample(remaining, n - len(selected)))
    rng.shuffle(selected)
    return selected


def sample_balanced(candidates: list[dict[str, Any]], n: int,
                    rng: random.Random, field: str) -> list[dict[str, Any]]:
    """Split a sample as evenly as possible among values of one field."""
    groups: dict[Any, list[dict[str, Any]]] = {}
    for candidate in candidates:
        groups.setdefault(candidate.get(field), []).append(candidate)
    values = list(groups)
    selected: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        take = n // len(values) + (1 if index < n % len(values) else 0)
        selected.extend(rng.sample(groups[value], min(take, len(groups[value]))))
    if len(selected) < n:
        selected_ids = {id(v) for v in selected}
        remaining = [v for v in candidates if id(v) not in selected_ids]
        selected.extend(rng.sample(remaining, n - len(selected)))
    rng.shuffle(selected)
    return selected


def assign_test_ids(vectors: list[dict[str, Any]], algorithm: str) -> None:
    start = TID_RANGES[algorithm]
    for i, v in enumerate(vectors):
        v["test_id"] = start + i


# ============================================================
# AppVar wire-format packer
# ============================================================

def h(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


def pack_payload(v: dict) -> bytes:
    """Algorithm-specific TLV payload. See src/main.c for wire format."""
    alg = v["algorithm"]
    if alg == "AES-GCM":
        key, iv = h(v["key_hex"]), h(v["iv_hex"])
        aad, data, tag = h(v["aad_hex"]), h(v["data_hex"]), h(v["tag_hex"])
        direction = 0 if v["operation"] == "encrypt" else 1
        return (bytes([direction, len(key)]) + key
                + bytes([len(iv)]) + iv
                + struct.pack("<H", len(aad)) + aad
                + struct.pack("<H", len(data)) + data
                + bytes([int(v["tag_len"])]) + tag)
    if alg == "AES-CBC":
        key, iv, data = h(v["key_hex"]), h(v["iv_hex"]), h(v["data_hex"])
        direction = 0 if v["operation"] == "encrypt" else 1
        return (bytes([direction, len(key)]) + key + iv
                + struct.pack("<H", len(data)) + data)
    if alg == "AES-CCM":
        key, nonce = h(v["key_hex"]), h(v["nonce_hex"])
        aad, data, tag = h(v["aad_hex"]), h(v["data_hex"]), h(v["tag_hex"])
        direction = 0 if v["operation"] == "encrypt" else 1
        return (bytes([direction, len(key)]) + key
                + bytes([len(nonce)]) + nonce
                + struct.pack("<H", len(aad)) + aad
                + struct.pack("<H", len(data)) + data
                + bytes([int(v["tag_len"])]) + tag)
    if alg == "SHA-256":
        msg = h(v["msg_hex"])
        return struct.pack("<H", len(msg)) + msg
    if alg == "HMAC-SHA-256":
        key, msg = h(v["key_hex"]), h(v["msg_hex"])
        return (struct.pack("<H", len(key)) + key
                + struct.pack("<H", len(msg)) + msg)
    if alg == "HKDF-SHA-256":
        ikm, salt, info = h(v["ikm_hex"]), h(v["salt_hex"]), h(v["info_hex"])
        L = int(v["l"])
        return (struct.pack("<H", len(ikm)) + ikm
                + struct.pack("<H", len(salt)) + salt
                + struct.pack("<H", len(info)) + info
                + struct.pack("<H", L))
    if alg == "RSA-PSS-SHA-256-VERIFY":
        modulus = h(v["modulus_hex"])
        exponent = h(v["exponent_hex"])
        msg = h(v["msg_hex"])
        sig = h(v["sig_hex"])
        salt_len = int(v["salt_len"])
        return (struct.pack("<H", len(modulus)) + modulus
                + bytes([len(exponent)]) + exponent
                + bytes([salt_len])
                + struct.pack("<H", len(msg)) + msg
                + struct.pack("<H", len(sig)) + sig)
    if alg == "X25519-PUBLICKEY":
        priv = h(v["priv_hex"])
        if len(priv) != 32:
            raise ValueError(f"X25519 priv must be 32 bytes, got {len(priv)}")
        return priv
    if alg == "X25519-SECRET":
        priv = h(v["priv_hex"])
        peer = h(v["peer_pub_hex"])
        if len(priv) != 32 or len(peer) != 32:
            raise ValueError("X25519 scalar/u must be 32 bytes each")
        return priv + peer
    if alg == "PBKDF2-HMAC-SHA256":
        password, salt = h(v["password_hex"]), h(v["salt_hex"])
        return (struct.pack("<H", len(password)) + password
                + struct.pack("<H", len(salt)) + salt
                + struct.pack("<H", int(v["rounds"]))
                + struct.pack("<H", int(v["key_len"])))
    if alg == "SHA-256-MCT":
        seed = h(v["seed_hex"])
        if len(seed) != 32:
            raise ValueError(f"SHA-256 MCT seed must be 32 bytes, got {len(seed)}")
        return seed
    raise ValueError(f"unknown algorithm: {alg}")


def pack_record(v: dict) -> bytes:
    """Pack one vector record."""
    alg_id = ALG_ID[v["algorithm"]]
    test_id = int(v["test_id"])
    payload = pack_payload(v)
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload for tid {test_id} too large ({len(payload)} bytes)")
    return (bytes([alg_id]) + struct.pack("<H", test_id)
            + struct.pack("<H", len(payload)) + payload)


def pack_bodies(vectors: list[dict]) -> list[bytes]:
    """Balance records across fixed small AppVars to limit transfer RAM."""
    bins: list[list[bytes]] = [[] for _ in APPVAR_NAMES]
    sizes = [6 for _ in APPVAR_NAMES]
    records = sorted((pack_record(v) for v in vectors), key=len, reverse=True)
    for record in records:
        index = min(range(len(bins)), key=lambda i: sizes[i])
        if 6 + len(record) > MAX_CHUNK_BODY:
            raise ValueError(f"single vector record is too large ({len(record)} bytes)")
        bins[index].append(record)
        sizes[index] += len(record)

    bodies = []
    for records_in_bin in bins:
        out = bytearray(b"AIN1")
        out += struct.pack("<H", len(records_in_bin))
        for record in records_in_bin:
            out += record
        if len(out) > MAX_CHUNK_BODY:
            raise ValueError(
                f"input chunk is {len(out)} bytes; reduce CAVP_FETCH_SAMPLE"
            )
        bodies.append(bytes(out))
    return bodies


def pack_body(vectors: list[dict]) -> bytes:
    """Compatibility helper used by tooling that wants one body."""
    out = bytearray(b"AIN1")
    out += struct.pack("<H", len(vectors))
    for v in vectors:
        out += pack_record(v)
    return bytes(out)


def write_8xv(body: bytes, output_path: Path, appvar_name: str) -> None:
    """Wrap body bytes into an AppVar. Uses convbin if
    available; falls back to a pure-Python packer."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("convbin"):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(body)
            bin_path = tf.name
        try:
            subprocess.run(
                ["convbin", "-i", bin_path, "-o", str(output_path),
                 "-j", "bin", "-k", "8xv", "-n", appvar_name, "-r"],
                check=True,
            )
        finally:
            os.unlink(bin_path)
        return

    # Native packer (TI .8xv format)
    sig = b"**TI83F*" + b"\x1a\n\x00"
    comment = b"lwIP-CE CAVP".ljust(42, b"\x00")
    name = appvar_name.encode("ascii")[:8].ljust(8, b"\x00")
    body_with_len_prefix = struct.pack("<H", len(body)) + body
    var_data_len = len(body_with_len_prefix)
    var_header = (
        struct.pack("<H", 0x0D)
        + struct.pack("<H", var_data_len)
        + bytes([0x15])
        + name
        + bytes([0x00])
        + bytes([0x00])
        + struct.pack("<H", var_data_len)
    )
    data_section = var_header + body_with_len_prefix
    data_section_len = len(data_section)
    checksum = sum(data_section) & 0xFFFF
    output_path.write_bytes(
        sig + comment
        + struct.pack("<H", data_section_len)
        + data_section
        + struct.pack("<H", checksum)
    )


# ============================================================
# expected.json (host-side grading source)
# ============================================================

def build_expected(vectors: list[dict[str, Any]], seed: int, sample_size: int) -> dict[str, Any]:
    """Produce a compact host-side grading record. The parser keys on test_id
    and looks up algorithm + expected_* fields."""
    out_vectors = []
    for v in vectors:
        rec = {
            "test_id": v["test_id"],
            "algorithm": v["algorithm"],
        }
        for k in ("expected_hex", "expected_tag_hex", "expected_data_hex",
                  "expected_accept", "operation",
                  "expected_okm_hex", "expected_pub_hex", "expected_shared_hex",
                  "expected_verify"):
            if k in v:
                rec[k] = v[k]
        # Include the source info for traceability in failure reports
        for k in ("source_file", "source_count", "cavp_result", "$source"):
            if k in v:
                rec[k] = v[k]
        out_vectors.append(rec)
    return {
        "$comment": (
            "Generated by tests/common/scripts/cavp_fetch.py. "
            "Maps test_id -> expected outputs for parse_cavp_output_appvar.py."
        ),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": seed,
        "sample_size": sample_size,
        "vectors": out_vectors,
    }


# ============================================================
# main
# ============================================================

def main() -> int:
    sample_size = int(os.environ.get("CAVP_FETCH_SAMPLE", DEFAULT_SAMPLE_SIZE))
    seed_env = os.environ.get("CAVP_FETCH_SEED")
    if seed_env is not None:
        seed = int(seed_env)
        print(f"==> using user-provided seed: {seed}", file=sys.stderr)
    else:
        seed = int(time.time())
        print(f"==> using time-based seed: {seed} "
              f"(set CAVP_FETCH_SEED={seed} to reproduce)", file=sys.stderr)
    rng = random.Random(seed)

    print(f"==> sample size per CAVP algorithm: {sample_size}", file=sys.stderr)
    print(f"==> cache: {CACHE_DIR}", file=sys.stderr)

    all_vectors: list[dict[str, Any]] = []

    # --- CAVP-sampled. Stratification makes each small random sample cover
    # both directions, all supported key sizes, negative AEAD cases, and the
    # distinct KAT/MMT or short/long vector classes where applicable.
    for label, fetcher, strata in [
        ("AES-GCM",      fetch_aes_gcm,      ("operation", "key_bits", "expected_accept")),
        ("AES-CBC",      fetch_aes_cbc,      ("operation", "key_bits", "vector_class")),
        ("AES-CCM",      fetch_aes_ccm,      ("operation", "key_bits", "expected_accept")),
        ("SHA-256",      fetch_sha256,       ("variant",)),
        ("HMAC-SHA-256", fetch_hmac_sha256,  ()),
    ]:
        print(f"==> [{label}] fetching ...", file=sys.stderr)
        try:
            pool = fetcher()
        except SystemExit:
            raise
        except Exception as e:
            print(f"==> [{label}] FAILED: {e}", file=sys.stderr)
            return 2
        target_count = max(sample_size, 24) if label == "AES-CCM" else sample_size
        print(f"==> [{label}] {len(pool)} candidates, sampling {target_count}",
              file=sys.stderr)
        if label == "AES-CCM":
            sampled = sample_ccm(pool, target_count, rng)
        elif label == "SHA-256":
            sampled = sample_balanced(pool, target_count, rng, "variant")
        else:
            sampled = (sample_stratified(pool, target_count, rng, strata)
                       if strata else sample_with_seed(pool, target_count, rng, label))
        assign_test_ids(sampled, label)
        all_vectors.extend(sampled)
        for v in sampled:
            print(f"    sampled tid={v['test_id']} <- {v['source_file']} "
                  f"Count={v['source_count']}", file=sys.stderr)

    # SHA-256 Monte Carlo: each vector performs 1000 chained hashes, so a
    # small cap gives meaningful state-transition coverage without dominating
    # calculator runtime.
    mct_label = "SHA-256-MCT"
    mct_count = min(1, sample_size)
    print(f"==> [{mct_label}] fetching ...", file=sys.stderr)
    try:
        mct_pool = fetch_sha256_mct()
    except Exception as e:
        print(f"==> [{mct_label}] FAILED: {e}", file=sys.stderr)
        return 2
    mct_vectors = sample_with_seed(mct_pool, mct_count, rng, mct_label)
    assign_test_ids(mct_vectors, mct_label)
    all_vectors.extend(mct_vectors)
    for v in mct_vectors:
        print(f"    sampled tid={v['test_id']} <- {v['source_file']} "
              f"Count={v['source_count']}", file=sys.stderr)

    # --- RSA-PSS: generated fresh per run (see fn docstring for why CAVP
    # vectors can't be used with our fixed-e=65537 verifier)
    rsa_label = "RSA-PSS-SHA-256-VERIFY"
    print(f"==> [{rsa_label}] generating {sample_size} fresh vectors ...",
          file=sys.stderr)
    try:
        rsa_vectors = gen_rsa_pss_sha256(rng, sample_size)
    except SystemExit:
        raise
    except Exception as e:
        print(f"==> [{rsa_label}] FAILED: {e}", file=sys.stderr)
        return 2
    assign_test_ids(rsa_vectors, rsa_label)
    all_vectors.extend(rsa_vectors)
    for v in rsa_vectors:
        verdict_note = f" verdict={'P' if v['expected_verify'] else 'F'}"
        print(f"    generated tid={v['test_id']} <- {v['source_file']} "
              f"Count={v['source_count']}{verdict_note}", file=sys.stderr)

    # PBKDF2 has an ACVP schema but no compact legacy CAVP archive matching
    # this downloader. Generate equivalent reference vectors and keep rounds
    # low because correctness—not password-cracking cost—is the goal here.
    pbkdf_label = "PBKDF2-HMAC-SHA256"
    print(f"==> [{pbkdf_label}] generating {sample_size} vectors "
          "(1..32 rounds) ...", file=sys.stderr)
    try:
        pbkdf_vectors = gen_pbkdf2_sha256(rng, sample_size)
    except SystemExit:
        raise
    except Exception as e:
        print(f"==> [{pbkdf_label}] FAILED: {e}", file=sys.stderr)
        return 2
    assign_test_ids(pbkdf_vectors, pbkdf_label)
    all_vectors.extend(pbkdf_vectors)
    for v in pbkdf_vectors:
        print(f"    generated tid={v['test_id']} <- {v['source_file']} "
              f"Count={v['source_count']}", file=sys.stderr)

    # --- RFC-pinned + generated coverage for primitives without CAVP archives.
    rfc_by_alg: dict[str, list[dict[str, Any]]] = {}
    for v in RFC_VECTORS:
        rfc_by_alg.setdefault(v["algorithm"], []).append(dict(v))

    hkdf_needed = max(0, sample_size - len(rfc_by_alg.get("HKDF-SHA-256", [])))
    print(f"==> [HKDF-SHA-256] adding {len(rfc_by_alg.get('HKDF-SHA-256', []))} RFC-pinned "
          f"+ generating {hkdf_needed} vectors ...", file=sys.stderr)
    try:
        hkdf_vectors = gen_hkdf_sha256(rng, hkdf_needed)
    except SystemExit:
        raise
    except Exception as e:
        print(f"==> [HKDF-SHA-256] FAILED: {e}", file=sys.stderr)
        return 2
    hkdf_vectors.extend(rfc_by_alg.get("HKDF-SHA-256", []))
    assign_test_ids(hkdf_vectors, "HKDF-SHA-256")
    all_vectors.extend(hkdf_vectors)
    for v in hkdf_vectors:
        source = v.get("source_file", v.get("$source", "unknown"))
        count = v.get("source_count", "pinned")
        print(f"    hkdf tid={v['test_id']} <- {source} Count={count}", file=sys.stderr)

    x25519_pub_pinned = rfc_by_alg.get("X25519-PUBLICKEY", [])
    x25519_secret_pinned = rfc_by_alg.get("X25519-SECRET", [])
    x25519_pub_needed = max(0, sample_size - len(x25519_pub_pinned))
    x25519_secret_needed = max(0, sample_size - len(x25519_secret_pinned))
    x25519_generate_count = max(x25519_pub_needed, x25519_secret_needed)
    print(f"==> [X25519] adding {len(x25519_pub_pinned)} public-key RFC-pinned "
          f"+ generating {x25519_pub_needed}; adding {len(x25519_secret_pinned)} secret RFC-pinned "
          f"+ generating {x25519_secret_needed} ...", file=sys.stderr)
    try:
        x25519_pub_vectors, x25519_secret_vectors = gen_x25519(rng, x25519_generate_count)
    except SystemExit:
        raise
    except Exception as e:
        print(f"==> [X25519] FAILED: {e}", file=sys.stderr)
        return 2
    x25519_pub_vectors = x25519_pub_vectors[:x25519_pub_needed]
    x25519_secret_vectors = x25519_secret_vectors[:x25519_secret_needed]
    x25519_pub_vectors.extend(x25519_pub_pinned)
    x25519_secret_vectors.extend(x25519_secret_pinned)
    assign_test_ids(x25519_pub_vectors, "X25519-PUBLICKEY")
    assign_test_ids(x25519_secret_vectors, "X25519-SECRET")
    all_vectors.extend(x25519_pub_vectors)
    all_vectors.extend(x25519_secret_vectors)
    for v in x25519_pub_vectors + x25519_secret_vectors:
        source = v.get("source_file", v.get("$source", "unknown"))
        count = v.get("source_count", "pinned")
        print(f"    x25519 tid={v['test_id']} <- {source} Count={count}", file=sys.stderr)

    # Sort for stable output
    all_vectors.sort(key=lambda v: v["test_id"])

    # --- Pack fixed small input AppVars. CEmu transfers an AppVar through
    # calculator RAM even when its final status is archived; one 30+ KiB
    # CAVPIN can crowd out the installer/runner before the sequence begins.
    try:
        legacy_input = VECTORS_DIR / "CAVPIN.8xv"
        if legacy_input.exists():
            legacy_input.unlink()
        bodies = pack_bodies(all_vectors)
        for appvar_name, body in zip(APPVAR_NAMES, bodies):
            path = VECTORS_DIR / f"{appvar_name}.8xv"
            write_8xv(body, path, appvar_name)
    except Exception as e:
        print(f"==> ERROR packing CAVP input AppVars: {e}", file=sys.stderr)
        return 2
    total_body = sum(map(len, bodies))
    print(f"==> wrote {len(bodies)} CAVP input AppVars "
          f"(body={total_body} bytes, max_chunk={max(map(len, bodies))} bytes, "
          f"{len(all_vectors)} vectors)", file=sys.stderr)

    # --- Write expected.json
    expected = build_expected(all_vectors, seed, sample_size)
    EXPECTED_PATH.write_text(json.dumps(expected, indent=2) + "\n")
    print(f"==> wrote {EXPECTED_PATH} ({len(all_vectors)} vectors)",
          file=sys.stderr)

    print(f"==> seed used: {seed}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
