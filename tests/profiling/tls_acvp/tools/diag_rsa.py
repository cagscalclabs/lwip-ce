#!/usr/bin/env python3
"""Diagnose RSA-PSS verify failures by comparing the calc's decrypted EM
against an independent reference (Python cryptography, via raw bignum).

Reads:
  ../ACVPRSA.8xv         — debug log written by src/main.c (run_rsa_pss_verify)
  ../vectors/ACVPIN.8xv  — input vectors (for the n + sig to recompute reference)

For each RSA-PSS test_id in the debug log, prints:
  - stage (modexp_fail, size_mismatch, pss_fail, ok)
  - calc's EM bytes
  - reference EM bytes (sig^e mod n, computed in Python)
  - byte-diff summary
  - if they match, the bug is in the PSS-decode side; if they differ, the
    bug is in the modexp (tls_rsa_decrypt_signature).

Usage:
    python3 diag_rsa.py

No flags. Reads/writes from hardcoded relative paths.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
TEST_DIR = SCRIPT_DIR.parent
ACVPRSA_PATH = TEST_DIR / "ACVPRSA.8xv"
ACVPIN_PATH = TEST_DIR / "vectors" / "ACVPIN.8xv"

# Algorithm IDs must match src/main.c / cavp_fetch.py
ALG_RSA_PSS = 6

STAGE_NAMES = {0: "ok", 1: "modexp_fail", 2: "size_mismatch", 3: "pss_fail"}


def strip_appvar_wrapper(appvar: bytes, magic: bytes) -> bytes:
    """Return the variable-data section starting at `magic`."""
    if len(appvar) < 76 or not appvar.startswith(b"**TI83F*"):
        raise SystemExit(f"not a valid .8xv AppVar: {appvar[:10]!r}")
    idx = appvar.find(magic, 53, len(appvar) - 2)
    if idx == -1:
        raise SystemExit(f"magic {magic!r} not found in AppVar")
    body_len = struct.unpack("<H", appvar[idx - 2:idx])[0]
    body_end = idx + body_len
    if body_end + 2 > len(appvar):
        body_end = len(appvar) - 2
    return appvar[idx:body_end]


def parse_rsa_inputs() -> dict[int, dict]:
    """Walk ACVPIN.8xv and pull out per-test_id (n, sig) for RSA records."""
    raw = ACVPIN_PATH.read_bytes()
    body = strip_appvar_wrapper(raw, b"AIN1")
    vc = struct.unpack("<H", body[4:6])[0]
    out: dict[int, dict] = {}
    off = 6
    for _ in range(vc):
        alg = body[off]
        off += 1
        tid = struct.unpack("<H", body[off:off + 2])[0]
        off += 2
        plen = struct.unpack("<H", body[off:off + 2])[0]
        off += 2
        payload = body[off:off + plen]
        off += plen
        if alg != ALG_RSA_PSS:
            continue
        # Parse RSA-PSS payload (matches src/main.c run_rsa_pss_verify)
        p = 0
        mlen = struct.unpack("<H", payload[p:p + 2])[0]
        p += 2
        modulus = payload[p:p + mlen]
        p += mlen
        elen = payload[p]
        p += 1
        exponent = payload[p:p + elen]
        p += elen
        _salt_len = payload[p]
        p += 1
        msg_len = struct.unpack("<H", payload[p:p + 2])[0]
        p += 2
        msg = payload[p:p + msg_len]
        p += msg_len
        slen = struct.unpack("<H", payload[p:p + 2])[0]
        p += 2
        sig = payload[p:p + slen]
        out[tid] = {
            "n": modulus,
            "e": exponent,
            "msg": msg,
            "sig": sig,
        }
    return out


def parse_debug_log() -> list[dict]:
    """Walk ACVPRSA.8xv and return per-vector records."""
    raw = ACVPRSA_PATH.read_bytes()
    body = strip_appvar_wrapper(raw, b"ARSA")
    count = struct.unpack("<H", body[4:6])[0]
    records: list[dict] = []
    off = 6
    for _ in range(count):
        if off + 6 > len(body):
            break
        tid = struct.unpack("<H", body[off:off + 2])[0]
        stage = body[off + 2]
        verdict = body[off + 3]
        em_len = struct.unpack("<H", body[off + 4:off + 6])[0]
        off += 6
        em = body[off:off + em_len]
        off += em_len
        records.append({
            "test_id": tid,
            "stage": stage,
            "verdict": verdict,
            "em": em,
        })
    return records


def hexdump_first_diff(a: bytes, b: bytes, context: int = 8) -> str:
    """Return a short string showing the first divergence between two byte strings."""
    if a == b:
        return "EQUAL"
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            lo = max(0, i - context)
            hi = min(n, i + context + 1)
            return (f"diverge at byte {i}: "
                    f"calc={a[lo:hi].hex()} ref={b[lo:hi].hex()} "
                    f"(len: calc={len(a)} ref={len(b)})")
    if len(a) != len(b):
        return f"common prefix matches; lengths differ calc={len(a)} ref={len(b)}"
    return "EQUAL after re-check (unexpected)"


def main() -> int:
    if not ACVPRSA_PATH.exists():
        print(f"ERROR: {ACVPRSA_PATH} not found "
              f"(run the ACVP test first to produce it)", file=sys.stderr)
        return 1
    if not ACVPIN_PATH.exists():
        print(f"ERROR: {ACVPIN_PATH} not found "
              f"(run cavp_fetch.py first)", file=sys.stderr)
        return 1

    inputs = parse_rsa_inputs()
    records = parse_debug_log()

    print(f"## RSA-PSS verify diagnostic")
    print(f"loaded {len(records)} debug records, {len(inputs)} RSA inputs")
    print()

    for rec in records:
        tid = rec["test_id"]
        inp = inputs.get(tid)
        stage_name = STAGE_NAMES.get(rec["stage"], f"unknown({rec['stage']})")
        print(f"### test_id={tid}  stage={stage_name}  calc_verdict={rec['verdict']}")
        if inp is None:
            print(f"  (no matching ACVPIN record for this test_id)")
            continue

        n = int.from_bytes(inp["n"], "big")
        e = int.from_bytes(inp["e"], "big")
        sig = int.from_bytes(inp["sig"], "big")
        modlen = len(inp["n"])

        # Compute the reference EM = sig^e mod n
        ref_em_int = pow(sig, e, n)
        ref_em = ref_em_int.to_bytes(modlen, "big")

        if rec["em"]:
            calc_em = rec["em"]
            print(f"  calc EM[0..15]:  {calc_em[:16].hex()}")
            print(f"  ref  EM[0..15]:  {ref_em[:16].hex()}")
            print(f"  calc EM[-16..]: ...{calc_em[-16:].hex()}")
            print(f"  ref  EM[-16..]: ...{ref_em[-16:].hex()}")
            print(f"  diff: {hexdump_first_diff(calc_em, ref_em)}")
            if calc_em == ref_em:
                print(f"  CONCLUSION: modexp is CORRECT.  "
                      f"Bug (if any) is in tls_rsa_pss_verify (PSS decode).")
            else:
                print(f"  CONCLUSION: modexp result DIFFERS from reference.  "
                      f"Bug is in tls_rsa_decrypt_signature (modexp).")
        else:
            print(f"  (no EM captured — calc bailed before modexp completed)")
            print(f"  ref EM[0..15]:  {ref_em[:16].hex()}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
