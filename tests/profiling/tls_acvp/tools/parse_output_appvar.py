#!/usr/bin/env python3
"""Parse ACVPOUT.8xv (calc-side responses) and grade against expected outputs.

Three places must agree on the AppVar name "ACVPOUT": this script,
autotest.json's saveVar sequence entry, and src/main.c's ACVPOUT_NAME.

Reads (hardcoded paths):
  - ../ACVPOUT.8xv          : binary AppVar produced by the calc-side runner
  - ../vectors/expected.json : per-run grading source produced by cavp_fetch.py

Emits:
  - A markdown table to stdout (or to a file via --markdown-out)
  - A JSON results file (via --json-out)
  - Exit code 0 if every grade-able vector passed; 1 if any failed.

A vector is "grade-able" iff the corresponding expected_* field in the
expected.json record is present. Vectors the calc returned
status=UNSUPPORTED for (e.g. DRBG until standalone API is wired) are
reported as UNSUPPORTED.

Usage:
    parse_output_appvar.py [--markdown-out path] [--json-out path]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---- Hardcoded paths ----
# Three places must agree on these names. The calc-side runner (src/main.c)
# writes ACVPOUT; cavp_fetch.py writes expected.json. Both are inputs here.
SCRIPT_DIR = Path(__file__).resolve().parent
TEST_DIR = SCRIPT_DIR.parent
INPUT_APPVAR = TEST_DIR / "ACVPOUT.8xv"
EXPECTED_JSON = TEST_DIR / "vectors" / "expected.json"
APPVAR_NAME = "ACVPOUT"

# Must match src/main.c
ALG_NAMES = {
    1: "AES-128-GCM",
    2: "SHA-256",
    3: "HMAC-SHA-256",
    4: "HKDF-SHA-256",
    5: "DRBG-SHA-256",
    6: "RSA-PSS-SHA-256-VERIFY",
    7: "X25519-PUBLICKEY",
    8: "X25519-SECRET",
}
STATUS_NAMES = {0: "ok", 1: "unsupported", 2: "internal_error"}


def strip_appvar_wrapper(appvar: bytes) -> bytes:
    """Strip the TI .8xv container and return the raw variable content.

    The on-disk .8xv file has a 53-byte file header, then a variable-data
    section that includes its own header plus a 2-byte length prefix
    immediately before the user-visible content. The user-visible content
    is what the calc-side runner sees via ti_GetDataPtr (NOT via
    os_GetAppVarData, which exposes the length prefix).

    Rather than chase byte offsets across convbin/TIVarFactory variants,
    we just scan forward for the recognized content magic ('AIN1' or
    'AOUT'). The body length sits in the two bytes immediately preceding
    the magic; we use it to bound the slice and tolerate trailing
    checksum bytes by clamping to (file_len - 2) if needed.
    """
    if len(appvar) < 76 or not appvar.startswith(b"**TI83F*"):
        raise ValueError("not a valid .8xv AppVar")

    for magic in (b"AIN1", b"AOUT"):
        idx = appvar.find(magic, 53, len(appvar) - 2)
        if idx == -1:
            continue
        if idx < 55:
            raise ValueError(f"magic {magic!r} found too early at offset {idx}")
        body_len = struct.unpack("<H", appvar[idx - 2:idx])[0]
        body_end = idx + body_len
        if body_end + 2 > len(appvar):
            body_end = len(appvar) - 2
        return appvar[idx:body_end]

    raise ValueError(
        "no recognized body magic ('AIN1' or 'AOUT') found in AppVar wrapper"
    )


def parse_responses(body: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse the ACVPOUT body into a list of {test_id, status, result_bytes}."""
    warnings: list[str] = []
    if len(body) < 6:
        raise ValueError(f"response body too short: {len(body)} bytes")
    if body[:4] != b"AOUT":
        raise ValueError(f"bad magic: {body[:4]!r} (expected b'AOUT')")
    response_count = struct.unpack("<H", body[4:6])[0]

    responses: list[dict[str, Any]] = []
    off = 6
    for i in range(response_count):
        if off + 5 > len(body):
            warnings.append(f"truncated at response {i}/{response_count}")
            break
        test_id = struct.unpack("<H", body[off:off + 2])[0]
        status = body[off + 2]
        result_len = struct.unpack("<H", body[off + 3:off + 5])[0]
        off += 5
        if off + result_len > len(body):
            warnings.append(f"response {test_id} claims {result_len} bytes but only "
                            f"{len(body) - off} remain; truncating")
            result_len = max(0, len(body) - off)
        result = body[off:off + result_len]
        off += result_len
        responses.append({"test_id": test_id, "status": status, "result": result})
    return responses, warnings


def grade_aes_gcm(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: tag_len(1) + tag(16) + ct_len(2) + ct(ct_len)."""
    if len(result) < 19:
        return False, f"result too short ({len(result)} bytes)"
    tag_len = result[0]
    if tag_len != 16:
        return False, f"tag_len={tag_len}, expected 16"
    tag = result[1:17]
    ct_len = struct.unpack("<H", result[17:19])[0]
    ct = result[19:19 + ct_len]
    if len(ct) != ct_len:
        return False, f"ct truncated: {len(ct)} of {ct_len} bytes"

    exp_tag = bytes.fromhex(expected["expected_tag_hex"])
    exp_ct = bytes.fromhex(expected["expected_ct_hex"]) if expected.get("expected_ct_hex") else b""

    if tag != exp_tag:
        return False, f"tag mismatch: got {tag.hex()}, expected {exp_tag.hex()}"
    if ct != exp_ct:
        return False, f"ciphertext mismatch: got {ct.hex()}, expected {exp_ct.hex()}"
    return True, "ok"


def grade_sha256(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: digest_len(1) + digest(32)."""
    if len(result) != 33 or result[0] != 32:
        return False, f"malformed result ({len(result)} bytes, first={result[:1].hex()})"
    digest = result[1:]
    exp = bytes.fromhex(expected["expected_hex"])
    if digest != exp:
        return False, f"digest mismatch: got {digest.hex()}, expected {exp.hex()}"
    return True, "ok"


def grade_hmac(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: tag_len(1) + tag(32)."""
    if len(result) != 33 or result[0] != 32:
        return False, f"malformed result ({len(result)} bytes, first={result[:1].hex()})"
    tag = result[1:]
    exp = bytes.fromhex(expected["expected_hex"])
    if tag != exp:
        return False, f"tag mismatch: got {tag.hex()}, expected {exp.hex()}"
    return True, "ok"


def grade_hkdf(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: okm_len(2) + okm(okm_len)."""
    if len(result) < 2:
        return False, f"result too short ({len(result)} bytes)"
    okm_len = struct.unpack("<H", result[:2])[0]
    okm = result[2:2 + okm_len]
    if len(okm) != okm_len:
        return False, f"okm truncated: {len(okm)} of {okm_len} bytes"
    exp = bytes.fromhex(expected["expected_okm_hex"])
    if okm != exp:
        return False, f"okm mismatch: got {okm.hex()}, expected {exp.hex()}"
    return True, "ok"


def grade_drbg(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: out_len(2) + out(out_len)."""
    if len(result) < 2:
        return False, f"result too short ({len(result)} bytes)"
    out_len = struct.unpack("<H", result[:2])[0]
    out = result[2:2 + out_len]
    if len(out) != out_len:
        return False, f"out truncated: {len(out)} of {out_len} bytes"
    exp = bytes.fromhex(expected["expected_hex"])
    if out != exp:
        return False, f"output mismatch: got {out.hex()}, expected {exp.hex()}"
    return True, "ok"


def grade_rsa_pss_verify(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: verdict(1)  (1 = signature valid, 0 = invalid).

    Note: an 'unsupported' status (handled at the caller level, not here)
    indicates the calc couldn't perform the verify — distinct from a verify
    that returned a definite false. We only see this grader for status=OK
    responses, where the calc's verdict byte should match expected_verify.
    """
    if len(result) != 1:
        return False, f"result must be 1 byte verdict, got {len(result)}"
    got = bool(result[0])
    exp = bool(expected["expected_verify"])
    if got != exp:
        kind = "positive" if exp else "negative"
        action = "accepted" if got else "rejected"
        wanted = "accept" if exp else "reject"
        return False, f"{kind} test: calc {action} but should have {wanted}ed"
    return True, "ok"


def grade_x25519_pub(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: pub[32]."""
    if len(result) != 32:
        return False, f"result must be 32 bytes, got {len(result)}"
    exp = bytes.fromhex(expected["expected_pub_hex"])
    if result != exp:
        return False, f"pubkey mismatch: got {result.hex()}, expected {exp.hex()}"
    return True, "ok"


def grade_x25519_secret(result: bytes, expected: dict[str, Any]) -> tuple[bool, str]:
    """Result wire format: shared[32]."""
    if len(result) != 32:
        return False, f"result must be 32 bytes, got {len(result)}"
    exp = bytes.fromhex(expected["expected_shared_hex"])
    if result != exp:
        return False, f"shared secret mismatch: got {result.hex()}, expected {exp.hex()}"
    return True, "ok"


GRADERS = {
    "AES-GCM": grade_aes_gcm,
    "SHA-256": grade_sha256,
    "HMAC-SHA-256": grade_hmac,
    "HKDF-SHA-256": grade_hkdf,
    "DRBG-SHA-256": grade_drbg,
    "RSA-PSS-SHA-256-VERIFY": grade_rsa_pss_verify,
    "X25519-PUBLICKEY": grade_x25519_pub,
    "X25519-SECRET": grade_x25519_secret,
}


def has_expected(vector: dict[str, Any]) -> bool:
    """Return True iff this vector record carries enough info to grade.

    expected.json (produced by cavp_fetch.py) holds only test_id + algorithm
    + expected_* fields — the inputs (modulus, sig, msg, etc.) live in the
    AppVar. So 'has expected' just means the relevant expected_* key is
    present and non-empty for string types, or present (regardless of
    value — False is a valid expected_verify) for the RSA-PSS bool.
    """
    for k in ("expected_tag_hex", "expected_hex", "expected_okm_hex",
              "expected_pub_hex", "expected_shared_hex"):
        if vector.get(k):
            return True
    if "expected_verify" in vector and isinstance(vector["expected_verify"], bool):
        return True
    return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--markdown-out", help="write markdown summary to this path "
                   "(default: stdout)")
    p.add_argument("--json-out", help="write structured results JSON to this path "
                   "(default: not written)")
    args = p.parse_args()

    if not INPUT_APPVAR.exists():
        print(f"ERROR: response AppVar not found: {INPUT_APPVAR}", file=sys.stderr)
        return 1
    if not EXPECTED_JSON.exists():
        print(f"ERROR: expected.json not found: {EXPECTED_JSON} "
              f"(run cavp_fetch.py first)", file=sys.stderr)
        return 1

    appvar_bytes = INPUT_APPVAR.read_bytes()
    expected_data = json.loads(EXPECTED_JSON.read_text())
    vectors_by_id = {int(v["test_id"]): v for v in expected_data["vectors"]}
    expected_gradeable = {
        int(v["test_id"]) for v in expected_data["vectors"] if has_expected(v)
    }

    if not vectors_by_id:
        print("ERROR: expected.json contains no ACVP vectors", file=sys.stderr)
        return 1
    if not expected_gradeable:
        print("ERROR: expected.json contains no gradeable ACVP vectors", file=sys.stderr)
        return 1

    body = strip_appvar_wrapper(appvar_bytes)
    responses, warnings = parse_responses(body)
    if not responses:
        warnings.append("ACVPOUT contained zero responses")

    # Grade each response
    rows: list[dict[str, Any]] = []
    by_alg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "skip": 0, "unsupported": 0}
    )

    for r in responses:
        vec = vectors_by_id.get(r["test_id"])
        if not vec:
            by_alg["?"]["fail"] += 1
            rows.append({
                "test_id": r["test_id"],
                "algorithm": "?",
                "status": "fail",
                "detail": "no vector with this test_id in the JSON",
            })
            continue

        alg = vec["algorithm"]
        if r["status"] == 1:  # UNSUPPORTED
            if has_expected(vec):
                by_alg[alg]["fail"] += 1
                rows.append({"test_id": r["test_id"], "algorithm": alg,
                             "status": "fail",
                             "detail": "calc returned UNSUPPORTED for a gradeable vector"})
            else:
                by_alg[alg]["unsupported"] += 1
                rows.append({"test_id": r["test_id"], "algorithm": alg,
                             "status": "unsupported", "detail": "calc returned UNSUPPORTED"})
            continue
        if r["status"] == 2:  # INTERNAL_ERROR
            by_alg[alg]["fail"] += 1
            rows.append({"test_id": r["test_id"], "algorithm": alg,
                         "status": "fail", "detail": "calc returned INTERNAL_ERROR"})
            continue
        if not has_expected(vec):
            by_alg[alg]["fail"] += 1
            rows.append({"test_id": r["test_id"], "algorithm": alg,
                         "status": "fail", "detail": "expected output is placeholder"})
            continue

        grader = GRADERS.get(alg)
        if not grader:
            by_alg[alg]["fail"] += 1
            rows.append({"test_id": r["test_id"], "algorithm": alg,
                         "status": "fail", "detail": f"no grader for {alg}"})
            continue

        ok, detail = grader(r["result"], vec)
        if ok:
            by_alg[alg]["pass"] += 1
            rows.append({"test_id": r["test_id"], "algorithm": alg,
                         "status": "pass", "detail": "ok"})
        else:
            by_alg[alg]["fail"] += 1
            rows.append({"test_id": r["test_id"], "algorithm": alg,
                         "status": "fail", "detail": detail})

    # Find vectors that were in the JSON but missing from the calc's response
    seen_ids = {r["test_id"] for r in responses}
    for tid, vec in vectors_by_id.items():
        if tid not in seen_ids:
            by_alg[vec["algorithm"]]["fail"] += 1
            rows.append({"test_id": tid, "algorithm": vec["algorithm"],
                         "status": "fail", "detail": "no response received"})

    # Build markdown
    md_lines: list[str] = []
    md_lines.append("## ACVP Primitive Validation")
    md_lines.append("")
    md_lines.append("Vectors derived from NIST SP / IETF RFC published test sets; structurally")
    md_lines.append("equivalent to what the NIST ACVP demo server emits for the same algorithms.")
    md_lines.append("")
    md_lines.append("### Summary by Algorithm")
    md_lines.append("")
    md_lines.append("| Algorithm | Pass | Fail | Skip (placeholder) | Unsupported |")
    md_lines.append("|---|---:|---:|---:|---:|")
    total_pass = total_fail = total_skip = total_unsup = 0
    # DRBG-SHA-256 intentionally omitted from the pinned vector set; see
    # acvp_vectors.json $comment for the reasoning. Kept in the dispatcher
    # in src/main.c as a stub so the wiring is ready when a standalone
    # DRBG API lands.
    for alg in ["AES-GCM", "SHA-256", "HMAC-SHA-256", "HKDF-SHA-256",
                "RSA-PSS-SHA-256-VERIFY", "X25519-PUBLICKEY", "X25519-SECRET"]:
        c = by_alg.get(alg, {"pass": 0, "fail": 0, "skip": 0, "unsupported": 0})
        total_pass += c["pass"]
        total_fail += c["fail"]
        total_skip += c["skip"]
        total_unsup += c["unsupported"]
        md_lines.append(f"| {alg} | {c['pass']} | {c['fail']} | {c['skip']} | {c['unsupported']} |")
    md_lines.append(f"| **Total** | **{total_pass}** | **{total_fail}** | **{total_skip}** | **{total_unsup}** |")
    md_lines.append("")

    if warnings:
        md_lines.append("### Warnings")
        md_lines.append("")
        for w in warnings:
            md_lines.append(f"- {w}")
        md_lines.append("")

    failures = [r for r in rows if r["status"] == "fail"]
    if failures:
        md_lines.append("### Failures")
        md_lines.append("")
        md_lines.append("| test_id | algorithm | detail |")
        md_lines.append("|---:|---|---|")
        for r in failures:
            detail = r["detail"].replace("|", "\\|")
            md_lines.append(f"| {r['test_id']} | {r['algorithm']} | {detail} |")
        md_lines.append("")

    md_lines.append("<details><summary>All results</summary>")
    md_lines.append("")
    md_lines.append("| test_id | algorithm | status | detail |")
    md_lines.append("|---:|---|---|---|")
    for r in sorted(rows, key=lambda r: r["test_id"]):
        detail = r["detail"].replace("|", "\\|")
        md_lines.append(f"| {r['test_id']} | {r['algorithm']} | {r['status']} | {detail} |")
    md_lines.append("")
    md_lines.append("</details>")

    md_text = "\n".join(md_lines) + "\n"

    if args.markdown_out:
        Path(args.markdown_out).write_text(md_text)
    else:
        sys.stdout.write(md_text)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "summary": {
                "pass": total_pass, "fail": total_fail,
                "skip": total_skip, "unsupported": total_unsup,
                "warnings": len(warnings),
                "expected_vectors": len(vectors_by_id),
                "gradeable_vectors": len(expected_gradeable),
                "responses": len(responses),
            },
            "by_algorithm": by_alg,
            "results": rows,
            "warnings": warnings,
        }, indent=2))

    return 1 if failures or total_skip or total_unsup or warnings else 0


if __name__ == "__main__":
    sys.exit(main())
