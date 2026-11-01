#!/usr/bin/env python3
"""Validate deterministic and generated-key ACVP corpus responses."""

from __future__ import annotations

from typing import Any


def vector_sets(document: Any) -> dict[int, dict]:
    return {int(item["vsId"]): item for item in document
            if isinstance(item, dict) and "vsId" in item}


def groups(vector: dict) -> dict[int, dict]:
    return {int(group["tgId"]): group for group in vector.get("testGroups", [])}


def tests(group: dict) -> dict[int, dict]:
    return {int(test["tcId"]): test for test in group.get("tests", [])}


def _semantic_generated(algorithm: str, prompt_group: dict, response_group: dict,
                        prompt_test: dict, actual: dict, oracle: dict,
                        seen: dict[tuple[int, str], tuple[str, str]]) -> tuple[bool, str]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519
        tc_id = int(prompt_test["tcId"])
        if algorithm == "DetECDSA":
            curve_name = prompt_group.get("curve", "P-256")
            if curve_name == "P-384":
                curve, hash_algo = ec.SECP384R1(), hashes.SHA384()
            else:
                curve, hash_algo = ec.SECP256R1(), hashes.SHA256()
            qx, qy = int(response_group["qx"], 16), int(response_group["qy"], 16)
            public = ec.EllipticCurvePublicNumbers(qx, qy, curve).public_key()
            r, s = int(actual["r"], 16), int(actual["s"], 16)
            signature = utils.encode_dss_signature(r, s)
            message = bytes.fromhex(prompt_test["message"])
            public.verify(signature, message, ec.ECDSA(hash_algo))
            key = (int(prompt_group["tgId"]), prompt_test["message"])
            value = (actual["r"].upper(), actual["s"].upper())
            if key in seen and seen[key] != value:
                return False, "RFC 6979 signature changed for a repeated message"
            seen[key] = value
            return True, "signature valid and deterministic"
        if algorithm == "XECDH":
            server = x25519.X25519PrivateKey.from_private_bytes(
                bytes.fromhex(oracle["x25519"][str(tc_id)]))
            public = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(actual["publicIut"]))
            return (server.exchange(public) == bytes.fromhex(actual["z"]),
                    "shared secret matched independent host computation")
        if algorithm == "KAS-ECC":
            curve_name = prompt_group.get("curve", "P-256")
            if curve_name == "P-384":
                curve = ec.SECP384R1()
                scalar = int(oracle["p384"][str(tc_id)], 16)
            else:
                curve = ec.SECP256R1()
                scalar = int(oracle["p256"][str(tc_id)], 16)
            server = ec.derive_private_key(scalar, curve)
            public = ec.EllipticCurvePublicNumbers(int(actual["publicIutX"], 16),
                                                   int(actual["publicIutY"], 16),
                                                   curve).public_key()
            return (server.exchange(ec.ECDH(), public) == bytes.fromhex(actual["z"]),
                    "shared secret matched independent host computation")
    except (KeyError, ValueError, InvalidSignature) as exc:
        return False, f"semantic validation failed: {exc}"
    return False, "no semantic validator"


def validate_document(prompt: Any, expected: Any, response: Any | None,
                      oracle: dict) -> dict[str, Any]:
    prompt_sets, expected_sets = vector_sets(prompt), vector_sets(expected)
    response_sets = vector_sets(response or [])
    rows: list[dict[str, Any]] = []
    seen: dict[tuple[int, str], tuple[str, str]] = {}
    generated = {"DetECDSA", "XECDH", "KAS-ECC"}
    for vs_id, vector in prompt_sets.items():
        algorithm = vector["algorithm"]
        response_vector = response_sets.get(vs_id, {})
        expected_vector = expected_sets.get(vs_id, {})
        response_groups, expected_groups = groups(response_vector), groups(expected_vector)
        for prompt_group in vector.get("testGroups", []):
            tg_id = int(prompt_group["tgId"])
            response_group = response_groups.get(tg_id, {})
            actual_tests, wanted_tests = tests(response_group), tests(expected_groups.get(tg_id, {}))
            mode = "/".join(str(value) for value in
                            (vector.get("mode"), prompt_group.get("testType"), prompt_group.get("direction"))
                            if value)
            for prompt_test in prompt_group.get("tests", []):
                tc_id = int(prompt_test["tcId"]); actual = actual_tests.get(tc_id)
                if actual is None:
                    passed, detail = False, "response missing"
                elif algorithm in generated:
                    passed, detail = _semantic_generated(algorithm, prompt_group, response_group,
                                                         prompt_test, actual, oracle, seen)
                else:
                    wanted = wanted_tests.get(tc_id)
                    passed = wanted is not None and actual == wanted
                    detail = "matched independent reference" if passed else "response mismatch"
                rows.append({"vsId": vs_id, "tgId": tg_id, "tcId": tc_id,
                             "algorithm": algorithm, "revision": vector.get("revision", ""),
                             "mode": mode, "passed": passed, "detail": detail})
    passed = sum(bool(row["passed"]) for row in rows)
    return {"passed": passed == len(rows) and bool(rows), "total": len(rows),
            "passedTests": passed, "failedTests": len(rows) - passed, "tests": rows}
