#!/usr/bin/env python3
"""Run one isolated CEmu ACVP RPC service per primitive, concurrently."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from run_nettests import cleanup_namespace, namespace_for, setup_namespace


@dataclass(frozen=True)
class AcvpUnit:
    directory: str
    algorithm: str
    mode: str | None
    program: str


UNITS = (
    AcvpUnit("test_sha2_256", "SHA2-256", None, "AVS256"),
    AcvpUnit("test_sha2_384", "SHA2-384", None, "AVS384"),
    AcvpUnit("test_sha2_512", "SHA2-512", None, "AVS512"),
    AcvpUnit("test_hmac_sha2_256", "HMAC-SHA2-256", None, "AVH256"),
    AcvpUnit("test_hmac_sha2_384", "HMAC-SHA2-384", None, "AVH384"),
    AcvpUnit("test_hmac_sha2_512", "HMAC-SHA2-512", None, "AVH512"),
    AcvpUnit("test_aes_cbc", "ACVP-AES-CBC", None, "AVCBC"),
    AcvpUnit("test_aes_gcm", "ACVP-AES-GCM", None, "AVGCM"),
    AcvpUnit("test_aes_ccm", "ACVP-AES-CCM", None, "AVCCM"),
    AcvpUnit("test_pbkdf", "PBKDF", None, "AVPBKDF"),
    AcvpUnit("test_hkdf", "KDA", "HKDF", "AVHKDF"),
    AcvpUnit("test_rsa_sigver", "RSA", "sigVer", "AVRSA"),
    AcvpUnit("test_ecdsa_sigver", "ECDSA", "sigVer", "AVECDSA"),
    AcvpUnit("test_detecdsa_siggen", "DetECDSA", "sigGen", "AVDECD"),
    AcvpUnit("test_x25519_ssc", "XECDH", "SSC", "AVX255"),
    AcvpUnit("test_p256_cdh", "KAS-ECC", "CDH-Component", "AVP256"),
)


def worker_count(requested: int | None = None, cpu_count: int | None = None) -> int:
    """Return a worker count that never oversubscribes available CPUs."""
    available = max(1, cpu_count if cpu_count is not None else (os.cpu_count() or 1))
    limit = available if requested is None else min(requested, available)
    return min(max(1, limit), len(UNITS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def vectors(document: Any) -> list[dict]:
    return [item for item in document if isinstance(item, dict) and "vsId" in item]


def header(document: Any) -> list[dict]:
    return [item for item in document if isinstance(item, dict) and "acvVersion" in item]


def select_document(document: Any, unit: AcvpUnit) -> list[dict]:
    selected = [item for item in vectors(document)
                if item.get("algorithm") == unit.algorithm
                and (unit.mode is None or item.get("mode") == unit.mode)]
    if len(selected) != 1:
        raise ValueError(f"expected one vector set for {unit.algorithm}/{unit.mode}, found {len(selected)}")
    return [*header(document), *selected]


def select_expected(document: Any, prompt: list[dict]) -> list[dict]:
    wanted = {item["vsId"] for item in vectors(prompt)}
    return [*header(document), *[item for item in vectors(document) if item["vsId"] in wanted]]


def select_oracle(document: dict, unit: AcvpUnit) -> dict:
    return {
        "counts": {unit.algorithm: document.get("counts", {}).get(unit.algorithm, 0)},
        "x25519": document.get("x25519", {}) if unit.algorithm == "XECDH" else {},
        "p256": document.get("p256", {}) if unit.algorithm == "KAS-ECC" else {},
    }


def nested_unit(unit: AcvpUnit, report: dict | None, returncode: int,
                *, build_error: bool = False) -> dict:
    tests = []
    for row in (report or {}).get("tests", []):
        mode = row.get("mode") or "vector"
        tests.append({
            "test": f"{mode} #{row['tcId']}",
            "description": str(row.get("detail", "")),
            "status": "pass" if row.get("passed") else "fail",
        })
    if not tests:
        name = "Primitive build" if build_error else "Primitive execution"
        tests = [{"test": name, "description": name, "status": "fail" if returncode else "pass"}]
    result = {
        "unit": unit.directory.removeprefix("test_"),
        "description": f"{unit.algorithm}{f' {unit.mode}' if unit.mode else ''}",
        "status": "fail" if returncode or any(row["status"] == "fail" for row in tests) else "pass",
        "tests": tests,
    }
    if build_error:
        result["build_error"] = True
    return result


def run_worker(args: argparse.Namespace, unit: AcvpUnit, ns, validate_module) -> tuple[dict, list[dict]]:
    work = (args.artifacts_dir / unit.directory).resolve()
    work.mkdir(parents=True, exist_ok=True)
    prompt = select_document(args.prompt_document, unit)
    expected = select_expected(args.expected_document, prompt)
    oracle = select_oracle(args.oracle_document, unit)
    for name, value in (("prompt.json", prompt), ("expected.json", expected), ("oracle.json", oracle)):
        (work / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    test_dir = (args.tests_dir / unit.directory).resolve()
    build = subprocess.run(["make", "-C", str(test_dir)], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (work / "build.log").write_text(build.stdout or "", encoding="utf-8")
    if build.returncode:
        return nested_unit(unit, None, build.returncode, build_error=True), []

    binary = test_dir / "bin" / f"{unit.program}.8xp"
    response = work / "response.json"
    child = [
        "ip", "netns", "exec", ns.name,
        "env", f"AUTOTESTER_IMAGE={os.environ['AUTOTESTER_IMAGE']}",
        sys.executable, str((args.validation_dir / "run.py").resolve()),
        "--autotester", str(args.autotester.resolve()),
        "--usb", args.usb,
        "--vectors", str(work / "prompt.json"),
        "--expected", str(work / "expected.json"),
        "--oracle", str(work / "oracle.json"),
        "--response", str(response),
        "--program", unit.program,
        "--binary", str(binary),
        "--work-dir", str(work),
        "--timeout-ms", str(args.timeout_ms),
    ]
    try:
        run = subprocess.run(child, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=args.process_timeout)
        output, returncode = run.stdout or "", run.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        output, returncode = partial + "\nworker timed out\n", 124
    (work / "host.log").write_text(output, encoding="utf-8")

    response_document = json.loads(response.read_text()) if response.is_file() else []
    report = validate_module.validate_document(prompt, expected, response_document, oracle)
    (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return nested_unit(unit, report, returncode), vectors(response_document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests_dir", type=Path)
    parser.add_argument("--validation-dir", type=Path, required=True)
    parser.add_argument("--autotester", type=Path, required=True)
    parser.add_argument("--usb", required=True)
    parser.add_argument("--prompt", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--timeout-ms", type=int, default=60_000_000)
    parser.add_argument("--process-timeout", type=int, default=3600)
    parser.add_argument("--max-workers", type=int,
                        help="optional lower concurrency cap; never exceeds os.cpu_count()")
    args = parser.parse_args()

    image = os.environ.get("AUTOTESTER_IMAGE")
    if not image or not Path(image).is_file():
        parser.error("AUTOTESTER_IMAGE must point to the prepared CEmu state")
    if not args.autotester.is_file():
        parser.error(f"autotester does not exist: {args.autotester}")
    if not args.tests_dir.is_dir():
        parser.error(f"ACVP test directory does not exist: {args.tests_dir}")
    if not args.validation_dir.is_dir():
        parser.error(f"ACVP validation directory does not exist: {args.validation_dir}")
    if args.max_workers is not None and args.max_workers < 1:
        parser.error("--max-workers must be positive")
    if os.geteuid() != 0:
        parser.error("ACVP concurrency requires root network namespaces")
    args.prompt_document = json.loads(args.prompt.read_text())
    args.expected_document = json.loads(args.expected.read_text())
    args.oracle_document = json.loads(args.oracle.read_text())
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    args.response.parent.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    validate_module = load_module("acvp_validate", args.validation_dir / "validate.py")
    workers = worker_count(args.max_workers)
    print(f"ACVP concurrency: {workers} workers for {len(UNITS)} primitives "
          f"(cpu_count={os.cpu_count() or 1})", flush=True)
    namespaces = {}
    results = {}
    try:
        for index, unit in enumerate(UNITS):
            ns = namespace_for(index)
            namespaces[unit.directory] = ns
            setup_namespace(ns)
        # ThreadPoolExecutor keeps the remaining primitives queued until an
        # active CEmu process releases one of the CPU-sized worker slots.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(run_worker, args, unit, namespaces[unit.directory], validate_module): unit
                       for unit in UNITS}
            for future in concurrent.futures.as_completed(futures):
                unit = futures[future]
                try:
                    results[unit.directory] = future.result()
                except Exception as exc:  # noqa: BLE001
                    work = args.artifacts_dir / unit.directory
                    work.mkdir(parents=True, exist_ok=True)
                    (work / "host.log").write_text(f"{type(exc).__name__}: {exc}\n")
                    results[unit.directory] = (nested_unit(unit, None, 1), [])
    finally:
        for ns in namespaces.values():
            cleanup_namespace(ns)

    units = []
    combined_vectors = []
    for unit in UNITS:
        result, responses = results[unit.directory]
        units.append(result)
        combined_vectors.extend(responses)
        log = args.artifacts_dir / unit.directory / "host.log"
        if log.is_file():
            print(f"\n===== {unit.algorithm} =====\n{log.read_text()}", flush=True)

    response_document = [*header(args.prompt_document), *combined_vectors]
    args.response.write_text(json.dumps(response_document, indent=2) + "\n", encoding="utf-8")
    status = "fail" if any(unit["status"] == "fail" for unit in units) else "pass"
    report = [{"module": "acvp", "description": "ACVP primitive validation",
               "status": status, "units": units}]
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    failed = sum(unit["status"] == "fail" for unit in units)
    print(f"ACVP primitives: {len(units)} total, {len(units) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(main())
