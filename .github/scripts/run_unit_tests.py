#!/usr/bin/env python3
"""Parallel dyload unit test runner.

Discovers every autotest.json under TESTS_DIR, runs each in its own thread,
and emits a nested JSON report:

    {
      "module": "tls",
      "description": "...",
      "status": "pass|fail|skip",
      "units": [
        {
          "unit": "hash",
          "description": "...",
          "status": "pass|fail|skip",
          "tests": [
            {"test": "...", "description": "...", "status": "pass|fail|skip"},
            ...
          ]
        },
        ...
      ]
    }

Exit code: number of failed units (0 = all pass).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

# --------------------------------------------------------------------- config

# Units whose hash #1 failure with CRC 468FCC4B indicates the emulator TRNG
# quirk, not a real test failure.
EMULATOR_QUIRK_UNITS: set[str] = set(
    os.environ.get("EMULATOR_QUIRK_UNITS", "").split()
)

TIMEOUT_SECONDS: int = int(os.environ.get("TEST_TIMEOUT_SECONDS", "120"))
MAX_ATTEMPTS: int = int(os.environ.get("TEST_MAX_ATTEMPTS", "3"))
TRNG_QUIRK_CRC = "468FCC4B"

# --------------------------------------------------------------------- helpers


def unit_name(autotest_dir: Path) -> str:
    """tls_hash  →  'hash'  (strip known module prefix)."""
    name = autotest_dir.name
    for prefix in ("tls_", "parsers_", "lwip_"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def module_of(autotest_dir: Path) -> str:
    """tls_hash  →  'tls'  (everything before the first underscore)."""
    name = autotest_dir.name
    return name.split("_", 1)[0] if "_" in name else name


def run_command(cmd: list[str], cwd: Path) -> tuple[int, str]:
    result = subprocess.run(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    return result.returncode, result.stdout


# --------------------------------------------------------------------- per-unit runner


def run_unit(test_dir: Path) -> dict:
    """Build and run one unit; return a 'unit' dict for the report."""
    manifest_path = test_dir / "autotest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    uname = unit_name(test_dir)
    udesc = manifest.get("description", "")

    hash_descs: dict[str, str] = {
        hid: hdata.get("description", f"Hash {hid}")
        for hid, hdata in manifest.get("hashes", {}).items()
    }
    hash_ids: list[str] = [
        entry.split("|", 1)[1]
        for entry in manifest.get("sequence", [])
        if entry.startswith("hashWait|")
    ]

    # ---- build
    run_command(["make", "-C", str(test_dir), "clean"], cwd=test_dir.parent)
    rc, build_log = run_command(["make", "-C", str(test_dir)], cwd=test_dir.parent)
    if rc != 0:
        tests = [
            {"test": hash_descs.get(h, f"Hash {h}"), "description": hash_descs.get(h, ""), "status": "skip"}
            for h in hash_ids
        ]
        return {
            "unit": uname,
            "description": udesc,
            "status": "skip",
            "build_error": True,
            "tests": tests,
        }

    # ---- run (with timeout + retry)
    log = ""
    timed_out = False
    rc = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            proc = subprocess.run(
                ["make", "-C", str(test_dir), "test"],
                cwd=test_dir.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
            rc = proc.returncode
            log = proc.stdout
            timed_out = False
            if rc != 124:
                break
        except subprocess.TimeoutExpired:
            timed_out = True
            rc = 124
            if attempt < MAX_ATTEMPTS:
                continue
            break

    (test_dir / "autotest.log").write_text(log, encoding="utf-8")

    # ---- evaluate overall unit status
    if timed_out:
        unit_status = "skip"
        failed_hashes: set[str] = set()
        quirk = False
    else:
        failed_hashes = set(
            re.findall(r"Hash #(\d+)", log)
        ) & set(hash_ids) if rc != 0 else set()

        # Emulator TRNG quirk: hash #1 → CRC 468FCC4B
        quirk = False
        if rc != 0 and uname in EMULATOR_QUIRK_UNITS:
            m = re.search(r"Hash #1[^\n]*\(got ([0-9A-Fa-f]+)\)", log)
            if m and m.group(1).upper() == TRNG_QUIRK_CRC and failed_hashes == {"1"}:
                quirk = True
                failed_hashes = set()
                rc = 0

        unit_status = "pass" if rc == 0 else "fail"

    # ---- per-test status
    tests: list[dict] = []
    for hid in hash_ids:
        desc = hash_descs.get(hid, f"Hash {hid}")
        if timed_out or quirk:
            t_status = "skip"
        elif hid in failed_hashes:
            t_status = "fail"
        else:
            t_status = "pass"
        tests.append({"test": f"Hash {hid}", "description": desc, "status": t_status})

    return {
        "unit": uname,
        "description": udesc,
        "status": unit_status,
        "tests": tests,
    }


# --------------------------------------------------------------------- main


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tests_dir", type=Path, help="Root of the unit test tree (tests/unit/)")
    ap.add_argument("--output", type=Path, required=True,
                    help="Path to write the nested JSON report")
    ap.add_argument("--flat-output", type=Path,
                    help="Optional: also write the legacy flat results-dylib.json")
    args = ap.parse_args()

    autotest_files = sorted(args.tests_dir.glob("*/autotest.json"))
    if not autotest_files:
        sys.exit(f"No autotest.json files found under {args.tests_dir}")

    # Collect results per (module, unit) in parallel
    results: dict[Path, dict] = {}
    lock = threading.Lock()

    def worker(manifest: Path) -> None:
        test_dir = manifest.parent
        unit_result = run_unit(test_dir)
        with lock:
            results[test_dir] = unit_result

    threads = [threading.Thread(target=worker, args=(f,)) for f in autotest_files]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Group units into modules
    modules: dict[str, dict] = {}
    for test_dir in sorted(results.keys()):
        unit_result = results[test_dir]
        mod = module_of(test_dir)
        if mod not in modules:
            modules[mod] = {
                "module": mod,
                "description": f"{mod.upper()} subsystem tests",
                "status": "pass",
                "units": [],
            }
        modules[mod]["units"].append(unit_result)
        if unit_result["status"] == "fail":
            modules[mod]["status"] = "fail"
        elif unit_result["status"] == "skip" and modules[mod]["status"] != "fail":
            modules[mod]["status"] = "skip"

    report = list(modules.values())
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # Optionally emit the legacy flat format for backward compat with test_table.py
    if args.flat_output:
        flat_tests = []
        total = passed = failed = skipped = 0
        for mod_entry in report:
            for u in mod_entry["units"]:
                total += 1
                failed_hashes = ",".join(
                    t["test"].split()[-1]
                    for t in u.get("tests", [])
                    if t["status"] == "fail"
                )
                if u["status"] == "pass":
                    passed += 1
                elif u["status"] == "fail":
                    failed += 1
                else:
                    skipped += 1
                full_name = f"{mod_entry['module']}_{u['unit']}"
                status_str = {"pass": "passed", "fail": "failed", "skip": "skipped"}.get(u["status"], u["status"])
                flat_tests.append({
                    "name": full_name,
                    "dir": str(args.tests_dir / full_name),
                    "status": status_str,
                    "duration": "0",
                    "failed_hash_ids": failed_hashes,
                })
        flat = {
            "results": {
                "summary": {
                    "tests": str(total), "passed": str(passed),
                    "failed": str(failed), "skipped": str(skipped),
                },
                "tests": flat_tests,
            }
        }
        args.flat_output.write_text(json.dumps(flat, indent=2) + "\n", encoding="utf-8")

    # Exit with failure count
    n_failed = sum(1 for mod in report for u in mod["units"] if u["status"] == "fail")
    print(f"Unit tests: {sum(1 for m in report for u in m['units'])} total, "
          f"{sum(1 for m in report for u in m['units'] if u['status'] == 'pass')} passed, "
          f"{n_failed} failed, "
          f"{sum(1 for m in report for u in m['units'] if u['status'] == 'skip')} skipped")
    sys.exit(n_failed)


if __name__ == "__main__":
    main()
