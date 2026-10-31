#!/usr/bin/env python3
"""Build and run every libFuzzer target concurrently.

The existing ``tests/fuzz`` make targets remain the per-target engine.  This
runner only supplies concurrency, isolated logs, and the common nested JSON
report used by the unit, network, and ACVP batch runners.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


TARGETS = ("json", "xml", "url", "base64", "asn1", "pcap", "x509", "ws", "tls")
STAT_PATTERN = re.compile(r"^stat::([a-zA-Z0-9_]+):\s*(.*?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class FuzzResult:
    target: str
    returncode: int
    duration_ms: int
    stats: dict[str, str]
    build_error: bool = False


def parse_stats(output: str) -> dict[str, str]:
    return {name: value for name, value in STAT_PATTERN.findall(output)}


def stats_text(result: FuzzResult) -> str:
    parts = [f"{result.duration_ms} ms"]
    executed = result.stats.get("number_of_executed_units")
    rate = result.stats.get("average_exec_per_sec")
    rss = result.stats.get("peak_rss_mb")
    if executed is not None:
        parts.append(f"{executed} executions")
    if rate is not None:
        parts.append(f"{rate} exec/s")
    if rss is not None:
        parts.append(f"{rss} MiB peak RSS")
    return "; ".join(parts)


def nested_unit(result: FuzzResult) -> dict:
    status = "pass" if result.returncode == 0 else "fail"
    test_name = "Harness build" if result.build_error else "Fuzz campaign"
    unit = {
        "unit": result.target,
        "description": f"libFuzzer target {result.target}",
        "status": status,
        "tests": [{
            "test": test_name,
            "description": stats_text(result),
            "status": status,
        }],
    }
    if result.build_error:
        unit["build_error"] = True
    return unit


def run_target(args: argparse.Namespace, target: str) -> FuzzResult:
    log_path = args.artifacts_dir / f"{target}.log"
    started = time.monotonic()
    build = subprocess.run(
        ["make", "-C", str(args.tests_dir), f"bin/fuzz_{target}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = build.stdout or ""
    if build.returncode:
        duration = round((time.monotonic() - started) * 1000)
        log_path.write_text(output, encoding="utf-8")
        return FuzzResult(target, build.returncode, duration, {}, build_error=True)

    command = [
        "make", "-C", str(args.tests_dir), f"run-{target}",
        f"FUZZ_SECONDS={args.seconds}",
    ]
    try:
        run = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=args.process_timeout,
        )
        output += run.stdout or ""
        returncode = run.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        output += partial + f"\n{target}: fuzz process timed out\n"
        returncode = 124
    duration = round((time.monotonic() - started) * 1000)
    log_path.write_text(output, encoding="utf-8")
    return FuzzResult(target, returncode, duration, parse_stats(output))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests_dir", type=Path)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--target", action="append", choices=TARGETS)
    parser.add_argument("--max-workers", type=int, default=len(TARGETS))
    parser.add_argument("--process-timeout", type=int)
    args = parser.parse_args()

    if not args.tests_dir.is_dir():
        parser.error(f"fuzz test directory does not exist: {args.tests_dir}")
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    if args.max_workers < 1:
        parser.error("--max-workers must be positive")
    if args.process_timeout is None:
        args.process_timeout = args.seconds + 300
    targets = args.target or list(TARGETS)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.rows.parent.mkdir(parents=True, exist_ok=True)

    results: dict[str, FuzzResult] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(args.max_workers, len(targets))
    ) as pool:
        futures = {pool.submit(run_target, args, target): target for target in targets}
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                results[target] = future.result()
            except Exception as exc:  # noqa: BLE001
                log = args.artifacts_dir / f"{target}.log"
                log.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
                results[target] = FuzzResult(target, 1, 0, {})

    units = [nested_unit(results[target]) for target in targets]
    status = "fail" if any(unit["status"] == "fail" for unit in units) else "pass"
    report = [{
        "module": "fuzz",
        "description": "Host libFuzzer campaigns",
        "status": status,
        "units": units,
    }]
    rows = [{
        "group": "FUZZ",
        "module": "FUZZ",
        "test": result.target,
        "grade": "Pass" if result.returncode == 0 else "Fail",
        "stats": stats_text(result),
    } for result in (results[target] for target in targets)]
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.rows.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    for target in targets:
        log = args.artifacts_dir / f"{target}.log"
        if log.is_file():
            print(f"\n===== {target} =====\n{log.read_text()}", flush=True)
    failed = sum(result.returncode != 0 for result in results.values())
    print(f"Fuzz targets: {len(targets)} total, {len(targets) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(main())
