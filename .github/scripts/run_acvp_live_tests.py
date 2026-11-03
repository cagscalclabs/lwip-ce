#!/usr/bin/env python3
"""Process live NIST ACVP vector sets concurrently in isolated CEmu instances."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from run_nettests import cleanup_namespace, namespace_for, setup_namespace


@dataclass(frozen=True)
class LiveUnit:
    index: int
    vsid: int
    algorithm: str
    mode: str | None
    vector: dict

    @property
    def name(self) -> str:
        label = re.sub(r"[^A-Za-z0-9]+", "_", self.algorithm).strip("_").lower()
        return f"{self.index:02d}_{label}_{self.vsid}"


def document_parts(document: Any) -> tuple[dict | None, list[dict]]:
    if not isinstance(document, list) or not document:
        raise ValueError("combined vector document must be a non-empty array")
    header = (document[0] if isinstance(document[0], dict) and
              "acvVersion" in document[0] else None)
    vectors = document[1:] if header else document
    if not vectors or not all(isinstance(item, dict) and
                              isinstance(item.get("vsId"), int) and
                              isinstance(item.get("algorithm"), str)
                              for item in vectors):
        raise ValueError("combined vector document contains malformed vector sets")
    vsids = [item["vsId"] for item in vectors]
    if len(vsids) != len(set(vsids)):
        raise ValueError("combined vector document contains duplicate vsIds")
    return header, vectors


def make_units(document: Any) -> tuple[dict | None, list[LiveUnit]]:
    header, vectors = document_parts(document)
    return header, [
        LiveUnit(index, vector["vsId"], vector["algorithm"],
                 vector.get("mode"), vector)
        for index, vector in enumerate(vectors)
    ]


def worker_count(unit_count: int, requested: int | None = None,
                 cpu_count: int | None = None) -> int:
    available = max(1, cpu_count if cpu_count is not None else (os.cpu_count() or 1))
    limit = available if requested is None else min(requested, available)
    return min(unit_count, max(1, limit))


def response_for_unit(path: Path, unit: LiveUnit) -> dict:
    if not path.is_file():
        raise RuntimeError(f"{unit.algorithm} produced no response document")
    document = json.loads(path.read_text())
    if not isinstance(document, list) or not document:
        raise RuntimeError(f"{unit.algorithm} produced a malformed response document")
    offset = (1 if isinstance(document[0], dict) and
              "acvVersion" in document[0] else 0)
    responses = document[offset:]
    if (len(responses) != 1 or not isinstance(responses[0], dict) or
            responses[0].get("vsId") != unit.vsid):
        found = [item.get("vsId") for item in responses if isinstance(item, dict)]
        raise RuntimeError(
            f"{unit.algorithm} response vsId mismatch: expected {unit.vsid}, found {found}"
        )
    return responses[0]


def combine_responses(header: dict | None, units: list[LiveUnit],
                      responses: dict[int, dict]) -> list[dict]:
    expected = {unit.vsid for unit in units}
    missing = [unit.vsid for unit in units if unit.vsid not in responses]
    unexpected = [vsid for vsid in responses if vsid not in expected]
    if missing or unexpected:
        raise RuntimeError(
            f"incomplete concurrent response set: missing={missing}, unexpected={unexpected}"
        )
    ordered = [responses[unit.vsid] for unit in units]
    for unit, response in zip(units, ordered):
        if response.get("vsId") != unit.vsid:
            raise RuntimeError(f"response ordering failed for vsId {unit.vsid}")
    return ([header] if header else []) + ordered


def run_streamed(command: list[str], log_path: Path, prefix: str,
                 timeout: int) -> int:
    """Run one worker with live prefixed output and bounded process lifetime."""
    process = subprocess.Popen(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, start_new_session=True,
    )
    lines: list[str] = []

    def drain() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line)
            print(f"[{prefix}] {line}", end="", flush=True)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        message = f"worker exceeded its {timeout}-second wall-clock timeout\n"
        lines.append(message)
        print(f"[{prefix}] {message}", end="", file=sys.stderr, flush=True)
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        returncode = 124
    reader.join(timeout=10)
    if process.stdout is not None:
        process.stdout.close()
    log_path.write_text("".join(lines), encoding="utf-8")
    return returncode


def run_worker(args: argparse.Namespace, unit: LiveUnit, namespace) -> tuple[int, dict | None]:
    work = (args.artifacts_dir / unit.name).resolve()
    vectors = work / "vectors"
    responses = work / "responses"
    cemu_work = work / "cemu_work"
    vectors.mkdir(parents=True, exist_ok=True)
    responses.mkdir(parents=True, exist_ok=True)
    prompt = ([args.header] if args.header else []) + [unit.vector]
    (vectors / "combined.json").write_text(
        json.dumps(prompt, indent=2) + "\n", encoding="utf-8"
    )

    child = [
        "ip", "netns", "exec", namespace.name,
        "env", f"AUTOTESTER_IMAGE={os.environ['AUTOTESTER_IMAGE']}",
        sys.executable, str(args.runner.resolve()),
        "--cemu",
        "--autotester", str(args.autotester.resolve()),
        "--usb", args.usb,
        "--binary", str(args.binary.resolve()),
        "--vectors", str(vectors),
        "--responses", str(responses),
        "--work-dir", str(cemu_work),
        "--timeout", str(args.socket_timeout),
        "--autotester-timeout-ms", str(args.autotester_timeout_ms),
    ]
    returncode = run_streamed(
        child, work / "host.log", f"{unit.vsid} {unit.algorithm}",
        args.process_timeout,
    )
    if returncode:
        return returncode, None
    try:
        return 0, response_for_unit(responses / "combined.json", unit)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        with (work / "host.log").open("a", encoding="utf-8") as stream:
            stream.write(f"\nresponse validation failed: {exc}\n")
        return 1, None


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True,
                        help="Per-CEmu live runner (tests/acvp-live/run.py)")
    parser.add_argument("--autotester", type=Path, required=True)
    parser.add_argument("--usb", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--vectors", type=Path, required=True,
                        help="Combined NIST prompt document")
    parser.add_argument("--response", type=Path, required=True,
                        help="Combined response document to create")
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--socket-timeout", type=int, default=21600)
    parser.add_argument("--autotester-timeout-ms", type=int, default=600_000_000)
    parser.add_argument("--process-timeout", type=int, default=18000)
    parser.add_argument("--max-workers", type=int,
                        help="optional concurrency cap; never exceeds CPU count")
    args = parser.parse_args()

    image = os.environ.get("AUTOTESTER_IMAGE")
    if not image or not Path(image).is_file():
        parser.error("AUTOTESTER_IMAGE must point to the prepared CEmu state")
    for label, path in (("autotester", args.autotester), ("binary", args.binary),
                        ("runner", args.runner), ("vectors", args.vectors)):
        if not path.is_file():
            parser.error(f"{label} does not exist: {path}")
    if args.max_workers is not None and args.max_workers < 1:
        parser.error("--max-workers must be positive")
    if os.geteuid() != 0:
        parser.error("concurrent CEmu execution requires root network namespaces")

    args.header, units = make_units(json.loads(args.vectors.read_text()))
    workers = worker_count(len(units), args.max_workers)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    args.response.parent.mkdir(parents=True, exist_ok=True)
    args.response.unlink(missing_ok=True)
    print(f"ACVP live concurrency: {workers} workers for {len(units)} vector sets "
          f"(cpu_count={os.cpu_count() or 1})", flush=True)

    namespaces = {}
    results: dict[int, tuple[int, dict | None]] = {}
    try:
        for unit in units:
            namespace = namespace_for(unit.index)
            namespaces[unit.vsid] = namespace
            setup_namespace(namespace)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(run_worker, args, unit, namespaces[unit.vsid]): unit
                for unit in units
            }
            for future in concurrent.futures.as_completed(futures):
                unit = futures[future]
                try:
                    results[unit.vsid] = future.result()
                except Exception as exc:  # noqa: BLE001
                    work = args.artifacts_dir / unit.name
                    work.mkdir(parents=True, exist_ok=True)
                    (work / "host.log").write_text(
                        f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                    )
                    results[unit.vsid] = (1, None)
                status = "PASS" if results[unit.vsid][0] == 0 else "FAIL"
                print(f"[{status}] vsId {unit.vsid} {unit.algorithm}", flush=True)
    finally:
        for namespace in namespaces.values():
            cleanup_namespace(namespace)

    responses = {
        vsid: response for vsid, (status, response) in results.items()
        if status == 0 and response is not None
    }
    # Preserve successful partial work for diagnostics, but only return success
    # when every registered vector set is present and correctly ordered.
    partial = ([args.header] if args.header else []) + [
        responses[unit.vsid] for unit in units if unit.vsid in responses
    ]
    atomic_json(args.response, partial)
    failed = [unit for unit in units
              if unit.vsid not in results or results[unit.vsid][0] != 0]
    if failed:
        print("Failed live vector sets: " + ", ".join(
            f"{unit.vsid} ({unit.algorithm})" for unit in failed
        ), file=sys.stderr)
        return 1

    atomic_json(args.response, combine_responses(args.header, units, responses))
    print(f"All {len(units)} live vector sets completed; response: {args.response}",
          flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ACVP live concurrency error: {exc}", file=sys.stderr)
        sys.exit(1)
