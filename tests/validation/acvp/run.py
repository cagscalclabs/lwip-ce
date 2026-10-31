#!/usr/bin/env python3
"""Run ACVP vector-set JSON through lwip.lib inside networked CEmu."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

from acvp_client import AcvpError, SocketBackend, process_file
from validate import validate_document

HERE = Path(__file__).resolve().parent
VERDICT_CRCS = ["A511C030", "22D544B5"]
CRASH_CRC = "93BFC41E"


class Control:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 7000))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            data, address = self.socket.recvfrom(256)
            sequence = data.split(b" ", 1)[0]
            self.socket.sendto(sequence + b" OK", address)


def write_autotest(path: Path, usb: str, timeout_ms: int,
                   program: str, binary: Path) -> None:
    relative = lambda item: os.path.relpath(item, path.parent)
    files = [relative(binary)]
    path.write_text(json.dumps({
        "description": "lwIP-CE ACVP network validation",
        "transfer_files": files,
        "target": {"name": program, "isASM": True},
        "sequence": ["delay|1000", usb, "action|launch", "hashWait|2", "delay|2000",
                     "saveVar|NETLOG", "key|enter"],
        "hashes": {
            "2": {"description": "ACVP service finished", "start": "vram_start", "size": "vram_8_size",
                  "expected_CRCs": VERDICT_CRCS + [CRASH_CRC], "timeout": timeout_ms},
        },
    }, indent=2) + "\n")


def read_log(path: Path) -> str:
    data = path.read_bytes()
    length = int.from_bytes(data[0x48:0x4A], "little")
    return data[0x4A:0x4A + length].decode("latin-1")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autotester", required=True)
    parser.add_argument("--usb", required=True)
    parser.add_argument("--vectors", type=Path, default=HERE / "corpus" / "prompt.json")
    parser.add_argument("--expected", type=Path, default=HERE / "corpus" / "expected.json")
    parser.add_argument("--oracle", type=Path, default=HERE / "corpus" / "oracle.json")
    parser.add_argument("--response", type=Path, default=HERE / "response.json")
    parser.add_argument("--program", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, default=HERE)
    # CEmu's autotester deadline advances with emulated time.  Full ACVP
    # Monte Carlo groups perform hundreds of thousands of primitive calls, so
    # use the same generous allowance as the legacy CAVP profiling harness.
    parser.add_argument("--timeout-ms", type=int, default=60000000)
    args = parser.parse_args()

    Control()
    ready = threading.Event()
    outcome: dict[str, object] = {}

    def serve() -> None:
        try:
            with socket.create_server(("0.0.0.0", 7200), reuse_port=False) as listener:
                listener.settimeout(max(300, args.timeout_ms // 1000))
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(300)
                    backend = SocketBackend(connection)
                    outcome["response"] = process_file(args.vectors, args.response, backend)
                    backend.stop()
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    if not ready.wait(10) or "error" in outcome:
        print(f"ACVP listener failed: {outcome.get('error', 'startup timeout')}", file=sys.stderr)
        return 1
    args.work_dir.mkdir(parents=True, exist_ok=True)
    autotest = args.work_dir / "autotest.json"
    log_path = args.work_dir / "NETLOG.8xv"
    log_path.unlink(missing_ok=True)
    write_autotest(autotest, args.usb, args.timeout_ms, args.program, args.binary)
    proc = subprocess.run([args.autotester, str(autotest)], cwd=args.work_dir)
    thread.join(timeout=10)

    if "error" in outcome:
        print(f"ACVP host error: {outcome['error']}", file=sys.stderr)
        return 1
    if thread.is_alive() or "response" not in outcome:
        print("ACVP host did not complete", file=sys.stderr)
        return 1
    report = validate_document(json.loads(args.vectors.read_text()),
                               json.loads(args.expected.read_text()),
                               outcome["response"], json.loads(args.oracle.read_text()))
    if not report["passed"]:
        failures = [row for row in report["tests"] if not row["passed"]]
        print(f"ACVP corpus failed {len(failures)}/{report['total']} vectors", file=sys.stderr)
        for row in failures[:20]:
            print(f"  {row['algorithm']} tcId {row['tcId']}: {row['detail']}", file=sys.stderr)
        return 1
    if not log_path.exists():
        print("calculator did not produce NETLOG", file=sys.stderr)
        return 1
    log = read_log(log_path)
    print(log)
    failed = any(line.startswith("FAIL ") for line in log.splitlines())
    return 1 if proc.returncode or failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AcvpError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ACVP error: {exc}", file=sys.stderr)
        sys.exit(1)
