#!/usr/bin/env python3
"""Run NIST ACVP vector sets through the calculator.

Two modes:

  Direct TCP (default) — connects to a real calculator over USB-ECM or any
  TCP host.  Processes each per-vsId file in vectors/ separately.

  CEmu (--cemu) — launches the calculator binary inside CEmu via the
  autotester, exactly like the acvp-fast workflow.  Processes the combined
  vectors/combined.json in a single session and writes
  responses/combined.json.

Typical flow (see acvp_offline.py for fetch/submit):

  1. acvp_offline.py fetch          # download vectors from NIST
  2. python3 run.py [--cemu ...]    # run against calc or CEmu
  3. acvp_offline.py submit         # upload responses to NIST
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS_DIR = HERE / "vectors"
RESPONSES_DIR = HERE / "responses"

# Reuse the protocol implementation from the offline validation harness.
sys.path.insert(0, str(HERE.parent / "validation" / "acvp"))
from acvp_client import AcvpError, SocketBackend, process_file  # noqa: E402

DEFAULT_HOST = "192.168.84.100"
DEFAULT_PORT = 7200
ACVP_PROGRAM = "ACVPRUN"


# ── CEmu control socket (mirrors tests/validation/acvp/run.py) ────────────────

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
                   binary: Path) -> None:
    relative = lambda item: os.path.relpath(item, path.parent)
    path.write_text(json.dumps({
        "description": "lwIP-CE ACVP live validation",
        "transfer_files": [relative(binary)],
        "target": {"name": ACVP_PROGRAM, "isASM": True},
        "sequence": ["delay|1000", usb, "action|launch", "hashWait|2", "delay|2000",
                     "key|enter"],
        "hashes": {
            "2": {"description": "ACVP service running",
                  "start": "vram_start", "size": "vram_8_size",
                  "expected_CRCs": [], "timeout": timeout_ms},
        },
    }, indent=2) + "\n")


def run_cemu(args: argparse.Namespace) -> int:
    combined = args.vectors / "combined.json"
    if not combined.exists():
        print(f"Combined vector file not found: {combined}", file=sys.stderr)
        print("Run: python3 acvp_offline.py fetch", file=sys.stderr)
        return 1

    args.responses.mkdir(parents=True, exist_ok=True)
    rsp_path = args.responses / "combined.json"

    Control()
    ready = threading.Event()
    outcome: dict[str, object] = {}

    def serve() -> None:
        try:
            with socket.create_server(("0.0.0.0", DEFAULT_PORT),
                                      reuse_port=False) as listener:
                listener.settimeout(max(300, args.timeout))
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(args.timeout)
                    backend = SocketBackend(connection)
                    outcome["response"] = process_file(combined, rsp_path, backend)
                    backend.stop()
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    if not ready.wait(10) or "error" in outcome:
        print(f"ACVP listener failed: {outcome.get('error', 'startup timeout')}",
              file=sys.stderr)
        return 1

    work_dir = HERE / "cemu_work"
    work_dir.mkdir(exist_ok=True)
    autotest = work_dir / "autotest.json"
    write_autotest(autotest, args.usb, args.timeout * 1000, args.binary)

    proc = subprocess.run([args.autotester, str(autotest)], cwd=work_dir)
    thread.join(timeout=10)

    if "error" in outcome:
        print(f"ACVP host error: {outcome['error']}", file=sys.stderr)
        return 1
    if thread.is_alive() or "response" not in outcome:
        print("ACVP host did not complete", file=sys.stderr)
        return 1

    print(f"CEmu run complete. Response written to {rsp_path}", flush=True)
    print("Next step: python3 acvp_offline.py submit", flush=True)
    return proc.returncode


# ── Direct TCP mode ────────────────────────────────────────────────────────────

def run_vector_set(vs_path: Path, rsp_path: Path, host: str, port: int,
                   timeout: int) -> bool:
    vsid = vs_path.stem
    print(f"vsId {vsid}: connecting to {host}:{port}", flush=True)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        print(f"  connection failed: {exc}", file=sys.stderr)
        return False
    try:
        sock.settimeout(timeout)
        backend = SocketBackend(sock)
        process_file(vs_path, rsp_path, backend)
        backend.stop()
    except AcvpError as exc:
        print(f"  ACVP error: {exc}", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"  socket error: {exc}", file=sys.stderr)
        return False
    finally:
        sock.close()
    n = len(json.loads(rsp_path.read_text()).get("testGroups", []))
    print(f"  vsId {vsid}: done ({n} group(s) → {rsp_path.name})", flush=True)
    return True


def run_direct(args: argparse.Namespace) -> int:
    vectors_dir: Path = args.vectors
    responses_dir: Path = args.responses

    if not vectors_dir.exists():
        print(f"Vectors directory not found: {vectors_dir}", file=sys.stderr)
        print("Run: python3 acvp_offline.py fetch", file=sys.stderr)
        return 1

    responses_dir.mkdir(parents=True, exist_ok=True)

    if args.vsid:
        files = []
        for vsid in args.vsid:
            p = vectors_dir / f"{vsid}.json"
            if not p.exists():
                print(f"Vector set not found: {p}", file=sys.stderr)
                return 1
            files.append(p)
    else:
        files = [f for f in sorted(vectors_dir.glob("*.json"))
                 if f.name != "combined.json"]
        if not files:
            print(f"No vector sets in {vectors_dir}", file=sys.stderr)
            return 1

    print(f"Processing {len(files)} vector set(s) against {args.host}:{args.port}",
          flush=True)

    failed = []
    for vs_path in files:
        rsp_path = responses_dir / vs_path.name
        if not run_vector_set(vs_path, rsp_path, args.host, args.port, args.timeout):
            failed.append(vs_path.stem)

    if failed:
        print(f"\nFailed vector sets: {', '.join(failed)}", file=sys.stderr)
        return 1

    print(f"\nAll {len(files)} vector set(s) complete. Responses in {responses_dir}/",
          flush=True)
    print("Next step: python3 acvp_offline.py submit", flush=True)
    return 0


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run NIST ACVP vectors through the calculator"
    )
    parser.add_argument("--vectors", type=Path, default=VECTORS_DIR)
    parser.add_argument("--responses", type=Path, default=RESPONSES_DIR)
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Socket / CEmu timeout in seconds (default: 3600)")

    cemu = parser.add_argument_group("CEmu mode (--cemu)")
    cemu.add_argument("--cemu", action="store_true",
                      help="Run inside CEmu via autotester instead of direct TCP")
    cemu.add_argument("--autotester", help="Path to autotester binary")
    cemu.add_argument("--usb", help="Autotester USB plug sequence step")
    cemu.add_argument("--binary", type=Path,
                      help="Path to ACVPRUN.8xp calculator binary")

    tcp = parser.add_argument_group("Direct TCP mode (default)")
    tcp.add_argument("--host", default=DEFAULT_HOST)
    tcp.add_argument("--port", type=int, default=DEFAULT_PORT)
    tcp.add_argument("vsid", nargs="*", type=int,
                     help="Specific vsId(s) to process (default: all)")

    args = parser.parse_args()

    if args.cemu:
        missing = [f"--{k}" for k in ("autotester", "usb", "binary")
                   if not getattr(args, k)]
        if missing:
            print(f"CEmu mode requires: {', '.join(missing)}", file=sys.stderr)
            return 1
        return run_cemu(args)
    return run_direct(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AcvpError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ACVP error: {exc}", file=sys.stderr)
        sys.exit(1)
