#!/usr/bin/env python3
"""Run NIST ACVP vector sets through the calculator over a direct TCP connection.

The calculator runs ACVPRUN.8xp, which listens on --port and accepts the same
ACV1/ACR1 binary protocol as the offline validation harness.  This script
feeds each vector set from vectors/ one vector at a time, collects responses,
and writes per-vsId response files to responses/.

Typical flow (see acvp_offline.py for fetch/submit):

  1. acvp_offline.py fetch          # download vectors from NIST
  2. python3 run.py                 # run against calc (USB-ECM or TCP)
  3. acvp_offline.py submit         # upload responses to NIST
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS_DIR = HERE / "vectors"
RESPONSES_DIR = HERE / "responses"

# acvp_client.py lives one directory up in the offline validation harness.
# Add it to the search path so we can reuse the same protocol implementation.
sys.path.insert(0, str(HERE.parent / "validation" / "acvp"))
from acvp_client import AcvpError, SocketBackend, process_file  # noqa: E402


DEFAULT_HOST = "192.168.84.100"
DEFAULT_PORT = 7200


def run_vector_set(vs_path: Path, rsp_path: Path, host: str, port: int,
                   timeout: int) -> bool:
    """Process one vector-set file and write the response file.

    Returns True on success.
    """
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run NIST ACVP vectors through the calculator"
    )
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Calculator host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"ACVP service port on calculator (default: {DEFAULT_PORT})")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Per-vector-set socket timeout in seconds (default: 3600)")
    parser.add_argument("--vectors", type=Path, default=VECTORS_DIR,
                        help=f"Directory of per-vsId vector JSON files (default: {VECTORS_DIR})")
    parser.add_argument("--responses", type=Path, default=RESPONSES_DIR,
                        help=f"Directory to write per-vsId response JSON files (default: {RESPONSES_DIR})")
    parser.add_argument("vsid", nargs="*", type=int,
                        help="Specific vsId(s) to process (default: all in vectors/)")
    args = parser.parse_args()

    vectors_dir: Path = args.vectors
    responses_dir: Path = args.responses

    if not vectors_dir.exists():
        print(f"Vectors directory not found: {vectors_dir}", file=sys.stderr)
        print("Run: python3 acvp_offline.py fetch", file=sys.stderr)
        return 1

    responses_dir.mkdir(parents=True, exist_ok=True)

    # Collect vector set files to process
    if args.vsid:
        files = []
        for vsid in args.vsid:
            p = vectors_dir / f"{vsid}.json"
            if not p.exists():
                print(f"Vector set not found: {p}", file=sys.stderr)
                return 1
            files.append(p)
    else:
        files = sorted(vectors_dir.glob("*.json"))
        if not files:
            print(f"No vector sets in {vectors_dir}", file=sys.stderr)
            return 1

    print(f"Processing {len(files)} vector set(s) against {args.host}:{args.port}",
          flush=True)

    failed = []
    for vs_path in files:
        rsp_path = responses_dir / vs_path.name
        ok = run_vector_set(vs_path, rsp_path, args.host, args.port, args.timeout)
        if not ok:
            failed.append(vs_path.stem)

    if failed:
        print(f"\nFailed vector sets: {', '.join(failed)}", file=sys.stderr)
        return 1

    print(f"\nAll {len(files)} vector set(s) complete. Responses in {responses_dir}/",
          flush=True)
    print("Next step: python3 acvp_offline.py submit", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AcvpError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ACVP error: {exc}", file=sys.stderr)
        sys.exit(1)
