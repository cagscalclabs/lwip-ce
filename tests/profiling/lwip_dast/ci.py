#!/usr/bin/env python3
"""Run the DAST harness unattended against LWDAST on CEmu.

CI has no physical calc, but CEmu-lwIP-CE emulates the calc's USB Ethernet
adapter on a TAP interface (set up by alessiodam/cemu-net-action), so the
probe runner can reach the emulated calc like a calc on a live network:

    sudo python3 tests/profiling/lwip_dast/ci.py --autotester PATH --usb 'usb|eth,cemu0,...'

LWDAST is launched in the autotester and left running; once it answers
pings, build-tools/dast/lwip-dast.py drives it over the control channel and
writes tests/dast.json. Grading stays automatic: a probe that leaves the
calc unresponsive is recorded as CRASH.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMON = ROOT / "tests" / "common"


def write_autotest(path: Path, usb: str) -> None:
    files = ["bin/LWDAST.8xp"] + sorted(os.path.relpath(f, HERE) for f in COMMON.glob("*.8x*"))
    path.write_text(json.dumps({
        "description": "LWDAST driven by build-tools/dast/lwip-dast.py over the emulated adapter",
        "transfer_files": files,
        "target": {"name": "LWDAST", "isASM": True},
        "sequence": ["delay|20000", "key|clear", "action|launch:INSTALL", "hashWait|1", "key|left",
                     "key|enter", "delay|2000", usb, "action|launch", "delay|86400000"],
        "hashes": {
            "1": {"description": "lwIP-CE installed", "start": "vram_start", "size": "vram_16_size",
                  "expected_CRCs": ["F7C03D8D"], "timeout": 200000},
        },
    }, indent=2) + "\n")


def wait_for_calc(ip: str, emulator: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and emulator.poll() is None:
        if subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True).returncode == 0:
            return True
        time.sleep(2)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--autotester", required=True)
    ap.add_argument("--usb", required=True)
    ap.add_argument("--ip", default="192.168.84.2")
    ap.add_argument("--iface", default="cemu0")
    args = ap.parse_args()

    autotest = HERE / "autotest.json"
    write_autotest(autotest, args.usb)
    with open(HERE / "autotester.log", "w") as log:
        emulator = subprocess.Popen([args.autotester, str(autotest)], cwd=HERE, stdout=log,
                                    stderr=subprocess.STDOUT)
        try:
            if not wait_for_calc(args.ip, emulator, 900):
                print(f"LWDAST never answered pings at {args.ip}")
                return 1
            print(f"LWDAST is up at {args.ip}, starting probes")
            return subprocess.run([sys.executable, str(ROOT / "build-tools" / "dast" / "lwip-dast.py"),
                                   "--ip", args.ip, "--iface", args.iface],
                                  input="\n", text=True).returncode
        finally:
            emulator.terminate()
            try:
                emulator.wait(10)
            except subprocess.TimeoutExpired:
                emulator.kill()


if __name__ == "__main__":
    sys.exit(main())
