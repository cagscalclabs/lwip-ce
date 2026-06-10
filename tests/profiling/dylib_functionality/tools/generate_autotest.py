#!/usr/bin/env python3
"""Generate a CEmu autotest file for the lwIP dylib smoke test."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def relpath(path: Path, start: Path) -> str:
    return Path(os.path.relpath(path.resolve(), start.resolve())).as_posix()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-dir", type=Path, default=Path.cwd())
    parser.add_argument("--release-dir", type=Path)
    parser.add_argument("--clibs", type=Path)
    parser.add_argument("--out", type=Path, default=Path("autotest.json"))
    args = parser.parse_args()

    test_dir = args.test_dir.resolve()
    transfer_files = [Path("bin/DYLBFUNC.8xp").as_posix()]

    if args.clibs:
        transfer_files.append(relpath(args.clibs, test_dir))

    payload = {
        "description": "Smoke-test lwIP dylib calls against a user-installed lwIP app",
        "transfer_files": transfer_files,
        "target": {
            "name": "DYLBFUNC",
            "isASM": True,
        },
        "sequence": [
            "action|launch",
            "hashWait|1",
            "key|enter",
        ],
        "hashes": {
            "1": {
                "description": "runtime bootstrap, SHA-256, HMAC-SHA-256, and mem_malloc/mem_free succeeded",
                "start": "vram_start",
                "size": "vram_16_size",
                "expected_CRCs": ["D1F2869F"],
                "timeout": 1000000000,
            }
        },
    }

    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
