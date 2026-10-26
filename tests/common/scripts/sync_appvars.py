#!/usr/bin/env python3
"""Make every autotest.json transfer the lwIP-CE installer appvars that exist.

The dylib is split into as many 64 KiB LWIP.<n>.8xv appvars as it needs, so the
count changes as the library grows or shrinks. A test whose transfer list misses
one fails with "Install failed. Missing an appvar.". This rewrites the
LWIP.<n>.8xv entries of each tests/**/autotest.json to match tests/common.

    python3 tests/common/scripts/sync_appvars.py [--check]

`make dylib` runs it after refreshing tests/common; CI runs it before the
emulator tests. --check only reports files that are out of date.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2]
COMMON = TESTS / "common"
APPVAR = re.compile(r"^(.*/common/)LWIP\.\d+\.8xv$")


def sync(path: Path, appvars: list[str]) -> bool:
    data = json.loads(path.read_text())
    files = data.get("transfer_files", [])
    hits = [i for i, f in enumerate(files) if APPVAR.match(f)]
    if not hits:
        return False
    prefix = APPVAR.match(files[hits[0]]).group(1)
    wanted = [prefix + name for name in appvars]
    if [files[i] for i in hits] == wanted:
        return False
    rest = [f for f in files if not APPVAR.match(f)]
    data["transfer_files"] = rest[:hits[0]] + wanted + rest[hits[0]:]
    path.write_text(json.dumps(data, indent=2) + "\n")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    appvars = sorted((p.name for p in COMMON.glob("LWIP.*.8xv")), key=lambda n: int(n.split(".")[1]))
    if not appvars:
        print(f"no LWIP.*.8xv in {COMMON}; build the dylib first", file=sys.stderr)
        return 1
    stale = []
    for path in sorted(TESTS.rglob("autotest.json")):
        original = path.read_text()
        if sync(path, appvars):
            stale.append(path.relative_to(TESTS.parent))
            if args.check:
                path.write_text(original)
    for path in stale:
        print(f"{'stale' if args.check else 'updated'}: {path}")
    print(f"{len(appvars)} installer appvars: {', '.join(appvars)}")
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
