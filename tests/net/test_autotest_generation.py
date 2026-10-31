#!/usr/bin/env python3
"""Check suite-specific CEmu deadlines in generated network autotests."""

import json
import tempfile
from pathlib import Path

from run import write_autotest


with tempfile.TemporaryDirectory() as tmp_name:
    tmp = Path(tmp_name)
    regular = tmp / "regular.json"
    timeouts = tmp / "timeouts.json"

    write_autotest(regular, "sockets", "usb|test", 1_800_000)
    write_autotest(timeouts, "timeouts", "usb|test", 1_800_000)

    regular_deadline = json.loads(regular.read_text())["hashes"]["2"]["timeout"]
    timeouts_deadline = json.loads(timeouts.read_text())["hashes"]["2"]["timeout"]

    assert regular_deadline == 1_800_000
    assert timeouts_deadline == 3_600_000

print("network autotest generation self-test: PASS")
