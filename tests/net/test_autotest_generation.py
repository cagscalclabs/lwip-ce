#!/usr/bin/env python3
"""Check timing-sensitive steps in generated network autotests."""

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

    regular_test = json.loads(regular.read_text())
    timeouts_test = json.loads(timeouts.read_text())

    assert regular_test["hashes"]["2"]["timeout"] == 1_800_000
    assert timeouts_test["hashes"]["2"]["timeout"] == 1_800_000
    for test in (regular_test, timeouts_test):
        sequence = test["sequence"]
        usb = sequence.index("usb|test")
        assert sequence[usb + 1:usb + 3] == ["delay|200000", "action|launch"]

print("network autotest generation self-test: PASS")
