#!/usr/bin/env python3
"""Host-only checks for the ephemeral runner-local certificate hierarchy."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from run import COMMON, HOST, local_ca_fixtures, write_autotest


with tempfile.TemporaryDirectory() as tmp_name:
    fixtures = local_ca_fixtures(Path(tmp_name))
    ca_cert, _ = fixtures["ca"]
    for key_type in ("ecdsa", "rsa"):
        cert, key = fixtures[key_type]
        subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca_cert), str(cert)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-checkip", HOST, "-noout"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-pubkey"],
            check=True,
            capture_output=True,
        )
        assert key.stat().st_size > 0

    # The gating boot must receive only the temporary CA-only profile, while
    # the informational boot must receive only the production profile.
    local_store = Path(tmp_name) / "lwIPCERT-local.8xv"
    local_store.touch()
    local_autotest = Path(tmp_name) / "local.json"
    external_autotest = Path(tmp_name) / "external.json"
    write_autotest(local_autotest, "tls", "usb|test", 1000, local_store)
    write_autotest(external_autotest, "tls", "usb|test", 1000)
    local_files = json.loads(local_autotest.read_text())["transfer_files"]
    external_files = json.loads(external_autotest.read_text())["transfer_files"]
    preinstalled = {"clibs.8xg", "fileioc.8xv", "libload.8xv", "usbdrvce.8xv",
                    "lwIPINST.8xp", "lwip.8xv"}
    assert not preinstalled.intersection(map(os.path.basename, local_files))
    assert not any(os.path.basename(path).startswith("LWIP.") for path in local_files)
    assert [p for p in local_files if "lwIPCERT" in p] == [
        os.path.relpath(local_store, local_autotest.parent)
    ]
    assert [p for p in external_files if "lwIPCERT" in p] == [
        os.path.relpath(COMMON / "lwIPCERT.8xv", external_autotest.parent)
    ]

print("runner-local PKI self-test: PASS")
