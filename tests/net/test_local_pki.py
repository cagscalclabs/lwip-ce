#!/usr/bin/env python3
"""Host-only checks for the ephemeral runner-local certificate hierarchy."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from run import (COMMON, HOST, PORT_OCSP, build_test_config,
                 local_ca_fixtures, write_autotest)


with tempfile.TemporaryDirectory() as tmp_name:
    fixtures, ocsp_responses = local_ca_fixtures(Path(tmp_name))
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

    cert_text = subprocess.run(
        ["openssl", "x509", "-in", str(fixtures["ecdsa"][0]),
         "-noout", "-text"],
        check=True, capture_output=True, text=True,
    ).stdout
    assert f"OCSP - URI:http://{HOST}:{PORT_OCSP}/ocsp" in cert_text
    for expected, response in ocsp_responses.items():
        response_file = Path(tmp_name) / f"{expected}.der"
        response_file.write_bytes(response)
        text = subprocess.run(
            ["openssl", "ocsp", "-respin", str(response_file),
             "-text", "-noverify"],
            check=True, capture_output=True, text=True,
        ).stdout
        assert f"Cert Status: {expected}" in text

    convbin = shutil.which("convbin")
    assert convbin
    config_off = Path(tmp_name) / "lwIPCFG-off.8xv"
    config_on = Path(tmp_name) / "lwIPCFG-on.8xv"
    build_test_config(False, config_off, Path(convbin))
    build_test_config(True, config_on, Path(convbin))
    for expected, config in ((0, config_off), (1, config_on)):
        encoded = config.read_bytes()
        length = int.from_bytes(encoded[0x48:0x4A], "little")
        assert encoded[0x4A:0x4A + length] == (
            b"LWCF" + bytes((1, 8, 3, 0, 13, 1, expected))
        )

    # The gating boot must receive only the temporary CA-only profile, while
    # the informational boot must receive only the production profile.
    local_store = Path(tmp_name) / "lwIPCERT-local.8xv"
    local_store.touch()
    local_autotest = Path(tmp_name) / "local.json"
    external_autotest = Path(tmp_name) / "external.json"
    write_autotest(local_autotest, "tls", "usb|test", 1000,
                   local_store, config_on)
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
    assert [p for p in local_files if "lwIPCFG" in p] == [
        os.path.relpath(config_on, local_autotest.parent)
    ]
    expected_external_store = (
        [os.path.relpath(COMMON / "lwIPCERT.8xv", external_autotest.parent)]
        if (COMMON / "lwIPCERT.8xv").is_file() else []
    )
    assert [p for p in external_files if "lwIPCERT" in p] == expected_external_store

print("runner-local PKI self-test: PASS")
