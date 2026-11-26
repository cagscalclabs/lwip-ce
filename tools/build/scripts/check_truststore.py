#!/usr/bin/env python3
"""Validate a lwIPCERT.8xv truststore for bundling into a release.

Checks that the file is a TI AppVar named lwIPCERT, that its truststore
header version matches TLS_TRUSTSTORE_VERSION in the library source (the
library rejects any other version), and that it has at least one root. On
success it writes a provenance record for the release zip.

The RSA signature is not checked here; the calculator verifies it before it
uses the store.

Usage:
    check_truststore.py STORE.8xv TRUSTSTORE_H --source WHERE --out RECORD.txt
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import struct
import sys

TI_SIGNATURE = b"**TI83F*\x1a\x0a\x00"
FILE_HEADER_LEN = 55          # signature(11) + comment(42) + data length(2)
APPVAR_TYPE = 0x15
VAR_NAME = b"lwIPCERT"
SIGNATURE_LEN = 256           # RSA-2048 signature precedes the header fields
STORE_HEADER = struct.Struct("<HIH")  # version, created (unix), entry count


def fail(message: str) -> None:
    print(f"check_truststore: {message}", file=sys.stderr)
    sys.exit(1)


def expected_version(header_path: str) -> int:
    with open(header_path, encoding="utf-8") as f:
        match = re.search(r"^#define\s+TLS_TRUSTSTORE_VERSION\s+(\d+)\b",
                          f.read(), re.MULTILINE)
    if not match:
        fail(f"TLS_TRUSTSTORE_VERSION not found in {header_path}")
    return int(match.group(1))


def appvar_payload(data: bytes) -> bytes:
    """The AppVar's contents, without the TI file and variable headers."""
    if len(data) < FILE_HEADER_LEN + 2 or not data.startswith(TI_SIGNATURE):
        fail("not a TI variable file")
    pos = FILE_HEADER_LEN
    entry_header_len, data_len = struct.unpack_from("<HH", data, pos)
    if entry_header_len not in (0x0B, 0x0D):
        fail(f"unexpected variable header length {entry_header_len:#x}")
    var_type = data[pos + 4]
    name = data[pos + 5:pos + 13].rstrip(b"\x00")
    if var_type != APPVAR_TYPE:
        fail(f"variable type {var_type:#04x} is not an AppVar")
    if name != VAR_NAME:
        fail(f"AppVar is named {name!r}, expected {VAR_NAME.decode()}")
    # The entry header length excludes its own field; a second copy of the
    # data length follows the header, then the data.
    body = pos + 2 + entry_header_len + 2
    var_data = data[body:body + data_len]
    if len(var_data) != data_len or data_len < 2:
        fail("file is truncated")
    (size,) = struct.unpack_from("<H", var_data, 0)
    if size != data_len - 2:
        fail("AppVar size word does not match the variable length")
    return var_data[2:]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("store")
    ap.add_argument("truststore_h")
    ap.add_argument("--source", required=True,
                    help="where the store came from, for the record")
    ap.add_argument("--out", required=True, help="provenance record to write")
    args = ap.parse_args()

    with open(args.store, "rb") as f:
        raw = f.read()
    blob = appvar_payload(raw)
    if len(blob) < SIGNATURE_LEN + STORE_HEADER.size:
        fail("truststore is shorter than its header")
    version, created, count = STORE_HEADER.unpack_from(blob, SIGNATURE_LEN)

    want = expected_version(args.truststore_h)
    if version != want:
        fail(f"truststore format v{version}, but this library expects "
             f"v{want}; the calculator would reject it. Publish a matching "
             f"store or pass TRUSTSTORE=path/to/lwIPCERT.8xv.")
    if count == 0:
        fail("truststore has no roots")

    def utc(ts: float) -> str:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")

    record = (
        "lwIPCERT.8xv: TLS root certificate store bundled with this release.\n"
        "Send it to the calculator along with lwip.8xv. Newer root sets are\n"
        "published at https://github.com/cagscalclabs/lwip-ce/releases/tag/truststore-latest\n"
        "\n"
        f"format version: {version}\n"
        f"roots:          {count}\n"
        f"store created:  {utc(created)}\n"
        f"bundled:        {utc(dt.datetime.now(dt.timezone.utc).timestamp())}\n"
        f"source:         {args.source}\n"
        f"sha256:         {hashlib.sha256(raw).hexdigest()}\n"
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(record)
    print(f"truststore OK: v{version}, {count} roots, created {utc(created)}")


if __name__ == "__main__":
    main()
