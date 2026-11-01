#!/usr/bin/env python3
"""Extract one variable from a TI-83/84 group into a standalone TI file."""

import argparse
import struct
from pathlib import Path


TI_HEADER_SIZE = 55


def extract(group: bytes, wanted: str) -> bytes:
    if len(group) < TI_HEADER_SIZE + 2 or not group.startswith(b"**TI83F*"):
        raise ValueError("not a TI-83/84 variable file")

    section_len = struct.unpack_from("<H", group, 53)[0]
    section_end = TI_HEADER_SIZE + section_len
    if section_end + 2 > len(group):
        raise ValueError("truncated TI group")

    offset = TI_HEADER_SIZE
    while offset < section_end:
        if offset + 17 > section_end:
            raise ValueError("truncated variable header")
        header_len, data_len = struct.unpack_from("<HH", group, offset)
        if header_len != 13:
            raise ValueError(f"unsupported variable header length {header_len}")
        name = group[offset + 5 : offset + 13].rstrip(b"\0").decode("ascii")
        repeated_len = struct.unpack_from("<H", group, offset + 15)[0]
        if repeated_len != data_len:
            raise ValueError(f"inconsistent length for {name}")
        entry_end = offset + 17 + data_len
        if entry_end > section_end:
            raise ValueError(f"truncated data for {name}")
        if name.casefold() == wanted.casefold():
            entry = group[offset:entry_end]
            header = group[:53] + struct.pack("<H", len(entry))
            checksum = struct.pack("<H", sum(entry) & 0xFFFF)
            return header + entry + checksum
        offset = entry_end

    raise ValueError(f"{wanted!r} not found in group")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("group", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("name")
    args = parser.parse_args()
    args.output.write_bytes(extract(args.group.read_bytes(), args.name))


if __name__ == "__main__":
    main()
