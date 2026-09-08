#!/usr/bin/env python3
"""
lwip-webpacker.py  —  Pack a www/ directory into a TI-84+CE AppVar.

Writes a raw binary payload, then shells out to convbin to produce the
final .8xv.  convbin must be on PATH (it ships with the CEdev toolchain).

AppVar binary layout
--------------------
  [0:4]    Magic 'LWFS'
  [4:6]    Entry count N  (uint16 LE)
  [6:]     Index table (one variable-length entry per file):
             [0:2]   path length L  (uint16 LE)
             [2:2+L] URL path string (NOT NUL-terminated, e.g. "/index.html")
             [2+L:6+L]  data offset from start of payload  (uint32 LE)
             [6+L:10+L] data length in bytes                (uint32 LE)
             [10+L]     MIME type index                     (uint8)
  After index table: raw file data blobs (concatenated).

MIME type indices (must match mime_table[] in main.c):
  0  text/html          4  application/json   8  image/svg+xml
  1  text/plain         5  image/png          9  application/octet-stream
  2  text/css           6  image/jpeg
  3  application/javascript  7  image/gif

Usage
-----
  python3 lwip-webpacker.py --www www/ --outname LWHTTPD
  (produces LWHTTPD.8xv with on-calc name LWHTTPD)
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile

MAGIC = b'LWFS'

MIME_MAP = {
    '.html': 0, '.htm': 0,
    '.txt':  1,
    '.css':  2,
    '.js':   3,
    '.json': 4,
    '.png':  5,
    '.jpg':  6, '.jpeg': 6,
    '.gif':  7,
    '.svg':  8,
}
MIME_FALLBACK = 9


def mime_for(filename: str) -> int:
    ext = os.path.splitext(filename)[1].lower()
    return MIME_MAP.get(ext, MIME_FALLBACK)


def collect_files(www: str):
    """Walk www/ and return list of (url_path, abs_path, mime_index)."""
    entries = []
    for root, _dirs, files in os.walk(www):
        for fname in sorted(files):
            abs_path = os.path.join(root, fname)
            rel = os.path.relpath(abs_path, www)
            url = '/' + rel.replace(os.sep, '/')
            entries.append((url, abs_path, mime_for(fname)))
    return entries


def build_payload(entries) -> bytes:
    """Build the raw binary payload (the AppVar content, without TI wrapper)."""
    # Pass 1: measure index table to compute data offsets.
    index_size = sum(2 + len(url.encode('ascii')) + 9 for (url, _, _) in entries)
    header_size = 4 + 2 + index_size  # magic + count + index

    index_buf = bytearray()
    data_buf  = bytearray()

    for (url, abs_path, mime) in entries:
        url_bytes = url.encode('ascii')
        with open(abs_path, 'rb') as f:
            file_data = f.read()

        data_offset = header_size + len(data_buf)
        index_buf += struct.pack('<H', len(url_bytes))
        index_buf += url_bytes
        index_buf += struct.pack('<IIB', data_offset, len(file_data), mime)
        data_buf  += file_data

        print(f"  {url:40s}  {len(file_data):6d} bytes  mime={mime}")

    payload = bytearray()
    payload += MAGIC
    payload += struct.pack('<H', len(entries))
    payload += index_buf
    payload += data_buf
    return bytes(payload)


def main():
    parser = argparse.ArgumentParser(
        description='Pack a www/ directory into a TI-84+CE AppVar for lwIP httpd.')
    parser.add_argument('--www',     required=True,
                        help='Path to the www/ directory')
    parser.add_argument('--outname', required=True,
                        help='Output base name (e.g. LWHTTPD → LWHTTPD.8xv, on-calc name LWHTTPD)')
    args = parser.parse_args()

    name = args.outname.upper()[:8]
    out  = name + '.8xv'

    if not os.path.isdir(args.www):
        sys.exit(f'error: {args.www!r} is not a directory')

    entries = collect_files(args.www)
    if not entries:
        sys.exit(f'error: no files found in {args.www!r}')

    print(f'Packing {len(entries)} file(s):')
    payload = build_payload(entries)
    print(f'Payload: {len(payload)} bytes')

    # Write payload to a temp file, then let convbin produce the .8xv.
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(payload)
        tmp_path = tmp.name

    try:
        cmd = [
            'convbin',
            '-j', 'bin', '-i', tmp_path,
            '-k', '8xv',
            '-n', name,
            '-r',           # mark archived
            '-o', out,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            sys.exit(f'convbin failed:\n{result.stderr}')
    finally:
        os.unlink(tmp_path)

    size = os.path.getsize(out)
    print(f'Written: {out}  ({size} bytes)')


if __name__ == '__main__':
    main()
