#!/usr/bin/env python3
"""Host regression tests for WS callbacks/parser using a mock lower transport.
Compile the production implementation before its vtable (no CE SDK required).
"""
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[2]
source = (root / 'src/apps/altcp_ws/altcp_ws.c').read_text()
source = source[source.index('/* WebSocket frame flags */'):]
source = source[:source.index('/* -------------------------------------------------------------------------\n * vtable')]
with tempfile.TemporaryDirectory() as tmp:
    unit = Path(tmp) / 'test.c'
    unit.write_text((here / 'mock.h').read_text() + '\n' + source + '\n' +
                    (here / 'test.c').read_text())
    binary = Path(tmp) / 'test'
    subprocess.run(['cc', '-std=c99', '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(unit), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
