#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[2]
with tempfile.TemporaryDirectory() as tmp:
    binary = Path(tmp) / 'test'
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-g',
                    '-fsanitize=address,undefined', str(here / 'test.c'),
                    str(root / 'src/tls/core/base64.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
