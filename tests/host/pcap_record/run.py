#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as tmp:
    binary = Path(tmp) / 'test'
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-g',
                    '-fsanitize=address,undefined', str(here / 'test.c'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
