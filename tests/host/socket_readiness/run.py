#!/usr/bin/env python3
"""Exercise production socket readiness code with mocked platform/transport."""
from pathlib import Path
import re
import subprocess
import tempfile

here = Path(__file__).resolve().parent
source = (here.parents[2] / 'src/lwIP.c').read_text()

def function(name):
    match = re.search(r'^static [^\n]*\b' + name + r'\([^;]*?\n\{', source, re.M)
    assert match, name
    start = match.start()
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

names = ['netif_service_base_ready', 'netif_service_ready',
         'socket_netif_changed', 'socket_required_services', 'socket_network_ready',
         'conn_registry_has_waiting_services', 'conn_waiting_services_poll',
         'services_dispatch', 'services_arm']
with tempfile.TemporaryDirectory() as tmp:
    unit = Path(tmp) / 'test.c'
    unit.write_text((here / 'mock.h').read_text() + '\n' +
                    '\n'.join(function(n) for n in names) + '\n' +
                    (here / 'test.c').read_text())
    binary = Path(tmp) / 'test'
    subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror',
                    '-g', '-fsanitize=address,undefined', str(unit), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
