#!/usr/bin/env python3
"""Check DAST IP certificates and route selection without sending packets."""
import ast
from datetime import datetime, timezone
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

root = Path(__file__).resolve().parents[3]
path = root / 'build-tools/dast/lwip-dast.py'
source = path.read_text()
compile(source, str(path), 'exec')

fingerprint = subprocess.run([sys.executable, str(path), '--src-hash'],
                             check=True, capture_output=True, text=True).stdout.strip()
assert len(fingerprint) == 64 and all(c in '0123456789abcdef' for c in fingerprint)

names = {'ensure_test_cert', 'TlsFixtures'}
selected = [n for n in ast.parse(source).body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]


def die(message):
    raise RuntimeError(message)


with tempfile.TemporaryDirectory() as tmp:
    ns = dict(Path=Path, subprocess=subprocess, datetime=datetime,
              timezone=timezone, socket=socket, TLS_TEST_CERT_DIR=Path(tmp),
              die=die, DAST_CTRL_PORT=9997, ssl=__import__('ssl'),
              TlsProbeServer=object, make_tls_context=MagicMock())
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), ns)
    for kind in ('rsa', 'ecdsa'):
        cert, _ = ns['ensure_test_cert'](kind, '192.0.2.10')
        for ip, match in [('192.0.2.10', True), ('192.0.2.11', False)]:
            result = subprocess.run(['openssl', 'x509', '-in', str(cert),
                                     '-noout', '-checkip', ip],
                                    capture_output=True, text=True)
            assert ('does match certificate' in result.stdout) == match, result.stdout
        result = subprocess.run(['openssl', 'x509', '-in', str(cert),
                                 '-noout', '-ext', 'subjectAltName'],
                                check=True, capture_output=True, text=True)
        assert 'IP Address:192.0.2.10' in result.stdout

    with patch.object(socket, 'socket') as factory:
        route = factory.return_value.__enter__.return_value
        route.getsockname.return_value = ('192.0.2.10', 50000)
        fixture = ns['TlsFixtures']('0.0.0.0', False, '192.0.2.32')
        first = fixture._context('tls_echo_clean')
        assert fixture._context('tls_echo_resume') is first
        route.connect.assert_called_once_with(('192.0.2.32', 9997))
        ns['make_tls_context'].assert_called_once_with('rsa', '192.0.2.10')
        fixture._context('tls_unsupported_certverify')
        ns['make_tls_context'].assert_called_with('ecdsa', '192.0.2.10')
        assert fixture._context('tls_missing_record') is None
        bad = ns['TlsFixtures']('192.0.2.11', False, '192.0.2.32')
        try:
            bad._context('tls_echo_clean')
        except RuntimeError:
            pass
        else:
            raise AssertionError('Unreachable fixture bind must be rejected')

print('DAST IP certificate and source-address tests passed')
