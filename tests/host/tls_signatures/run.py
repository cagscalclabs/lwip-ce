#!/usr/bin/env python3
"""Exercise production certificate parsing/dispatch with instrumented crypto.

Like the WS host tests, compile selected production code with platform mocks.
These tests check routing and lifecycle; they do not test RSA arithmetic.
"""
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[2]
x509 = (root / 'src/tls/core/x509.c').read_text()
hs = (root / 'src/tls/core/handshake.c').read_text()


def function(source, name):
    # Find the definition (skip prototypes), preserving its full body.
    import re
    match = re.search(r'^(?:static )?\w+\s*\*?\s*' + name + r'\([^;]*?\)\s*\{', source, re.M)
    start = match.start()
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == '{') - (source[pos] == '}')
        pos += 1
    return source[start:pos] + '\n'


def tlv(tag, value):
    n = len(value)
    length = (bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256
              else bytes([0x82, n >> 8, n & 255]))
    return bytes([tag]) + length + value


def seq(*values):
    return tlv(0x30, b''.join(values))


def oid(hexstr):
    return tlv(6, bytes.fromhex(hexstr))


rsa = oid('2a864886f70d010101')
pkcs = seq(oid('2a864886f70d01010b'), b'\x05\x00')
sha = seq(oid('608648016503040201'), b'\x05\x00')
mgf = seq(oid('2a864886f70d010108'), sha)
params = tlv(0xa0, sha) + tlv(0xa1, mgf) + tlv(0xa2, b'\x02\x01\x20')
pss_oid = oid('2a864886f70d01010a')
pss = seq(pss_oid, seq(params))
ecdsa = seq(oid('2a8648ce3d040302'))
spki = seq(seq(rsa, b'\x05\x00'), tlv(3, b'\0' + seq(
    tlv(2, b'\0' + b'\x81' * 128), tlv(2, b'\x01\x00\x01'))))
ec_spki = seq(seq(oid('2a8648ce3d0201'), oid('2a8648ce3d030107')),
              tlv(3, b'\0\x04' + b'\x01' * 64))
name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'example.test'))))
valid = seq(tlv(0x17, b'200101000000Z'), tlv(0x17, b'491231235959Z'))


def cert(algorithm, key=spki, inner=None):
    tbs = seq(b'\x02\x01\x01', inner or algorithm, name, valid, name, key)
    signature = bytes([0x22 if algorithm == pss else 0x11]) * 128
    return seq(tbs, algorithm, tlv(3, b'\0' + signature))


vectors = {
    'alg_pkcs': pkcs, 'alg_pss': pss, 'alg_ec': ecdsa,
    'alg_pss_trailer': seq(pss_oid, seq(params + tlv(0xa3, b'\x02\x01\x01'))),
    'bad_default': seq(pss_oid, seq()),
    'bad_absent': seq(pss_oid),
    'bad_salt': seq(pss_oid, seq(params[:-1] + b'\x14')),
    'bad_hash': seq(pss_oid, seq(params.replace(bytes.fromhex('608648016503040201'),
                                              bytes.fromhex('608648016503040202'), 1))),
    'bad_mgf_hash': seq(pss_oid, seq(tlv(0xa0, sha) + tlv(0xa1, mgf[:-3] + b'\x02\x05\x00')
                                      + tlv(0xa2, b'\x02\x01\x20'))),
    'bad_duplicate': seq(pss_oid, seq(params + tlv(0xa2, b'\x02\x01\x20'))),
    'bad_trailer': seq(pss_oid, seq(params + tlv(0xa3, b'\x02\x01\x02'))),
    'bad_key_oid': seq(rsa, b'\x05\x00'),
    'cert_pkcs': cert(pkcs), 'cert_pss': cert(pss),
    'cert_ec': cert(pkcs, ec_spki), 'cert_mismatch': cert(pss, inner=pkcs),
}

source = (here / 'mock.h').read_text()
source += x509[x509.index('static bool tls_x509_is_string_tag'):x509.index('static bool tls_x509_decode_pem_certificate')]
source += x509[x509.index('static const uint8_t oid_rsa_encryption'):]
key_source = (root / 'src/tls/core/key.c').read_text()
for name in ['tls_key_verify', 'tls_key_sign']:
    source += function(key_source, name)
# Include internal AES helpers and blob helpers (not aes_encrypt_oneshot, which is mocked).
source += key_source[key_source.index('/* ---------------------------------------------------------------------------\n * Internal helpers'):
                     key_source.index('/* ---------------------------------------------------------------------------\n * AES one-shot encrypt')]
for name in ['tls_cipher_blob_free', 'tls_cipher_encrypt', 'tls_cipher_encrypt_aad']:
    source += function(key_source, name)
source += hs[hs.index('enum tls_cert_walk_state'):hs.index('/* Feed body bytes into the walker.')]
for name in ['transcript_hash_init', 'transcript_hash_update', 'transcript_hash_digest',
             'tls_handshake_init', 'tls_send_client_hello',
             'tls_recv_certificate_streamed', 'tls_certverify_rsa_pss_sha256',
             'tls_handshake_cleanup']:
    source += function(hs, name)
for name, data in vectors.items():
    source += f'static const uint8_t {name}[] = {{' + ','.join(map(str, data)) + '};\n'
source += (here / 'test.c').read_text()

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / 'lwip').mkdir()
    (tmp / 'lwip/logging.h').write_text('#define INFO(...) ((void)0)\n#define ERROR(...) ((void)0)\n#define DEBUG(...) ((void)0)\n#define WARN(...) ((void)0)\n')
    unit = tmp / 'test.c'
    unit.write_text(source)
    binary = tmp / 'test'
    subprocess.run(['cc', '-std=c99', '-g', '-Wall', '-Wextra',
                    '-Wno-unused-function', '-Wno-unused-parameter',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(tmp), '-I' + str(root / 'src/tls/includes'),
                    '-I' + str(root / 'src/tls/core'), str(unit),
                    str(root / 'src/tls/core/asn1.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
