#!/usr/bin/env python3
"""Exercise production certificate parsing/dispatch with instrumented crypto.

Like the WS host tests, compile selected production code with platform mocks.
These tests check routing and lifecycle; they do not test RSA arithmetic.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
# The harness extracts individual functions from handshake.c, so file-scope
# helpers (the phase-trace function and its #if-gated no-op macros) are not
# part of the generated TU. Stub the trace entry points alongside the log
# macros so the extracted functions compile unchanged.
LOGGING_SHIM = ('#define INFO(...) ((void)0)\n#define ERROR(...) ((void)0)\n'
                '#define DEBUG(...) ((void)0)\n#define WARN(...) ((void)0)\n'
                '#define tls_phase_trace(p) ((void)0)\n'
                '#define tls_phase_trace_begin() ((void)0)\n')
root = here.parents[2]
x509 = (root / 'src/tls/core/x509.c').read_text()
hs = (root / 'src/tls/core/handshake.c').read_text()


def function(source, name):
    # Find the definition (skip prototypes), preserving its full body.
    import re
    match = re.search(r'^(?:static )?(?:const\s+)?\w+\s*\*?\s*' + name +
                      r'\([^;]*?\)\s*\{', source, re.M)
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
    tlv(2, b'\0' + b'\x81' * 256), tlv(2, b'\x01\x00\x01'))))
ec_spki = seq(seq(oid('2a8648ce3d0201'), oid('2a8648ce3d030107')),
              tlv(3, b'\0\x04' + b'\x01' * 64))
name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'example.test'))))
name_org_rdn = tlv(0x31, seq(oid('55040a'), tlv(0x0c, b'Example Org')))
deep_name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'example.test'))),
                name_org_rdn)
rollover_name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'rollover.test'))))
ordinary_child_name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'child.test'))))
ordinary_parent_name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'parent.test'))))
root_name = seq(tlv(0x31, seq(oid('550403'), tlv(0x0c, b'root.test'))))
valid = seq(tlv(0x17, b'200101000000Z'), tlv(0x17, b'491231235959Z'))
epoch_spanning_valid = seq(tlv(0x17, b'500101000000Z'),
                           tlv(0x17, b'491231235959Z'))
base_extensions = (
    seq(oid('551d11'), tlv(4, seq(tlv(0x82, b'example.test')))),
    seq(oid('551d13'), tlv(1, b'\xff'), tlv(4, seq(tlv(1, b'\xff')))),
    seq(oid('551d0f'), tlv(1, b'\xff'), tlv(4, tlv(3, b'\x02\x84'))),
    seq(oid('551d25'), tlv(4, seq(oid('2b06010505070301')))),
)
cert_extensions = tlv(0xa3, seq(*base_extensions))
authority_key_id = bytes(range(0xa0, 0xb4))
aki_extension = seq(oid('551d23'), tlv(4, seq(tlv(0x80, authority_key_id))))
cert_extensions_aki = tlv(0xa3, seq(
    *base_extensions,
    aki_extension,
))
cert_extensions_duplicate_aki = tlv(0xa3, seq(
    *base_extensions, aki_extension, aki_extension,
))
cert_extensions_bad_aki = tlv(0xa3, seq(
    *base_extensions,
    seq(oid('551d23'), tlv(4, seq(tlv(0xa0, authority_key_id)))),
))
cert_extensions_nonminimal_ku = tlv(0xa3, seq(
    base_extensions[0],
    base_extensions[1],
    seq(oid('551d0f'), tlv(1, b'\xff'), tlv(4, tlv(3, b'\x00\x84'))),
    base_extensions[3],
))
cert_extensions_pathlen0 = tlv(0xa3, seq(
    base_extensions[0],
    seq(oid('551d13'), tlv(1, b'\xff'),
        tlv(4, seq(tlv(1, b'\xff'), tlv(2, b'\x00')))),
    base_extensions[2],
    base_extensions[3],
))


def san_extension(*names):
    return seq(oid('551d11'), tlv(4, seq(*names)))


def nc_extension(permitted=(), excluded=(), critical=True,
                 raw_fields=None):
    fields = raw_fields
    if fields is None:
        fields = b''
        if permitted:
            fields += tlv(0xa0, b''.join(seq(base) for base in permitted))
        if excluded:
            fields += tlv(0xa1, b''.join(seq(base) for base in excluded))
    parts = [oid('551d1e')]
    if critical:
        parts.append(tlv(1, b'\xff'))
    parts.append(tlv(4, seq(fields)))
    return seq(*parts)


def extensions_with_san(san, *extra):
    return tlv(0xa3, seq(san, *base_extensions[1:], *extra))


def eku_extension(*purposes, critical=False):
    parts = [oid('551d25')]
    if critical:
        parts.append(tlv(1, b'\xff'))
    parts.append(tlv(4, seq(*purposes)))
    return seq(*parts)


def extensions_with_eku(eku=None):
    values = list(base_extensions[:3])
    if eku is not None:
        values.append(eku)
    return tlv(0xa3, seq(*values))


server_auth_purpose = oid('2b06010505070301')
client_auth_purpose = oid('2b06010505070302')
any_eku_purpose = oid('551d2500')
eku_any_extensions = extensions_with_eku(eku_extension(any_eku_purpose))
eku_absent_extensions = extensions_with_eku()
eku_client_extensions = extensions_with_eku(eku_extension(client_auth_purpose))
eku_empty_extensions = extensions_with_eku(eku_extension())
eku_critical_extensions = extensions_with_eku(
    eku_extension(server_auth_purpose, critical=True))
eku_malformed_oid_extensions = extensions_with_eku(
    eku_extension(server_auth_purpose, tlv(6, b'\x80\x01')))


nc_dns_permitted = nc_extension(permitted=(tlv(0x82, b'example.test'),))
nc_dns_excluded_upper = nc_extension(excluded=(tlv(0x82, b'.EXAMPLE.TEST'),))
nc_directory_permitted = nc_extension(permitted=(tlv(0xa4, name),))
nc_noncritical = nc_extension(permitted=(tlv(0x82, b'example.test'),),
                              critical=False)
nc_bad_minimum = nc_extension(raw_fields=tlv(
    0xa0, seq(tlv(0x82, b'example.test'), tlv(0x80, b'\0'))))
nc_empty_subtrees = nc_extension(raw_fields=tlv(0xa0, b''))
nc_unsupported_ip = nc_extension(
    permitted=(tlv(0x87, bytes((192, 0, 2, 0, 255, 255, 255, 0))),))
nc_duplicate_permitted = nc_extension(raw_fields=(
    tlv(0xa0, seq(tlv(0x82, b'example.test'))) +
    tlv(0xa0, seq(tlv(0x82, b'example.test')))))

leaf_good_extensions = extensions_with_san(
    san_extension(tlv(0x82, b'WWW.Example.test'),
                  tlv(0x82, b'api.example.test')))
leaf_extra_extensions = extensions_with_san(
    san_extension(tlv(0x82, b'www.example.test'),
                  tlv(0x82, b'evil.test')))
leaf_ip_extensions = extensions_with_san(
    san_extension(tlv(0x87, bytes((192, 0, 2, 1)))))
ca_nc_dns_extensions = extensions_with_san(base_extensions[0], nc_dns_permitted)
ca_nc_excluded_extensions = extensions_with_san(base_extensions[0],
                                                 nc_dns_excluded_upper)
ca_nc_directory_extensions = extensions_with_san(base_extensions[0],
                                                  nc_directory_permitted)
ca_nc_noncritical_extensions = extensions_with_san(base_extensions[0],
                                                    nc_noncritical)
ca_nc_bad_minimum_extensions = extensions_with_san(base_extensions[0],
                                                    nc_bad_minimum)
ca_nc_empty_extensions = extensions_with_san(base_extensions[0],
                                              nc_empty_subtrees)
ca_nc_unsupported_extensions = extensions_with_san(base_extensions[0],
                                                    nc_unsupported_ip)
ca_nc_duplicate_extensions = extensions_with_san(base_extensions[0],
                                                  nc_duplicate_permitted)


def cert(algorithm, key=spki, inner=None, extensions=cert_extensions,
         issuer=name, subject=name, validity=valid):
    # Extensions require v3 (version INTEGER 2 in [0] EXPLICIT).
    tbs = seq(tlv(0xa0, b'\x02\x01\x02'), b'\x02\x01\x01',
              inner or algorithm, issuer, validity, subject, key,
              extensions)
    signature = bytes([0x22 if algorithm == pss else 0x11]) * 256
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
    'cert_epoch_spanning': cert(pkcs, validity=epoch_spanning_valid),
    'cert_aki': cert(pkcs, extensions=cert_extensions_aki),
    'cert_duplicate_aki': cert(pkcs, extensions=cert_extensions_duplicate_aki),
    'cert_bad_aki': cert(pkcs, extensions=cert_extensions_bad_aki),
    'cert_nonminimal_ku': cert(pkcs, extensions=cert_extensions_nonminimal_ku),
    'cert_eku_any': cert(pkcs, extensions=eku_any_extensions),
    'cert_eku_absent': cert(pkcs, extensions=eku_absent_extensions),
    'cert_eku_client': cert(pkcs, extensions=eku_client_extensions),
    'cert_eku_empty': cert(pkcs, extensions=eku_empty_extensions),
    'cert_eku_critical': cert(pkcs, extensions=eku_critical_extensions),
    'cert_eku_malformed_oid': cert(pkcs,
                                  extensions=eku_malformed_oid_extensions),
    'cert_ca_self_issued': cert(
        pkcs, issuer=rollover_name, subject=rollover_name),
    'cert_ca_rollover_parent': cert(
        pkcs, extensions=cert_extensions_pathlen0,
        issuer=root_name, subject=rollover_name),
    'cert_ca_ordinary': cert(
        pkcs, issuer=ordinary_parent_name, subject=ordinary_child_name),
    'cert_ca_ordinary_parent': cert(
        pkcs, extensions=cert_extensions_pathlen0,
        issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_leaf_good': cert(pkcs, extensions=leaf_good_extensions,
                             issuer=ordinary_parent_name, subject=deep_name),
    'cert_nc_leaf_extra': cert(pkcs, extensions=leaf_extra_extensions,
                              issuer=ordinary_parent_name, subject=deep_name),
    'cert_nc_leaf_ip': cert(pkcs, extensions=leaf_ip_extensions,
                           issuer=ordinary_parent_name, subject=deep_name),
    'cert_nc_ca_dns': cert(pkcs, extensions=ca_nc_dns_extensions,
                          issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_excluded': cert(pkcs, extensions=ca_nc_excluded_extensions,
                               issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_directory': cert(pkcs, extensions=ca_nc_directory_extensions,
                                issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_noncritical': cert(pkcs, extensions=ca_nc_noncritical_extensions,
                                  issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_bad_minimum': cert(pkcs, extensions=ca_nc_bad_minimum_extensions,
                                  issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_empty': cert(pkcs, extensions=ca_nc_empty_extensions,
                            issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_unsupported': cert(pkcs, extensions=ca_nc_unsupported_extensions,
                                  issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_ca_duplicate': cert(pkcs, extensions=ca_nc_duplicate_extensions,
                                issuer=root_name, subject=ordinary_parent_name),
    'cert_nc_leaf_has_nc': cert(pkcs, extensions=ca_nc_dns_extensions,
                               issuer=ordinary_parent_name, subject=deep_name),
    'cert_ec': cert(pkcs, ec_spki), 'cert_mismatch': cert(pss, inner=pkcs),
}

source = (here / 'mock.h').read_text() + '\n#include "ip_identity.h"\n#include "base64.h"\n'
source += function(x509, 'tls_ecdsa_parse_int')
# Allocation helpers must precede production functions that now use heap-backed
# cryptographic/parser workspaces.
source += x509[x509.index('static void *tls_x509_alloc'):x509.index('static bool tls_x509_is_string_tag')]
source += x509[x509.index('static bool tls_x509_is_string_tag'):x509.index('static bool tls_x509_decode_pem_certificate')]
source += x509[x509.index('static const uint8_t oid_rsa_encryption'):]
# PEM decode/import/free, so parse_cert_chain (cert config load) can be driven.
source += x509[x509.index('static bool tls_x509_decode_pem_certificate'):
               x509.index('static const uint8_t oid_rsa_encryption')]
key_source = (root / 'src/tls/core/key.c').read_text()
source += function((root / 'src/tls/core/rsa.c').read_text(), 'tls_rsa_public_key_shape_ok')
# tls_p256_sign lives in eZ80 assembly; stub it for the host build. The client
# CertificateVerify test drives it with a known r||s so the DER encoding and the
# message framing can be checked byte for byte; every other test sees failure.
source += ('static bool test_p256_sign_ok;\n'
           'static const uint8_t test_p256_sign_rs[64] = {\n'
           '    0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,\n'
           '    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,\n'
           '    0x00, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,\n'
           '    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };\n'
           'static bool tls_p256_sign(uint8_t *sig, const uint8_t *hash, const uint8_t *priv) {\n'
           '    (void)hash; (void)priv;\n'
           '    if (!test_p256_sign_ok) return false;\n'
           '    memcpy(sig, test_p256_sign_rs, sizeof(test_p256_sign_rs));\n'
           '    return true;\n'
           '}\n'
           '/* tls_p384_sign is provided by mock.h */\n'
           '/* tls_crypto_guard_cleanup: eZ80-only; no-op for host build */\n'
           'static void tls_crypto_guard_cleanup(void) {}\n')
for name in ['ecdsa_der_integer', 'ecdsa_raw_to_der', 'tls_key_verify', 'tls_key_sign']:
    source += function(key_source, name)
# Include internal AES helpers and blob helpers (not aes_encrypt_oneshot, which is mocked).
source += key_source[key_source.index('/* ---------------------------------------------------------------------------\n * Internal helpers'):
                     key_source.index('/* ---------------------------------------------------------------------------\n * AES one-shot encrypt')]
for name in ['tls_cipher_blob_free', 'tls_cipher_encrypt', 'tls_cipher_encrypt_aad']:
    source += function(key_source, name)
source += hs[hs.index('enum tls_cert_walk_state'):hs.index('/* Feed body bytes into the walker.')]

# Certificate-chain splitting used when a cert listener/client config loads its
# AppVars. Driven with an exactly-sized, non-NUL-terminated buffer so ASan
# catches any overread of the kind read_appvar_pem() produces.
altcp_src = (root / 'src/apps/altcp_tls/altcp_tls_ce.c').read_text()
source += ('static void *mem_malloc(size_t n) { return malloc(n); }\n'
           'static void mem_free(void *p) { free(p); }\n')
_m = re.search(r"^static [\w \*]+parse_cert_chain\([^;]*?\)\s*\{", altcp_src, re.M)
assert _m, "parse_cert_chain"
_pos = _m.end()
_depth = 1
while _depth:
    _depth += (altcp_src[_pos] == "{") - (altcp_src[_pos] == "}")
    _pos += 1
source += altcp_src[_m.start():_pos] + "\n"
source += '#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403\n'
source += '#define TLS_SIG_ECDSA_SECP384R1_SHA384 0x0503\n'
# Suite table plus its lookup helper; they are file-scope data and a
# struct-returning pointer function the per-function extractor cannot take.
source += hs[hs.index('#define TLS_AES_GCM_RECORD_LIMIT'):hs.index('static bool tls_cipher_suite_supported')]
for name in ['transcript_hash_init', 'transcript_hash_update', 'transcript_hash_digest',
             'tls_parse_handshake_header',
             'tls_cipher_suite_supported', 'tls_cipher_suite_offered',
             'tls_cipher_suite_hash', 'tls_client_hello_clear',
             'tls_client_hello_save', 'tls_transcript_select_suite_hash',
             'tls_extension_type_known',
             'tls_handshake_init_common', 'tls_handshake_keyshares_begin',
             'tls_handshake_keyshare_fail', 'tls_handshake_keyshares_step',
             'tls_handshake_p256_step',
             'tls_handshake_init', 'tls_send_client_hello',
             'tls_recv_server_hello',
             'tls_recv_encrypted_extensions', 'tls_recv_certificate_request',
             'tls_recv_certificate_streamed', 'tls_certverify_rsa_pss_sha256',
             'tls_certverify_ecdsa_p384_sha384',
             'tls_send_empty_certificate', 'der_encode_integer',
             'der_encode_ecdsa_sig', 'tls_send_client_certificate',
             'tls_hs_defer_bytes', 'tls_cert_jobs_pending', 'tls_cert_jobs_step',
             'tls_handshake_cleanup']:
    source += function(hs, name)
for name, data in vectors.items():
    source += f'static const uint8_t {name}[] = {{' + ','.join(map(str, data)) + '};\n'

# A PEM fullchain, exactly as an AppVar would hold it (no trailing NUL).
import base64 as _b64


def _pem(der: bytes) -> str:
    body = _b64.b64encode(der).decode()
    lines = '\n'.join(body[i:i + 64] for i in range(0, len(body), 64))
    return ('-----BEGIN CERTIFICATE-----\n' + lines +
            '\n-----END CERTIFICATE-----\n')


_chain_pem = (_pem(bytes(vectors['cert_ec'])) + _pem(bytes(vectors['cert_mismatch'])))
source += ('static const uint8_t chain_pem[] = {' +
           ','.join(str(b) for b in _chain_pem.encode()) + '};\n')
source += 'static const uint8_t single_pem[] = {' + \
          ','.join(str(b) for b in _pem(bytes(vectors['cert_ec'])).encode()) + '};\n'
source += f'#define CERT_EC_DER_LEN {len(vectors["cert_ec"])}\n'
source += f'#define CERT_MISMATCH_DER_LEN {len(vectors["cert_mismatch"])}\n'
# Exercise the real matcher with DER SANs, including negative identities.
import ipaddress

def extensions(*names):
    return seq(seq(oid('551d11'), tlv(4, seq(*names))))

cases = []
def identity(ext, host, expected, cn=None):
    cases.append((ext, host, expected, cn or host))

v4 = tlv(0x87, ipaddress.ip_address('192.168.2.10').packed)
v6 = tlv(0x87, ipaddress.ip_address('2001:db8::1').packed)
for host, expected in [('192.168.2.10', True), ('192.168.2.11', False),
                       ('192.168.002.10', False), ('192.168.2', False),
                       ('256.168.2.10', False), ('192.168.2.10.', False)]:
    identity(extensions(v4), host, expected)
for host, expected in [('2001:db8::1', True), ('2001:0DB8:0:0:0:0:0:1', True),
                       ('2001:db8::2', False), ('2001::db8::1', False),
                       ('[2001:db8::1]', False), ('2001:db8::1%en0', False),
                       ('2001:db8:0:0:0:0:0:1::', False)]:
    identity(extensions(v6), host, expected)
for host in ['::', '::1', '1::', '::ffff:192.168.2.10']:
    identity(extensions(tlv(0x87, ipaddress.ip_address(host).packed)), host, True)
identity(extensions(v4, v6), '2001:db8::1', True)
identity(extensions(v4, v6), '192.168.2.10', True)
identity(extensions(v6), '192.168.2.10', False)
identity(extensions(tlv(0x87, b'192.168.2.10')), '192.168.2.10', False)
identity(extensions(tlv(0x82, b'192.168.2.10')), '192.168.2.10', False)
identity(extensions(tlv(0x82, b'*.168.2.10')), '192.168.2.10', False)
identity(b'', '192.168.2.10', False)
for alias in ['0xc0a8020a', '192.0xa8.2.10', '3232236042', '0300.0250.2.012']:
    identity(extensions(tlv(0x82, alias.encode())), alias, False)
identity(b'', '2001:db8::1', False)
identity(extensions(v4), 'example.test', False)
identity(extensions(tlv(0x82, b'*.example.test')), 'www.example.test', True)
identity(extensions(tlv(0x82, b'*.example.test')), 'a.b.example.test', False)
identity(b'', 'example.test', False)  # RFC 9525 forbids CommonName fallback.
identity(extensions(tlv(0x82, b'other.test')), 'example.test', False)
# A match must not hide a truncated following GeneralName.
identity(seq(seq(oid('551d11'), tlv(4, tlv(0x30, v4 + b'\x87\x04\x01')))), '192.168.2.10', False)
checks = []
for i, (ext, host, expected, cn) in enumerate(cases):
    source += f'static const uint8_t identity_{i}[] = {{' + ','.join(map(str, ext or b'\0')) + '};\n'
    checks.append(f'assert(tls_x509_hostname_matches(identity_{i}, {len(ext)}, (const uint8_t *)"{cn}", {len(cn)}, "{host}") == {int(expected)});')
source += 'static void identity_tests(void) {\n' + '\n'.join(checks) + '\n}\n'

if len(sys.argv) > 1:
    out = Path(sys.argv[1])
    (out / 'lwip').mkdir(parents=True, exist_ok=True)
    (out / 'lwip/logging.h').write_text(LOGGING_SHIM)
    (out / 'tls_unit.c').write_text(source + function(hs, 'tls_cert_walker_feed'))
    sys.exit(0)

# ---------------------------------------------------------------------------
# OCSP steps 1-3 host tests — injected BEFORE test.c (which contains main()).
# ---------------------------------------------------------------------------

def aia_extension(entries):
    """Build a DER AIA extension (id-pe-authorityInfoAccess).

    entries: list of (access_method_oid_hex, access_location_tag, value_bytes)
    Returns the full Extension SEQUENCE bytes.
    """
    access_descs = b''
    for method_hex, loc_tag, loc_val in entries:
        method_oid = oid(method_hex)
        loc = tlv(loc_tag, loc_val)
        access_descs += seq(method_oid + loc)
    access_list = tlv(0x30, access_descs)
    ext_value = tlv(4, access_list)
    return seq(oid('2b06010505070101') + ext_value)

def extensions_inner_with_aia(aia_ext, *extra):
    """Return the raw SEQUENCE OF Extension bytes (no [3] wrapper) for passing
    directly to tls_x509_get_ocsp_url as ext_data."""
    return seq(*(list(base_extensions) + [aia_ext] + list(extra)))

_ocsp_url = b'http://ocsp.example.com'
_cai_url  = b'http://ca.example.com/issuer.crt'

aia_ocsp_only        = aia_extension([('2b06010505073001', 0x86, _ocsp_url)])
aia_caissuers_only   = aia_extension([('2b06010505073002', 0x86, _cai_url)])
aia_ocsp_and_cai     = aia_extension([
    ('2b06010505073001', 0x86, _ocsp_url),
    ('2b06010505073002', 0x86, _cai_url),
])
aia_cai_then_ocsp    = aia_extension([
    ('2b06010505073002', 0x86, _cai_url),
    ('2b06010505073001', 0x86, _ocsp_url),
])

ext_with_ocsp     = extensions_inner_with_aia(aia_ocsp_only)
ext_no_ocsp       = extensions_inner_with_aia(aia_caissuers_only)
ext_ocsp_and_cai  = extensions_inner_with_aia(aia_ocsp_and_cai)
ext_cai_then_ocsp = extensions_inner_with_aia(aia_cai_then_ocsp)

def _c_bytes(data):
    return ','.join(map(str, data))

ocsp_checks = []
def ocsp_url_case(ext_bytes, expected_url):
    idx = len(ocsp_checks)
    source_name = f'ocsp_ext_{idx}'
    null_or_str = f'"{expected_url}"' if expected_url is not None else 'NULL'
    ocsp_checks.append((source_name, ext_bytes, expected_url, null_or_str))

ocsp_url_case(ext_with_ocsp,     _ocsp_url.decode())
ocsp_url_case(ext_no_ocsp,       None)
ocsp_url_case(ext_ocsp_and_cai,  _ocsp_url.decode())
ocsp_url_case(ext_cai_then_ocsp, _ocsp_url.decode())
ocsp_url_case(b'',               None)

source += '#include "ocsp.h"\n'
for name, ext_bytes, _, _ in ocsp_checks:
    _eb = ext_bytes if ext_bytes else b'\x00'
    source += f'static const uint8_t {name}[] = {{{_c_bytes(_eb)}}};\n'
source += 'static void ocsp_url_tests(void) {\n'
for name, ext_bytes, expected_url, null_or_str in ocsp_checks:
    ext_len = len(ext_bytes)
    null_ptr = 'NULL' if ext_len == 0 else name
    source += f'  {{ char *url = NULL;\n'
    source += f'    assert(tls_x509_get_ocsp_url({null_ptr}, {ext_len}, &url));\n'
    if expected_url is not None:
        source += f'    assert(url && strcmp(url, {null_or_str}) == 0);\n'
        source += f'    free(url);\n'
    else:
        source += f'    assert(url == NULL);\n'
    source += '  }\n'
source += '}\n'

source += (
    'static void ocsp_sha1_test(void) {\n'
    '  static const uint8_t abc[] = {0x61,0x62,0x63};\n'
    '  static const uint8_t expected[] = {\n'
    '    0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,\n'
    '    0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d\n'
    '  };\n'
    '  uint8_t nh[OCSP_SHA1_LEN], kh[OCSP_SHA1_LEN];\n'
    '  assert(tls_ocsp_hash_issuer(abc, 3, abc, 3, nh, kh));\n'
    '  assert(memcmp(nh, expected, OCSP_SHA1_LEN) == 0);\n'
    '  assert(memcmp(kh, expected, OCSP_SHA1_LEN) == 0);\n'
    '}\n'
)
source += (
    'static void ocsp_build_request_test(void) {\n'
    '  static const uint8_t serial[] = {0x01,0x02,0x03};\n'
    '  uint8_t nh[OCSP_SHA1_LEN], kh[OCSP_SHA1_LEN];\n'
    '  memset(nh, 0xAA, OCSP_SHA1_LEN);\n'
    '  memset(kh, 0xBB, OCSP_SHA1_LEN);\n'
    '  uint8_t *req = NULL; size_t req_len = 0;\n'
    '  assert(tls_ocsp_build_request(serial, sizeof(serial), nh, kh, &req, &req_len));\n'
    '  assert(req && req_len > 0);\n'
    '  assert(req[0] == 0x30);\n'
    '  int found = 0;\n'
    '  for (size_t i = 0; i + 3 <= req_len; i++)\n'
    '    if (memcmp(req+i, serial, 3) == 0) { found = 1; break; }\n'
    '  assert(found);\n'
    '  free(req);\n'
    '  assert(!tls_ocsp_build_request(NULL, 1, nh, kh, &req, &req_len));\n'
    '  assert(!tls_ocsp_build_request(serial, 0, nh, kh, &req, &req_len));\n'
    '  assert(!tls_ocsp_build_request(serial, 21, nh, kh, &req, &req_len));\n'
    '}\n'
)

source += (here / 'test.c').read_text()

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / 'lwip').mkdir()
    (tmp / 'lwip/logging.h').write_text(LOGGING_SHIM)
    unit = tmp / 'test.c'
    unit.write_text(source)
    # ocsp.c calls tls_fileio_alloc/free as external symbols; provide them in a
    # separate TU so the static definitions in mock.h don't interfere.
    alloc_shim = tmp / 'ocsp_alloc_shim.c'
    alloc_shim.write_text(
        '#include <stdlib.h>\n'
        '#include <stddef.h>\n'
        'void *tls_fileio_alloc(size_t n) { return malloc(n); }\n'
        'void  tls_fileio_free(void *p)   { free(p); }\n'
    )
    binary = tmp / 'test'
    subprocess.run(['cc', '-std=c99', '-g', '-Wall', '-Wextra',
                    '-Wno-unused-function', '-Wno-unused-parameter',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(tmp), '-I' + str(root / 'src/tls/includes'),
                    '-I' + str(root / 'src/tls/core'), str(unit),
                    str(root / 'src/tls/core/asn1.c'),
                    str(root / 'src/tls/core/base64.c'),
                    str(root / 'src/tls/core/ocsp.c'),
                    str(alloc_shim),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
