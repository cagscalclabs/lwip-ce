#!/usr/bin/env python3
"""Host regression tests for authenticated OCSP parsing and request encoding."""

from pathlib import Path
import hashlib
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes((n,))
    elif n < 0x100:
        length = bytes((0x81, n))
    else:
        length = bytes((0x82, n >> 8, n & 0xFF))
    return bytes((tag,)) + length + value


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


OID_BASIC = tlv(0x06, bytes.fromhex("2b0601050507300101"))
OID_SHA1 = seq(tlv(0x06, bytes.fromhex("2b0e03021a")), tlv(0x05, b""))
ALG_ECDSA_SHA256 = seq(tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
NAME_HASH = bytes(range(1, 21))
KEY_HASH = bytes(range(21, 41))
SERIAL = b"\x00\xc8"
RESPONDER_ISSUER_NAME = seq(tlv(0x31, seq(tlv(0x06, bytes.fromhex("550403")),
                                         tlv(0x0c, b"OCSP Test CA"))))
RESPONDER_KEY_RAW = b"delegated responder public key"
DELEGATED_NAME_HASH = hashlib.sha1(RESPONDER_ISSUER_NAME).digest()
DELEGATED_RESPONDER_HASH = hashlib.sha1(RESPONDER_KEY_RAW).digest()
DELEGATED_CERT = seq(tlv(0x02, b"\x01"))


def response(*, status_tag: int = 0x80, name_hash: bytes = NAME_HASH,
             key_hash: bytes = KEY_HASH, responder_hash: bytes = KEY_HASH,
             produced: bytes = b"GOODPRODUCED000",
             this_update: bytes = b"GOODTHISUPDATE0",
             next_update: bytes | None = b"GOODNEXTUPDATE0",
             embedded_cert: bytes | None = None) -> bytes:
    cert_id = seq(OID_SHA1, tlv(0x04, name_hash), tlv(0x04, key_hash),
                  tlv(0x02, SERIAL))
    fields = cert_id + tlv(status_tag, b"" if status_tag != 0xA1 else
                              tlv(0x18, b"GOODREVOKEDATE0"))
    fields += tlv(0x18, this_update)
    if next_update is not None:
        fields += tlv(0xA0, tlv(0x18, next_update))
    single = seq(fields)
    tbs = seq(tlv(0x82, responder_hash), tlv(0x18, produced), seq(single))
    basic_fields = tbs + ALG_ECDSA_SHA256 + tlv(0x03, b"\x00\xaa")
    if embedded_cert is not None:
        basic_fields += tlv(0xA0, seq(embedded_cert))
    basic = seq(basic_fields)
    response_bytes = seq(OID_BASIC, tlv(0x04, basic))
    return seq(tlv(0x0A, b"\x00"), tlv(0xA0, response_bytes))


def c_array(name: str, data: bytes) -> str:
    return f"static const uint8_t {name}[] = {{" + ",".join(map(str, data)) + "};\n"


good = response()
revoked = response(status_tag=0xA1)
unknown = response(status_tag=0x82)
bad_certid = response(name_hash=b"\xff" * 20)
bad_responder = response(responder_hash=b"\xee" * 20)
stale = response(next_update=b"STALE0000000000")
future = response(this_update=b"FUTURE000000000")
delegated = response(name_hash=DELEGATED_NAME_HASH,
                     responder_hash=DELEGATED_RESPONDER_HASH,
                     embedded_cert=DELEGATED_CERT)
delegated_without_cert = response(name_hash=DELEGATED_NAME_HASH,
                                  responder_hash=DELEGATED_RESPONDER_HASH)

# Expected request encoding for the same complete CertID.
cert_id = seq(OID_SHA1, tlv(0x04, NAME_HASH), tlv(0x04, KEY_HASH), tlv(0x02, b"\x00\xc8"))
expected_request = seq(seq(seq(seq(cert_id))))


def openssl_vector() -> tuple[bytes, bytes, bytes]:
    """Produce the same issuer-signed response shape used by NETTLS."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ca_key, ca_cert = td / "ca.key", td / "ca.pem"
        leaf_key, leaf_csr, leaf_cert = td / "leaf.key", td / "leaf.csr", td / "leaf.pem"
        index, request, response_file = td / "index.txt", td / "request.der", td / "response.der"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "2", "-subj", "/CN=OCSP Test CA", "-keyout", str(ca_key),
            "-out", str(ca_cert), "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=leaf",
            "-keyout", str(leaf_key), "-out", str(leaf_csr),
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "x509", "-req", "-in", str(leaf_csr), "-sha256",
            "-CA", str(ca_cert), "-CAkey", str(ca_key), "-set_serial", "200",
            "-days", "2", "-out", str(leaf_cert),
        ], check=True, capture_output=True)
        subject = subprocess.run([
            "openssl", "x509", "-in", str(leaf_cert), "-noout", "-subject",
            "-nameopt", "RFC2253",
        ], check=True, capture_output=True, text=True).stdout.strip().removeprefix("subject=").strip()
        index.write_text(f"V\t351231235959Z\t\tC8\tunknown\t{subject}\n")
        subprocess.run([
            "openssl", "ocsp", "-issuer", str(ca_cert), "-cert", str(leaf_cert),
            "-reqout", str(request),
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "ocsp", "-index", str(index), "-CA", str(ca_cert),
            "-rsigner", str(ca_cert), "-rkey", str(ca_key),
            "-reqin", str(request), "-respout", str(response_file), "-noverify",
        ], check=True, capture_output=True)
        request_text = subprocess.run([
            "openssl", "ocsp", "-reqin", str(request), "-req_text",
        ], check=True, capture_output=True, text=True).stdout
        name = re.search(r"Issuer Name Hash:\s*([0-9A-Fa-f]+)", request_text)
        key = re.search(r"Issuer Key Hash:\s*([0-9A-Fa-f]+)", request_text)
        assert name and key
        return response_file.read_bytes(), bytes.fromhex(name.group(1)), bytes.fromhex(key.group(1))


openssl_response, openssl_name_hash, openssl_key_hash = openssl_vector()

source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ocsp.h"
#include "x509_internal.h"

static bool force_bad_signature;
static bool responder_authorized = true;
static bool responder_valid = true;
static unsigned verify_calls;
static const uint8_t responder_issuer_name[] = {
'''
source += ",".join(map(str, RESPONDER_ISSUER_NAME))
source += r'''};
static const uint8_t responder_key_raw[] = {
'''
source += ",".join(map(str, RESPONDER_KEY_RAW))
source += r'''};

void *tls_fileio_alloc(size_t n) { return malloc(n); }
void tls_fileio_free(void *p) { free(p); }

bool tls_x509_signature_algorithm(const struct tls_asn1_tlv *identifier,
                                  tls_alg_t *alg)
{
    (void)identifier;
    *alg = TLS_ALG_ECDSA_SECP256R1_SHA256;
    return true;
}

bool tls_x509_parse_certificate(const uint8_t *der, size_t len,
                                struct tls_x509_object *cert)
{
    static const uint8_t encoded[] = {0x30,0x03,0x02,0x01,0x01};
    if (len != sizeof(encoded) || memcmp(der, encoded, len)) return false;
    memset(cert, 0, sizeof(*cert));
    cert->from_handshake = true;
    cert->issuer_name = responder_issuer_name;
    cert->issuer_name_len = sizeof(responder_issuer_name);
    cert->subject_pubkey_raw = responder_key_raw;
    cert->subject_pubkey_raw_len = sizeof(responder_key_raw);
    cert->pubkey.type = TLS_KEY_TYPE_EC_P256;
    cert->pubkey.ec.pub = responder_key_raw;
    cert->pubkey.ec.len = sizeof(responder_key_raw);
    return true;
}

bool tls_x509_time_in_validity(const struct tls_x509_object *cert,
                               uint32_t now)
{
    (void)cert; (void)now;
    return responder_valid;
}

bool tls_x509_validate_ocsp_responder_extensions(
    const struct tls_x509_object *cert)
{
    (void)cert;
    return responder_authorized;
}

bool tls_x509_certificate_signature_material(const uint8_t *der, size_t len,
                                              const uint8_t **tbs,
                                              size_t *tbs_len,
                                              tls_alg_t *alg,
                                              const uint8_t **sig,
                                              size_t *sig_len)
{
    static const uint8_t signed_data[] = {0x30,0x00};
    static const uint8_t signature[] = {0xaa};
    (void)der; (void)len;
    *tbs = signed_data; *tbs_len = sizeof(signed_data);
    *alg = TLS_ALG_ECDSA_SECP256R1_SHA256;
    *sig = signature; *sig_len = sizeof(signature);
    return true;
}

tls_key_op_result_t tls_x509_signature_verify(const uint8_t *content,
                                               size_t content_len,
                                               const uint8_t *sig,
                                               size_t sig_len,
                                               const struct tls_key *key,
                                               tls_alg_t alg)
{
    assert(content && content_len && key);
    assert(alg == TLS_ALG_ECDSA_SECP256R1_SHA256);
    (void)sig;
    verify_calls++;
    return !force_bad_signature && sig_len > 0
        ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
}

bool tls_x509_time_to_unix(const uint8_t *data, size_t len, uint8_t tag,
                           uint32_t *out)
{
    (void)tag;
    if (len != 15) return false;
    if (!memcmp(data, "GOODPRODUCED000", 15)) *out = 1200;
    else if (!memcmp(data, "GOODTHISUPDATE0", 15)) *out = 1000;
    else if (!memcmp(data, "GOODNEXTUPDATE0", 15)) *out = 2000;
    else if (!memcmp(data, "GOODREVOKEDATE0", 15)) *out = 900;
    else if (!memcmp(data, "STALE0000000000", 15)) *out = 1000;
    else if (!memcmp(data, "FUTURE000000000", 15)) *out = 3000;
    else *out = 1500; /* OpenSSL-generated GeneralizedTime fixture. */
    return true;
}
'''
for name, data in {
    "good": good,
    "revoked": revoked,
    "unknown": unknown,
    "bad_certid": bad_certid,
    "bad_responder": bad_responder,
    "stale": stale,
    "future": future,
    "delegated": delegated,
    "delegated_without_cert": delegated_without_cert,
    "delegated_name_hash": DELEGATED_NAME_HASH,
    "expected_request": expected_request,
    "openssl_response": openssl_response,
    "openssl_name_hash": openssl_name_hash,
    "openssl_key_hash": openssl_key_hash,
}.items():
    source += c_array(name, data)

source += r'''
static tls_ocsp_status_t parse(const uint8_t *p, size_t n)
{
    static const struct tls_key issuer = {.type = TLS_KEY_TYPE_EC_P256};
    static const uint8_t serial[] = {0, 0xc8};
    return tls_ocsp_parse_response(p, n, serial, sizeof(serial),
                                   (const uint8_t[]){1,2,3,4,5,6,7,8,9,10,
                                       11,12,13,14,15,16,17,18,19,20},
                                   (const uint8_t[]){21,22,23,24,25,26,27,28,29,30,
                                       31,32,33,34,35,36,37,38,39,40},
                                   &issuer, 1500);
}

static tls_ocsp_status_t parse_openssl(void)
{
    static const struct tls_key issuer = {.type = TLS_KEY_TYPE_RSA};
    static const uint8_t serial[] = {0, 0xc8};
    return tls_ocsp_parse_response(openssl_response, sizeof(openssl_response),
                                   serial, sizeof(serial),
                                   openssl_name_hash, openssl_key_hash,
                                   &issuer, 1500);
}

static tls_ocsp_status_t parse_delegated(const uint8_t *p, size_t n)
{
    static const struct tls_key issuer = {.type = TLS_KEY_TYPE_EC_P256};
    static const uint8_t serial[] = {0, 0xc8};
    return tls_ocsp_parse_response(p, n, serial, sizeof(serial),
                                   delegated_name_hash,
                                   (const uint8_t[]){21,22,23,24,25,26,27,28,29,30,
                                       31,32,33,34,35,36,37,38,39,40},
                                   &issuer, 1500);
}

int main(void)
{
    uint8_t *request = NULL;
    uint8_t name_hash[20], key_hash[20];
    size_t request_len = 0;
    static const uint8_t serial[] = {0, 0xc8};
    static const uint8_t abc[] = {'a','b','c'};
    static const uint8_t sha1_abc[] = {
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
        0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};

    assert(tls_ocsp_hash_issuer(abc, sizeof(abc), abc, sizeof(abc),
                                name_hash, key_hash));
    assert(!memcmp(name_hash, sha1_abc, sizeof(name_hash)));
    assert(!memcmp(key_hash, sha1_abc, sizeof(key_hash)));

    assert(tls_ocsp_build_request(serial, sizeof(serial),
                                  (const uint8_t[]){1,2,3,4,5,6,7,8,9,10,
                                      11,12,13,14,15,16,17,18,19,20},
                                  (const uint8_t[]){21,22,23,24,25,26,27,28,29,30,
                                      31,32,33,34,35,36,37,38,39,40},
                                  &request, &request_len));
    assert(request_len == sizeof(expected_request));
    assert(!memcmp(request, expected_request, request_len));
    tls_ocsp_free(request);

    assert(parse(good, sizeof(good)) == OCSP_GOOD);
    assert(parse(revoked, sizeof(revoked)) == OCSP_REVOKED);
    assert(parse(unknown, sizeof(unknown)) == OCSP_UNKNOWN);
    assert(parse(bad_certid, sizeof(bad_certid)) == OCSP_UNKNOWN);
    assert(parse(bad_responder, sizeof(bad_responder)) == OCSP_PARSE_ERROR);
    assert(parse(stale, sizeof(stale)) == OCSP_PARSE_ERROR);
    assert(parse(future, sizeof(future)) == OCSP_PARSE_ERROR);
    assert(parse_openssl() == OCSP_GOOD);
    {
        unsigned before = verify_calls;
        assert(parse_delegated(delegated, sizeof(delegated)) == OCSP_GOOD);
        assert(verify_calls == before + 2); /* responder cert, then response */
        assert(parse_delegated(delegated_without_cert,
                               sizeof(delegated_without_cert)) ==
               OCSP_PARSE_ERROR);
        responder_authorized = false;
        assert(parse_delegated(delegated, sizeof(delegated)) ==
               OCSP_PARSE_ERROR);
        responder_authorized = true;
        responder_valid = false;
        assert(parse_delegated(delegated, sizeof(delegated)) ==
               OCSP_PARSE_ERROR);
        responder_valid = true;
        force_bad_signature = true;
        assert(parse_delegated(delegated, sizeof(delegated)) ==
               OCSP_PARSE_ERROR);
        force_bad_signature = false;
    }
    force_bad_signature = true;
    assert(parse(good, sizeof(good)) == OCSP_PARSE_ERROR);
    assert(verify_calls == 11);
    return 0;
}
'''

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    c_file = td / "test.c"
    binary = td / "test"
    c_file.write_text(source)
    subprocess.run([
        "cc", "-std=c99", "-g", "-Wall", "-Wextra", "-Duint24_t=uint32_t",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        f"-I{ROOT / 'src/tls/core'}", f"-I{ROOT / 'src/tls/includes'}",
        f"-I{ROOT / 'src/include'}", str(c_file),
        str(ROOT / "src/tls/core/ocsp.c"),
        str(ROOT / "src/tls/core/asn1.c"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)

print("Authenticated OCSP request/response regressions: PASS")
