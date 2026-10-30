#!/usr/bin/env python3
"""Guard the TLS 1.3 certificate-server flight and signed transcript order."""

from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[3]
source = (root / "src/tls/core/handshake.c").read_text()
altcp_source = (root / "src/apps/altcp_tls/altcp_tls_ce.c").read_text()
hello_start = source.index("bool tls_server_recv_client_hello(")
hello_end = source.index("\n/* Encode a raw 32-byte", hello_start)
hello = source[hello_start:hello_end]
start = source.index("bool tls_server_send_flight(")
end = source.index("\nbool tls_server_recv_finished(", start)
flight = source[start:end]

# The flight is emitted one message per call, so the order is expressed by the
# cursor cases rather than by a single function body.
encrypted_extensions = flight.index("case TLS_SERVER_FLIGHT_ENCRYPTED_EXTENSIONS:")
certificate = flight.index("case TLS_SERVER_FLIGHT_CERTIFICATE:")
certificate_verify = flight.index("case TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY:")
finished = flight.index("case TLS_SERVER_FLIGHT_FINISHED:")

assert encrypted_extensions < certificate < certificate_verify < finished

# Each case emits its own message type.
assert flight.index("out[0] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;") > encrypted_extensions
assert flight.index("out[0] = TLS_HANDSHAKE_CERTIFICATE;") > certificate
assert flight.index("out[0] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;") > certificate_verify

# EncryptedExtensions and Certificate enter the transcript before the
# CertificateVerify signing content is produced; CertificateVerify enters it
# after signing.
ee_hash = flight.index("transcript_hash_update", encrypted_extensions)
cert_hash = flight.index("transcript_hash_update", certificate)
cv_hash = flight.index("transcript_hash_update", certificate_verify)
sign = flight.index("tls_key_sign(")
assert ee_hash < sign and cert_hash < sign and sign < cv_hash

# The cursor advances in order, and a certificate-less server skips straight
# from EncryptedExtensions to Finished.
assert "? TLS_SERVER_FLIGHT_CERTIFICATE : TLS_SERVER_FLIGHT_FINISHED;" in flight
assert "ctx->server_flight_step = TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY;" in flight
assert "ctx->server_flight_step = TLS_SERVER_FLIGHT_FINISHED;" in flight
assert "ctx->server_flight_step = TLS_SERVER_FLIGHT_DONE;" in flight

# The ALTCP bridge must reserve the handshake header, extensions vector,
# ALPN extension header, ProtocolNameList length, name length, and name bytes:
# 6 + 7 + negotiated_alpn_len bytes in total.
assert re.search(
    r"msg_cap\s*=\s*6u\s*\+\s*\(ctx->negotiated_alpn\s*"
    r"\?\s*7u\s*\+\s*ctx->negotiated_alpn_len\s*:\s*0u\)",
    altcp_source,
    re.S,
)

# Certificate-only ClientHellos do not contain the PSK extensions.  Keep the
# external-PSK requirements and ServerHello selection confined to that mode.
assert "!cert_mode && (!psk_modes_seen || !psk_seen || !dhe_mode || !psk_ok)" in hello
assert "!suite || !groups_seen || !x25519_group" in hello
assert "cert_mode && (!sigalgs_seen || !p256_signature" in hello
assert "TLS_SIG_ECDSA_SECP256R1_SHA256" in hello
assert "ctx->psk_mode = !cert_mode;" in hello
assert "(cert_mode ? 0 : 6)" in hello
assert hello.count("if (!cert_mode)") >= 3

# The server sends one legal X25519 HRR, performs RFC 8446 transcript
# replacement, and requires CH2 to contain exactly the requested share.
assert "ctx->hrr_requested_group = TLS_NAMED_GROUP_X25519;" in hello
assert "uint8_t synth[36] = {0xfe, 0, 0, 32};" in hello
assert "share_entries != 1" in hello
assert "offer_gcm ? TLS_AES_128_GCM_SHA256" in hello


def function(name: str) -> str:
    match = re.search(r"^static size_t " + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos]


c_test = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
""" + function("der_encode_integer") + function("der_encode_ecdsa_sig") + r"""
int main(void)
{
    uint8_t value[64] = {0};
    uint8_t encoded[72];
    size_t len;

    value[31] = 1;
    len = der_encode_integer(encoded, value);
    assert(len == 3 && encoded[0] == 2 && encoded[1] == 1 && encoded[2] == 1);

    memset(value, 0, sizeof(value));
    value[0] = 0x80;
    len = der_encode_integer(encoded, value);
    assert(len == 35 && encoded[0] == 2 && encoded[1] == 33 && encoded[2] == 0);

    memset(value, 0, sizeof(value));
    value[31] = 1;
    value[32] = 0x80;
    len = der_encode_ecdsa_sig(encoded, value);
    assert(len == 40 && encoded[0] == 0x30 && encoded[1] == 38);
    assert(encoded[2] == 2 && encoded[3] == 1 && encoded[4] == 1);
    assert(encoded[5] == 2 && encoded[6] == 33 && encoded[7] == 0);
    return 0;
}
"""

# Drive the emitter itself, not just the DER encoders: one message per call, in
# order, with the transcript updated before CertificateVerify signs it.
c_emit = r"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ERROR_CODE(...) ((void)0)
#define TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS 0x08
#define TLS_HANDSHAKE_CERTIFICATE 0x0b
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 0x0f
#define TLS_EXT_ALPN 0x0010
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SHA256_DIGEST_LEN 32
#define TLS_SHA384_DIGEST_LEN 48
#define TLS_HASH_MAX_DIGEST_LEN 48
#define TLS_ALG_ECDSA_SECP256R1_SHA256 1
#define TLS_STATE_HANDSHAKE_KEYS_DERIVED 3
#define TLS_STATE_SERVER_FINISHED_RECEIVED 4
#define TLS_SERVER_FLIGHT_ENCRYPTED_EXTENSIONS 0
#define TLS_SERVER_FLIGHT_CERTIFICATE 1
#define TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY 2
#define TLS_SERVER_FLIGHT_FINISHED 3
#define TLS_SERVER_FLIGHT_DONE 4

typedef enum { TLS_KEY_OP_OK, TLS_KEY_OP_INVALID } tls_key_op_result_t;

struct tls_hash_context { unsigned marker; };
struct tls_key { unsigned marker; };
struct tls_x509_object { const uint8_t *der; size_t der_len; };
struct tls_handshake_context {
    uint8_t server_flight_step;
    int state;
    struct tls_hash_context *transcript_hash;
    uint8_t hash_len;
    struct tls_x509_object *server_cert;
    struct tls_key *server_key;
    struct tls_x509_object **server_chain;
    size_t server_chain_len;
    const uint8_t *negotiated_alpn;
    size_t negotiated_alpn_len;
};

static uint8_t transcript[1024];
static size_t transcript_len;
static unsigned transcript_updates;
static bool sign_called;
static size_t sign_content_len;

static void transcript_hash_update(struct tls_hash_context *ctx, const void *data, size_t len)
{
    assert(ctx);
    assert(transcript_len + len <= sizeof(transcript));
    memcpy(transcript + transcript_len, data, len);
    transcript_len += len;
    transcript_updates++;
}
static void tls_hash_context_copy(struct tls_hash_context *dst, const struct tls_hash_context *src)
{
    *dst = *src;
}
static void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *out)
{
    (void)ctx;
    memset(out, 0x42, 32);
}
static void tls_hash_clear(struct tls_hash_context *ctx) { memset(ctx, 0, sizeof(*ctx)); }
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }

static tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                        uint8_t *sig_out, size_t *sig_len_out,
                                        const struct tls_key *key, int alg)
{
    static const char label[] = "TLS 1.3, server CertificateVerify";
    assert(key != NULL);
    assert(alg == TLS_ALG_ECDSA_SECP256R1_SHA256);
    sign_content_len = content_len;
    assert(content_len == 64 + sizeof(label) - 1 + 1 + 32);
    for (size_t i = 0; i < 64; i++) assert(content[i] == 0x20);
    assert(memcmp(content + 64, label, sizeof(label) - 1) == 0);
    assert(content[64 + sizeof(label) - 1] == 0);
    for (size_t i = 0; i < 32; i++) assert(content[64 + sizeof(label) + i] == 0x42);
    for (size_t i = 0; i < 32; i++) sig_out[i] = (uint8_t)(0x80 + i);
    for (size_t i = 0; i < 32; i++) sig_out[32 + i] = (uint8_t)(0x01 + i);
    *sig_len_out = 64;
    sign_called = true;
    return TLS_KEY_OP_OK;
}
static bool tls_send_finished(struct tls_handshake_context *ctx, bool is_client,
                              uint8_t *out, size_t out_cap, size_t *written)
{
    (void)ctx;
    assert(!is_client);
    if (out_cap < 36) return false;
    memset(out, 0xa5, 36);
    *written = 36;
    return true;
}
"""
c_emit += function("der_encode_integer")
c_emit += function("der_encode_ecdsa_sig")
def exported_function(name: str) -> str:
    """Like function(), for the non-static builders (bool <name>(...))."""
    match = re.search(r"^bool " + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos]

c_emit += exported_function("tls_server_send_flight")
c_emit += r"""
static size_t u24(const uint8_t *p)
{
    return ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
}

int main(void)
{
    static const uint8_t leaf[] = {0x30, 0x01, 0x11};
    static const uint8_t intermediate[] = {0x30, 0x02, 0x22, 0x33};
    struct tls_x509_object leaf_obj = {leaf, sizeof(leaf)};
    struct tls_x509_object intermediate_obj = {intermediate, sizeof(intermediate)};
    struct tls_x509_object *chain[] = {&leaf_obj, &intermediate_obj};
    struct tls_hash_context hash = {0};
    struct tls_key key = {0};
    struct tls_handshake_context ctx;
    uint8_t out[512];
    size_t written = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.transcript_hash = &hash;
    ctx.hash_len = 32;
    ctx.server_cert = &leaf_obj;
    ctx.server_key = &key;
    ctx.server_chain = chain;
    ctx.server_chain_len = 2;

    /* 1. EncryptedExtensions, no ALPN negotiated: 4-byte header + empty ext. */
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(written == 6);
    assert(out[0] == TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS);
    assert(u24(out + 1) == 2 && out[4] == 0 && out[5] == 0);
    assert(ctx.server_flight_step == TLS_SERVER_FLIGHT_CERTIFICATE);
    assert(transcript_updates == 1 && transcript_len == 6);

    /* 2. Certificate with both entries. */
    memset(out, 0, sizeof(out));
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(out[0] == TLS_HANDSHAKE_CERTIFICATE);
    size_t body = u24(out + 1);
    assert(written == 4 + body);
    assert(out[4] == 0);   /* certificate_request_context */
    size_t list = u24(out + 5);
    assert(list == (3 + sizeof(leaf) + 2) + (3 + sizeof(intermediate) + 2));
    size_t p = 8;
    assert(u24(out + p) == sizeof(leaf));
    p += 3;
    assert(memcmp(out + p, leaf, sizeof(leaf)) == 0);
    p += sizeof(leaf);
    assert(out[p] == 0 && out[p + 1] == 0);
    p += 2;
    assert(u24(out + p) == sizeof(intermediate));
    p += 3;
    assert(memcmp(out + p, intermediate, sizeof(intermediate)) == 0);
    p += sizeof(intermediate);
    assert(out[p] == 0 && out[p + 1] == 0);
    p += 2;
    assert(p == written);
    assert(ctx.server_flight_step == TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY);
    assert(!sign_called);
    assert(transcript_updates == 2 && transcript_len == 6 + written);

    /* 3. CertificateVerify, signed over the transcript through Certificate. */
    memset(out, 0, sizeof(out));
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(sign_called);
    assert(sign_content_len == 64 + 33 + 1 + 32);
    assert(out[0] == TLS_HANDSHAKE_CERTIFICATE_VERIFY);
    assert(out[4] == 0x04 && out[5] == 0x03);
    size_t sig_len = ((size_t)out[6] << 8) | out[7];
    assert(written == 8 + sig_len);
    assert(out[8] == 0x30 && (size_t)out[9] + 2 == sig_len);
    assert(ctx.server_flight_step == TLS_SERVER_FLIGHT_FINISHED);
    assert(transcript_len == 6 + (4 + body) + written);

    /* 4. Finished. */
    memset(out, 0, sizeof(out));
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(written == 36 && out[0] == 0xa5);
    assert(ctx.server_flight_step == TLS_SERVER_FLIGHT_DONE);
    assert(ctx.state == TLS_STATE_SERVER_FINISHED_RECEIVED);

    /* 5. Nothing left. */
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(written == 0);

    /* 6. A server without a certificate goes straight from
     *    EncryptedExtensions to Finished. */
    memset(&ctx, 0, sizeof(ctx));
    transcript_len = transcript_updates = 0;
    sign_called = false;
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.transcript_hash = &hash;
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(written == 6);
    assert(ctx.server_flight_step == TLS_SERVER_FLIGHT_FINISHED);
    assert(tls_server_send_flight(&ctx, out, sizeof(out), &written));
    assert(written == 36 && !sign_called);

    /* 7. A buffer that cannot hold the message is refused, not truncated. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.transcript_hash = &hash;
    assert(!tls_server_send_flight(&ctx, out, 4, &written));

    /* 8. ALPN adds seven framing bytes plus the selected protocol. The caller
     *    must reserve all 15 bytes for a two-byte protocol such as h2. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.transcript_hash = &hash;
    ctx.negotiated_alpn = (const uint8_t *)"h2";
    ctx.negotiated_alpn_len = 2;
    assert(!tls_server_send_flight(&ctx, out, 14, &written));
    assert(tls_server_send_flight(&ctx, out, 15, &written));
    assert(written == 15 && out[0] == TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS);
    assert(out[13] == 'h' && out[14] == '2');
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="tls-server-flight-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", str(unit), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)

    unit.write_text(c_emit)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(unit),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print("TLS server certificate flight order: PASS")
