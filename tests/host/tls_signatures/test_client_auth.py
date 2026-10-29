#!/usr/bin/env python3
"""Exercise the production TLS 1.3 client Certificate flight builder."""

from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[3]
source = (root / "src/tls/core/handshake.c").read_text()
altcp = (root / "src/apps/altcp_tls/altcp_tls_ce.c").read_text()
socket_api = (root / "src/lwIP.c").read_text()

# Guard the ALTCP integration as well as the serializer: client auth must be
# encrypted under handshake keys and sent before the client Finished.
auth_start = altcp.index("if (state->tls_ctx.client_certificate_requested)")
finished_start = altcp.index("/* Generate client Finished message", auth_start)
auth_path = altcp[auth_start:finished_start]
assert "tls_send_client_certificate(" in auth_path
assert "altcp_tls_ce_write_handshake_fragments(" in auth_path
# The empty-identity path now lives inside the Certificate case of the emitter.
assert "tls_send_empty_certificate(" not in auth_path

# At socket level, setting the certificate fields must select the mTLS client
# configuration before the external-PSK branch.
connect_start = socket_api.index("static lwip_error_t lwip_socket_connect_now(")
connect_end = socket_api.index("lwip_error_t lwip_socket_connect(", connect_start)
connect_path = socket_api[connect_start:connect_end]
assert connect_path.index("altcp_tls_ce_create_config_cert_client(") < connect_path.index(
    "altcp_tls_ce_create_config_psk_client("
)


def function(name: str) -> str:
    match = re.search(
        r"^(?:static )?(?:size_t|bool) " + name + r"\([^;]*?\)\s*\{",
        source,
        re.M,
    )
    assert match, name
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos] + "\n"


c_test = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ERROR_CODE(...) ((void)0)
#define TLS_HANDSHAKE_CERTIFICATE 0x0b
#define TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY 0x0f
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 0x0f
#define TLS_CLIENT_FLIGHT_CERTIFICATE 0
#define TLS_CLIENT_FLIGHT_CERTIFICATE_VERIFY 1
#define TLS_CLIENT_FLIGHT_DONE 2
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_ALG_ECDSA_SECP256R1_SHA256 1
#define TLS_STATE_SERVER_FINISHED_RECEIVED 2

typedef enum {
    TLS_KEY_OP_OK,
    TLS_KEY_OP_INVALID
} tls_key_op_result_t;

struct tls_hash_context { unsigned marker; };
struct tls_key { unsigned marker; };
struct tls_x509_object {
    const uint8_t *der;
    size_t der_len;
};
struct tls_handshake_context {
    uint8_t client_flight_step;
    bool client_certificate_requested;
    bool client_certificate_compatible;
    int state;
    struct tls_hash_context *transcript_hash;
    struct tls_key *client_key;
    struct tls_x509_object **client_chain;
    size_t client_chain_len;
};

static uint8_t transcript[1024];
static size_t transcript_len;
static unsigned transcript_updates;
static bool sign_called;

static void transcript_hash_update(struct tls_hash_context *ctx,
                                   const uint8_t *data, size_t len)
{
    assert(ctx != NULL);
    assert(transcript_len + len <= sizeof(transcript));
    memcpy(transcript + transcript_len, data, len);
    transcript_len += len;
    transcript_updates++;
}

static void tls_hash_context_copy(struct tls_hash_context *dst,
                                  const struct tls_hash_context *src)
{
    *dst = *src;
}

static void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *out)
{
    (void)ctx;
    memset(out, 0x42, 32);
}

static void tls_hash_clear(struct tls_hash_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

static void tls_secure_memzero(void *p, size_t len)
{
    memset(p, 0, len);
}

static tls_key_op_result_t tls_key_sign(
    const uint8_t *content, size_t content_len,
    uint8_t *sig, size_t *sig_len,
    const struct tls_key *key, int algorithm)
{
    static const char label[] = "TLS 1.3, client CertificateVerify";
    assert(key != NULL);
    assert(algorithm == TLS_ALG_ECDSA_SECP256R1_SHA256);
    assert(content_len == 64 + sizeof(label) - 1 + 1 + 32);
    for (size_t i = 0; i < 64; i++) assert(content[i] == 0x20);
    assert(memcmp(content + 64, label, sizeof(label) - 1) == 0);
    assert(content[64 + sizeof(label) - 1] == 0);
    for (size_t i = 0; i < 32; i++)
        assert(content[64 + sizeof(label) + i] == 0x42);

    memset(sig, 0, 64);
    sig[0] = 0x80;   /* Force positive-INTEGER padding for r. */
    sig[63] = 1;     /* Force leading-zero trimming for s. */
    *sig_len = 64;
    sign_called = true;
    return TLS_KEY_OP_OK;
}
'''

c_test += function("tls_send_empty_certificate")
c_test += function("der_encode_integer")
c_test += function("der_encode_ecdsa_sig")
c_test += function("tls_send_client_certificate")
c_test += r'''
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
    struct tls_handshake_context ctx = {
        .client_certificate_requested = true,
        .client_certificate_compatible = true,
        .state = TLS_STATE_SERVER_FINISHED_RECEIVED,
        .transcript_hash = &hash,
        .client_key = &key,
        .client_chain = chain,
        .client_chain_len = 2,
    };
    uint8_t out[512];
    size_t written = 0;

    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(out[0] == TLS_HANDSHAKE_CERTIFICATE);
    size_t certificate_len = 4 + u24(out + 1);
    assert(out[4] == 0);
    assert(u24(out + 5) == (3 + sizeof(leaf) + 2) +
                              (3 + sizeof(intermediate) + 2));
    size_t p = 8;
    assert(u24(out + p) == sizeof(leaf)); p += 3;
    assert(memcmp(out + p, leaf, sizeof(leaf)) == 0); p += sizeof(leaf);
    assert(out[p] == 0 && out[p + 1] == 0); p += 2;
    assert(u24(out + p) == sizeof(intermediate)); p += 3;
    assert(memcmp(out + p, intermediate, sizeof(intermediate)) == 0);

    /* The Certificate is one message per call, so the flight ends there for
     * this call and the transcript holds only that message. */
    assert(written == certificate_len);
    assert(transcript_updates == 1);
    assert(transcript_len == certificate_len);
    assert(memcmp(transcript, out, certificate_len) == 0);
    uint8_t certificate[512];
    memcpy(certificate, out, certificate_len);

    /* Second call: CertificateVerify alone. */
    memset(out, 0xa5, sizeof(out));
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(sign_called);
    assert(out[0] == TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY);
    assert(out[4] == 0x04 && out[5] == 0x03);
    size_t signature_len = ((size_t)out[6] << 8) | out[7];
    assert(signature_len == 40);
    assert(out[8] == 0x30);
    assert(written == 8 + signature_len);
    assert(transcript_updates == 2);
    assert(transcript_len == certificate_len + written);
    assert(memcmp(transcript, certificate, certificate_len) == 0);
    assert(memcmp(transcript + certificate_len, out, written) == 0);

    /* Nothing left. */
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 0);

    /* An incompatible request must produce the RFC-required empty
     * Certificate, without a CertificateVerify. */
    ctx.client_certificate_compatible = false;
    ctx.client_flight_step = 0;
    transcript_len = transcript_updates = 0;
    sign_called = false;
    written = 0;
    memset(out, 0xa5, sizeof(out));
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    static const uint8_t empty[] = {0x0b, 0, 0, 4, 0, 0, 0, 0};
    assert(written == sizeof(empty));
    assert(memcmp(out, empty, sizeof(empty)) == 0);
    assert(!sign_called && transcript_updates == 1);

    /* Empty list ends the flight: no CertificateVerify follows. */
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 0);
    assert(!sign_called && transcript_updates == 1);

    /* Too small a buffer is refused rather than truncated. */
    ctx.client_certificate_compatible = true;
    ctx.client_flight_step = 0;
    assert(!tls_send_client_certificate(&ctx, out, 16, &written));
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="tls-client-auth-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(unit), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("TLS client certificate flight: PASS")
