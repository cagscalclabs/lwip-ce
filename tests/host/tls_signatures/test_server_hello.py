#!/usr/bin/env python3
"""Exercise the production TLS 1.3 server ClientHello/HRR state machine."""

from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[3]
source = (root / "src/tls/core/handshake.c").read_text()


def function(name: str) -> str:
    match = re.search(r"^(?:static )?(?:bool|size_t|uint16_t) " + name +
                      r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos]


c_test = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ERROR_CODE(x) ((void)(x))
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_VERSION_1_3 0x0304
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_128_CCM_SHA256 0x1304
#define TLS_EXT_ALPN 0x0010
#define TLS_EXT_SUPPORTED_GROUPS 0x000a
#define TLS_EXT_SIGNATURE_ALGORITHMS 0x000d
#define TLS_EXT_PRE_SHARED_KEY 0x0029
#define TLS_EXT_EARLY_DATA 0x002a
#define TLS_EXT_COOKIE 0x002c
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES 0x002d
#define TLS_EXT_SIGNATURE_ALGORITHMS_CERT 0x0032
#define TLS_EXT_KEY_SHARE 0x0033
#define TLS_NAMED_GROUP_X25519 0x001d
#define TLS_NAMED_GROUP_SECP256R1 0x0017
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_LEVEL_FATAL 2
#define TLS_PSK_TYPE_EXTERNAL 1
#define TLS_RNG_STRENGTH_128 128
#define TLS_HASH_SHA256 1
#define TLS_STATE_INIT 0
#define TLS_STATE_HRR_RECEIVED 2
#define TLS_STATE_SERVER_HELLO_RECEIVED 3
#define TLS_STATE_ERROR 10

struct tls_hash_context { size_t bytes; unsigned resets; uint32_t hash; };
struct tls_handshake_context {
    int state;
    struct tls_hash_context hash;
    struct tls_hash_context *transcript_hash;
    uint16_t ecdhe_job;
    void *server_cert;
    void *server_key;
    void **server_chain;
    size_t server_chain_len;
    uint8_t client_random[32], server_random[32];
    uint8_t hrr_session_id[32], hrr_session_id_len;
    uint8_t hrr_ch1_invariant_hash[32];
    bool hrr_done;
    uint16_t hrr_requested_group, cipher_suite;
    const uint8_t *alpn_protocols, *negotiated_alpn;
    size_t alpn_protocols_len;
    uint8_t negotiated_alpn_len;
    bool psk_mode;
    int psk_type;
    uint8_t ecdhe_shared[32], ecdhe_private[32], ecdhe_public[32];
    bool ecdhe_negotiated;
};

static uint8_t last_alert;
static size_t tls_parse_handshake_header(const uint8_t *p, size_t n,
                                         uint8_t type, size_t *body)
{
    if (n < 4 || p[0] != type) return 0;
    *body = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    return *body + 4 <= n ? 4 : 0;
}
static bool tls_server_check_psk(struct tls_handshake_context *ctx,
                                 const uint8_t *msg, size_t ext_off,
                                 const uint8_t *ext, size_t ext_len,
                                 uint16_t *selected)
{
    (void)ctx; (void)msg; (void)ext_off; (void)ext; (void)ext_len;
    *selected = 0; return true;
}
static bool tls_x25519_secret(uint8_t *out, const uint8_t *priv,
                              const uint8_t *peer, void *a, void *b)
{
    (void)priv; (void)peer; (void)a; (void)b; memset(out, 0x5a, 32); return true;
}
static void *tls_random_bytes_ex(void *out, size_t n, int strength)
{
    (void)strength; memset(out, 0xa5, n); return out;
}
static void transcript_hash_update(struct tls_hash_context *h,
                                   const uint8_t *p, size_t n)
{ for (size_t i = 0; i < n; i++) h->hash = h->hash * 33u + p[i]; h->bytes += n; }
static bool tls_hash_context_init(struct tls_hash_context *h, int alg)
{ (void)alg; h->bytes = 0; h->resets = 0; h->hash = 5381u; return true; }
static void tls_hash_update(struct tls_hash_context *h, const uint8_t *p, size_t n)
{ transcript_hash_update(h, p, n); }
static void tls_hash_digest(struct tls_hash_context *h, uint8_t out[32])
{ for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(h->hash >> ((i & 3) * 8)); }
static void tls_hash_clear(struct tls_hash_context *h) { (void)h; }
static bool transcript_hash_init(struct tls_hash_context *h)
{ h->bytes = 0; h->hash = 5381u; h->resets++; return true; }
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }
static bool tls_send_alert(struct tls_handshake_context *ctx, uint8_t level,
                           uint8_t description)
{ (void)level; last_alert = description; ctx->state = TLS_STATE_ERROR; return true; }
''' + function("tls_srv_be16") + function("tls_server_recv_client_hello") + r'''

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static size_t extension(uint8_t *p, uint16_t type, const uint8_t *body, size_t n)
{
    put16(p, type); put16(p + 2, (uint16_t)n); memcpy(p + 4, body, n); return n + 4;
}

enum share_kind { NO_SHARE, X25519_SHARE, P256_SHARE };
static size_t client_hello(uint8_t *p, bool x_group, enum share_kind share,
                           bool gcm, bool ccm, bool p256_sig, bool duplicate_versions,
                           uint8_t random_byte, uint8_t sid_byte)
{
    size_t o = 4;
    p[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    p[o++] = 3; p[o++] = 3;
    memset(p + o, random_byte, 32); o += 32;
    p[o++] = 1; p[o++] = sid_byte;
    size_t suites_at = o; o += 2;
    size_t suites = 0;
    if (ccm) { put16(p + o, TLS_AES_128_CCM_SHA256); o += 2; suites += 2; }
    if (gcm) { put16(p + o, TLS_AES_128_GCM_SHA256); o += 2; suites += 2; }
    if (!suites) { put16(p + o, 0x1303); o += 2; suites = 2; }
    put16(p + suites_at, (uint16_t)suites);
    p[o++] = 1; p[o++] = 0;
    size_t ext_len_at = o; o += 2;
    static const uint8_t versions[] = {2, 3, 4};
    o += extension(p + o, TLS_EXT_SUPPORTED_VERSIONS, versions, sizeof(versions));
    if (duplicate_versions)
        o += extension(p + o, TLS_EXT_SUPPORTED_VERSIONS, versions, sizeof(versions));
    uint8_t groups[6] = {0, 2, 0, 0x17, 0, 0};
    if (x_group) { groups[1] = 4; groups[2] = 0; groups[3] = 0x1d;
                   groups[4] = 0; groups[5] = 0x17; }
    o += extension(p + o, TLS_EXT_SUPPORTED_GROUPS, groups, x_group ? 6 : 4);
    uint8_t sigs[4] = {0, 2, p256_sig ? 0x04 : 0x08, p256_sig ? 0x03 : 0x04};
    o += extension(p + o, TLS_EXT_SIGNATURE_ALGORITHMS, sigs, sizeof(sigs));
    if (share != NO_SHARE)
    {
        uint16_t group = share == X25519_SHARE ? TLS_NAMED_GROUP_X25519
                                               : TLS_NAMED_GROUP_SECP256R1;
        size_t key_len = share == X25519_SHARE ? 32 : 65;
        uint8_t body[71];
        put16(body, (uint16_t)(4 + key_len)); put16(body + 2, group);
        put16(body + 4, (uint16_t)key_len); memset(body + 6, 0x42, key_len);
        if (share == P256_SHARE) body[6] = 4;
        o += extension(p + o, TLS_EXT_KEY_SHARE, body, 6 + key_len);
    }
    put16(p + ext_len_at, (uint16_t)(o - ext_len_at - 2));
    size_t body_len = o - 4;
    p[1] = body_len >> 16; p[2] = body_len >> 8; p[3] = body_len;
    return o;
}

static void init(struct tls_handshake_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = TLS_STATE_INIT;
    ctx->transcript_hash = &ctx->hash;
    ctx->server_cert = ctx->server_key = ctx;
    ctx->server_chain = (void **)&ctx->server_cert;
    ctx->server_chain_len = 1;
    memset(ctx->ecdhe_public, 0x24, sizeof(ctx->ecdhe_public));
    last_alert = 0;
}

int main(void)
{
    struct tls_handshake_context ctx;
    uint8_t ch[512], out[256];
    size_t n, written;

    /* Direct X25519: prefer GCM even when CCM appears first; P-256 need not
     * be a key-exchange group when its CertificateVerify scheme is offered. */
    init(&ctx);
    n = client_hello(ch, true, X25519_SHARE, true, true, true, false, 1, 7);
    assert(tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(ctx.state == TLS_STATE_SERVER_HELLO_RECEIVED);
    assert(ctx.cipher_suite == TLS_AES_128_GCM_SHA256 && !ctx.psk_mode);
    assert(out[0] == TLS_HANDSHAKE_SERVER_HELLO);

    /* A listed X25519 group without an X25519 share gets exactly one HRR. */
    init(&ctx);
    n = client_hello(ch, true, P256_SHARE, true, true, true, false, 2, 8);
    assert(tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(ctx.state == TLS_STATE_HRR_RECEIVED && ctx.hrr_done);
    assert(ctx.hrr_requested_group == TLS_NAMED_GROUP_X25519);
    assert(ctx.hash.resets == 1 && out[6] == 0xcf && out[written - 1] == 0x1d);
    n = client_hello(ch, true, X25519_SHARE, true, true, true, false, 2, 8);
    assert(tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(ctx.state == TLS_STATE_SERVER_HELLO_RECEIVED);

    /* CH2 must retain random/session/cipher and contain exactly X25519. */
    init(&ctx);
    n = client_hello(ch, true, NO_SHARE, true, false, true, false, 3, 9);
    assert(tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    n = client_hello(ch, true, NO_SHARE, true, false, true, false, 3, 9);
    assert(!tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(last_alert == TLS_ALERT_ILLEGAL_PARAMETER);

    /* No mutually supported group cannot legally be repaired with HRR. */
    init(&ctx);
    n = client_hello(ch, false, P256_SHARE, true, false, true, false, 4, 1);
    assert(!tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(last_alert == TLS_ALERT_HANDSHAKE_FAILURE);

    /* CCM is selected when it is the only mutually supported suite. */
    init(&ctx);
    n = client_hello(ch, true, X25519_SHARE, false, true, true, false, 5, 1);
    assert(tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(ctx.cipher_suite == TLS_AES_128_CCM_SHA256);

    init(&ctx);
    n = client_hello(ch, true, X25519_SHARE, false, false, true, false, 6, 1);
    assert(!tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(last_alert == TLS_ALERT_HANDSHAKE_FAILURE);

    init(&ctx);
    n = client_hello(ch, true, X25519_SHARE, true, false, true, true, 7, 1);
    assert(!tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(last_alert == TLS_ALERT_ILLEGAL_PARAMETER);

    init(&ctx);
    n = client_hello(ch, true, X25519_SHARE, true, false, false, false, 8, 1);
    assert(!tls_server_recv_client_hello(&ctx, ch, n, out, sizeof(out), &written));
    assert(last_alert == TLS_ALERT_HANDSHAKE_FAILURE);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="tls-server-hello-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                    str(unit), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print("TLS server ClientHello/HRR regressions: PASS")
