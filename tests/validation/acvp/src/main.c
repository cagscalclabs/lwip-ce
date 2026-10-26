/* ACVP network validation service.
 *
 * The host owns ACVP JSON, credentials and test-session state.  This program
 * only accepts compact operation frames over the private CEmu TAP network and
 * dispatches them to the cryptographic primitives exported by lwip.lib.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <lwip/cryptography/bytes.h>
#include <lwip/cryptography/aes.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/hkdf.h>
#include <lwip/cryptography/hmac.h>
#include <lwip/cryptography/p256.h>
#include <lwip/cryptography/passwords.h>
#include <lwip/cryptography/rsa.h>
#include <lwip/cryptography/random.h>
#include <lwip/cryptography/x25519.h>

#include "net.h"

#define ACVP_PORT 7200
#define HEADER_LEN 12
#define MAX_REQUEST 8192

enum acvp_operation {
    ACVP_OP_STOP = 0,
    ACVP_OP_SHA2_256 = 1,
    ACVP_OP_HMAC_SHA2_256 = 2,
    ACVP_OP_SHA2_256_MCT = 3,
    ACVP_OP_AES_CBC = 4,
    ACVP_OP_AES_GCM = 5,
    ACVP_OP_AES_CCM = 6,
    ACVP_OP_PBKDF2_SHA2_256 = 7,
    ACVP_OP_HKDF_SHA2_256 = 8,
    ACVP_OP_RSA_PSS_SHA2_256_VERIFY = 9,
    ACVP_OP_RSA_PKCS1_SHA2_256_VERIFY = 10,
    ACVP_OP_X25519_PUBLIC = 11,
    ACVP_OP_X25519_SECRET = 12,
    ACVP_OP_P256_PUBLIC = 13,
    ACVP_OP_P256_SECRET = 14,
    ACVP_OP_P256_SIGGEN = 15,
    ACVP_OP_P256_SIGVER = 16,
    ACVP_OP_X25519_SSC = 17,
    ACVP_OP_P256_CDH = 18,
    ACVP_OP_P256_SIGGEN_BEGIN = 19,
    ACVP_OP_P256_SIGGEN_ACTIVE = 20,
    ACVP_OP_AES_CBC_MCT = 21,
};

enum acvp_status {
    ACVP_STATUS_OK = 0,
    ACVP_STATUS_UNSUPPORTED = 1,
    ACVP_STATUS_MALFORMED = 2,
    ACVP_STATUS_INTERNAL = 3,
};

static uint8_t request[MAX_REQUEST];
static uint8_t result[MAX_REQUEST];
static uint8_t p256_signing_key[32];
static bool p256_signing_key_ready;

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static bool sha256(const uint8_t *message, size_t message_len, uint8_t digest[32])
{
    struct tls_hash_context ctx;
    if (!tls_hash_context_init(&ctx, TLS_HASH_SHA256)) return false;
    if (message_len) tls_hash_update(&ctx, message, message_len);
    tls_hash_digest(&ctx, digest);
    tls_hash_clear(&ctx);
    return true;
}

static bool sha256_mct(const uint8_t seed[32], uint8_t digest[32])
{
    static uint8_t state[96];
    memcpy(state, seed, 32);
    memcpy(state + 32, seed, 32);
    memcpy(state + 64, seed, 32);
    for (uint16_t i = 0; i < 1000; i++) {
        if (!sha256(state, sizeof(state), digest)) {
            tls_secure_memzero(state, sizeof(state));
            return false;
        }
        memmove(state, state + 32, 64);
        memcpy(state + 64, digest, 32);
    }
    tls_secure_memzero(state, sizeof(state));
    return true;
}

/* Symmetric payload: direction, key length+key, IV length+IV, AAD length+AAD,
 * data length+data, tag length+tag (tag is present only for decrypt).
 * All lengths wider than one byte are network byte order.  The response is
 * accepted, data length+data, tag length+tag. */
static uint8_t run_aead(enum tls_aes_modes mode, const uint8_t *in, size_t in_len,
                        size_t *out_len)
{
    size_t off = 0;
    if (in_len < 2) return ACVP_STATUS_MALFORMED;
    uint8_t decrypt = in[off++], key_len = in[off++];
    if (decrypt > 1 || (key_len != 16 && key_len != 24 && key_len != 32) ||
        off + key_len + 1 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *key = in + off; off += key_len;
    uint8_t iv_len = in[off++];
    if (off + iv_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *iv = in + off; off += iv_len;
    uint16_t aad_len = read_be16(in + off); off += 2;
    if (off + aad_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *aad = in + off; off += aad_len;
    uint16_t data_len = read_be16(in + off); off += 2;
    if (off + data_len + 1 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *data = in + off; off += data_len;
    uint8_t tag_len = in[off++];
    if (off + (decrypt ? tag_len : 0) != in_len ||
        (mode == TLS_AES_GCM && tag_len != TLS_AES_AUTH_TAG_SIZE))
        return ACVP_STATUS_MALFORMED;
    const uint8_t *tag = decrypt ? in + off : NULL;
    if ((size_t)data_len + tag_len + 4 > sizeof(result)) return ACVP_STATUS_MALFORMED;

    struct tls_aes_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool ok = mode == TLS_AES_CCM
        ? tls_aes_ccm_init(&ctx, key, key_len, iv, iv_len, tag_len, data_len, aad_len)
        : tls_aes_init(&ctx, mode, key, key_len, iv, iv_len);
    if (!ok) return ACVP_STATUS_INTERNAL;

    result[0] = 1;
    write_be16(result + 1, data_len);
    size_t o = 3;
    if (!decrypt) {
        ok = (!aad_len || tls_aes_update_aad(&ctx, aad, aad_len)) &&
             (!data_len || tls_aes_encrypt(&ctx, data, data_len, result + o));
        o += data_len;
        result[o++] = tag_len;
        uint8_t digest[TLS_AES_AUTH_TAG_SIZE];
        if (ok) ok = tls_aes_digest(&ctx, digest);
        if (ok) memcpy(result + o, digest, tag_len);
        tls_secure_memzero(digest, sizeof(digest));
        o += tag_len;
    } else {
        ok = tls_aes_verify(&ctx, aad_len ? aad : NULL, aad_len,
                            data_len ? data : NULL, data_len, tag);
        result[0] = ok ? 1 : 0;
        if (ok && data_len) ok = tls_aes_decrypt(&ctx, data, data_len, result + o);
        if (ok) o += data_len;
        else { result[0] = 0; write_be16(result + 1, 0); o = 3; }
        result[o++] = 0;
    }
    tls_aes_destroy_ctx(&ctx);
    if (!ok && !decrypt) return ACVP_STATUS_INTERNAL;
    *out_len = o;
    return ACVP_STATUS_OK;
}

/* CBC payload: direction, key length+key, IV[16], data length+data. */
static uint8_t run_cbc(const uint8_t *in, size_t in_len, size_t *out_len)
{
    if (in_len < 20) return ACVP_STATUS_MALFORMED;
    size_t off = 0;
    uint8_t decrypt = in[off++], key_len = in[off++];
    if (decrypt > 1 || (key_len != 16 && key_len != 24 && key_len != 32) ||
        off + key_len + 18 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *key = in + off; off += key_len;
    const uint8_t *iv = in + off; off += 16;
    uint16_t data_len = read_be16(in + off); off += 2;
    if (off + data_len != in_len || data_len % 16 || data_len + 2 > sizeof(result))
        return ACVP_STATUS_MALFORMED;
    struct tls_aes_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (!tls_aes_init(&ctx, TLS_AES_CBC, key, key_len, iv, 16))
        return ACVP_STATUS_INTERNAL;
    bool ok = decrypt ? tls_aes_decrypt(&ctx, in + off, data_len, result + 2)
                      : tls_aes_encrypt(&ctx, in + off, data_len, result + 2);
    tls_aes_destroy_ctx(&ctx);
    if (!ok) return ACVP_STATUS_INTERNAL;
    write_be16(result, data_len); *out_len = data_len + 2;
    return ACVP_STATUS_OK;
}

/* One 1000-iteration ACVP CBC Monte Carlo inner loop.  Return the
 * penultimate and final output blocks; the host performs the specified key
 * shuffle and emits the 100 outer-loop records. */
static uint8_t run_cbc_mct(const uint8_t *in, size_t in_len, size_t *out_len)
{
    if (in_len < 52) return ACVP_STATUS_MALFORMED;
    size_t off = 0;
    uint8_t decrypt = in[off++], key_len = in[off++];
    if (decrypt > 1 || (key_len != 16 && key_len != 24 && key_len != 32) ||
        off + key_len + 34 != in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *key = in + off; off += key_len;
    uint8_t initial_iv[16], chain[16], input[16], previous[16], output[16];
    memcpy(initial_iv, in + off, 16); memcpy(chain, initial_iv, 16); off += 16;
    if (read_be16(in + off) != 16) return ACVP_STATUS_MALFORMED;
    off += 2; memcpy(input, in + off, 16); memset(previous, 0, sizeof(previous));
    for (uint16_t j = 0; j < 1000; j++) {
        struct tls_aes_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        bool ok = tls_aes_init(&ctx, TLS_AES_CBC, key, key_len, chain, 16) &&
                  (decrypt ? tls_aes_decrypt(&ctx, input, 16, output)
                           : tls_aes_encrypt(&ctx, input, 16, output));
        tls_aes_destroy_ctx(&ctx);
        if (!ok) return ACVP_STATUS_INTERNAL;
        uint8_t next[16];
        memcpy(next, j == 0 ? initial_iv : previous, 16);
        memcpy(chain, decrypt ? input : output, 16);
        memcpy(previous, output, 16);
        memcpy(input, next, 16);
        tls_secure_memzero(next, sizeof(next));
    }
    memcpy(result, input, 16); memcpy(result + 16, previous, 16);
    tls_secure_memzero(initial_iv, sizeof(initial_iv));
    tls_secure_memzero(chain, sizeof(chain)); tls_secure_memzero(input, sizeof(input));
    tls_secure_memzero(previous, sizeof(previous)); tls_secure_memzero(output, sizeof(output));
    *out_len = 32; return ACVP_STATUS_OK;
}

static uint8_t run_pbkdf2(const uint8_t *in, size_t in_len, size_t *out_len)
{
    size_t off = 0;
    if (in_len < 2) return ACVP_STATUS_MALFORMED;
    uint16_t pw_len = read_be16(in + off); off += 2;
    if (off + pw_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *pw = in + off; off += pw_len;
    uint16_t salt_len = read_be16(in + off); off += 2;
    if (off + salt_len + 8 != in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *salt = in + off; off += salt_len;
    uint32_t rounds = read_be32(in + off); off += 4;
    uint32_t key_len = read_be32(in + off);
    if (!rounds || !key_len || key_len + 4 > sizeof(result)) return ACVP_STATUS_MALFORMED;
    if (!tls_pbkdf2((const char *)pw, pw_len, salt, salt_len, result + 4,
                    key_len, rounds, TLS_HASH_SHA256)) return ACVP_STATUS_INTERNAL;
    write_be32(result, key_len); *out_len = key_len + 4;
    return ACVP_STATUS_OK;
}

static uint8_t run_hkdf(const uint8_t *in, size_t in_len, size_t *out_len)
{
    size_t off = 0;
    if (in_len < 2) return ACVP_STATUS_MALFORMED;
    uint16_t z_len = read_be16(in + off); off += 2;
    if (off + z_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *z = in + off; off += z_len;
    uint16_t salt_len = read_be16(in + off); off += 2;
    if (off + salt_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *salt = in + off; off += salt_len;
    uint16_t info_len = read_be16(in + off); off += 2;
    if (off + info_len + 2 != in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *info = in + off; off += info_len;
    uint16_t length = read_be16(in + off);
    if (!length || length > 8160 || length + 2 > sizeof(result)) return ACVP_STATUS_MALFORMED;
    uint8_t prk[32];
    bool ok = tls_hkdf_extract(TLS_HASH_SHA256, salt, salt_len, z, z_len, prk) &&
              tls_hkdf_expand(TLS_HASH_SHA256, prk, sizeof(prk), info, info_len,
                              result + 2, length);
    tls_secure_memzero(prk, sizeof(prk));
    if (!ok) return ACVP_STATUS_INTERNAL;
    write_be16(result, length); *out_len = length + 2;
    return ACVP_STATUS_OK;
}

static uint8_t run_rsa_verify(bool pss, const uint8_t *in, size_t in_len,
                              size_t *out_len)
{
    size_t off = 0;
    if (in_len < 2) return ACVP_STATUS_MALFORMED;
    uint16_t n_len = read_be16(in + off); off += 2;
    if (n_len > RSA_MODULUS_MAX_SUPPORTED || off + n_len + 1 > in_len)
        return ACVP_STATUS_MALFORMED;
    const uint8_t *n = in + off; off += n_len;
    uint8_t e_len = in[off++];
    if (off + e_len + 2 > in_len || e_len != 3 || memcmp(in + off, "\x01\x00\x01", 3))
        return ACVP_STATUS_MALFORMED;
    off += e_len;
    uint16_t msg_len = read_be16(in + off); off += 2;
    if (off + msg_len + 2 > in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *msg = in + off; off += msg_len;
    uint16_t sig_len = read_be16(in + off); off += 2;
    if (off + sig_len != in_len) return ACVP_STATUS_MALFORMED;
    const uint8_t *sig = in + off;
    result[0] = 0; *out_len = 1;
    if (sig_len != n_len) return ACVP_STATUS_OK;
    uint8_t hash[32];
    if (!sha256(msg, msg_len, hash)) return ACVP_STATUS_INTERNAL;
    static const uint8_t exponent[] = {1, 0, 1};
    struct tls_rsa_key key = {sizeof(exponent), exponent, n_len, n};
    if (pss) {
        static uint8_t encoded[RSA_MODULUS_MAX_SUPPORTED];
        result[0] = tls_rsa_decrypt_signature(sig, sig_len, encoded, &key) &&
                    tls_rsa_pss_verify(encoded, n_len, hash, sizeof(hash), TLS_HASH_SHA256);
        tls_secure_memzero(encoded, sizeof(encoded));
    } else {
        result[0] = tls_rsa_pkcs1_v15_sha256_verify(sig, sig_len, hash, &key);
    }
    tls_secure_memzero(hash, sizeof(hash));
    return ACVP_STATUS_OK;
}

static uint8_t dispatch(uint8_t operation, const uint8_t *payload,
                        size_t payload_len, size_t *result_len)
{
    *result_len = 0;
    switch (operation) {
    case ACVP_OP_SHA2_256:
        if (!sha256(payload, payload_len, result)) return ACVP_STATUS_INTERNAL;
        *result_len = 32;
        return ACVP_STATUS_OK;

    case ACVP_OP_HMAC_SHA2_256: {
        struct tls_hmac_context ctx;
        if (payload_len < 4) return ACVP_STATUS_MALFORMED;
        size_t key_len = read_be16(payload);
        size_t mac_len = read_be16(payload + 2);
        if (!key_len || !mac_len || mac_len > 32 ||
            key_len > payload_len - 4) return ACVP_STATUS_MALFORMED;
        const uint8_t *key = payload + 4;
        const uint8_t *message = key + key_len;
        size_t message_len = payload_len - 4 - key_len;
        if (!tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key, key_len))
            return ACVP_STATUS_INTERNAL;
        if (message_len) tls_hmac_update(&ctx, message, message_len);
        tls_hmac_digest(&ctx, result);
        tls_hmac_clear(&ctx);
        *result_len = mac_len;
        return ACVP_STATUS_OK;
    }

    case ACVP_OP_SHA2_256_MCT:
        if (payload_len != 32) return ACVP_STATUS_MALFORMED;
        if (!sha256_mct(payload, result)) return ACVP_STATUS_INTERNAL;
        *result_len = 32;
        return ACVP_STATUS_OK;

    case ACVP_OP_AES_CBC:
        return run_cbc(payload, payload_len, result_len);
    case ACVP_OP_AES_GCM:
        return run_aead(TLS_AES_GCM, payload, payload_len, result_len);
    case ACVP_OP_AES_CCM:
        return run_aead(TLS_AES_CCM, payload, payload_len, result_len);
    case ACVP_OP_PBKDF2_SHA2_256:
        return run_pbkdf2(payload, payload_len, result_len);
    case ACVP_OP_HKDF_SHA2_256:
        return run_hkdf(payload, payload_len, result_len);
    case ACVP_OP_RSA_PSS_SHA2_256_VERIFY:
        return run_rsa_verify(true, payload, payload_len, result_len);
    case ACVP_OP_RSA_PKCS1_SHA2_256_VERIFY:
        return run_rsa_verify(false, payload, payload_len, result_len);

    case ACVP_OP_X25519_PUBLIC:
        if (payload_len != 32) return ACVP_STATUS_MALFORMED;
        if (!tls_x25519_publickey(result, payload, NULL, NULL)) return ACVP_STATUS_INTERNAL;
        *result_len = 32; return ACVP_STATUS_OK;
    case ACVP_OP_X25519_SECRET:
        if (payload_len != 64) return ACVP_STATUS_MALFORMED;
        if (!tls_x25519_secret(result, payload, payload + 32, NULL, NULL))
            return ACVP_STATUS_INTERNAL;
        *result_len = 32; return ACVP_STATUS_OK;
    case ACVP_OP_P256_PUBLIC:
        if (payload_len != 32) return ACVP_STATUS_MALFORMED;
        if (!tls_p256_publickey(result, payload)) return ACVP_STATUS_INTERNAL;
        *result_len = 65; return ACVP_STATUS_OK;
    case ACVP_OP_P256_SECRET:
        if (payload_len != 97) return ACVP_STATUS_MALFORMED;
        if (!tls_p256_secret(result, payload, payload + 32)) return ACVP_STATUS_INTERNAL;
        *result_len = 32; return ACVP_STATUS_OK;
    case ACVP_OP_P256_SIGGEN:
        if (payload_len != 64) return ACVP_STATUS_MALFORMED;
        if (!tls_p256_sign(result, payload + 32, payload)) return ACVP_STATUS_INTERNAL;
        *result_len = 64; return ACVP_STATUS_OK;
    case ACVP_OP_P256_SIGVER:
        if (payload_len != 161) return ACVP_STATUS_MALFORMED;
        result[0] = tls_p256_verify(payload + 97, payload + 65, payload) ? 1 : 0;
        *result_len = 1; return ACVP_STATUS_OK;
    case ACVP_OP_X25519_SSC: {
        uint8_t private_key[32];
        if (payload_len != 32) return ACVP_STATUS_MALFORMED;
        if (!tls_random_bytes_ex(private_key, sizeof(private_key), TLS_RNG_STRENGTH_128) ||
            !tls_x25519_publickey(result, private_key, NULL, NULL) ||
            !tls_x25519_secret(result + 32, private_key, payload, NULL, NULL)) {
            tls_secure_memzero(private_key, sizeof(private_key));
            return ACVP_STATUS_INTERNAL;
        }
        tls_secure_memzero(private_key, sizeof(private_key));
        *result_len = 64; return ACVP_STATUS_OK;
    }
    case ACVP_OP_P256_CDH: {
        uint8_t private_key[32];
        if (payload_len != 65) return ACVP_STATUS_MALFORMED;
        for (uint8_t attempt = 0; attempt < 8; attempt++) {
            if (!tls_random_bytes_ex(private_key, sizeof(private_key), TLS_RNG_STRENGTH_128))
                break;
            if (tls_p256_publickey(result, private_key) &&
                tls_p256_secret(result + 65, private_key, payload)) {
                tls_secure_memzero(private_key, sizeof(private_key));
                *result_len = 97; return ACVP_STATUS_OK;
            }
        }
        tls_secure_memzero(private_key, sizeof(private_key));
        return ACVP_STATUS_INTERNAL;
    }
    case ACVP_OP_P256_SIGGEN_BEGIN:
        if (payload_len) return ACVP_STATUS_MALFORMED;
        p256_signing_key_ready = false;
        tls_secure_memzero(p256_signing_key, sizeof(p256_signing_key));
        for (uint8_t attempt = 0; attempt < 8; attempt++) {
            if (!tls_random_bytes_ex(p256_signing_key, sizeof(p256_signing_key),
                                     TLS_RNG_STRENGTH_128)) break;
            if (tls_p256_publickey(result, p256_signing_key)) {
                p256_signing_key_ready = true;
                *result_len = 65; return ACVP_STATUS_OK;
            }
        }
        tls_secure_memzero(p256_signing_key, sizeof(p256_signing_key));
        return ACVP_STATUS_INTERNAL;
    case ACVP_OP_P256_SIGGEN_ACTIVE:
        if (payload_len != 32 || !p256_signing_key_ready)
            return ACVP_STATUS_MALFORMED;
        if (!tls_p256_sign(result, payload, p256_signing_key))
            return ACVP_STATUS_INTERNAL;
        *result_len = 64; return ACVP_STATUS_OK;
    case ACVP_OP_AES_CBC_MCT:
        return run_cbc_mct(payload, payload_len, result_len);

    default:
        return ACVP_STATUS_UNSUPPORTED;
    }
}

static bool send_response(struct lwip_socket *socket, uint8_t status,
                          uint16_t request_id, size_t result_len)
{
    uint8_t header[HEADER_LEN] = {'A', 'C', 'R', '1', status, 0, 0, 0, 0, 0, 0, 0};
    write_be16(header + 6, request_id);
    write_be32(header + 8, (uint32_t)result_len);
    return write_all(socket, header, sizeof(header)) &&
           (!result_len || write_all(socket, result, result_len));
}

static bool run_service(void)
{
    struct lwip_socket *socket = open_socket(LWIP_SOCKET_TCP, HOST, ACVP_PORT,
                                              NULL, 30000);
    uint8_t header[HEADER_LEN];
    bool ok = socket != NULL;
    check("ACVP host connection", ok);
    while (ok) {
        if (read_exact(socket, header, sizeof(header), 30000) != sizeof(header)) {
            ok = false;
            break;
        }
        if (memcmp(header, "ACV1", 4) || header[5] != 0) {
            ok = false;
            break;
        }
        uint8_t operation = header[4];
        uint16_t request_id = read_be16(header + 6);
        uint32_t payload_len = read_be32(header + 8);
        if (payload_len > sizeof(request)) {
            send_response(socket, ACVP_STATUS_MALFORMED, request_id, 0);
            ok = false;
            break;
        }
        if (payload_len && read_exact(socket, request, payload_len, 30000) != payload_len) {
            ok = false;
            break;
        }
        if (operation == ACVP_OP_STOP) {
            ok = payload_len == 0 && send_response(socket, ACVP_STATUS_OK,
                                                    request_id, 0);
            break;
        }
        size_t result_len;
        uint8_t status = dispatch(operation, request, payload_len, &result_len);
        if (!send_response(socket, status, request_id, result_len)) {
            ok = false;
            break;
        }
        tls_secure_memzero(request, payload_len);
        tls_secure_memzero(result, sizeof(result));
    }
    close_socket(socket);
    tls_secure_memzero(request, sizeof(request));
    tls_secure_memzero(result, sizeof(result));
    tls_secure_memzero(p256_signing_key, sizeof(p256_signing_key));
    p256_signing_key_ready = false;
    return ok;
}

static bool wait_rng_ready(uint32_t timeout_ms)
{
    uint32_t start = lwip_now_ms();
    while (tls_rng_available_strength() < TLS_RNG_STRENGTH_128) {
        tls_rng_state_t state = tls_rng_status();
        if (state == TLS_RNG_STOPPED || state == TLS_RNG_FAILED ||
            (uint32_t)(lwip_now_ms() - start) >= timeout_ms) return false;
        lwip_service_events();
    }
    return true;
}

int main(void)
{
    if (net_begin("acvp") &&
        check("ACVP RNG readiness", wait_rng_ready(30000u)))
        check("ACVP vector service", run_service());
    return net_end();
}
