/**
 * @file main.c
 * @brief NIST CAVP-format primitive validation runner (calculator side).
 *
 * Streams CAVP00..15.8xv (input vectors), dispatches each vector to the
 * appropriate primitive, and writes responses to CAVPOUT.8xv. Does NOT
 * grade itself; expected outputs live host-side in vectors/expected.json
 * and are compared by tests/common/scripts/parse_cavp_output_appvar.py.
 *
 * AppVar wire format (host-readable, see tests/common/scripts/cavp_fetch.py):
 *
 *   Each CAVPxx.8xv:
 *     magic[4]      = 'A','I','N','1'
 *     vector_count  uint16  little-endian
 *     repeat vector_count:
 *       algorithm_id  uint8   (1=AES-GCM, 2=SHA-256, 3=HMAC, 4=HKDF,
 *                              5=DRBG, 6=RSA-PSS, 7/8=X25519,
 *                              9=AES-CBC, 10=AES-CCM, 11=PBKDF2,
 *                              12=SHA-256-MCT, 13=RSA-PKCS1v15-verify)
 *       test_id       uint16  little-endian
 *       payload_len   uint16  little-endian
 *       payload[payload_len]  algorithm-specific TLV (see runners below)
 *
 *   CAVPOUT.8xv:
 *     magic[4]      = 'A','O','U','T'
 *     response_count uint16 little-endian
 *     repeat response_count:
 *       test_id      uint16
 *       status       uint8   (0=ok, 1=unsupported, 2=internal_error)
 *       result_len   uint16
 *       result[result_len]
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/vars.h>
#include <fileioc.h>
#include <ti/getkey.h>

#include <lwip/cryptography/aes.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/hmac.h>
#include <lwip/cryptography/hkdf.h>
#include <lwip/cryptography/passwords.h>
#include <lwip/cryptography/rsa.h>
#include <lwip/cryptography/x25519.h>
#include <lwip.h>

#define CAVPIN_CHUNKS 16
#define CAVPOUT_NAME "CAVPOUT"

#define ALG_AES_GCM                1
#define ALG_SHA256                 2
#define ALG_HMAC_SHA256            3
#define ALG_HKDF_SHA256            4
#define ALG_DRBG_SHA256            5
#define ALG_RSA_PSS_SHA256_VERIFY  6
#define ALG_X25519_PUBLICKEY       7
#define ALG_X25519_SECRET          8
#define ALG_AES_CBC                9
#define ALG_AES_CCM               10
#define ALG_PBKDF2_HMAC_SHA256    11
#define ALG_SHA256_MCT            12
#define ALG_RSA_PKCS1_SHA256_VERIFY 13

#define STATUS_OK 0
#define STATUS_UNSUPPORTED 1
#define STATUS_INTERNAL 2

/* ---------- AppVar helpers (little-endian readers/writers) ---------- */

static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void wr_u16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
}

/* ---------- Per-algorithm payload runners ---------- */

/*
 * AES-GCM payload TLV:
 *   direction    uint8   (0=encrypt, 1=decrypt)
 *   key_len      uint8   (16, 24, or 32)
 *   key          [key_len]
 *   iv_len       uint8   (always 12)
 *   iv           [iv_len]
 *   aad_len      uint16
 *   aad          [aad_len]
 *   data_len     uint16
 *   data         [data_len] (plaintext for encrypt, ciphertext for decrypt)
 *   tag_len      uint8   (16; GCM API exposes a fixed-size tag)
 *   tag           [tag_len] (decrypt only)
 *
 * Response (little-endian):
 *   accepted     uint8   (decrypt tag verdict; always 1 for encrypt)
 *   data_len     uint16
 *   data         [data_len] (ciphertext for encrypt, plaintext for decrypt)
 *   tag_len      uint8
 *   tag          [tag_len] (encrypt only)
 */
static size_t run_aes_gcm(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    size_t off = 0;
    uint8_t direction = in[off++];
    if (direction > 1)
        return 0;
    uint8_t key_len = in[off++];
    if (off + key_len > in_len)
        return 0;
    const uint8_t *key = in + off;
    off += key_len;

    if (off + 1 > in_len)
        return 0;
    uint8_t iv_len = in[off++];
    if (off + iv_len > in_len)
        return 0;
    const uint8_t *iv = in + off;
    off += iv_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t aad_len = rd_u16(in + off);
    off += 2;
    if (off + aad_len > in_len)
        return 0;
    const uint8_t *aad = in + off;
    off += aad_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t data_len = rd_u16(in + off);
    off += 2;
    if (off + data_len > in_len)
        return 0;
    const uint8_t *data = in + off;
    off += data_len;

    if (off + 1 > in_len)
        return 0;
    uint8_t tag_len = in[off++];
    if (tag_len != 16 || off + (direction ? tag_len : 0) != in_len)
        return 0;
    const uint8_t *tag_in = direction ? in + off : NULL;

    if (out_max < (size_t)1 + 2 + data_len + 1 + (direction ? 0 : tag_len))
        return 0;

    struct tls_aes_context ctx;
    if (!tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len))
        return 0;

    size_t o = 0;
    if (direction == 0) {
        if (aad_len && !tls_aes_update_aad(&ctx, aad, aad_len))
            return 0;
        out[o++] = 1;
        wr_u16(out + o, data_len); o += 2;
        if (data_len && !tls_aes_encrypt(&ctx, data, data_len, out + o))
            return 0;
        o += data_len;
        out[o++] = tag_len;
        if (!tls_aes_digest(&ctx, out + o))
            return 0;
        o += tag_len;
    } else {
        bool accepted = tls_aes_verify(&ctx,
                                       aad_len ? aad : NULL, aad_len,
                                       data_len ? data : NULL, data_len,
                                       tag_in);
        out[o++] = accepted ? 1 : 0;
        wr_u16(out + o, accepted ? data_len : 0); o += 2;
        if (accepted && data_len) {
            if (!tls_aes_decrypt(&ctx, data, data_len, out + o))
                return 0;
            o += data_len;
        }
        out[o++] = 0;
    }
    return o;
}

/* AES-CBC: direction, key_len+key, IV[16], data_len+data.
 * Response: output_len uint16 + output bytes. */
static size_t run_aes_cbc(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2) return 0;
    size_t off = 0;
    uint8_t direction = in[off++];
    uint8_t key_len = in[off++];
    if (direction > 1 || off + key_len + 16 + 2 > in_len) return 0;
    const uint8_t *key = in + off; off += key_len;
    const uint8_t *iv = in + off; off += 16;
    uint16_t data_len = rd_u16(in + off); off += 2;
    if (off + data_len != in_len || (data_len % 16) != 0) return 0;
    if (out_max < (size_t)2 + data_len) return 0;

    struct tls_aes_context ctx;
    if (!tls_aes_init(&ctx, TLS_AES_CBC, key, key_len, iv, 16)) return 0;
    bool ok = direction
        ? tls_aes_decrypt(&ctx, in + off, data_len, out + 2)
        : tls_aes_encrypt(&ctx, in + off, data_len, out + 2);
    if (!ok) return 0;
    wr_u16(out, data_len);
    return (size_t)2 + data_len;
}

/* AES-CCM uses the same response framing as AES-GCM. */
static size_t run_aes_ccm(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 3) return 0;
    size_t off = 0;
    uint8_t direction = in[off++];
    uint8_t key_len = in[off++];
    if (direction > 1 || off + key_len + 1 > in_len) return 0;
    const uint8_t *key = in + off; off += key_len;
    uint8_t nonce_len = in[off++];
    if (off + nonce_len + 2 > in_len) return 0;
    const uint8_t *nonce = in + off; off += nonce_len;
    uint16_t aad_len = rd_u16(in + off); off += 2;
    if (off + aad_len + 2 > in_len) return 0;
    const uint8_t *aad = in + off; off += aad_len;
    uint16_t data_len = rd_u16(in + off); off += 2;
    if (off + data_len + 1 > in_len) return 0;
    const uint8_t *data = in + off; off += data_len;
    uint8_t tag_len = in[off++];
    if (off + (direction ? tag_len : 0) != in_len) return 0;
    const uint8_t *tag_in = direction ? in + off : NULL;
    if (out_max < (size_t)1 + 2 + data_len + 1 + (direction ? 0 : tag_len)) return 0;

    size_t o = 0;
    out[o++] = 1;
    wr_u16(out + o, data_len); o += 2;
    if (direction == 0) {
        uint8_t *ciphertext = out + o;
        uint8_t *tag_out = ciphertext + data_len + 1;
        if (!tls_aes_ccm_encrypt(key, key_len, nonce, nonce_len,
                                 aad_len ? aad : NULL, aad_len,
                                 data, data_len, ciphertext, tag_out, tag_len))
            return 0;
        o += data_len;
        out[o++] = tag_len;
        o += tag_len;
    } else {
        bool accepted = tls_aes_ccm_decrypt(key, key_len, nonce, nonce_len,
                                            aad_len ? aad : NULL, aad_len,
                                            data, data_len, tag_in, tag_len,
                                            out + o);
        out[0] = accepted ? 1 : 0;
        if (accepted) {
            o += data_len;
        } else {
            wr_u16(out + 1, 0);
            o = 3;
        }
        out[o++] = 0;
    }
    return o;
}

/*
 * SHA-256 payload TLV:
 *   msg_len  uint16
 *   msg      [msg_len]
 *
 * Response:
 *   digest_len uint8 (32)
 *   digest     [32]
 */
static size_t run_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    uint16_t msg_len = rd_u16(in);
    if ((size_t)2 + msg_len > in_len)
        return 0;
    if (out_max < 1 + 32)
        return 0;

    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
        return 0;
    if (msg_len)
        tls_hash_update(&hctx, in + 2, msg_len);
    uint8_t digest[32];
    tls_hash_digest(&hctx, digest);

    out[0] = 32;
    memcpy(out + 1, digest, 32);
    return 33;
}

/* SHA-256 Monte Carlo payload: seed[32]. Each response performs the NIST
 * 1000-step three-digest chaining operation and returns digest_len+digest. */
static size_t run_sha256_mct(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_max)
{
    if (in_len != 32 || out_max < 33) return 0;
    static uint8_t state[96];
    uint8_t digest[32];
    memcpy(state, in, 32);
    memcpy(state + 32, in, 32);
    memcpy(state + 64, in, 32);

    for (uint16_t i = 0; i < 1000; i++) {
        struct tls_hash_context hctx;
        if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256)) return 0;
        tls_hash_update(&hctx, state, sizeof(state));
        tls_hash_digest(&hctx, digest);
        memmove(state, state + 32, 64);
        memcpy(state + 64, digest, 32);
    }
    out[0] = 32;
    memcpy(out + 1, digest, 32);
    return 33;
}

/*
 * HMAC-SHA-256 payload TLV:
 *   key_len  uint16
 *   key      [key_len]
 *   msg_len  uint16
 *   msg      [msg_len]
 *
 * Response: tag_len uint8 (32) + tag[32]
 */
static size_t run_hmac_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    size_t off = 0;
    uint16_t key_len = rd_u16(in + off);
    off += 2;
    if (off + key_len > in_len)
        return 0;
    const uint8_t *key = in + off;
    off += key_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t msg_len = rd_u16(in + off);
    off += 2;
    if (off + msg_len > in_len)
        return 0;
    const uint8_t *msg = in + off;

    if (out_max < 1 + 32)
        return 0;

    struct tls_hmac_context hctx;
    if (!tls_hmac_context_init(&hctx, TLS_HASH_SHA256, key, key_len))
        return 0;
    if (msg_len)
        tls_hmac_update(&hctx, msg, msg_len);
    uint8_t tag[32];
    tls_hmac_digest(&hctx, tag);

    out[0] = 32;
    memcpy(out + 1, tag, 32);
    return 33;
}

/*
 * HKDF-SHA-256 payload TLV:
 *   ikm_len   uint16
 *   ikm       [ikm_len]
 *   salt_len  uint16
 *   salt      [salt_len]
 *   info_len  uint16
 *   info      [info_len]
 *   L         uint16   (output length in bytes; must be <= 255*32 = 8160)
 *
 * Response: okm_len uint16 + okm[okm_len]
 */
static size_t run_hkdf_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    size_t off = 0;
    uint16_t ikm_len = rd_u16(in + off);
    off += 2;
    if (off + ikm_len > in_len)
        return 0;
    const uint8_t *ikm = in + off;
    off += ikm_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t salt_len = rd_u16(in + off);
    off += 2;
    if (off + salt_len > in_len)
        return 0;
    const uint8_t *salt = in + off;
    off += salt_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t info_len = rd_u16(in + off);
    off += 2;
    if (off + info_len > in_len)
        return 0;
    const uint8_t *info = in + off;
    off += info_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t L = rd_u16(in + off);

    if (L > 8160)
        return 0;
    if (out_max < (size_t)2 + L)
        return 0;

    /* HKDF = Extract + Expand. Most implementations of tls_hkdf_expand_label
     * already do Extract+Expand internally; here we use the lower-level
     * primitives that just do Expand. To be vendor-correct, we use the
     * two-step API: tls_hkdf_extract then tls_hkdf_expand. */
    uint8_t prk[32];
    if (!tls_hkdf_extract(TLS_HASH_SHA256, salt, salt_len, ikm, ikm_len, prk))
        return 0;
    if (!tls_hkdf_expand(TLS_HASH_SHA256, prk, 32, info, info_len, out + 2, L))
        return 0;

    wr_u16(out, L);
    return (size_t)2 + L;
}

/* PBKDF2-HMAC-SHA-256 payload:
 * password_len+password, salt_len+salt, rounds uint16, key_len uint16.
 * Response: derived_len uint16 + derived bytes. */
static size_t run_pbkdf2_sha256(const uint8_t *in, size_t in_len,
                                uint8_t *out, size_t out_max)
{
    if (in_len < 2) return 0;
    size_t off = 0;
    uint16_t password_len = rd_u16(in + off); off += 2;
    if (off + password_len + 2 > in_len) return 0;
    const uint8_t *password = in + off; off += password_len;
    uint16_t salt_len = rd_u16(in + off); off += 2;
    if (off + salt_len + 4 != in_len) return 0;
    const uint8_t *salt = in + off; off += salt_len;
    uint16_t rounds = rd_u16(in + off); off += 2;
    uint16_t key_len = rd_u16(in + off);
    if (!rounds || !key_len || out_max < (size_t)2 + key_len) return 0;

    if (!tls_pbkdf2((const char *)password, password_len,
                    salt, salt_len, out + 2, key_len,
                    rounds, TLS_HASH_SHA256))
        return 0;
    wr_u16(out, key_len);
    return (size_t)2 + key_len;
}

/*
 * DRBG-SHA-256 payload TLV:
 *   entropy_len           uint16
 *   entropy               [entropy_len]
 *   nonce_len             uint16
 *   nonce                 [nonce_len]
 *   personalization_len   uint16
 *   personalization       [personalization_len]
 *   output_len            uint16
 *
 * Response: output_len uint16 + output[output_len]
 *
 * NOTE: This is a stub that returns STATUS_UNSUPPORTED for now because the
 * DRBG in this codebase is integrated with the TLS context, not exposed
 * as a standalone Hash_DRBG SP 800-90A API. To validate against NIST DRBG
 * vectors we'd need to add tls_drbg_instantiate / tls_drbg_generate /
 * tls_drbg_reseed entry points that accept caller-provided entropy.
 */
static size_t run_drbg_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_max;
    /* Signal unsupported via length 0 + caller sets status. */
    return 0;
}

/*
 * RSA-PSS-SHA-256 verify payload TLV:
 *   modulus_len  uint16    (n size, big-endian; typically 256 for RSA-2048)
 *   modulus      [modulus_len]
 *   exponent_len uint8
 *   exponent     [exponent_len]    (NOTE: project's RSA hardcodes e=65537;
 *                                   this field is accepted but ignored.)
 *   salt_len     uint8             (32 for PSS-SHA-256)
 *   msg_len      uint16
 *   msg          [msg_len]
 *   sig_len      uint16            (= modulus_len)
 *   sig          [sig_len]
 *
 * Response:
 *   verdict      uint8     (1 = signature valid, 0 = invalid)
 *
 * Verify is the composition of (a) RSA modexp to recover EM from the
 * signature using the supplied modulus, and (b) PSS padding check of EM
 * against SHA-256(msg). Both must succeed for verdict=1.
 */
static size_t run_rsa_pss_verify(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2 || out_max < 1) return 0;
    size_t off = 0;

    uint16_t modulus_len = rd_u16(in + off); off += 2;
    if (off + modulus_len > in_len) return 0;
    const uint8_t *modulus = in + off; off += modulus_len;

    if (off + 1 > in_len) return 0;
    uint8_t exp_len = in[off++];
    if (off + exp_len > in_len) return 0;
    /* Skip the exponent bytes — project's RSA hardcodes e=65537. */
    off += exp_len;

    if (off + 1 > in_len) return 0;
    uint8_t /* unused, format byte */ salt_len_byte = in[off++];
    (void)salt_len_byte;

    if (off + 2 > in_len) return 0;
    uint16_t msg_len = rd_u16(in + off); off += 2;
    if (off + msg_len > in_len) return 0;
    const uint8_t *msg = in + off; off += msg_len;

    if (off + 2 > in_len) return 0;
    uint16_t sig_len = rd_u16(in + off); off += 2;
    if (off + sig_len > in_len) return 0;
    const uint8_t *sig = in + off;

    /* sig and modulus must be the same length for RSA */
    if (sig_len != modulus_len) {
        out[0] = 0;  /* verdict: invalid (size mismatch is a hard reject) */
        return 1;
    }

    /* Step 1: RSA modexp to recover EM from sig.
     * em_buf is in a file-scope static rather than stack: powmod_exp_u24
     * carves ~2*modulus_len bytes of scratch off the stack internally,
     * and the eZ80 stack is tight. Moving the EM buffer off-stack also
     * rules out any caller-side stack-smash interaction with the bigint
     * workspace. */
    if (modulus_len > 256) {
        out[0] = 0;
        return 1;
    }
    static uint8_t em_buf[256];
    static const uint8_t cavp_exp_be[] = {0x01, 0x00, 0x01}; /* 65537 */
    struct tls_rsa_key cavp_key = {
        sizeof(cavp_exp_be), cavp_exp_be,
        modulus_len, modulus,
    };
    if (!tls_rsa_decrypt_signature(sig, sig_len, em_buf, &cavp_key)) {
        out[0] = 0;
        return 1;
    }

    /* Step 2: SHA-256 the message. This intentionally happens after
     * modexp so the bigint stack workspace cannot clobber mhash. */
    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256)) return 0;
    if (msg_len) tls_hash_update(&hctx, msg, msg_len);
    uint8_t mhash[32];
    tls_hash_digest(&hctx, mhash);

    /* Step 3: PSS padding check */
    bool ok = tls_rsa_pss_verify(em_buf, modulus_len, mhash, 32, TLS_HASH_SHA256);
    out[0] = ok ? 1 : 0;
    return 1;
}

/*
 * RSA-PKCS1v15-SHA-256 verify payload TLV:
 *   modulus_len  uint16    (n size, big-endian; typically 256 for RSA-2048)
 *   modulus      [modulus_len]
 *   exponent_len uint8
 *   exponent     [exponent_len]    (NOTE: project's RSA hardcodes e=65537;
 *                                   this field is accepted but ignored.)
 *   msg_len      uint16
 *   msg          [msg_len]
 *   sig_len      uint16            (= modulus_len)
 *   sig          [sig_len]
 *
 * Response:
 *   verdict      uint8     (1 = signature valid, 0 = invalid)
 *
 * Unlike RSA-PSS above, tls_rsa_pkcs1_v15_sha256_verify composes the
 * modexp and EMSA-PKCS1-v1.5 encoding check internally -- this is the
 * same function src/tls/core/x509.c uses to verify adjacent-link
 * signatures in the certificate chain walk (RSA-2048+SHA-256 links),
 * so this is the primitive that actually gates chain acceptance.
 */
static size_t run_rsa_pkcs1_v15_verify(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2 || out_max < 1) return 0;
    size_t off = 0;

    uint16_t modulus_len = rd_u16(in + off); off += 2;
    if (off + modulus_len > in_len) return 0;
    const uint8_t *modulus = in + off; off += modulus_len;

    if (off + 1 > in_len) return 0;
    uint8_t exp_len = in[off++];
    if (off + exp_len > in_len) return 0;
    /* Skip the exponent bytes — project's RSA hardcodes e=65537. */
    off += exp_len;

    if (off + 2 > in_len) return 0;
    uint16_t msg_len = rd_u16(in + off); off += 2;
    if (off + msg_len > in_len) return 0;
    const uint8_t *msg = in + off; off += msg_len;

    if (off + 2 > in_len) return 0;
    uint16_t sig_len = rd_u16(in + off); off += 2;
    if (off + sig_len > in_len) return 0;
    const uint8_t *sig = in + off;

    if (sig_len != modulus_len) {
        out[0] = 0;  /* verdict: invalid (size mismatch is a hard reject) */
        return 1;
    }
    if (modulus_len > 256) {
        out[0] = 0;
        return 1;
    }

    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256)) return 0;
    if (msg_len) tls_hash_update(&hctx, msg, msg_len);
    uint8_t mhash[32];
    tls_hash_digest(&hctx, mhash);

    static const uint8_t cavp_exp_be[] = {0x01, 0x00, 0x01}; /* 65537 */
    struct tls_rsa_key cavp_key = {
        sizeof(cavp_exp_be), cavp_exp_be,
        modulus_len, modulus,
    };
    bool ok = tls_rsa_pkcs1_v15_sha256_verify(sig, sig_len, mhash, &cavp_key);
    out[0] = ok ? 1 : 0;
    return 1;
}

/*
 * X25519-PUBLICKEY payload: priv[32].
 * Response: pub[32].
 */
static size_t run_x25519_publickey(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len != 32 || out_max < 32) return 0;
    if (!tls_x25519_publickey(out, in, NULL, NULL)) return 0;
    return 32;
}

/*
 * X25519-SECRET payload: priv[32] || peer_pub[32].
 * Response: shared[32].
 */
static size_t run_x25519_secret(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len != 64 || out_max < 32) return 0;
    const uint8_t *priv = in;
    const uint8_t *peer = in + 32;
    if (!tls_x25519_secret(out, priv, peer, NULL, NULL)) return 0;
    return 32;
}

/* ---------- Main runner ---------- */

int main(void)
{
    os_ClrHome();
    printf("CAVP runner\n");

    if (!lwip_start())
    {
        printf("ERROR: lwip_start failed\n");
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* Open output AppVar */
    (void)ti_Delete(CAVPOUT_NAME);
    uint8_t out_handle = ti_Open(CAVPOUT_NAME, "w");
    if (!out_handle)
    {
        printf("ERROR: open %s\n", CAVPOUT_NAME);
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* Write magic + placeholder response_count; we'll patch the count at end */
    uint8_t header[6] = {'A', 'O', 'U', 'T', 0, 0};
    ti_Write(header, sizeof(header), 1, out_handle);

    uint16_t responses_written = 0;
    /* Per-response scratch buffer: enough for the largest expected primitive
     * output. HKDF can emit up to 8160 bytes; cap response payload to keep
     * total AppVar size sane for this CI sample. */
    static uint8_t scratch[8192];

    printf("running vectors\n");

    for (uint8_t chunk = 0; chunk < CAVPIN_CHUNKS; chunk++)
    {
        char input_name[9] = "CAVP00";
        input_name[4] = (char)('0' + chunk / 10);
        input_name[5] = (char)('0' + chunk % 10);
        uint8_t in_handle = ti_Open(input_name, "r");
        if (!in_handle) {
            ti_Close(out_handle);
            printf("ERROR: no %s\n", input_name);
            printf("Press any key");
            os_GetKey();
            return 1;
        }

        /* ti_GetDataPtr returns variable content without the on-disk
         * length prefix. Each chunk is an independent AIN1 record stream. */
        size_t in_size = ti_GetSize(in_handle);
        const uint8_t *in = ti_GetDataPtr(in_handle);
        if (!in || in_size < 6 ||
            in[0] != 'A' || in[1] != 'I' || in[2] != 'N' || in[3] != '1') {
            ti_Close(in_handle);
            ti_Close(out_handle);
            printf("ERROR: bad %s\n", input_name);
            printf("Press any key");
            os_GetKey();
            return 1;
        }

        uint16_t vector_count = rd_u16(in + 4);
        size_t in_off = 6;
        for (uint16_t i = 0; i < vector_count; i++)
        {
        if (in_off + 5 > in_size)
            break;
        uint8_t alg = in[in_off++];
        uint16_t test_id = rd_u16(in + in_off);
        in_off += 2;
        uint16_t payload_len = rd_u16(in + in_off);
        in_off += 2;
        if (in_off + payload_len > in_size)
            break;
        const uint8_t *payload = in + in_off;
        in_off += payload_len;

        size_t result_len = 0;
        uint8_t status = STATUS_OK;

        switch (alg)
        {
        case ALG_AES_GCM:
            result_len = run_aes_gcm(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_SHA256:
            result_len = run_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_HMAC_SHA256:
            result_len = run_hmac_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_HKDF_SHA256:
            result_len = run_hkdf_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_DRBG_SHA256:
            result_len = run_drbg_sha256(payload, payload_len, scratch, sizeof(scratch));
            status = STATUS_UNSUPPORTED;
            result_len = 0;
            break;
        case ALG_RSA_PSS_SHA256_VERIFY:
            result_len = run_rsa_pss_verify(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_RSA_PKCS1_SHA256_VERIFY:
            result_len = run_rsa_pkcs1_v15_verify(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_X25519_PUBLICKEY:
            result_len = run_x25519_publickey(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_X25519_SECRET:
            result_len = run_x25519_secret(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_AES_CBC:
            result_len = run_aes_cbc(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_AES_CCM:
            result_len = run_aes_ccm(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_PBKDF2_HMAC_SHA256:
            result_len = run_pbkdf2_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_SHA256_MCT:
            result_len = run_sha256_mct(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        default:
            status = STATUS_UNSUPPORTED;
            result_len = 0;
            break;
        }

        uint8_t rec_header[5];
        wr_u16(rec_header, test_id);
        rec_header[2] = status;
        wr_u16(rec_header + 3, (uint16_t)result_len);
        ti_Write(rec_header, sizeof(rec_header), 1, out_handle);
        if (result_len)
            ti_Write(scratch, result_len, 1, out_handle);

        responses_written++;
        }
        ti_Close(in_handle);
    }

    /* Patch the response_count field in the AppVar header */
    ti_Seek(4, SEEK_SET, out_handle);
    uint8_t count_le[2];
    wr_u16(count_le, responses_written);
    ti_Write(count_le, 2, 1, out_handle);

    ti_SetArchiveStatus(true, out_handle);
    ti_Close(out_handle);

    os_ClrHome();
    printf("CAVP runner\n");
    printf("Done.");
    os_GetKey();
    return 0;
}
