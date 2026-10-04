/**
 * @file key.c
 * @author Anthony Cagliano
 * @brief Forward-facing key operations — verify, sign, encrypt, decrypt.
 *
 * All functions dispatch on key->alg.  AES encrypt/decrypt operations are
 * fully one-shot: the AES context is constructed internally, a fresh IV is
 * generated via tls_random_bytes, and the context is destroyed before return.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/aes.h"
#include "../includes/random.h"
#include "../includes/bytes.h"
#include "../includes/key.h"
#include "../includes/x509.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_KEY
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

/* ---------------------------------------------------------------------------
 * tls_key_verify / tls_key_sign
 * --------------------------------------------------------------------------- */

tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const struct tls_key *key)
{
    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }
    return tls_x509_signature_verify(content, content_len, sig, sig_len, key);
}

tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                  uint8_t *sig_out, size_t *sig_len_out,
                                  const struct tls_key *key)
{
    (void)content;
    (void)content_len;
    (void)sig_out;
    (void)sig_len_out;

    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_PSS_RSAE_SHA256:
        case TLS_ALG_RSA_PKCS1_SHA256:
        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return TLS_KEY_OP_UNSUPPORTED;

        case TLS_ALG_UNKNOWN:
            return TLS_KEY_OP_UNKNOWN;

        default:
            /* Encryption-range alg passed to sign — wrong key type. */
            return TLS_KEY_OP_UNKNOWN;
    }
}

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

/* Returns the IV/nonce length for a given AES alg, or 0 if not AES. */
static size_t key_iv_len(tls_alg_t alg)
{
    switch (alg)
    {
        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
            return TLS_KEY_GCM_IV_LEN;
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            return TLS_KEY_CCM_NONCE_LEN;
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return TLS_AES_IV_SIZE;
        default:
            return 0;
    }
}

/* Maps tls_alg_t to the tls_aes_modes value expected by tls_aes_init. */
static uint8_t key_aes_mode(tls_alg_t alg)
{
    switch (alg)
    {
        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
            return TLS_AES_GCM;
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            return TLS_AES_CCM;
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
        default:
            return TLS_AES_CBC;
    }
}

static bool key_is_aead(tls_alg_t alg)
{
    return alg == TLS_ALG_AES_128_GCM || alg == TLS_ALG_AES_256_GCM ||
           alg == TLS_ALG_AES_128_CCM || alg == TLS_ALG_AES_256_CCM;
}

/* ---------------------------------------------------------------------------
 * AES one-shot encrypt (shared by plain and AAD variants)
 * --------------------------------------------------------------------------- */

static bool aes_encrypt_oneshot(tls_alg_t alg,
                                 const uint8_t *key_data, size_t key_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *inbuf, size_t in_len,
                                 struct tls_key_cipher_io *io)
{
    struct tls_aes_context ctx;
    size_t iv_len = key_iv_len(alg);
    uint8_t mode  = key_aes_mode(alg);
    bool ok = false;

    if (!io || !io->iv || !io->obuf)
    {
        return false;
    }
    if (key_is_aead(alg) && !io->tag)
    {
        return false;
    }

    /* Generate a fresh IV/nonce. */
    tls_random_bytes(io->iv, iv_len);

    /* Compute actual ciphertext length: CBC pads partial last block; all others
     * are same length as plaintext. */
    size_t ct_len;
    if (mode == TLS_AES_CBC)
    {
        size_t rem = in_len % TLS_AES_BLOCK_SIZE;
        ct_len = rem ? (in_len - rem + TLS_AES_BLOCK_SIZE) : in_len;
    }
    else
    {
        ct_len = in_len;
    }

    if (mode == TLS_AES_CCM)
    {
        if (!tls_aes_ccm_encrypt(key_data, key_len,
                                  io->iv, iv_len,
                                  aad, aad_len,
                                  inbuf, in_len,
                                  io->obuf, io->tag, TLS_KEY_AES_TAG_LEN))
        {
            goto cleanup;
        }
        ok = true;
    }
    else
    {
        if (!tls_aes_init(&ctx, mode, key_data, key_len, io->iv, iv_len))
        {
            goto cleanup;
        }
        if (aad && aad_len && !tls_aes_update_aad(&ctx, aad, aad_len))
        {
            goto cleanup;
        }
        if (!tls_aes_encrypt(&ctx, inbuf, in_len, io->obuf))
        {
            goto cleanup;
        }
        if (key_is_aead(alg) && !tls_aes_digest(&ctx, io->tag))
        {
            goto cleanup;
        }
        ok = true;
    }
    io->obuf_len = ct_len;

cleanup:
    tls_secure_memzero(&ctx, sizeof(ctx));
    return ok;
}


/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

bool tls_key_encrypt(struct tls_key *key,
                     const uint8_t *inbuf, size_t in_len,
                     struct tls_key_cipher_io *io)
{
    if (!key || !inbuf || !io)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            if (!io->obuf)
            {
                return false;
            }
            return tls_rsa_encrypt(inbuf, in_len, io->obuf,
                                   &key->rsa, TLS_HASH_SHA256);

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(key->alg,
                                       key->aes.data, key->aes.len,
                                       NULL, 0,
                                       inbuf, in_len, io);

        default:
            return false;
    }
}

bool tls_key_encrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *inbuf, size_t in_len,
                         struct tls_key_cipher_io *io)
{
    if (!key || !inbuf || !io)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            /* AAD not applicable to RSA-OAEP here; treat as plain encrypt. */
            if (!io->obuf)
            {
                return false;
            }
            return tls_rsa_encrypt(inbuf, in_len, io->obuf,
                                   &key->rsa, TLS_HASH_SHA256);

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(key->alg,
                                       key->aes.data, key->aes.len,
                                       aad, aad_len,
                                       inbuf, in_len, io);

        default:
            return false;
    }
}

bool tls_key_decrypt(struct tls_key *key,
                     struct tls_key_cipher_io *io,
                     uint8_t *outbuf, size_t outbuf_len)
{
    return tls_key_decrypt_aad(key, NULL, 0, io, outbuf, outbuf_len);
}

bool tls_key_decrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         struct tls_key_cipher_io *io,
                         uint8_t *outbuf, size_t outbuf_len)
{
    if (!key || !io || !io->iv || !io->obuf || !outbuf || outbuf_len < io->obuf_len)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            /* AAD not applicable to RSA-OAEP; aad is ignored. */
            if (io->obuf_len > RSA_TRANSIENT_SIZE)
            {
                return false;
            }
            {
                bool ok = false;
                if (tls_rsa_decrypt_signature(io->obuf, io->obuf_len, __rsa_transient, &key->rsa))
                {
                    ok = tls_rsa_decode_oaep(__rsa_transient, io->obuf_len,
                                             outbuf, NULL, TLS_HASH_SHA256) > 0;
                }
                tls_secure_memzero(__rsa_transient, io->obuf_len);
                return ok;
            }

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
        {
            if (key_is_aead(key->alg) && !io->tag)
            {
                return false;
            }
            struct tls_aes_context ctx;
            size_t iv_len = key_iv_len(key->alg);
            bool ok = false;
            if (!tls_aes_init(&ctx, key_aes_mode(key->alg),
                              key->aes.data, key->aes.len, io->iv, iv_len))
            {
                goto gcm_cbc_cleanup;
            }
            if (key_is_aead(key->alg))
            {
                if (!tls_aes_verify(&ctx, aad, aad_len,
                                    io->obuf, io->obuf_len, io->tag))
                {
                    goto gcm_cbc_cleanup;
                }
            }
            if (tls_aes_decrypt(&ctx, io->obuf, io->obuf_len, outbuf))
            {
                ok = true;
            }
gcm_cbc_cleanup:
            tls_secure_memzero(&ctx, sizeof(ctx));
            return ok;
        }

        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            if (!io->tag)
            {
                return false;
            }
            return tls_aes_ccm_decrypt(key->aes.data, key->aes.len,
                                        io->iv, key_iv_len(key->alg),
                                        aad, aad_len,
                                        io->obuf, io->obuf_len,
                                        io->tag, TLS_KEY_AES_TAG_LEN,
                                        outbuf);

        default:
            return false;
    }
}
