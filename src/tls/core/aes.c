#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../includes/aes.h"
#include "../includes/bytes.h"
#include "../includes/crypto_guard.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_AES
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define MIN(x, y) ((x) < (y)) ? (x) : (y)
#define KE_ROTWORD(x) (((x) << 8) | ((x) >> 24))

void bytelen_to_bitlen(size_t val, uint8_t *dst);

/**************************** DATA TYPES ****************************/
#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

#define AES_BLOCK_SIZE 16 // AES operates on 16 bytes at a time

// External functions implemented in aes.s

// XORs the in and out buffers, storing the result in out. Length is in bytes, must be <= AES_BLOCK_SIZE
void aes_xor_buf(const uint8_t in[], uint8_t out[], size_t len);

// Must be called before aes_key_schedule or aes_encrypt_block. Loads data and code into fastmem.
void aes_prepare_encrypt(void);
// Expands the given AES key into the round_keys buffer. key_len must be pre-validated as a supported key size
void aes_key_schedule(uint8_t *round_keys, const uint8_t *key, size_t key_len);
// Encrypts an AES block with the given initialized context.
void aes_encrypt_block(const uint8_t *in, uint8_t *out, struct tls_aes_context *ks);

// Must be called before gf128_mul. Loads code into fastmem, can co-exist with aes_prepare_encrypt functions.
void aes_prepare_ghash(void);
// Multiplies two 128-bit Galois field polynomials.
void gf128_mul(uint8_t *a, const uint8_t *b, uint8_t *c);

// Must be called before aes_decrypt_block. Loads data and code into fastmem.
void aes_prepare_decrypt(void);
// Decrypts an AES block with the given initialized context.
void aes_decrypt_block(const uint8_t *in, uint8_t *out, struct tls_aes_context *ks);

/*********************** FUNCTION DEFINITIONS ***********************/

static void increment_iv(uint8_t iv[], size_t counter_start, size_t counter_size)
{
    uint24_t idx;

    // Use counter_size bytes at the end of the IV as the big-endian integer to increment.
    for (idx = counter_start + counter_size - 1; idx >= counter_start; idx--)
    {
        iv[idx]++;
        if (iv[idx] != 0)
            break;
    }
}

// CCM helpers
#define AES_CCM_NONCE_MIN_LEN 7
#define AES_CCM_NONCE_MAX_LEN 13
#define AES_CCM_TAG_MIN_LEN 4
#define AES_CCM_TAG_MAX_LEN 16

static bool ccm_validate_params(size_t nonce_len, uint8_t tag_len, size_t msg_len)
{
    if ((nonce_len < AES_CCM_NONCE_MIN_LEN) || (nonce_len > AES_CCM_NONCE_MAX_LEN))
        return false;
    if ((tag_len < AES_CCM_TAG_MIN_LEN) || (tag_len > AES_CCM_TAG_MAX_LEN) || (tag_len & 1))
        return false;
    uint8_t L = 15 - (uint8_t)nonce_len;
    if ((L < 2) || (L > 8))
        return false;
    if (L < 8)
    {
        uint64_t max = 1ULL << (8 * L);
        if ((uint64_t)msg_len >= max)
            return false;
    }
    return true;
}

static void ccm_store_len_be(uint8_t *dst, size_t len, uint8_t bytes)
{
    uint64_t v = (uint64_t)len;
    for (uint8_t idx = 0; idx < bytes; idx++)
        dst[bytes - 1 - idx] = (uint8_t)((v >> (idx * 8)) & 0xFF);
}

static void ccm_mac_update_block(struct tls_aes_context *ctx, const uint8_t *block)
{
    aes_xor_buf(block, ctx->private.ccm.mac, AES_BLOCK_SIZE);
    aes_encrypt_block(ctx->private.ccm.mac, ctx->private.ccm.mac, ctx);
}

static bool ccm_update_aad(struct tls_aes_context *ctx, const uint8_t *aad, size_t aad_len)
{
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t hdr[10];
    size_t hdr_len;
    size_t hdr_pos = 0;
    size_t aad_pos = 0;

    if (aad_len == 0)
        return ctx->private.ccm.aad_len_total == 0;
    if ((aad == NULL) || (ctx->private.ccm.aad_len != 0))
        return false;
    if (ctx->private.ccm.aad_len_total != aad_len)
        return false;

    uint64_t len64 = (uint64_t)aad_len;
    if (len64 < 0xFF00)
    {
        hdr_len = 2;
        hdr[0] = (uint8_t)((len64 >> 8) & 0xFF);
        hdr[1] = (uint8_t)(len64 & 0xFF);
    }
    else if (len64 <= 0xFFFFFFFFu)
    {
        uint32_t len32 = (uint32_t)len64;
        hdr_len = 6;
        hdr[0] = 0xFF;
        hdr[1] = 0xFE;
        hdr[2] = (uint8_t)((len32 >> 24) & 0xFF);
        hdr[3] = (uint8_t)((len32 >> 16) & 0xFF);
        hdr[4] = (uint8_t)((len32 >> 8) & 0xFF);
        hdr[5] = (uint8_t)(len32 & 0xFF);
    }
    else
    {
        hdr_len = 10;
        hdr[0] = 0xFF;
        hdr[1] = 0xFF;
        hdr[2] = (uint8_t)((len64 >> 56) & 0xFF);
        hdr[3] = (uint8_t)((len64 >> 48) & 0xFF);
        hdr[4] = (uint8_t)((len64 >> 40) & 0xFF);
        hdr[5] = (uint8_t)((len64 >> 32) & 0xFF);
        hdr[6] = (uint8_t)((len64 >> 24) & 0xFF);
        hdr[7] = (uint8_t)((len64 >> 16) & 0xFF);
        hdr[8] = (uint8_t)((len64 >> 8) & 0xFF);
        hdr[9] = (uint8_t)(len64 & 0xFF);
    }

    while ((hdr_pos < hdr_len) || (aad_pos < aad_len))
    {
        size_t idx = 0;
        while ((idx < AES_BLOCK_SIZE) && (hdr_pos < hdr_len))
            block[idx++] = hdr[hdr_pos++];
        while ((idx < AES_BLOCK_SIZE) && (aad_pos < aad_len))
            block[idx++] = aad[aad_pos++];
        while (idx < AES_BLOCK_SIZE)
            block[idx++] = 0;
        ccm_mac_update_block(ctx, block);
    }

    ctx->private.ccm.aad_len = aad_len;
    tls_secure_memzero(block, sizeof block);
    tls_secure_memzero(hdr, sizeof hdr);
    return true;
}

static void ccm_prepare_counter(struct tls_aes_context *ctx, uint32_t counter)
{
    uint8_t L = ctx->private.ccm.L;
    size_t counter_start = AES_BLOCK_SIZE - L;
    tls_secure_memzero(ctx->private.ccm.ctr, AES_BLOCK_SIZE);
    ctx->private.ccm.ctr[0] = (uint8_t)(L - 1);
    memcpy(&ctx->private.ccm.ctr[1], ctx->private.ccm.nonce, ctx->private.ccm.nonce_len);
    ccm_store_len_be(&ctx->private.ccm.ctr[counter_start], counter, L);
}

static bool ccm_process_message(struct tls_aes_context *ctx, const uint8_t *inbuf, size_t in_len,
                                uint8_t *outbuf, bool encrypt)
{
    if ((ctx->private.ccm.msg_processed != 0) || (in_len != ctx->private.ccm.msg_len))
        return false;

    size_t blocks = in_len / AES_BLOCK_SIZE;
    size_t rem = in_len % AES_BLOCK_SIZE;
    uint8_t keystream[AES_BLOCK_SIZE];

    aes_prepare_encrypt();
    for (size_t idx = 0; idx < blocks; idx++)
    {
        const uint8_t *in = &inbuf[idx * AES_BLOCK_SIZE];
        uint8_t *out = outbuf ? &outbuf[idx * AES_BLOCK_SIZE] : NULL;

        aes_encrypt_block(ctx->private.ccm.ctr, keystream, ctx);
        if (encrypt)
        {
            ccm_mac_update_block(ctx, in);
            if (out)
            {
                aes_xor_buf(in, keystream, AES_BLOCK_SIZE);
                memcpy(out, keystream, AES_BLOCK_SIZE);
            }
        }
        else
        {
            aes_xor_buf(in, keystream, AES_BLOCK_SIZE);
            ccm_mac_update_block(ctx, keystream);
            if (out)
                memcpy(out, keystream, AES_BLOCK_SIZE);
        }
        increment_iv(ctx->private.ccm.ctr, AES_BLOCK_SIZE - ctx->private.ccm.L, ctx->private.ccm.L);
    }

    if (rem)
    {
        size_t offset = blocks * AES_BLOCK_SIZE;
        const uint8_t *in = &inbuf[offset];
        uint8_t *out = outbuf ? &outbuf[offset] : NULL;
        aes_encrypt_block(ctx->private.ccm.ctr, keystream, ctx);
        if (encrypt)
        {
            uint8_t tmp[AES_BLOCK_SIZE];
            memcpy(tmp, in, rem);
            tls_secure_memzero(&tmp[rem], AES_BLOCK_SIZE - rem);
            ccm_mac_update_block(ctx, tmp);
            if (out)
            {
                aes_xor_buf(tmp, keystream, rem);
                memcpy(out, keystream, rem);
            }
            tls_secure_memzero(tmp, sizeof tmp);
        }
        else
        {
            aes_xor_buf(in, keystream, rem);
            tls_secure_memzero(&keystream[rem], AES_BLOCK_SIZE - rem);
            ccm_mac_update_block(ctx, keystream);
            if (out)
                memcpy(out, keystream, rem);
        }
        increment_iv(ctx->private.ccm.ctr, AES_BLOCK_SIZE - ctx->private.ccm.L, ctx->private.ccm.L);
    }

    ctx->private.ccm.msg_processed = in_len;
    tls_secure_memzero(keystream, sizeof keystream);
    return true;
}

enum _aes_op_assoc
{
    AES_OP_NONE,
    AES_OP_ENCRYPT,
    AES_OP_DECRYPT
};
enum GCM_OPS_ALLOWED
{
    LOCK_ALLOW_ALL,
    LOCK_ALLOW_ENCRYPT,
    LOCK_ALLOW_NONE
};
#define AES_GCM_NONCE_LEN 12
#define AES_GCM_CTR_LEN 4
#define AES_GCM_POLY 0xe1 // polynomial used in AES-GCM
#define ghash_start(buf) tls_secure_memzero((buf), 16)

static void ghash(struct tls_aes_context *ctx, uint8_t *out_buf, const uint8_t *data, size_t len)
{
    size_t data_offset = 0;

    // the cache allows for incomplete blocks to be queued
    // the next call to update will concat the queue and new aad
    if (ctx->private.gcm.aad_cache_len)
    {
        size_t cache_len = ctx->private.gcm.aad_cache_len;
        data_offset = MIN(len, AES_BLOCK_SIZE - cache_len);
        if (data_offset + cache_len < AES_BLOCK_SIZE)
        {
            // if new aad is not enough to fill a block, update queue and stop w/o processing
            memcpy(&ctx->private.gcm.aad_cache[cache_len], data, data_offset);
            ctx->private.gcm.aad_cache_len += data_offset;
            return;
        }
        else
        {
            // if new aad is enough to fill a block, concat queue and rest of block from aad
            // then update hash
            aes_xor_buf(ctx->private.gcm.aad_cache, out_buf, cache_len);
            aes_xor_buf(data, &out_buf[cache_len], data_offset);
            gf128_mul(out_buf, ctx->private.gcm.ghash_key, out_buf);
            ctx->private.gcm.aad_cache_len = 0;
        }
    }

    // now process any remaining aad data
    for (uint24_t idx = data_offset; idx < len; idx += AES_BLOCK_SIZE)
    {
        size_t bytes_copy = MIN(AES_BLOCK_SIZE, len - idx);
        if (bytes_copy < AES_BLOCK_SIZE)
        {
            // if aad_len < block size, write bytes to queue.
            // no return here because this condition should just exit out next loop
            memcpy(ctx->private.gcm.aad_cache, &data[idx], bytes_copy);
            ctx->private.gcm.aad_cache_len = bytes_copy;
        }
        else
        {
            // if aad_len >= block size, update hash for block
            aes_xor_buf(&data[idx], out_buf, AES_BLOCK_SIZE);
            gf128_mul(out_buf, ctx->private.gcm.ghash_key, out_buf);
        }
    }
}

static void aes_gcm_prepare_iv(struct tls_aes_context *ctx, const uint8_t *iv, size_t iv_len)
{
    // memset(ctx->iv, 0, AES_BLOCK_SIZE);
    // ^^ this should already be zero'd from aes_init

    if (iv_len == 12)
    {
        /* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
        // memcpy(ctx->iv, iv, iv_len);
        // ^^ this should already be done by aes_init
        ctx->iv[AES_BLOCK_SIZE - 1] = 0x01;
    }
    else
    {
        aes_prepare_ghash();
        /*
         * s = 128 * ceil(len(IV)/128) - len(IV)
         * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
         */
        // hash the IV. Pad to block size
        uint8_t tbuf[AES_BLOCK_SIZE] = {0};
        memcpy(tbuf, iv, iv_len);
        tls_secure_memzero(ctx->iv, AES_BLOCK_SIZE);
        ghash(ctx, ctx->iv, tbuf, sizeof(tbuf));
        // aes_xor_buf(tbuf, ctx->iv, AES_BLOCK_SIZE);
        // gf128_mul(out_buf, ctx->mode.gcm.ghash_key, out_buf);

        tls_secure_memzero(tbuf, AES_BLOCK_SIZE >> 1);
        bytelen_to_bitlen(iv_len, &tbuf[8]); // outputs in BE

        ghash(ctx, ctx->iv, tbuf, sizeof(tbuf));
    }
}

#define AES_GCM_NONCE_LEN 12
#define AES_GCM_CTR_LEN 4
#define AES_GCM_POLY 0xe1 // polynomial used in AES-GCM

// Performs the action of generating the keys that will be used in every round of
// encryption. "key" is the user-supplied input key, "w" is the output key schedule,
// "keysize" is the length in bits of "key", must be 128, 192, or 256.
bool tls_aes_init(struct tls_aes_context *ctx, uint8_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len)
{
    if ((ctx == NULL) ||
        (key == NULL) ||
        (iv == NULL))
    {
        ERROR();
        return false;
    }

    if (iv_len > AES_BLOCK_SIZE)
    {
        ERROR();
        return false;
    }
    tls_secure_memzero(ctx, sizeof(struct tls_aes_context));
    switch (key_len)
    {
    case 16:
        break;
    case 24:
        break;
    case 32:
        break;
    default:
        ERROR_CODE(key_len);
        return false;
    }

    memcpy(ctx->iv, iv, iv_len);
    // memset(&ctx->iv[iv_len], 0, 16-iv_len);
    ctx->keysize = key_len << 3;

    aes_prepare_encrypt();
    aes_key_schedule(ctx->round_keys, key, key_len);

    switch (mode)
    {
    case TLS_AES_GCM:
    {
        // generate ghash key
        uint8_t tmp[16] = {0};
        aes_encrypt_block(tmp, ctx->private.gcm.ghash_key, ctx);
        // sort out IV wonkiness in GCM mode
        aes_gcm_prepare_iv(ctx, iv, iv_len);
        tls_secure_memzero(ctx->private.gcm.auth_tag, AES_BLOCK_SIZE);
        memcpy(ctx->private.gcm.auth_j0, ctx->iv, AES_BLOCK_SIZE);
        increment_iv(ctx->iv, AES_GCM_NONCE_LEN, AES_GCM_CTR_LEN);
        break;
    }
    case TLS_AES_CBC:
        // i don't think anything needs setup here
        break;
    default:
        ERROR_CODE(mode);
        return false;
    }
    ctx->mode = mode;

    return true;
}

bool tls_aes_ccm_init(struct tls_aes_context *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      uint8_t tag_len, size_t msg_len, size_t aad_len)
{
    uint8_t b0[AES_BLOCK_SIZE];
    uint8_t zero_iv[AES_BLOCK_SIZE] = {0};

    if ((ctx == NULL) || (key == NULL) || (nonce == NULL))
        return false;
    if (!ccm_validate_params(nonce_len, tag_len, msg_len))
        return false;

    if (!tls_aes_init(ctx, TLS_AES_CBC, key, key_len, zero_iv, 0))
        return false;

    ctx->mode = TLS_AES_CCM;
    ctx->private.ccm.nonce_len = (uint8_t)nonce_len;
    ctx->private.ccm.tag_len = tag_len;
    ctx->private.ccm.L = (uint8_t)(15 - nonce_len);
    ctx->private.ccm.msg_len = msg_len;
    ctx->private.ccm.aad_len_total = aad_len;
    ctx->private.ccm.lock = LOCK_ALLOW_ALL;
    ctx->private.ccm.msg_processed = 0;
    ctx->private.ccm.aad_len = 0;

    memcpy(ctx->private.ccm.nonce, nonce, nonce_len);

    b0[0] = (uint8_t)((aad_len ? 0x40 : 0x00) | (((tag_len - 2) / 2) << 3) | (ctx->private.ccm.L - 1));
    memcpy(&b0[1], nonce, nonce_len);
    ccm_store_len_be(&b0[AES_BLOCK_SIZE - ctx->private.ccm.L], msg_len, ctx->private.ccm.L);
    aes_encrypt_block(b0, ctx->private.ccm.mac, ctx);

    ccm_prepare_counter(ctx, 0);
    aes_encrypt_block(ctx->private.ccm.ctr, ctx->private.ccm.s0, ctx);
    ccm_prepare_counter(ctx, 1);

    tls_secure_memzero(b0, sizeof b0);
    return true;
}

bool tls_aes_update_aad(struct tls_aes_context *ctx, const uint8_t *aad, size_t aad_len)
{
    if (ctx->mode == TLS_AES_GCM)
    {
        if (ctx->private.gcm.lock > LOCK_ALLOW_ALL)
            return false;
        // update the tag for full blocks of aad in input, cache any partial blocks
        aes_prepare_ghash();
        ghash(ctx, ctx->private.gcm.auth_tag, aad, aad_len);
        ctx->private.gcm.aad_len += aad_len;
        return true;
    }
    if (ctx->mode == TLS_AES_CCM)
    {
        if (ctx->private.ccm.lock > LOCK_ALLOW_ALL)
            return false;
        return ccm_update_aad(ctx, aad, aad_len);
    }
    return false;
}

bool tls_aes_digest(struct tls_aes_context *ctx, uint8_t *digest)
{
    if ((ctx == NULL) || (digest == NULL))
        return false;

    uint8_t tbuf[AES_BLOCK_SIZE];
    if (ctx->mode == TLS_AES_GCM)
    {
        aes_prepare_encrypt();
        aes_prepare_ghash();

        ctx->private.gcm.lock = LOCK_ALLOW_NONE;
        uint8_t *tag = ctx->private.gcm.auth_tag;

        // pad rest of ciphertext cache with 0s — but ONLY if there's
        // actually a cached partial block. Without the guard, the zero-fill
        // ghashes a phantom full block when both AAD and CT happen to be
        // block-aligned (or empty), corrupting the tag. Caught by the
        // CAVP test: see whitepaper section on continuous validation.
        if (ctx->private.gcm.aad_cache_len)
        {
            tls_secure_memzero(tbuf, AES_BLOCK_SIZE);
            ghash(ctx, tag, tbuf, AES_BLOCK_SIZE - ctx->private.gcm.aad_cache_len);
        }
        // at this point, tag should be GHASH(0-padded aad || 0-padded ciphertext)

        // final tag computed as GHASH( 0-padded aad || 0-padded ciphertext || u64-be-aad-len || u64-be-ciphertext-len)
        bytelen_to_bitlen(ctx->private.gcm.aad_len, tbuf);
        bytelen_to_bitlen(ctx->private.gcm.ct_len, &tbuf[8]);
        ghash(ctx, tag, tbuf, AES_BLOCK_SIZE);

        // encrypt auth tag with CTR0
        aes_encrypt_block(ctx->private.gcm.auth_j0, digest, ctx);
        aes_xor_buf(tag, digest, AES_BLOCK_SIZE);
        tls_secure_memzero(tbuf, sizeof tbuf);
        return true;
    }
    else if (ctx->mode == TLS_AES_CCM)
    {
        if (ctx->private.ccm.aad_len_total != ctx->private.ccm.aad_len)
            return false;
        if (ctx->private.ccm.msg_processed != ctx->private.ccm.msg_len)
            return false;
        ctx->private.ccm.lock = LOCK_ALLOW_NONE;
        memcpy(tbuf, ctx->private.ccm.mac, AES_BLOCK_SIZE);
        aes_xor_buf(ctx->private.ccm.s0, tbuf, AES_BLOCK_SIZE);
        tls_secure_memzero(digest, AES_BLOCK_SIZE);
        memcpy(digest, tbuf, ctx->private.ccm.tag_len);
        tls_secure_memzero(tbuf, sizeof tbuf);
        return true;
    }
    return false;
}

bool tls_aes_update_ciphertext(struct tls_aes_context *ctx, const uint8_t *ct, size_t ct_len)
{
    if (ctx == NULL || ct == NULL || ctx->mode != TLS_AES_GCM)
        return false;

    aes_prepare_ghash();

    uint8_t *tag = ctx->private.gcm.auth_tag;

    /* Transition: if we are still allowing AAD, we must now close the AAD section.
     * GCM requires zero-padding the AAD hash context to the next block boundary. */
    if (ctx->private.gcm.lock == LOCK_ALLOW_ALL)
    {
        if (ctx->private.gcm.aad_cache_len > 0)
        {
            uint8_t zero_pad[16] = {0};
            ghash(ctx, tag, zero_pad, 16 - ctx->private.gcm.aad_cache_len);
            ctx->private.gcm.aad_cache_len = 0; /* Reset cache for ciphertext use */
        }
        ctx->private.gcm.lock = LOCK_ALLOW_ENCRYPT;
    }

    /* Update the hash over the provided ciphertext bytes */
    ghash(ctx, tag, ct, ct_len);
    ctx->private.gcm.ct_len += ct_len;
    return true;
}

#define AES_BLOCKSIZE 16

/*
 * GCM CTR keystream XOR — the shared core of both streaming encrypt and
 * decrypt. GCM encryption and decryption apply the *same* CTR keystream to the
 * data (only the GHASH-vs-ciphertext ordering differs between the two), so this
 * single routine handles both directions correctly across an arbitrary number
 * of chunked calls.
 *
 * Streaming-state contract (struct _gcm_private):
 *   - ctx->iv holds the counter block for the NEXT fresh keystream block to
 *     generate (init leaves it at J0+1; we advance it as blocks are produced).
 *   - last_block holds the most recently generated keystream block.
 *   - last_block_len is how many bytes of last_block have ALREADY been consumed
 *     (0..15). 0 means "no partial block pending — generate a fresh block for
 *     the next byte". It never holds 16; a fully consumed block wraps to 0.
 *
 * This replaces the previous last_block/bytes_offset continuation, which had an
 * off-by-one block loop (idx <= blocks), incoherent counter advance across
 * chunk boundaries, and a size_t underflow in the per-iteration length — all of
 * which desynced the keystream on the first non-block-aligned chunk (observed
 * as a freeze right after the multi-chunk Certificate record was "decrypted"
 * into garbage).
 */
static void gcm_ctr_xor(struct tls_aes_context *ctx,
                        const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t *ks = ctx->private.gcm.last_block;
    size_t consumed = ctx->private.gcm.last_block_len;
    size_t i = 0;

    /* 1. Drain any leftover keystream from a previously partial block. */
    if (consumed != 0)
    {
        while (i < len && consumed < AES_BLOCK_SIZE)
        {
            out[i] = in[i] ^ ks[consumed];
            i++;
            consumed++;
        }
        if (consumed == AES_BLOCK_SIZE)
        {
            consumed = 0; /* block fully spent */
        }
        ctx->private.gcm.last_block_len = (uint8_t)consumed;
        if (consumed != 0)
        {
            /* Ran out of input mid-block; leftover keystream stays cached. */
            return;
        }
    }

    /* 2. Generate fresh keystream blocks for the remaining input. */
    aes_prepare_encrypt();
    while (i < len)
    {
        size_t take = MIN((size_t)AES_BLOCK_SIZE, len - i);

        aes_encrypt_block(ctx->iv, ks, ctx);
        increment_iv(ctx->iv, AES_GCM_NONCE_LEN, AES_GCM_CTR_LEN);

        for (size_t j = 0; j < take; j++)
        {
            out[i + j] = in[i + j] ^ ks[j];
        }
        i += take;

        /* If this block was only partially used, remember how much so the next
         * chunk continues from the right keystream offset. */
        ctx->private.gcm.last_block_len =
            (take == AES_BLOCK_SIZE) ? 0 : (uint8_t)take;
    }
}

// CRYPTO_FN
bool tls_aes_encrypt(struct tls_aes_context *ctx, const uint8_t *inbuf, size_t in_len, uint8_t *outbuf)
{
    // int keysize = key->keysize;
    // uint32_t *round_keys = key->round_keys;
    bool ok = false;

    if (inbuf == NULL || outbuf == NULL || ctx == NULL)
        return false;
    if ((in_len == 0) && !(ctx && (ctx->mode == TLS_AES_CCM) && (ctx->private.ccm.msg_len == 0)))
        return false;
    tls_crypto_guard_enable();
    if (ctx->op_assoc == AES_OP_DECRYPT)
        goto cleanup;
    if (ctx->private.gcm.lock > LOCK_ALLOW_ENCRYPT)
        goto cleanup;
    ctx->op_assoc = AES_OP_ENCRYPT;
    uint8_t *iv = ctx->iv;

    switch (ctx->mode)
    {
    case TLS_AES_GCM:
    {
        uint8_t *tag = ctx->private.gcm.auth_tag;

        /* Close the AAD section on first encrypt: zero-pad the cached partial
         * AAD block up to the GHASH boundary before any ciphertext is hashed. */
        if ((ctx->private.gcm.lock == LOCK_ALLOW_ALL) &&
            (ctx->private.gcm.aad_cache_len))
        {
            aes_prepare_ghash();
            uint8_t buf[AES_BLOCK_SIZE] = {0};
            ghash(ctx, tag, buf, AES_BLOCK_SIZE - ctx->private.gcm.aad_cache_len);
        }
        ctx->private.gcm.lock = LOCK_ALLOW_ENCRYPT;

        /* CTR-encrypt this chunk (correctly continues a partial keystream block
         * left over from a previous chunk), then GHASH the produced ciphertext. */
        gcm_ctr_xor(ctx, inbuf, outbuf, in_len);

        if (!tls_aes_update_ciphertext(ctx, outbuf, in_len))
            goto cleanup;
        break;
    }
    case TLS_AES_CBC:
    {
        aes_prepare_encrypt();
        size_t blocks = in_len / AES_BLOCK_SIZE;
        size_t rem = in_len % AES_BLOCK_SIZE;
        for (size_t idx = 0; idx < blocks; idx++)
        {
            aes_xor_buf(inbuf, iv, AES_BLOCK_SIZE);
            aes_encrypt_block(iv, iv, ctx);
            memcpy(outbuf, iv, AES_BLOCK_SIZE);
            inbuf += AES_BLOCK_SIZE;
            outbuf += AES_BLOCK_SIZE;
        }
        if (rem)
        {
            uint8_t byte_to_pad = (uint8_t)(AES_BLOCK_SIZE - rem);
            aes_xor_buf(inbuf, iv, rem);
            for (size_t idx = rem; idx < AES_BLOCK_SIZE; idx++)
            {
                iv[rem] ^= byte_to_pad;
            }
            aes_encrypt_block(iv, iv, ctx);
            memcpy(outbuf, iv, AES_BLOCK_SIZE);
        }
        break;
    }
    case TLS_AES_CCM:
    {
        if (ctx->private.ccm.lock > LOCK_ALLOW_ENCRYPT)
            goto cleanup;
        ctx->private.ccm.lock = LOCK_ALLOW_ENCRYPT;
        if (!ccm_process_message(ctx, inbuf, in_len, outbuf, true))
            goto cleanup;
        break;
    }
    }
    ok = true;
cleanup:
    tls_crypto_guard_disable();
    return ok;
}

// CRYPTO_FN
bool tls_aes_decrypt(struct tls_aes_context *ctx, const uint8_t *inbuf, size_t in_len, uint8_t *outbuf)
{

    if ((ctx == NULL) ||
        (inbuf == NULL) ||
        ((in_len == 0) && !(ctx->mode == TLS_AES_CCM && ctx->private.ccm.msg_len == 0)))
        return false;
    bool ok = false;

    tls_crypto_guard_enable();
    if (ctx->op_assoc == AES_OP_ENCRYPT)
        goto cleanup;
    if (ctx->private.gcm.lock > LOCK_ALLOW_ENCRYPT)
        goto cleanup;
    ctx->op_assoc = AES_OP_DECRYPT;
    uint8_t *iv = ctx->iv;

    switch (ctx->mode)
    {
    case TLS_AES_GCM:
    {
        /* GHASH is computed over the ciphertext (the input), so hash first... */
        if (!tls_aes_update_ciphertext(ctx, inbuf, in_len))
            goto cleanup;

        /* ...then CTR-decrypt into outbuf. Same keystream as encrypt; the helper
         * continues a partial keystream block left over from a previous chunk. */
        if (outbuf)
        {
            gcm_ctr_xor(ctx, inbuf, outbuf, in_len);
        }
        break;
    }
    case TLS_AES_CBC:
    {
        if ((in_len % AES_BLOCK_SIZE) != 0)
            goto cleanup;

        aes_prepare_decrypt();

        uint8_t block_in[AES_BLOCK_SIZE];
        size_t blocks = in_len / AES_BLOCK_SIZE;
        for (size_t idx = 0; idx < blocks; idx++)
        {
            /* Copy into a temporary block buffer in case inbuf == outbuf */
            memcpy(block_in, inbuf, AES_BLOCK_SIZE);
            aes_decrypt_block(block_in, outbuf, ctx);
            aes_xor_buf(iv, outbuf, AES_BLOCK_SIZE);
            memcpy(iv, block_in, AES_BLOCK_SIZE);
            inbuf += AES_BLOCK_SIZE;
            outbuf += AES_BLOCK_SIZE;
        }
        tls_secure_memzero(block_in, sizeof block_in);
        ok = true;
        break;
    }
    case TLS_AES_CCM:
    {
        if (ctx->private.ccm.lock > LOCK_ALLOW_ENCRYPT)
            goto cleanup;
        ctx->private.ccm.lock = LOCK_ALLOW_ENCRYPT;
        if (!ccm_process_message(ctx, inbuf, in_len, outbuf, false))
            goto cleanup;
        ok = true;
        break;
    }
    }
    ok = true;
cleanup:
    tls_crypto_guard_disable();
    return ok;
}

bool tls_aes_verify(struct tls_aes_context *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag)
{
    if ((ctx == NULL) ||
        (ciphertext == NULL) ||
        (ciphertext_len == 0) ||
        (tag == NULL))
        return false;
    if ((ctx->mode != TLS_AES_GCM) && (ctx->mode != TLS_AES_CCM))
        return false;
    if (aad && (aad_len == 0))
        return false;
    struct tls_aes_context tmp;
    uint8_t digest[AES_BLOCK_SIZE];

    // do this work on a copy of ctx
    memcpy(&tmp, ctx, sizeof(tmp));

    if (aad != NULL)
        tls_aes_update_aad(&tmp, aad, aad_len);
    tls_aes_update_ciphertext(&tmp, ciphertext, ciphertext_len);
    tls_aes_digest(&tmp, digest);

    // memset(&tmp, 0, sizeof(tmp));
    bool tag_ok = (ctx->mode == TLS_AES_CCM)
        ? tls_bytes_compare(tag, digest, ctx->private.ccm.tag_len)
        : tls_bytes_compare(tag, digest, AES_BLOCK_SIZE);
    if (!tag_ok)
    {
        ERROR();
    }
    return tag_ok;
}

bool tls_aes_ccm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t pt_len,
                         uint8_t *ciphertext, uint8_t *tag, size_t tag_len)
{
    struct tls_aes_context ctx;
    uint8_t digest[AES_BLOCK_SIZE];

    if ((key == NULL) || (nonce == NULL) || (plaintext == NULL) || (ciphertext == NULL) || (tag == NULL))
        return false;
    if (aad && (aad_len == 0))
        return false;

    if (!tls_aes_ccm_init(&ctx, key, key_len, nonce, nonce_len, (uint8_t)tag_len, pt_len, aad_len))
        return false;
    if (aad_len)
    {
        if (!tls_aes_update_aad(&ctx, aad, aad_len))
            return false;
    }
    if (!tls_aes_encrypt(&ctx, plaintext, pt_len, ciphertext))
        return false;
    if (!tls_aes_digest(&ctx, digest))
        return false;
    memcpy(tag, digest, tag_len);
    tls_secure_memzero(digest, sizeof digest);
    return true;
}

bool tls_aes_ccm_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *tag, size_t tag_len,
                         uint8_t *plaintext)
{
    struct tls_aes_context ctx;
    uint8_t digest[AES_BLOCK_SIZE];
    bool ok = false;

    if ((key == NULL) || (nonce == NULL) || (ciphertext == NULL) || (tag == NULL) || (plaintext == NULL))
        return false;
    if (aad && (aad_len == 0))
        return false;

    if (!tls_aes_ccm_init(&ctx, key, key_len, nonce, nonce_len, (uint8_t)tag_len, ct_len, aad_len))
        return false;
    if (aad_len)
    {
        if (!tls_aes_update_aad(&ctx, aad, aad_len))
            return false;
    }
    if (!tls_aes_decrypt(&ctx, ciphertext, ct_len, plaintext))
        return false;
    if (!tls_aes_digest(&ctx, digest))
        return false;
    ok = tls_bytes_compare(tag, digest, tag_len);
    if (!ok)
    {
        ERROR();
        if (plaintext != ciphertext)
            tls_secure_memzero(plaintext, ct_len);
    }
    tls_secure_memzero(digest, sizeof digest);
    return ok;
}
