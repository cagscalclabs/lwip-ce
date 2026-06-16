
#include <stdint.h>
#include <string.h>
#include "../includes/bytes.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/crypto_guard.h"

#define TLS_SCRATCH_SIZE 520u
extern uint8_t __tls_scratch[TLS_SCRATCH_SIZE];

/* Temporary RSA decrypt tracing (key-gated). Set RSA_TRACE_ON 1 to
 * re-enable. Superseded by the TLS debug callback (tls_debug.h). */
#define RSA_TRACE_ON 0
#if RSA_TRACE_ON
#include <ti/screen.h>
#include <ti/getkey.h>
#define RSA_TRACE(msg) do { os_ClrHome(); os_PutStrFull(msg); \
                            os_PutStrFull(" [key]"); os_GetKey(); } while (0)
#else
#define RSA_TRACE(msg) ((void)0)
#endif

#define ENCODE_START 0
#define ENCODE_SALT (1 + ENCODE_START)

static bool rsa_buffers_overlap(const void *a, size_t a_len,
                                const void *b, size_t b_len)
{
    uintptr_t a_start = (uintptr_t)a;
    uintptr_t b_start = (uintptr_t)b;
    uintptr_t a_end = a_start + a_len;
    uintptr_t b_end = b_start + b_len;

    return a_len != 0 && b_len != 0 && a_start < b_end && b_start < a_end;
}

static bool rsa_mgf1_digest(const uint8_t *seed, size_t seed_len,
                            uint32_t counter, uint8_t *digest,
                            size_t *digest_len, uint8_t hash_alg)
{
    struct tls_hash_context hash;
    uint8_t ctr[4];

    if (!tls_hash_context_init(&hash, hash_alg))
        return false;
    if (hash.digestlen > TLS_SHA256_DIGEST_LEN)
        return false;

    ctr[0] = (uint8_t)(counter >> 24);
    ctr[1] = (uint8_t)(counter >> 16);
    ctr[2] = (uint8_t)(counter >> 8);
    ctr[3] = (uint8_t)counter;

    hash.update(&hash._private, seed, seed_len);
    hash.update(&hash._private, ctr, sizeof(ctr));
    hash.digest(&hash._private, digest);
    *digest_len = hash.digestlen;
    return true;
}

static bool rsa_mgf1_xor(uint8_t *buf, size_t len,
                         const uint8_t *seed, size_t seed_len,
                         uint8_t hash_alg)
{
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    size_t digest_len = 0;
    uint32_t counter = 0;
    size_t off = 0;

    while (off < len)
    {
        if (!rsa_mgf1_digest(seed, seed_len, counter++, digest, &digest_len, hash_alg))
            return false;
        size_t chunk = len - off;
        if (chunk > digest_len)
            chunk = digest_len;
        for (size_t i = 0; i < chunk; i++)
            buf[off + i] ^= digest[i];
        off += chunk;
    }
    return true;
}

// CRYPTO_FN
bool tls_rsa_encode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                         size_t modulus_len, const char *auth, uint8_t hash_alg)
{
    // initial sanity checks
    if ((modulus_len > RSA_MODULUS_MAX_SUPPORTED) ||
        (modulus_len < RSA_MODULUS_MIN_SUPPORTED) ||
        (inbuf == NULL) ||
        (outbuf == NULL) ||
        (in_len == 0))
        return false;

    tls_crypto_guard_enable();
    bool ok = false;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        goto cleanup;
    size_t min_padding_len = (hash.digestlen << 1) + 2;
    size_t ps_len = modulus_len - in_len - min_padding_len;
    size_t db_len = modulus_len - hash.digestlen - 1;
    size_t encode_lhash = ENCODE_SALT + hash.digestlen;
    size_t encode_ps = encode_lhash + hash.digestlen;

    if ((in_len + min_padding_len) > modulus_len)
        goto cleanup;
    if (inbuf != outbuf && rsa_buffers_overlap(inbuf, in_len, outbuf, modulus_len))
        goto cleanup;

    size_t msg_offset = encode_ps + ps_len + 1;
    /* Exact in-place encode is allowed. Move the plaintext to its final
     * OAEP location before writing the leading fields that would overwrite it. */
    memmove(&outbuf[msg_offset], inbuf, in_len);

    // set first byte to 00
    outbuf[ENCODE_START] = 0x00;
    // seed next 32 bytes
    tls_random_bytes(&outbuf[ENCODE_SALT], hash.digestlen);

    // hash the authentication string
    if (auth != NULL)
        hash.update(&hash._private, (const uint8_t *)auth, strlen(auth));
    hash.digest(&hash._private, &outbuf[encode_lhash]); // nothing to actually hash

    memset(&outbuf[encode_ps], 0, ps_len);                  // write padding zeros
    outbuf[encode_ps + ps_len] = 0x01;                      // write 0x01

    // XOR MGF1(seed) with DB in place.
    if (!rsa_mgf1_xor(&outbuf[encode_lhash], db_len,
                      &outbuf[ENCODE_SALT], hash.digestlen, hash_alg))
        goto cleanup;

    // XOR MGF1(maskedDB) with seed in place.
    if (!rsa_mgf1_xor(&outbuf[ENCODE_SALT], hash.digestlen,
                      &outbuf[encode_lhash], db_len, hash_alg))
        goto cleanup;

    // Return the static size of 256
    ok = true;
cleanup:
    tls_crypto_guard_disable();
    return ok;
}

// CRYPTO_FN
size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg)
{
    if ((in_len > RSA_MODULUS_MAX_SUPPORTED) ||
        (in_len < RSA_MODULUS_MIN_SUPPORTED) ||
        (inbuf == NULL) ||
        (outbuf == NULL))
        return 0;
    if (inbuf != outbuf && rsa_buffers_overlap(inbuf, in_len, outbuf, in_len))
        return 0;

    tls_crypto_guard_enable();
    size_t out_len = 0;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        goto cleanup;

    size_t db_len = in_len - hash.digestlen - 1;
    uint8_t sha256_digest[TLS_SHA256_DIGEST_LEN];
    uint8_t seed[TLS_SHA256_DIGEST_LEN];
    uint8_t mgf_block[TLS_SHA256_DIGEST_LEN];
    size_t mgf_len = 0;
    uint32_t counter = 0;
    size_t masked_db = ENCODE_SALT + hash.digestlen;
    bool have_delimiter = false;

    if (hash.digestlen > sizeof(seed))
        goto cleanup;
    if (inbuf[ENCODE_START] != 0)
        goto cleanup;

    memcpy(seed, &inbuf[ENCODE_SALT], hash.digestlen);
    if (!rsa_mgf1_xor(seed, hash.digestlen, &inbuf[masked_db], db_len, hash_alg))
        goto cleanup;

    // verify authentication
    if (auth != NULL)
        hash.update(&hash._private, (const uint8_t *)auth, strlen(auth));
    hash.digest(&hash._private, sha256_digest);

    for (size_t i = 0; i < db_len; i++)
    {
        if ((i % hash.digestlen) == 0)
        {
            if (!rsa_mgf1_digest(seed, hash.digestlen, counter++,
                                 mgf_block, &mgf_len, hash_alg))
                goto cleanup;
        }

        uint8_t db = inbuf[masked_db + i] ^ mgf_block[i % hash.digestlen];
        if (i < hash.digestlen)
        {
            if (db != sha256_digest[i])
                goto cleanup;
            continue;
        }
        if (!have_delimiter)
        {
            if (db == 0)
                continue;
            if (db != 0x01)
                goto cleanup;
            have_delimiter = true;
            continue;
        }
        outbuf[out_len++] = db;
    }

    if (!have_delimiter)
        goto cleanup;
cleanup:
    tls_crypto_guard_disable();
    return out_len;
}

void powmod_exp_u24(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
#define RSA_PUBLIC_EXP 65537
// CRYPTO_FN
bool tls_rsa_encrypt(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                     const uint8_t *pubkey, size_t keylen, uint8_t hash_alg)
{
    size_t spos = 0;
    if ((inbuf == NULL) ||
        (pubkey == NULL) ||
        (outbuf == NULL) ||
        (in_len == 0) ||
        (keylen > RSA_MODULUS_MAX_SUPPORTED) ||
        (keylen < RSA_MODULUS_MIN_SUPPORTED) ||
        (!(pubkey[keylen - 1] & 1)))
        return false;

    tls_crypto_guard_enable();
    bool ok = false;

    while (pubkey[spos] == 0)
    {
        outbuf[spos++] = 0;
    }
    if (!tls_rsa_encode_oaep(inbuf, in_len, &outbuf[spos], keylen - spos, NULL, hash_alg))
        goto cleanup;
    powmod_exp_u24((uint8_t)keylen, outbuf, RSA_PUBLIC_EXP, pubkey);
    tls_secure_memzero(__tls_scratch, TLS_SCRATCH_SIZE);
    ok = true;
cleanup:
    tls_crypto_guard_disable();
    return ok;
}

// CRYPTO_FN
bool tls_rsa_decrypt_signature(const uint8_t *signature,
                               size_t signature_len,
                               uint8_t *outbuf,
                               const uint8_t *pubkey,
                               size_t keylen)
{
    if ((signature == NULL) ||
        (pubkey == NULL) ||
        (outbuf == NULL) ||
        (signature_len == 0) ||
        (keylen > RSA_MODULUS_MAX_SUPPORTED) ||
        (keylen < RSA_MODULUS_MIN_SUPPORTED) ||
        (!(pubkey[keylen - 1] & 1)))
        return false;

    RSA_TRACE("decsig: pre-guard");
    tls_crypto_guard_enable();
    bool ok = false;

    memcpy(outbuf, signature, keylen);
    tls_crypto_guard_disable();
    RSA_TRACE("decsig: pre-powmod");
    tls_crypto_guard_enable();
    powmod_exp_u24((uint8_t)keylen, outbuf, RSA_PUBLIC_EXP, pubkey);
    tls_secure_memzero(__tls_scratch, TLS_SCRATCH_SIZE);
    ok = true;
    tls_crypto_guard_disable();
    RSA_TRACE("decsig: post-powmod");
    return ok;
}

bool tls_rsa_decrypt_signature_exp(const uint8_t *signature,
                                   size_t signature_len,
                                   uint8_t *outbuf,
                                   uint24_t exp,
                                   const uint8_t *pubkey,
                                   size_t keylen)
{
    if ((signature == NULL) ||
        (pubkey == NULL) ||
        (outbuf == NULL) ||
        (signature_len == 0) ||
        (keylen > RSA_MODULUS_MAX_SUPPORTED) ||
        (keylen < RSA_MODULUS_MIN_SUPPORTED) ||
        (!(pubkey[keylen - 1] & 1)) ||
        (exp == 0))
        return false;

    tls_crypto_guard_enable();
    bool ok = false;

    memcpy(outbuf, signature, keylen);
    tls_crypto_guard_disable();
    tls_crypto_guard_enable();
    powmod_exp_u24((uint8_t)keylen, outbuf, exp, pubkey);
    tls_secure_memzero(__tls_scratch, TLS_SCRATCH_SIZE);
    ok = true;
    tls_crypto_guard_disable();
    return ok;
}

/**
 * @brief Verify RSA-PSS padding on an already-decrypted signature.
 *
 * This function verifies that the encoded message (EM) matches the expected
 * PSS padding structure for the given message hash. It does NOT perform
 * RSA modular exponentiation - the caller must decrypt the signature first.
 *
 * Uses only fixed-size local scratch buffers.
 * em_bits is derived internally as (em_len * 8) - 1.
 *
 * @param encoded_msg   The decrypted signature (EM), big-endian, emLen bytes
 * @param em_len        Length of encoded message in bytes (same as modulus length)
 * @param mhash         Hash of the message being verified
 * @param mhash_len     Length of mhash (must equal hash digest length)
 * @param hash_alg      Hash algorithm ID (TLS_HASH_SHA256, etc.)
 * @return true if PSS padding is valid, false otherwise
 */
// CRYPTO_FN
bool tls_rsa_pss_verify(const uint8_t *encoded_msg, size_t em_len,
                        const uint8_t *mhash, size_t mhash_len,
                        uint8_t hash_alg)
{
    if (encoded_msg == NULL || mhash == NULL)
        return false;
    if (em_len == 0)
        return false;

    /* Derive em_bits from em_len: modBits - 1 */
    uint16_t em_bits = (uint16_t)((em_len * 8) - 1);

    tls_crypto_guard_enable();
    bool ok = false;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        goto cleanup;
    if (mhash_len != hash.digestlen)
        goto cleanup; /* enforce TLS 1.3 salt length rule */

    size_t db_len = em_len - hash.digestlen - 1;
    if (db_len <= hash.digestlen)
        goto cleanup;

    /* RFC 8017: Verify unused bits are zero */
    uint8_t unused = (uint8_t)(em_len * 8 - em_bits);
    if (unused > 8 || unused == 0)
        goto cleanup;
    uint8_t top_mask = (uint8_t)(0xFFu >> unused);

    if ((encoded_msg[0] & ~top_mask) != 0)
        goto cleanup;

    /* Verify 0xBC trailer */
    if (encoded_msg[em_len - 1] != 0xBC)
        goto cleanup;

    const uint8_t *H = &encoded_msg[em_len - 1 - hash.digestlen];
    uint8_t mgf_block[TLS_SHA256_DIGEST_LEN];
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    uint8_t zeros[8] = {0};
    size_t mgf_len = 0;
    uint32_t counter = 0;
    size_t sep_index = db_len - hash.digestlen - 1;

    if (hash.digestlen > sizeof(mgf_block))
        goto cleanup;

    hash.update(&hash._private, zeros, sizeof(zeros));
    hash.update(&hash._private, mhash, hash.digestlen);

    /* Decode DB byte-by-byte as maskedDB XOR MGF1(H). TLS 1.3 fixes
     * salt length to hLen, so the 0x01 separator has one valid position. */
    for (size_t i = 0; i < db_len; i++)
    {
        if ((i % hash.digestlen) == 0)
        {
            if (!rsa_mgf1_digest(H, hash.digestlen, counter++,
                                 mgf_block, &mgf_len, hash_alg))
                goto cleanup;
        }

        uint8_t db = encoded_msg[i] ^ mgf_block[i % hash.digestlen];
        if (i == 0)
            db &= top_mask;

        if (i < sep_index)
        {
            if (db != 0)
                goto cleanup;
        }
        else if (i == sep_index)
        {
            if (db != 0x01)
                goto cleanup;
        }
        else
        {
            hash.update(&hash._private, &db, 1);
        }
    }

    hash.digest(&hash._private, digest);

    /* Verify H' == H */
    ok = tls_bytes_compare(digest, H, hash.digestlen);
cleanup:
    tls_crypto_guard_disable();
    return ok;
}
