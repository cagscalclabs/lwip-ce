
#include <stdint.h>
#include <string.h>
#include "../includes/bytes.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/tls.h"

/* External reference to TLS context for scratch buffers */
extern struct tls_context
{
    uint8_t *rsa_scratch;
    uint8_t *ecc_scratch;
    bool initialized;
} tls_ctx;

#define ENCODE_START 0
#define ENCODE_SALT (1 + ENCODE_START)
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

    /* Check TLS context is initialized */
    if (!tls_ctx.initialized || tls_ctx.rsa_scratch == NULL)
        return false;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        return false;
    size_t min_padding_len = (hash.digestlen << 1) + 2;
    size_t ps_len = modulus_len - in_len - min_padding_len;
    size_t db_len = modulus_len - hash.digestlen - 1;
    size_t encode_lhash = ENCODE_SALT + hash.digestlen;
    size_t encode_ps = encode_lhash + hash.digestlen;
    uint8_t *mgf1_digest = tls_ctx.rsa_scratch; /* Use TLS scratch buffer */

    if ((in_len + min_padding_len) > modulus_len)
        return false;

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
    memcpy(&outbuf[encode_ps + ps_len + 1], inbuf, in_len); // write plaintext to end of output

    // hash the salt with MGF1, return hash length of db
    tls_mgf1(&outbuf[ENCODE_SALT], hash.digestlen, mgf1_digest, db_len, hash_alg);

    // XOR hash with db
    for (size_t i = 0; i < db_len; i++)
        outbuf[encode_lhash + i] ^= mgf1_digest[i];

    // hash db with MGF1, return hash length of RSA_SALT_SIZE
    tls_mgf1(&outbuf[encode_lhash], db_len, mgf1_digest, hash.digestlen, hash_alg);

    // XOR hash with salt
    for (size_t i = 0; i < hash.digestlen; i++)
        outbuf[ENCODE_SALT + i] ^= mgf1_digest[i];

    // Return the static size of 256
    return true;
}

size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg)
{

    if ((in_len > RSA_MODULUS_MAX_SUPPORTED) ||
        (in_len < RSA_MODULUS_MIN_SUPPORTED) ||
        (inbuf == NULL) ||
        (outbuf == NULL))
        return 0;

    /* Check TLS context is initialized */
    if (!tls_ctx.initialized || tls_ctx.rsa_scratch == NULL)
        return 0;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        return false;

    size_t db_len = in_len - hash.digestlen - 1;
    uint8_t sha256_digest[TLS_SHA256_DIGEST_LEN];
    size_t encode_lhash = ENCODE_SALT + hash.digestlen;
    size_t encode_ps = encode_lhash + hash.digestlen;
    size_t i;

    /* Layout: tmp[512] || mgf1_digest[512] */
    uint8_t *tmp = tls_ctx.rsa_scratch;
    uint8_t *mgf1_digest = tmp + RSA_MODULUS_MAX_SUPPORTED;

    memcpy(tmp, inbuf, in_len);

    // Copy last 16 bytes of input buf to salt to get encoded salt
    // memcpy(salt, &in[len-RSA_SALT_SIZE-1], RSA_SALT_SIZE);

    // SHA-256 hash db
    tls_mgf1(&tmp[encode_lhash], db_len, mgf1_digest, hash.digestlen, hash_alg);

    // XOR hash with encoded salt to return salt
    for (i = 0; i < TLS_SHA256_DIGEST_LEN; i++)
        tmp[ENCODE_SALT + i] ^= mgf1_digest[i];

    // MGF1 hash the salt
    tls_mgf1(&tmp[ENCODE_SALT], hash.digestlen, mgf1_digest, db_len, hash_alg);

    // XOR MGF1 of salt with encoded message to get decoded message
    for (i = 0; i < db_len; i++)
        tmp[encode_lhash + i] ^= mgf1_digest[i];

    // verify authentication
    if (auth != NULL)
        hash.update(&hash._private, (const uint8_t *)auth, strlen(auth));
    hash.digest(&hash._private, sha256_digest);

    if (!tls_bytes_compare(sha256_digest, &tmp[encode_lhash], TLS_SHA256_DIGEST_LEN))
        return 0;

    for (i = encode_ps; i < in_len; i++)
        if (tmp[i] == 0x01)
            break;
    if (i == in_len)
        return false;
    i++;
    memcpy(outbuf, &tmp[i], in_len - i);

    return in_len - i;
}

void powmod_exp_u24(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
#define RSA_PUBLIC_EXP 65537
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

    while (pubkey[spos] == 0)
    {
        outbuf[spos++] = 0;
    }
    if (!tls_rsa_encode_oaep(inbuf, in_len, &outbuf[spos], keylen - spos, NULL, hash_alg))
        return false;
    powmod_exp_u24((uint8_t)keylen, outbuf, RSA_PUBLIC_EXP, pubkey);
    return true;
}

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

    memcpy(outbuf, signature, keylen);
    powmod_exp_u24((uint8_t)keylen, outbuf, RSA_PUBLIC_EXP, pubkey);
    return true;
}

/**
 * @brief Verify RSA-PSS padding on an already-decrypted signature.
 *
 * This function verifies that the encoded message (EM) matches the expected
 * PSS padding structure for the given message hash. It does NOT perform
 * RSA modular exponentiation - the caller must decrypt the signature first.
 *
 * Uses internal TLS scratch buffer for temporary computations.
 * em_bits is derived internally as (em_len * 8) - 1.
 *
 * @param encoded_msg   The decrypted signature (EM), big-endian, emLen bytes
 * @param em_len        Length of encoded message in bytes (same as modulus length)
 * @param mhash         Hash of the message being verified
 * @param mhash_len     Length of mhash (must equal hash digest length)
 * @param hash_alg      Hash algorithm ID (TLS_HASH_SHA256, etc.)
 * @return true if PSS padding is valid, false otherwise
 */
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

    /* Check TLS context is initialized */
    if (!tls_ctx.initialized || tls_ctx.rsa_scratch == NULL)
        return false;

    struct tls_hash_context hash;
    if (!tls_hash_context_init(&hash, hash_alg))
        return false;
    if (mhash_len != hash.digestlen)
        return false; /* enforce TLS 1.3 salt length rule */

    size_t db_len = em_len - hash.digestlen - 1;

    /* Use TLS scratch buffer: db_mask[em_len] || tmp[72] */
    uint8_t *db_mask = tls_ctx.rsa_scratch;
    uint8_t *tmp = db_mask + em_len;

    /* Copy EM to db_mask buffer for in-place modification */
    uint8_t *em = db_mask; /* will hold DB after unmasking */
    memcpy(em, encoded_msg, em_len);

    /* RFC 8017: Verify unused bits are zero */
    uint8_t unused = (uint8_t)(em_len * 8 - em_bits);
    if (unused > 8 || unused == 0)
        return false;
    uint8_t top_mask = (uint8_t)(0xFFu >> unused);

    if ((em[0] & ~top_mask) != 0)
        return false;
    em[0] &= top_mask;

    /* Verify 0xBC trailer */
    if (em[em_len - 1] != 0xBC)
        return false;

    /* Extract H and DB pointers */
    uint8_t *H = &em[em_len - 1 - hash.digestlen];
    uint8_t *DB = em;

    /* Unmask DB: maskedDB XOR MGF(H, dbLen) */
    if (!tls_mgf1(H, hash.digestlen, tmp, db_len, hash_alg))
        return false;
    for (size_t i = 0; i < db_len; i++)
        DB[i] ^= tmp[i];
    DB[0] &= top_mask;

    /* Verify padding structure: 0x00...00 || 0x01 || salt */
    size_t ps_end = 0;
    while (ps_end < db_len && DB[ps_end] == 0)
        ps_end++;
    if (ps_end >= db_len || DB[ps_end] != 0x01)
        return false;
    ps_end++;

    /* TLS 1.3 requires salt length == hash length */
    if (db_len - ps_end != hash.digestlen)
        return false;
    uint8_t *salt = &DB[ps_end];

    /* Compute H' = Hash(0x00*8 || mHash || salt) */
    memset(tmp, 0, 8);
    memcpy(&tmp[8], mhash, hash.digestlen);
    memcpy(&tmp[8 + hash.digestlen], salt, hash.digestlen);

    hash.update(&hash._private, tmp, 8 + (hash.digestlen << 1));
    hash.digest(&hash._private, tmp); /* write H' to tmp */

    /* Verify H' == H */
    return tls_bytes_compare(tmp, H, hash.digestlen);
}
