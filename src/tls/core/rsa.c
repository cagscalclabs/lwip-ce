
#include <stdint.h>
#include <string.h>
#include "../includes/bytes.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/tls.h"

/* External reference to TLS context for scratch buffers */
extern struct tls_context {
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
    uint8_t *mgf1_digest = tls_ctx.rsa_scratch;  /* Use TLS scratch buffer */

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
        (keylen < RSA_MODULUS_MAX_SUPPORTED) ||
        (keylen > RSA_MODULUS_MIN_SUPPORTED) ||
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

/* internal: count significant bits in big-endian modulus */
static uint16_t tls_rsa_mod_bitlen(const uint8_t *mod, size_t mod_len)
{
    size_t i = 0;
    while (i < mod_len && mod[i] == 0)
        i++;
    if (i == mod_len)
        return 0;
    uint8_t msb = mod[i];
    uint8_t bits = 8;
    while (bits && ((msb >> (bits - 1)) == 0))
        bits--;
    return (uint16_t)((mod_len - i - 1) * 8 + bits);
}

/* big-endian comparison: returns -1,0,1 */
static int tls_big_cmp_be(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (a[i] != b[i])
            return (a[i] > b[i]) ? 1 : -1;
    }
    return 0;
}

/* big-endian subtract: assumes a >= b, stores into a */
static void tls_big_sub_be(uint8_t *a, const uint8_t *b, size_t len)
{
    int borrow = 0;
    for (size_t i = 0; i < len; i++)
    {
        size_t idx = len - 1 - i;
        int diff = (int)a[idx] - (int)b[idx] - borrow;
        if (diff < 0)
        {
            diff += 256;
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }
        a[idx] = (uint8_t)diff;
    }
}

/* shift remainder left by 8 and add byte */
static void tls_big_shift8_add(uint8_t *r, size_t len, uint8_t byte)
{
    memmove(r, r + 1, len - 1);
    r[len - 1] = byte;
}

/* shift-left by one byte (8 bits) modulo mod (all big-endian, len bytes) */
static void tls_big_lshift8_mod(uint8_t *val, const uint8_t *mod, size_t len)
{
    uint16_t carry = 0;
    for (size_t i = 0; i < len; i++)
    {
        size_t idx = len - 1 - i;
        uint16_t v = ((uint16_t)val[idx] << 8) | carry;
        val[idx] = (uint8_t)v;
        carry = (uint8_t)(v >> 8);
    }
    if (tls_big_cmp_be(val, mod, len) >= 0)
        tls_big_sub_be(val, mod, len);
}

/* Compute (a * b) mod mod (all big-endian, same length).
 * scratch: prod[2*len] || rem[len]
 */
static void tls_big_mul_mod_be(const uint8_t *a, const uint8_t *b, size_t len,
                               const uint8_t *mod, uint8_t *out,
                               uint8_t *scratch)
{
    uint8_t *prod = scratch;
    uint8_t *rem = prod + (len << 1);
    memset(prod, 0, (len << 1));
    /* schoolbook mul */
    for (size_t i = 0; i < len; i++)
    {
        uint32_t carry = 0;
        uint8_t ai = a[len - 1 - i];
        for (size_t j = 0; j < len; j++)
        {
            size_t idx = (len << 1) - 1 - (i + j);
            uint32_t sum = (uint32_t)prod[idx] + (uint32_t)ai * b[len - 1 - j] + carry;
            prod[idx] = (uint8_t)sum;
            carry = sum >> 8;
        }
        size_t k = (len << 1) - 1 - (i + len);
        while (carry)
        {
            uint32_t sum = (uint32_t)prod[k] + carry;
            prod[k] = (uint8_t)sum;
            carry = sum >> 8;
            if (k == 0)
                break;
            k--;
        }
    }
    /* modulo via long division */
    memset(rem, 0, len);
    for (size_t idx = 0; idx < (len << 1); idx++)
    {
        tls_big_shift8_add(rem, len, prod[idx]);
        while (tls_big_cmp_be(rem, mod, len) >= 0)
        {
            tls_big_sub_be(rem, mod, len);
        }
    }
    memcpy(out, rem, len);
}

/* Compute base^65537 mod modulus using square-and-multiply.
 * All inputs/outputs are big-endian.
 * scratch layout: prod[2*len] || rem[len] || x[len] || tmp[len]
 * scratch_len must be >= 5*len
 */
static bool tls_modexp65537_be(const uint8_t *base, const uint8_t *mod, size_t len,
                               uint8_t *out, uint8_t *scratch, size_t scratch_len)
{
    size_t need = len * 5; /* prod(2*len) + rem(len) + x(len) + tmp(len) */
    if (scratch_len < need || len == 0)
        return false;

    uint8_t *mul_scratch = scratch;   /* 3*len for tls_big_mul_mod_be */
    uint8_t *x = scratch + (len * 3); /* accumulator */
    uint8_t *tmp = x + len;           /* temporary for squaring */

    /* x = base mod modulus (in case base >= mod) */
    memcpy(x, base, len);
    if (tls_big_cmp_be(x, mod, len) >= 0)
    {
        /* reduce base modulo mod - use tmp for remainder computation */
        uint8_t *rem = tmp;
        memset(rem, 0, len);
        for (size_t idx = 0; idx < len; idx++)
        {
            tls_big_shift8_add(rem, len, x[idx]);
            while (tls_big_cmp_be(rem, mod, len) >= 0)
                tls_big_sub_be(rem, mod, len);
        }
        memcpy(x, rem, len);
    }

    /* 65537 = 0x10001 = 2^16 + 1
     * Compute: x = base^(2^16) mod n, then x = x * base mod n
     */

    /* Square 16 times: x = base^(2^16) mod n */
    for (int i = 0; i < 16; i++)
    {
        tls_big_mul_mod_be(x, x, len, mod, tmp, mul_scratch);
        memcpy(x, tmp, len);
    }

    /* Multiply by base: x = x * base mod n */
    tls_big_mul_mod_be(x, base, len, mod, tmp, mul_scratch);
    memcpy(out, tmp, len);

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
 *
 * @param encoded_msg   The decrypted signature (EM), big-endian, emLen bytes
 * @param em_len        Length of encoded message in bytes (same as modulus length)
 * @param em_bits       Length of encoded message in bits (modBits - 1)
 * @param mhash         Hash of the message being verified
 * @param mhash_len     Length of mhash (must equal hash digest length)
 * @param hash_alg      Hash algorithm ID (TLS_HASH_SHA256, etc.)
 * @return true if PSS padding is valid, false otherwise
 */
bool tls_rsa_pss_verify(const uint8_t *encoded_msg, size_t em_len, uint16_t em_bits,
                        const uint8_t *mhash, size_t mhash_len,
                        uint8_t hash_alg)
{
    if (encoded_msg == NULL || mhash == NULL)
        return false;
    if (em_len == 0 || em_bits == 0)
        return false;

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
