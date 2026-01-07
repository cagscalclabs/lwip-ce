/**
 * @file hkdf.c
 * @brief HMAC-based Key Derivation Function (HKDF) - RFC 5869
 *
 * Implementation of HKDF for TLS 1.3 key derivation.
 */

#include "../includes/hkdf.h"
#include "../includes/hmac.h"
#include "../includes/hash.h"
#include <string.h>

/**
 * @brief Get hash output length for algorithm
 */
static size_t get_hash_length(uint8_t hash_algorithm) {
    switch (hash_algorithm) {
        case TLS_HASH_SHA256:
            return 32;
        default:
            return 0;
    }
}

/**
 * @brief HKDF-Extract: Extract a fixed-length pseudorandom key
 *
 * RFC 5869:
 *   HKDF-Extract(salt, IKM) -> PRK
 *   PRK = HMAC-Hash(salt, IKM)
 *
 * If salt is NULL or zero-length, use HashLen zero bytes.
 */
bool tls_hkdf_extract(
    uint8_t hash_algorithm,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk
) {
    struct tls_hmac_context ctx;
    size_t hash_len = get_hash_length(hash_algorithm);

    if (hash_len == 0 || !ikm || !prk) {
        return false;
    }

    /* If no salt provided, use hash_len zeros */
    uint8_t zero_salt[32] = {0};  /* Max hash length */
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = hash_len;
    }

    /* PRK = HMAC(salt, ikm) */
    if (!tls_hmac_context_init(&ctx, hash_algorithm, salt, salt_len)) {
        return false;
    }

    tls_hmac_update(&ctx, ikm, ikm_len);
    tls_hmac_digest(&ctx, prk);

    return true;
}

/**
 * @brief HKDF-Expand: Expand PRK to desired length
 *
 * RFC 5869:
 *   HKDF-Expand(PRK, info, L) -> OKM
 *
 *   N = ceil(L/HashLen)
 *   T = T(1) | T(2) | ... | T(N)
 *   OKM = first L octets of T
 *
 *   where:
 *   T(0) = empty string
 *   T(1) = HMAC(PRK, T(0) | info | 0x01)
 *   T(2) = HMAC(PRK, T(1) | info | 0x02)
 *   ...
 *   T(N) = HMAC(PRK, T(N-1) | info | N)
 */
bool tls_hkdf_expand(
    uint8_t hash_algorithm,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len
) {
    struct tls_hmac_context ctx;
    size_t hash_len = get_hash_length(hash_algorithm);
    uint8_t t_prev[32];  /* Previous T(i) */
    uint8_t counter;
    size_t n, i;
    size_t offset = 0;

    if (hash_len == 0 || !prk || !okm) {
        return false;
    }

    /* Check okm_len is not too large: max = 255 * HashLen */
    if (okm_len > 255 * hash_len) {
        return false;
    }

    /* Calculate N = ceil(okm_len / hash_len) */
    n = (okm_len + hash_len - 1) / hash_len;

    /* Generate T(1) through T(N) */
    for (i = 1; i <= n; i++) {
        counter = (uint8_t)i;

        /* Initialize HMAC with PRK */
        if (!tls_hmac_context_init(&ctx, hash_algorithm, prk, prk_len)) {
            return false;
        }

        /* T(i) = HMAC(PRK, T(i-1) | info | i) */
        if (i > 1) {
            /* Add T(i-1) */
            tls_hmac_update(&ctx, t_prev, hash_len);
        }

        /* Add info */
        if (info && info_len > 0) {
            tls_hmac_update(&ctx, info, info_len);
        }

        /* Add counter byte */
        tls_hmac_update(&ctx, &counter, 1);

        /* Compute T(i) */
        tls_hmac_digest(&ctx, t_prev);

        /* Copy to output (possibly partial on last iteration) */
        size_t to_copy = hash_len;
        if (offset + to_copy > okm_len) {
            to_copy = okm_len - offset;
        }
        memcpy(okm + offset, t_prev, to_copy);
        offset += to_copy;
    }

    return true;
}

/**
 * @brief HKDF-Expand-Label: TLS 1.3 specific key derivation
 *
 * RFC 8446 Section 7.1:
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *       HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   Where HkdfLabel is:
 *   struct {
 *       uint16 length = Length;
 *       opaque label<7..255> = "tls13 " + Label;
 *       opaque context<0..255> = Context;
 *   } HkdfLabel;
 */
bool tls_hkdf_expand_label(
    uint8_t hash_algorithm,
    const uint8_t *secret,
    size_t secret_len,
    const char *label,
    size_t label_len,
    const uint8_t *context,
    size_t context_len,
    uint8_t *out,
    size_t out_len
) {
    uint8_t hkdf_label[512];  /* Buffer for HkdfLabel structure */
    size_t offset = 0;
    const char *tls13_prefix = "tls13 ";
    size_t prefix_len = 6;
    size_t full_label_len = prefix_len + label_len;

    if (!secret || !label || !out) {
        return false;
    }

    /* Check label length: "tls13 " + label must be 7..255 bytes */
    if (full_label_len < 7 || full_label_len > 255) {
        return false;
    }

    /* Check context length: 0..255 bytes */
    if (context_len > 255) {
        return false;
    }

    /* Build HkdfLabel structure:
     * struct {
     *     uint16 length;           // big-endian
     *     opaque label<7..255>;    // length byte + data
     *     opaque context<0..255>;  // length byte + data
     * }
     */

    /* uint16 length (big-endian) */
    hkdf_label[offset++] = (uint8_t)(out_len >> 8);
    hkdf_label[offset++] = (uint8_t)(out_len & 0xFF);

    /* opaque label<7..255> */
    hkdf_label[offset++] = (uint8_t)full_label_len;
    memcpy(hkdf_label + offset, tls13_prefix, prefix_len);
    offset += prefix_len;
    memcpy(hkdf_label + offset, label, label_len);
    offset += label_len;

    /* opaque context<0..255> */
    hkdf_label[offset++] = (uint8_t)context_len;
    if (context && context_len > 0) {
        memcpy(hkdf_label + offset, context, context_len);
        offset += context_len;
    }

    /* Call HKDF-Expand with constructed HkdfLabel as info */
    return tls_hkdf_expand(
        hash_algorithm,
        secret,
        secret_len,
        hkdf_label,
        offset,
        out,
        out_len
    );
}

/**
 * @brief Derive-Secret: TLS 1.3 transcript-based key derivation
 *
 * RFC 8446 Section 7.1:
 *   Derive-Secret(Secret, Label, Messages) =
 *       HKDF-Expand-Label(Secret, Label,
 *                         Transcript-Hash(Messages), Hash.length)
 */
bool tls_derive_secret(
    uint8_t hash_algorithm,
    const uint8_t *secret,
    size_t secret_len,
    const char *label,
    size_t label_len,
    const uint8_t *transcript_hash,
    size_t transcript_hash_len,
    uint8_t *out
) {
    size_t hash_len = get_hash_length(hash_algorithm);

    if (hash_len == 0 || transcript_hash_len != hash_len) {
        return false;
    }

    return tls_hkdf_expand_label(
        hash_algorithm,
        secret,
        secret_len,
        label,
        label_len,
        transcript_hash,
        transcript_hash_len,
        out,
        hash_len
    );
}
