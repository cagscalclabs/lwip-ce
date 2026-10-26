/**
 * @file hmac.h
 * @author Anthony Cagliano
 * @brief Hash-independent HMAC construction.
 * @license: GNU GPL v3.0
 * @reference: RFC 2104
 * @reference: RFC 4231
 */

#ifndef tls_hmac_h
#define tls_hmac_h

#include "hash.h"

/** @struct Defines HMAC context. */
struct tls_hmac_context
{
    uint8_t digestlen;
    uint8_t blocklen;
    void (*update)(struct tls_hmac_context *ctx, const uint8_t *data, size_t len);
    void (*digest)(struct tls_hmac_context *ctx, uint8_t *digest);
    struct tls_hash_context _inner;
    union tls_hash_state _outer; /**< state after processing the outer padded key */
};

/***************************************************************************
 * @brief Initializes an HMAC context to the the specified hash algorithm.
 * @param ctx       Pointer to an HMAC context to initialize.
 * @param algorithm     One of \p _hash_algorithms .
 * @param key       Pointer to a key to initialize with.
 * @param keylen    Length of key.
 * @returns @b true if success, @b false if error.
 */
bool tls_hmac_context_init(struct tls_hmac_context *ctx, uint8_t algorithm,
                           const uint8_t *key, size_t keylen);

/***************************************************************************
 * @brief Updates an HMAC context for data.
 * @param ctx       Pointer to a HMAC context to update.
 * @param data     Pointer to data to hash.
 * @param len       Length of data to hash.
 * @note A more object-oriented call style may be used. @code ctx.update(&ctx, data, len) @endcode.
 */
void tls_hmac_update(struct tls_hmac_context *ctx, const uint8_t *data, size_t len);

/***************************************************************************
 * @brief Returns an HMAC digest from the context state.
 * @param ctx       Pointer to an HMAC context.
 * @param digest     Pointer to buffer to write digest to.
 * @note A more object-oriented call style may be used. @code ctx.digest(&ctx, digest) @endcode.
 */
void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *digest);

/***************************************************************************
 * @brief Securely clears an HMAC context.
 * @param ctx       Pointer to the HMAC context to clear. May be NULL.
 * @note Call when the context is no longer needed to erase the key-derived
 *       inner/outer hash states.
 */
void tls_hmac_clear(struct tls_hmac_context *ctx);

#endif
