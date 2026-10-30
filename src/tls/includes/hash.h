/**
 * @file hash.h
 * @author Anthony Cagliano
 * @author Adam Beckingham
 * @brief SHA-256 and SHA-384 implementation
 *
 */
//
//  hashes.h
//
//
//  Created by Anthony Cagliano on 7/11/24.
//

#ifndef tls_hash_h
#define tls_hash_h

#include <stdbool.h>
#include <stdint.h>

/** @def Defines digest length of SHA-256. */
#define TLS_SHA256_DIGEST_LEN 32
#define TLS_SHA256_BLOCK_LEN 64

/** @def Defines digest and block length of SHA-384. */
#define TLS_SHA384_DIGEST_LEN 48
#define TLS_SHA384_BLOCK_LEN 128

/* Largest block and digest among the hash backends compiled into this build.
 * Increase these when registering a backend with larger parameters. */
#define TLS_HASH_MAX_BLOCK_LEN TLS_SHA384_BLOCK_LEN
#define TLS_HASH_MAX_DIGEST_LEN TLS_SHA384_DIGEST_LEN

/** @enum Implemented hash algorithms. */
enum _hash_algorithms
{
    TLS_HASH_SHA256,
    TLS_HASH_SHA384,
    //  TLS_HASH_SHA256HW
};

/** @struct Defines context structure for SHA-256. */
struct tls_sha256_context
{
    uint8_t data[64];
    uint8_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
};

/** init, update, and digest functions for SHA-256. */
bool tls_sha256_init(struct tls_sha256_context *ctx);
void tls_sha256_update(struct tls_sha256_context *ctx, const uint8_t *data, size_t len);
void tls_sha256_digest(struct tls_sha256_context *ctx, uint8_t *digest);

/** @struct Defines context structure for SHA-384. */
struct tls_sha384_context
{
    uint8_t data[TLS_SHA384_BLOCK_LEN];
    uint8_t datalen;
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
    uint64_t state[8];
};

/** init, update, and digest functions for SHA-384. */
bool tls_sha384_init(struct tls_sha384_context *ctx);
void tls_sha384_update(struct tls_sha384_context *ctx, const uint8_t *data, size_t len);
void tls_sha384_digest(struct tls_sha384_context *ctx, uint8_t *digest);

/** init, update, and digest functions for the TI-84+ SHA-256 accelerator. */
/*
bool tls_sha256hw_init(struct tls_sha256_context *ctx);
void tls_sha256hw_update(struct tls_sha256_context *ctx, const uint8_t *data, size_t len);
void tls_sha256hw_digest(struct tls_sha256_context *ctx, uint8_t *digest);
 */

/** Storage for any registered hash backend's private state. */
union tls_hash_state
{
    struct tls_sha384_context sha384;
    struct tls_sha256_context sha256;
};

/** @struct Defines generic hash context. */
struct tls_hash_context
{
    uint8_t digestlen;
    uint8_t blocklen;
    bool (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*digest)(void *ctx, uint8_t *digest);
    union tls_hash_state _private;
};

/***************************************************************************
 * @brief Initializes a context to the the specified hash algorithm.
 * @param ctx       Pointer to a hash context to initialize.
 * @param algorithm     One of \p _hash_algorithms .
 * @returns @b true if success, @b false if error.
 */
bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t algorithm);

/***************************************************************************
 * @brief Copies a hash context's state into another, independent context.
 * @param dst       Pointer to the destination context (overwritten).
 * @param src       Pointer to the context to copy from.
 * @note The context is a pure value type (no heap pointers), so this is a
 *       plain struct copy. Digesting dst afterward does not disturb src --
 *       used to branch a transcript hash (e.g. to compute a PSK binder
 *       over a snapshot of the running transcript without finalizing the
 *       transcript hash itself).
 */
void tls_hash_context_copy(struct tls_hash_context *dst, const struct tls_hash_context *src);

/***************************************************************************
 * @brief Updates a hash context for data.
 * @param ctx       Pointer to a hash context to update.
 * @param data     Pointer to data to hash.
 * @param len       Length of data to hash.
 * @note A more object-oriented call style may be used. @code ctx.update(ctx._private, data, len) @endcode.
 */
void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *data, size_t len);

/***************************************************************************
 * @brief Returns a digest from the context state.
 * @param ctx       Pointer to a hash context.
 * @param digest     Pointer to buffer to write digest to.
 * @note A more object-oriented call style may be used. @code ctx.digest(ctx._private, digest) @endcode.
 */
void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *digest);

/***************************************************************************
 * @brief Securely clears a hash context.
 * @param ctx       Pointer to the hash context to clear. May be NULL.
 * @note Call when the context is no longer needed to erase buffered input
 *       and intermediate hash state.
 */
void tls_hash_clear(struct tls_hash_context *ctx);

/***************************************************************************
 * @brief Returns a MGF1 digest from some data. Used with RSA.
 * @param data      Pointer to data to hash.
 * @param datalen   Length of data to hash.
 * @param outbuf        Pointer to buffer to write output digest to.
 * @param outlen        Length of digest to return.
 * @param hash_alg      One of \p _hash_algorithms .
 */
bool tls_mgf1(const uint8_t *data, size_t datalen, uint8_t *outbuf, size_t outlen, uint8_t hash_alg);

#endif
