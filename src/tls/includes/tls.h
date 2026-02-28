#ifndef tls_h
#define tls_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "truststore.h"

struct tls_context
{
    uint8_t *rsa_scratch;
    uint8_t *ecc_scratch;
    bool initialized;
    struct tls_truststore_state truststore;
};

extern struct tls_context tls_ctx;

/**
 * @brief Initialize the TLS subsystem.
 *
 * Allocates memory for cryptographic operations including:
 * - RSA scratch buffers (for OAEP and PSS operations)
 * - ECC scratch buffers (for ECDH operations)
 *
 * This function must be called before any TLS operations.
 * Uses lwIP's memory allocator for controlled allocation.
 *
 * @return true on success, false on memory allocation failure
 */
bool tls_init(void);

/**
 * @brief Clean up the TLS subsystem and free all allocated memory.
 *
 * Releases all memory allocated by tls_init().
 * Should be called when TLS is no longer needed.
 */
void tls_cleanup(void);

/***************************************************************************
 * @brief Runs one immediate RNG health check cycle.
 *
 * Executes the same lightweight sanity and recovery logic used by the
 * periodic RNG health timer. If health checks have repeatedly failed,
 * this may trigger a re-initialization attempt of the entropy source.
 *
 * @return @b true if RNG health is currently acceptable, @b false otherwise.
 */
bool tls_rng_healthcheck(void);

/**
 * @brief Allocate from the shared TLS FILEIO buffer (lazy-created on first use).
 * @param size Allocation size in bytes.
 * @return Allocated pointer, or NULL on failure.
 */
void *tls_fileio_alloc(size_t size);

/**
 * @brief Free a pointer previously allocated by tls_fileio_alloc().
 * @param ptr Pointer to free (NULL-safe).
 */
void tls_fileio_free(void *ptr);

/***************************************************************************
 * @brief Callback invoked when an RNG request completes.
 *
 * @param ok      true on success, false on failure.
 * @param arg     Opaque caller pointer supplied to tls_request_random_bytes().
 */
typedef void (*tls_random_request_cb_t)(bool ok, void *arg);

/***************************************************************************
 * @brief Request random data for TLS usage.
 *
 * The request gathers entropy in timed chunks until @p len bytes are available.
 * If @p blocking is true, gathering is done immediately in the caller thread.
 * If @p blocking is false, gathering runs on lwIP timers and @p cb is invoked
 * once complete.
 *
 * Only one request can be active at a time.
 *
 * @param out      Caller-provided destination buffer.
 * @param len      Number of random bytes requested.
 * @param cb       Optional completion callback.
 * @param arg      Opaque user context passed to @p cb.
 * @param blocking true for immediate completion path, false for async timer path.
 * @return true if request started/completed successfully, false on failure.
 * @note If @p blocking is true, this function may take a long time to return while gathering entropy.
 * The caller is responsble for ensuring that @b out remains valid until the request completes, especially in the async case where @p cb may be invoked later.
 */
bool tls_request_random_bytes(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg, bool blocking);

/***************************************************************************
 * @brief Returns whether the TLS RNG request engine currently has an active request.
 * @return true if a request is in progress, false otherwise.
 */
bool tls_rng_is_busy(void);

#endif
