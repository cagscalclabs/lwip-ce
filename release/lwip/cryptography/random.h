/*
 * File: random.h
 * Author: Anthony Cagliano, Adam Beckingham
 * Description: Module providing a TRNG for use with TLS and other secure applications
 *              /// @warning Use this module for ALL applications requiring security.
 *              The toolchain @b rand functions are /// suitable for generic use but are
 *              **not cryptographically secure**. #ifndef tls_random_h #define
 *              tls_random_h #include <stdbool.h> #include <stdint.h> #include
 *              <stddef.h>
 * Generated: 2026-05-26T14:35:24Z
 */
/// @file random.h
/// @author ACagliano & Adam Beckingham
/// @brief Module providing a TRNG for use with TLS and other secure applications
/// @warning Use this module for ALL applications requiring security. The toolchain @b rand functions are
///     suitable for generic use but are **not cryptographically secure**.

#ifndef LWIP_PUBLIC_CRYPTOGRAPHY_RANDOM_H
#define LWIP_PUBLIC_CRYPTOGRAPHY_RANDOM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*************************************************************************************
 * @brief Initializes the cryptographic TRNG within this module.
 * @returns @b true if generator initialization succeeded, @b false if failed.
 * @warning DO NOT USE the toolchain @b rand functions with the TLS functions of lwIP-CE. They are not secure
 * for cryptography. Use this module instead.
 */
bool tls_random_init_entropy(void);

/*************************************************************************************
 * @brief Returns a secure 64-bit random integer.
 * @returns A secure 64-bit random integer.
 */
uint64_t tls_random(void);

/*************************************************************************************
 * @brief Fills a buffer with securely random bytes.
 * @param buffer    Pointer to a buffer to fill with random bytes.
 * @param len    Length of buffer to fill.
 * @returns Pointer to random buffer. Should be equal to @p buffer .
 */
void* tls_random_bytes(void* buffer, size_t len);

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
