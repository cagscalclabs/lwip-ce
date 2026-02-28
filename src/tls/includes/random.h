/// @file random.h
/// @author ACagliano & Adam Beckingham
/// @brief Module providing a TRNG for use with TLS and other secure applications
/// @warning Use this module for ALL applications requiring security. The toolchain @b rand functions are
///     suitable for generic use but are **not cryptographically secure**.

#ifndef tls_random_h
#define tls_random_h

#include <stdbool.h>
#include <stdint.h>

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

/*************************************************************************************
 * @brief Debug/test hook: returns the current sampled entropy source address.
 * @return Pointer used by the RNG sampler after @ref tls_random_init_entropy .
 * @warning Intended for diagnostics/tests only.
 */
void* tls_random_debug_source_ptr(void);


#endif
