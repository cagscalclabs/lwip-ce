#ifndef tls_h
#define tls_h

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initialize the TLS subsystem.
 *
 * Allocates static memory for cryptographic operations including:
 * - RSA scratch buffers (for OAEP and PSS operations)
 * - ECC scratch buffers (for ECDH and ECDSA operations)
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

#endif
