/**
 * @file tls.h
 * @author Claude Code
 * @brief TLS subsystem initialization, cleanup, and allocator bootstrap APIs.
 */

#ifndef tls_h
#define tls_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "truststore.h"
#include "lwip/logging.h"
#include "lwip/pbuf.h"

struct tls_context
{
    bool initialized;
    struct tls_truststore_state truststore; /* status field retained for future use */
};

extern struct tls_context tls_ctx;

/**
 * Allocate a TLS-owned PBUF_CUSTOM pbuf of `len` payload bytes.
 *
 * Use in place of pbuf_alloc(PBUF_RAW, len, PBUF_RAM) for all TLS
 * decrypted-record output buffers.  When pbuf_free reduces the reference
 * count to zero at ANY call site, the custom free function automatically
 * releases the bytes from the T: memory accounting and securely wipes the
 * payload — no changes to existing pbuf_free callers required.
 */
struct pbuf *tls_rx_pbuf_alloc(uint16_t len);

/** Initialize the TLS subsystem (starts RNG). Call before any TLS operations. */
bool tls_init(void);

/**
 * @brief Clean up the TLS subsystem and free all allocated memory.
 *
 * Releases all memory allocated by tls_init().
 * Should be called when TLS is no longer needed.
 */
void tls_cleanup(void);

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

#endif
