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
#include "handshake.h"
#include "lwip/logging.h"
#include "lwip/pbuf.h"

/* In-memory PSK/session-ticket cache. TLS-global (not per-connection):
 * entries are written here the instant a NewSessionTicket is parsed, read
 * back at connect time by hostname, and the whole table is loaded from /
 * saved to a single appvar at tls_init()/tls_cleanup() only. There is no
 * per-ticket disk I/O. Capacity is small and fixed; eviction is LRU-ish
 * (oldest received_at) once full. */
#define TLS_PSK_CACHE_MAX_ENTRIES 8u
#define TLS_PSK_CACHE_HOSTNAME_MAX 64u

struct tls_psk_cache_entry
{
    bool in_use;
    char hostname[TLS_PSK_CACHE_HOSTNAME_MAX]; /* NUL-terminated */
    uint8_t psk_type;                          /* enum tls_psk_type */
    uint8_t psk[32];
    struct tls_psk_identity identity;
    uint32_t received_at;   /* rtc_Time() seconds when the ticket was accepted */
    uint32_t ticket_lifetime; /* NST ticket_lifetime, seconds */
};

struct tls_context
{
    bool initialized;
    bool network_up;
    struct tls_truststore_state truststore; /* status field retained for future use */
};

extern struct tls_context tls_ctx;

/**
 * Store/refresh a PSK identity for `hostname` in the in-memory cache.
 * Finds an existing entry for the same hostname, or allocates a free slot,
 * or evicts the oldest entry if the cache is full. No disk I/O.
 */
void tls_psk_cache_put(const char *hostname, uint8_t psk_type,
                       const uint8_t *psk, const struct tls_psk_identity *identity,
                       uint32_t ticket_lifetime);

/**
 * Look up a non-expired PSK identity cached for `hostname`.
 * @return true and fills psk_type/psk/identity on a live hit, false otherwise.
 */
bool tls_psk_cache_get(const char *hostname, uint8_t *psk_type,
                       uint8_t *psk, struct tls_psk_identity *identity);

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

/** Initialize the TLS subsystem (starts RNG only). No network/connection
 *  support data (truststore, PSK cache) is touched here — see
 *  tls_network_up(). Call before any TLS operations. */
bool tls_init(void);

/** Bring up TLS connection-support data that depends on the network being
 *  available: the cert truststore and the PSK/session-ticket resumption
 *  cache. Internal — dispatched from lwip_network_up(), not part of the
 *  public surface. */
bool tls_network_up(void);

/**
 * @brief Clean up the TLS subsystem and free all allocated memory.
 *
 * Releases all memory allocated by tls_init() and tls_network_up().
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
