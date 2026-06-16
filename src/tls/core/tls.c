#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"
#include "../includes/random.h"
#include "../includes/bytes.h"
#include "../includes/truststore.h"
#include "../../drivers/mem.h"

/* Init-phase debug events route through the unified stack-wide debug sink
 * (lwip_set_debug). The library does no I/O — the callback decides. */
static inline void tls_init_debug(lwip_debug_state_t state, int errnum)
{
    lwip_debug_emit(LWIP_DBG_MOD_TLS, state, errnum, 0);
}

struct tls_context tls_ctx = {
    .initialized = false,
    .truststore = {
        .status = TLS_STORE_NOT_FOUND,
        .size = 0,
        .entry_count = 0,
        .version = 0,
        .created_timestamp = 0}};

bool tls_init(void)
{
    tls_init_debug(LWIP_DBG_TLS_INIT_START, 0);
    if (tls_ctx.initialized)
    {
        tls_init_debug(LWIP_DBG_TLS_INIT_DONE, 0);
        return true;
    }

    tls_ctx.initialized = true;
    tls_rng_start();
    tls_truststore_init();

    tls_init_debug(LWIP_DBG_TLS_INIT_DONE, 0);
    return true;
}

void tls_cleanup(void)
{
    tls_rng_cleanup();

    tls_ctx.initialized = false;
    tls_ctx.truststore.status = TLS_STORE_NOT_FOUND;
    tls_ctx.truststore.size = 0;
    tls_ctx.truststore.entry_count = 0;
    tls_ctx.truststore.version = 0;
    tls_ctx.truststore.created_timestamp = 0;
}

/*
 * TLS object allocator — replaces the old MEM_BUFFER_FILE-based "fileio"
 * buffer.  Instead of pre-reserving 32 KB (which showed a permanent 32K
 * limit in the T: stats line regardless of actual usage), every allocation
 * now draws directly from the unified heap and is tracked per-alloc via
 * mem_stats_tls_direct_add/release.  T: therefore shows only live bytes
 * (bytes of TLS objects that are currently parsed and in use), not a
 * reserved headroom that is almost never fully occupied.
 *
 * The allocation header stores the payload size so tls_fileio_free can
 * release the exact byte count without a separate size argument.
 *
 * File I/O (loading certs / keys from appvars) is the caller's
 * responsibility: pass raw DER/PEM bytes directly to tls_x509_*,
 * tls_pkcs8_*, etc.  The library never opens files itself.
 */
typedef struct
{
    uint32_t size; /* payload bytes, stored before the payload */
} tls_alloc_hdr_t;

void *tls_fileio_alloc(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }
    tls_alloc_hdr_t *hdr =
        (tls_alloc_hdr_t *)mem_buffer_custom_malloc(sizeof(tls_alloc_hdr_t) + size);
    if (!hdr)
    {
        return NULL;
    }
    hdr->size = (uint32_t)size;
    mem_stats_tls_direct_add(size, size);
    return hdr + 1;
}

void tls_fileio_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }
    tls_alloc_hdr_t *hdr = (tls_alloc_hdr_t *)ptr - 1;
    mem_stats_tls_direct_release(hdr->size, hdr->size);
    tls_secure_memzero(hdr, sizeof(tls_alloc_hdr_t) + hdr->size);
    mem_buffer_custom_free(hdr);
}

/* -----------------------------------------------------------------------
 * TLS RX custom pbuf
 *
 * All decrypted TLS record buffers (decrypt output, RX copies in the
 * altcp_tls_ce layer) are allocated through tls_rx_pbuf_alloc instead of
 * pbuf_alloc(PBUF_RAW, len, PBUF_RAM).  Each allocation is a single heap
 * block containing:
 *
 *   [ tls_rx_pbuf_hdr_t (struct pbuf_custom + size field) ]
 *   [ payload bytes     (len bytes)                       ]
 *
 * Because the pbuf type is PBUF_CUSTOM, lwIP's pbuf_free calls
 * tls_rx_pbuf_free_fn automatically when the reference count reaches 0 —
 * from ANY call site, without changes to existing pbuf_free callers.
 * The free function wipes key material and releases the exact byte count
 * from the T: accounting (mem_stats_tls_direct_release).
 *
 * T: therefore reflects every byte of decrypted TLS data that is currently
 * live: being decrypted, sitting in the receive queue, or in transit to the
 * app.  The stat drops to zero once the app has consumed all pending data.
 * ----------------------------------------------------------------------- */
typedef struct
{
    struct pbuf_custom pc; /* MUST be first — pbuf_free casts pbuf* to this */
    uint32_t payload_len;  /* payload bytes, for stats release */
} tls_rx_pbuf_hdr_t;

static void tls_rx_pbuf_free_fn(struct pbuf *p)
{
    tls_rx_pbuf_hdr_t *hdr = (tls_rx_pbuf_hdr_t *)p;
    uint32_t len = hdr->payload_len;
    tls_secure_memzero(hdr, sizeof(*hdr) + len);
    mem_stats_tls_direct_release(len, len);
    mem_buffer_custom_free(hdr);
}

struct pbuf *tls_rx_pbuf_alloc(uint16_t len)
{
    if (len == 0)
    {
        return NULL;
    }
    tls_rx_pbuf_hdr_t *hdr =
        (tls_rx_pbuf_hdr_t *)mem_buffer_custom_malloc(sizeof(*hdr) + len);
    if (!hdr)
    {
        return NULL;
    }
    hdr->payload_len = len;
    hdr->pc.custom_free_function = tls_rx_pbuf_free_fn;
    mem_stats_tls_direct_add(len, len);
    return pbuf_alloced_custom(PBUF_RAW, len, PBUF_RAM,
                               &hdr->pc,
                               (uint8_t *)(hdr + 1),
                               len);
}
