#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lwip/opt.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"
#include "../includes/random.h"
#include "../includes/bytes.h"
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

    tls_init_debug(LWIP_DBG_TLS_INIT_DONE, 0);
    return true;
}

void tls_cleanup(void)
{
    tls_rng_cleanup();
    tls_rsa_padding_cleanup();

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
