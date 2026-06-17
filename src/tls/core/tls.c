#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/rtc.h>
#include <ti/vars.h>
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

/* -----------------------------------------------------------------------
 * PSK / session-ticket cache (TLS-global, in-memory)
 *
 * Tickets are written here the moment a NewSessionTicket is parsed
 * (tls_psk_cache_put) and read back by hostname at connect time
 * (tls_psk_cache_get). The table itself is heap-allocated lazily (on first
 * tls_init()) under TLS memory accounting, and is the only thing persisted
 * to flash: loaded once at tls_init(), saved once at tls_cleanup(). There
 * is no per-ticket disk I/O.
 *
 * Expiry uses rtc_Time() (free-running hardware seconds counter that
 * survives a stack restart) rather than sys_now(), which resets to 0 on
 * every restart and therefore can't be compared against a timestamp saved
 * in a previous run.
 * ----------------------------------------------------------------------- */
#define TLS_PSK_CACHE_APPVAR "lwIPPSKC"
#define TLS_PSK_CACHE_MAGIC 0x434B5350u /* "PSKC" */
#define TLS_PSK_CACHE_VERSION 1u

struct tls_psk_cache_store_header
{
    uint32_t magic;
    uint16_t version;
    uint16_t count;
};

static struct tls_psk_cache_entry *g_psk_cache = NULL;

static bool tls_psk_cache_entry_expired(const struct tls_psk_cache_entry *e, uint32_t now)
{
    uint32_t age = now - e->received_at; /* unsigned wraparound is fine here */
    return age >= e->ticket_lifetime;
}

static void tls_psk_cache_alloc(void)
{
    if (g_psk_cache)
    {
        return;
    }
    size_t bytes = sizeof(struct tls_psk_cache_entry) * TLS_PSK_CACHE_MAX_ENTRIES;
    g_psk_cache = (struct tls_psk_cache_entry *)mem_buffer_custom_malloc(bytes);
    if (!g_psk_cache)
    {
        return;
    }
    memset(g_psk_cache, 0, bytes);
    mem_stats_tls_direct_add(bytes, bytes);
}

static void tls_psk_cache_free(void)
{
    if (!g_psk_cache)
    {
        return;
    }
    size_t bytes = sizeof(struct tls_psk_cache_entry) * TLS_PSK_CACHE_MAX_ENTRIES;
    tls_secure_memzero(g_psk_cache, bytes);
    mem_stats_tls_direct_release(bytes, bytes);
    mem_buffer_custom_free(g_psk_cache);
    g_psk_cache = NULL;
}

void tls_psk_cache_put(const char *hostname, uint8_t psk_type,
                       const uint8_t *psk, const struct tls_psk_identity *identity,
                       uint32_t ticket_lifetime)
{
    size_t host_len;
    int slot = -1;
    int oldest = -1;

    if (!g_psk_cache || !hostname || !psk || !identity)
    {
        return;
    }
    host_len = strlen(hostname);
    if (host_len == 0 || host_len >= TLS_PSK_CACHE_HOSTNAME_MAX ||
        identity->identity_len > sizeof(identity->identity))
    {
        return;
    }

    for (unsigned i = 0; i < TLS_PSK_CACHE_MAX_ENTRIES; i++)
    {
        struct tls_psk_cache_entry *e = &g_psk_cache[i];
        if (e->in_use && strcmp(e->hostname, hostname) == 0)
        {
            slot = (int)i;
            break;
        }
        if (!e->in_use)
        {
            if (slot < 0)
            {
                slot = (int)i;
            }
        }
        else if (oldest < 0 || e->received_at < g_psk_cache[oldest].received_at)
        {
            oldest = (int)i;
        }
    }
    if (slot < 0)
    {
        slot = oldest; /* cache full of distinct hosts: evict the oldest */
    }
    if (slot < 0)
    {
        return;
    }

    struct tls_psk_cache_entry *e = &g_psk_cache[slot];
    memset(e, 0, sizeof(*e));
    e->in_use = true;
    memcpy(e->hostname, hostname, host_len + 1);
    e->psk_type = psk_type;
    memcpy(e->psk, psk, sizeof(e->psk));
    memcpy(&e->identity, identity, sizeof(e->identity));
    e->received_at = rtc_Time();
    e->ticket_lifetime = ticket_lifetime;
}

bool tls_psk_cache_get(const char *hostname, uint8_t *psk_type,
                       uint8_t *psk, struct tls_psk_identity *identity)
{
    if (!g_psk_cache || !hostname)
    {
        return false;
    }
    uint32_t now = rtc_Time();
    for (unsigned i = 0; i < TLS_PSK_CACHE_MAX_ENTRIES; i++)
    {
        struct tls_psk_cache_entry *e = &g_psk_cache[i];
        if (!e->in_use || strcmp(e->hostname, hostname) != 0)
        {
            continue;
        }
        if (tls_psk_cache_entry_expired(e, now))
        {
            e->in_use = false;
            return false;
        }
        if (psk_type)
        {
            *psk_type = e->psk_type;
        }
        if (psk)
        {
            memcpy(psk, e->psk, 32);
        }
        if (identity)
        {
            memcpy(identity, &e->identity, sizeof(*identity));
            /* The fresh tls_handshake_context this identity is about to seed
             * starts with ticket_received_ms == 0, so handshake.c's "elapsed
             * since received" math (handshake.c:1874) is skipped and it would
             * otherwise send the stale obfuscated_ticket_age verbatim — wrong
             * by however long the ticket has sat in the cache (or survived a
             * stack restart). Fold that real elapsed time in now, using the
             * RTC-measured age (seconds, survives restart) converted to ms,
             * so the ClientHello carries a correct age regardless of when it
             * is actually sent. */
            uint32_t elapsed_ms = (now - e->received_at) * 1000u;
            identity->obfuscated_ticket_age += elapsed_ms;
        }
        return true;
    }
    return false;
}

/* Load the persisted cache from flash into g_psk_cache, dropping any entry
 * that has already expired (judged against the live RTC, so expiry survives
 * a stack restart). Called once from tls_init(). */
static void tls_psk_cache_load(void)
{
    var_t *var;
    const uint8_t *data;
    uint16_t size;
    struct tls_psk_cache_store_header hdr;
    uint32_t now;

    if (!g_psk_cache)
    {
        return;
    }
    var = os_GetAppVarData(TLS_PSK_CACHE_APPVAR, NULL);
    if (!var)
    {
        return;
    }
    size = *((uint16_t *)var);
    data = (const uint8_t *)var + 2;
    if (size < sizeof(hdr))
    {
        return;
    }
    memcpy(&hdr, data, sizeof(hdr));
    if (hdr.magic != TLS_PSK_CACHE_MAGIC || hdr.version != TLS_PSK_CACHE_VERSION ||
        hdr.count > TLS_PSK_CACHE_MAX_ENTRIES)
    {
        return;
    }
    if (size != sizeof(hdr) + hdr.count * sizeof(struct tls_psk_cache_entry))
    {
        return;
    }

    now = rtc_Time();
    const uint8_t *entry_data = data + sizeof(hdr);
    unsigned out = 0;
    for (uint16_t i = 0; i < hdr.count && out < TLS_PSK_CACHE_MAX_ENTRIES; i++)
    {
        struct tls_psk_cache_entry e;
        memcpy(&e, entry_data + (size_t)i * sizeof(e), sizeof(e));
        if (!e.in_use || tls_psk_cache_entry_expired(&e, now))
        {
            continue;
        }
        g_psk_cache[out++] = e;
    }
}

/* Serialize the live cache back to flash in one write. Called once from
 * tls_cleanup(). Expired entries are dropped rather than persisted. */
static void tls_psk_cache_save(void)
{
    if (!g_psk_cache)
    {
        return;
    }

    struct tls_psk_cache_entry live[TLS_PSK_CACHE_MAX_ENTRIES];
    uint32_t now = rtc_Time();
    uint16_t count = 0;
    for (unsigned i = 0; i < TLS_PSK_CACHE_MAX_ENTRIES; i++)
    {
        if (g_psk_cache[i].in_use && !tls_psk_cache_entry_expired(&g_psk_cache[i], now))
        {
            live[count++] = g_psk_cache[i];
        }
    }

    struct tls_psk_cache_store_header hdr = {
        .magic = TLS_PSK_CACHE_MAGIC,
        .version = TLS_PSK_CACHE_VERSION,
        .count = count};
    size_t total = sizeof(hdr) + (size_t)count * sizeof(struct tls_psk_cache_entry);

    os_DelAppVar(TLS_PSK_CACHE_APPVAR);
    if (count == 0)
    {
        return; /* nothing live to persist; leave no stale appvar behind */
    }
    var_t *var = os_CreateAppVar(TLS_PSK_CACHE_APPVAR, (uint16_t)total);
    if (!var)
    {
        return;
    }
    memcpy(var->data, &hdr, sizeof(hdr));
    memcpy(var->data + sizeof(hdr), live, count * sizeof(struct tls_psk_cache_entry));
}

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

bool tls_network_up(void)
{
    if (tls_ctx.network_up)
    {
        return true;
    }

    tls_ctx.network_up = true;
    tls_truststore_init();
    tls_psk_cache_alloc();
    tls_psk_cache_load();
    return true;
}

void tls_cleanup(void)
{
    tls_psk_cache_save();
    tls_psk_cache_free();
    tls_rng_cleanup();

    tls_ctx.initialized = false;
    tls_ctx.network_up = false;
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
