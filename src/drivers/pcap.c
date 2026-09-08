#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "lwip/netif.h"
#include "lwip/debug.h"
#include "usb_ethernet.h"
#include "mem.h"
#include "pcap.h"
#include "../lwip-imports.h"

#define LWIP_DBG_MODULE  LWIP_DBG_MOD_DRIVER

const char *pcap_file = "lwIPPCAP";

/* Pool the per-interface capture buffers are carved out of. Created lazily on
 * the first enable and torn down when the last capture is disabled, so a build
 * that never captures pays nothing for it. */
static struct mem_buffer *pcap_pool;
static uint8_t pcap_pool_refs;

/* Hand a capture buffer back to the pool, tearing the pool down once the last
 * one is returned. Safe on an interface that isn't capturing. */
static void pcap_free_buffer(eth_device_t *eth)
{
    if (eth == NULL || eth->pcap.buf == NULL)
        return;

    mem_buffer_free(pcap_pool, eth->pcap.buf);
    eth->pcap.buf = NULL;
    eth->pcap.offset = 0;

    if (pcap_pool_refs > 0 && --pcap_pool_refs == 0)
    {
        mem_buffer_destroy(pcap_pool);
        pcap_pool = NULL;
    }
}

pcap_err_t pcap_enable_on_netif(struct netif *netif)
{
    if (netif == NULL)
        return PCAP_ERR_ARG;

    eth_device_t *eth = netif->state;
    if (eth == NULL)
        return PCAP_ERR_ARG;

    /* Already capturing on this interface: keep the existing buffer. */
    if (eth->pcap.buf != NULL)
        return PCAP_OK;

    if (pcap_pool == NULL)
    {
        pcap_pool = mem_buffer_create(MEM_BUFFER_POOL,
                                      PCAP_POOL_INIT_SIZE,
                                      PCAP_POOL_MAX_SIZE,
                                      PCAP_POOL_STEP_SIZE,
                                      0);
        if (pcap_pool == NULL)
        {
            LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                        ("pcap: capture pool allocation failed\n"));
            return PCAP_ERR_MEM;
        }
    }

    uint8_t *buf_candidate = mem_buffer_malloc(pcap_pool, PCAP_BUFFER_LEN);
    if (buf_candidate == NULL)
    {
        LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                    ("pcap: capture buffer allocation failed\n"));
        /* Nothing else is using the pool we just created — don't leave it. */
        if (pcap_pool_refs == 0)
        {
            mem_buffer_destroy(pcap_pool);
            pcap_pool = NULL;
        }
        return PCAP_ERR_MEM;
    }

    eth->pcap.buf = buf_candidate;
    eth->pcap.offset = 0;
    pcap_pool_refs++;
    return PCAP_OK;
}

/* Internal fail-closed path: stop capturing when a write can't be completed. */
static void pcap_disable_netif(struct netif *netif)
{
    if (netif)
        pcap_free_buffer((eth_device_t *)netif->state);
}

/* Append `nbytes` from `src` to the capture appvar, creating it on first
 * write. Returns false on failure; the caller is responsible for disabling
 * capture. */
static bool pcap_append_appvar(const uint8_t *src, size_t nbytes)
{
    uint8_t h = file_fn.ti_open(pcap_file, "r+");
    if (!h)
    {
        h = file_fn.ti_open(pcap_file, "w");
    }
    if (!h)
    {
        LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE, ("pcap: ti_open failed\n"));
        return false;
    }
    file_fn.ti_seek(0, SEEK_END, h);
    size_t written = file_fn.ti_write(src, 1, nbytes, h);
    file_fn.ti_close(h);
    if (written != nbytes)
    {
        LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE, ("pcap: ti_write short\n"));
        return false;
    }
    return true;
}

bool pcap_flush(struct netif *netif)
{
    if (netif == NULL)
        return false;

    eth_device_t *eth = netif->state;
    if (eth == NULL || eth->pcap.buf == NULL)
        return false;

    if (eth->pcap.offset == 0)
        return true; /* nothing staged */

    if (!pcap_append_appvar(eth->pcap.buf, eth->pcap.offset))
    {
        LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                    ("pcap: flush failed, disabling capture\n"));
        /* Drop the staged bytes: they can't be written, and keeping them would
         * stall every subsequent write against a buffer that never drains. */
        eth->pcap.offset = 0;
        pcap_disable_netif(netif);
        return false;
    }

    eth->pcap.offset = 0;
    return true;
}

bool pcap_disable_on_netif(struct netif *netif)
{
    if (netif == NULL)
        return false;

    eth_device_t *eth = netif->state;
    if (eth == NULL)
        return false;

    /* Don't lose the tail of the capture. If the flush fails it has already
     * dropped the staged bytes, so the release below is still correct. */
    pcap_flush(netif);
    pcap_free_buffer(eth);
    return true;
}

void pcap_release_on_teardown(struct netif *netif)
{
    if (netif == NULL)
        return;

    eth_device_t *eth = netif->state;
    if (eth == NULL || eth->pcap.buf == NULL)
        return;

    /* netif_remove() normally flushes via eth_netif_remove_callback, so by the
     * time we get here offset is usually 0 and this is a no-op backstop for a
     * device freed without going through netif_remove. Skip it on a dead
     * device: flushing runs OS appvar routines (InsertMem) that move the heap,
     * and this can run from the deferred reap path rather than a normal stack. */
    if (!eth->dead)
        pcap_flush(netif);

    pcap_free_buffer(eth);
}

bool pcap_write(struct netif *netif, pcap_direction_t dir, const uint8_t *data, uint16_t len)
{
    if (netif == NULL || (data == NULL && len != 0))
        return false;

    eth_device_t *eth = netif->state;
    if (eth == NULL || eth->pcap.buf == NULL)
        return false; /* capture not enabled */

    size_t rec_size = sizeof(struct pcap) + len;

    /* PCAP_BUFFER_LEN is sized so a full-MTU record always fits in an empty
     * buffer; anything larger is a malformed length we refuse rather than
     * stage past the end of the buffer. */
    if (rec_size > PCAP_BUFFER_LEN)
    {
        LWIP_DEBUGF(LWIP_DBG_LEVEL_SERIOUS,
                    ("pcap: record too large (%u), dropping\n", (unsigned)rec_size));
        return false;
    }

    /* Not enough room for this record: flush what's staged and start over. */
    if (eth->pcap.offset + rec_size > PCAP_BUFFER_LEN)
    {
        if (!pcap_flush(netif))
            return false; /* pcap_flush already disabled capture */
    }

    struct pcap rec;
    memset(&rec, 0, sizeof(rec));
    rec.ifname[0] = (char)(unsigned char)netif->name[0];
    rec.ifname[1] = (char)(unsigned char)netif->name[1];
    rec.ifnum     = netif->num;
    rec.direction = (uint8_t)(unsigned int)dir;
    rec.len       = len;

    uint8_t *dest = eth->pcap.buf + eth->pcap.offset;
    memcpy(dest, &rec, sizeof(struct pcap));
    if (len)
        memcpy(dest + sizeof(struct pcap), data, len);
    eth->pcap.offset += rec_size;
    return true;
}

bool pcap_init_reader_ctx(struct pcap_reader_ctx *ctx)
{
    if (!ctx)
        return false;

    /* Checkpoint every capturing interface so the reader sees everything
     * captured up to now, not just what happened to be flushed already. */
    for (struct netif *nif = netif_list; nif != NULL; nif = nif->next)
    {
        eth_device_t *eth = nif->state;
        if (eth && eth->pcap.buf && eth->pcap.offset)
            pcap_flush(nif);
    }

    ctx->ifname_filter[0] = 0;
    ctx->ifname_filter[1] = 0;
    ctx->ifnum_filter = 0xFF; /* 0xFF = no filter, match all */
    ctx->offset = 0;
    ctx->handle = file_fn.ti_open(pcap_file, "r");
    return ctx->handle != 0;
}

void pcap_close_reader_ctx(struct pcap_reader_ctx *ctx)
{
    if (!ctx || !ctx->handle)
        return;
    file_fn.ti_close(ctx->handle);
    ctx->handle = 0;
}

bool pcap_set_filter_netif(struct pcap_reader_ctx *ctx, struct netif *netif)
{
    if (!ctx || !netif)
        return false;
    ctx->ifname_filter[0] = netif->name[0];
    ctx->ifname_filter[1] = netif->name[1];
    ctx->ifnum_filter = netif->num;
    return true;
}

bool pcap_set_filter_name_num(struct pcap_reader_ctx *ctx, char ifname[2], uint8_t ifnum)
{
    if (!ctx || !ifname)
        return false;
    ctx->ifname_filter[0] = ifname[0];
    ctx->ifname_filter[1] = ifname[1];
    ctx->ifnum_filter = ifnum;
    return true;
}

bool pcap_read_next(struct pcap_reader_ctx *ctx, struct pcap **hdr, const uint8_t **data)
{
    if (!ctx || !hdr || !data || !ctx->handle)
        return false;

    uint16_t total = file_fn.ti_getsize(ctx->handle);
    uint8_t *base = (uint8_t *)file_fn.ti_getdataptr(ctx->handle);

    while (ctx->offset + sizeof(struct pcap) <= total)
    {
        struct pcap *rec = (struct pcap *)(base + ctx->offset);

        /* Bounds check: ensure the frame data fits within the appvar. */
        if (ctx->offset + sizeof(struct pcap) + rec->len > total)
            return false;

        ctx->offset += sizeof(struct pcap) + rec->len;

        /* Apply filter: skip if ifnum_filter is set and doesn't match. */
        if (ctx->ifnum_filter != 0xFF)
        {
            if (rec->ifname[0] != ctx->ifname_filter[0] ||
                rec->ifname[1] != ctx->ifname_filter[1] ||
                rec->ifnum     != ctx->ifnum_filter)
                continue;
        }

        *hdr  = rec;
        *data = (const uint8_t *)rec + sizeof(struct pcap);
        return true;
    }

    return false; /* no more records */
}