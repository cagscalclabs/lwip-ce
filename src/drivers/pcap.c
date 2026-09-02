#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tice.h>
#include "lwip/netif.h"
#include "lwip/debug.h"
#include "usb_ethernet.h"
#include "pcap.h"

#define LWIP_DBG_MODULE  LWIP_DBG_MOD_DRIVER

const char *pcap_file = "lwIPPCAP";

/* ROM call wrappers implemented in pcap.s */
extern bool pcap_enough_mem(void *addr, size_t nbytes);
extern void pcap_insert_mem(void *addr, size_t nbytes);

bool pcap_enable_on_netif(struct netif *netif)
{
    eth_device_t *eth = netif->state;
    eth->pcap_enabled = true;
    return true;
}

bool pcap_disable_on_netif(struct netif *netif)
{
    eth_device_t *eth = netif->state;
    eth->pcap_enabled = false;
    return true;
}

static void pcap_disable_netif(struct netif *netif)
{
    eth_device_t *eth = (eth_device_t *)netif->state;
    if (eth)
        eth->pcap_enabled = false;
}

bool pcap_write(struct netif *netif, pcap_direction_t dir, const uint8_t *data, uint16_t len)
{
    size_t rec_size = sizeof(struct pcap) + len;

    var_t *var = os_GetAppVarData(pcap_file, NULL);
    if (!var)
    {
        /* First write: create the appvar at exactly rec_size. */
        var = os_CreateAppVar(pcap_file, (uint16_t)rec_size);
        if (!var)
        {
            LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                        ("pcap: os_CreateAppVar failed, disabling capture\n"));
            pcap_disable_netif(netif);
            return false;
        }
    }
    else
    {
        /* Grow in place: insert rec_size bytes at the end of the appvar data,
         * then bump the size word so os_GetAppVarData reports the new length. */
        uint16_t old_size = var->size;
        uint8_t *insert_at = (uint8_t *)var->data + old_size;

        if (!pcap_enough_mem(insert_at, rec_size))
        {
            LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                        ("pcap: out of memory, disabling capture\n"));
            pcap_disable_netif(netif);
            return false;
        }

        pcap_insert_mem(insert_at, rec_size);

        /* Re-fetch: InsertMem may shift the heap, invalidating `var`. */
        var = os_GetAppVarData(pcap_file, NULL);
        if (!var)
        {
            LWIP_DEBUGF(LWIP_DBG_LEVEL_SEVERE,
                        ("pcap: re-fetch after InsertMem failed, disabling capture\n"));
            pcap_disable_netif(netif);
            return false;
        }

        var->size = old_size + (uint16_t)rec_size;
    }

    /* Write record header + frame data into the new slot at the end. */
    uint16_t old_size = var->size - (uint16_t)rec_size;
    uint8_t *dest = (uint8_t *)var->data + old_size;

    unsigned int dir_uint = (unsigned int)dir;
    uint8_t dir_byte = (uint8_t)dir_uint;
    struct pcap rec;
    memset(&rec, 0, sizeof(rec));
    rec.ifname[0] = (char)(unsigned char)netif->name[0];
    rec.ifname[1] = (char)(unsigned char)netif->name[1];
    rec.ifnum     = netif->num;
    rec.direction = dir_byte;
    rec.len       = len;
    memcpy(dest, &rec, sizeof(struct pcap));
    memcpy(dest + sizeof(struct pcap), data, len);
    return true;
}

bool pcap_init_reader_ctx(struct pcap_reader_ctx *ctx)
{
    if (!ctx)
        return false;
    ctx->ifname_filter[0] = 0;
    ctx->ifname_filter[1] = 0;
    ctx->ifnum_filter = 0xFF; /* 0xFF = no filter, match all */
    ctx->offset = 0;
    return true;
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
    if (!ctx || !hdr || !data)
        return false;

    var_t *var = os_GetAppVarData(pcap_file, NULL);
    if (!var)
        return false;

    uint16_t total = var->size;
    uint8_t *base = (uint8_t *)var->data;

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