#include <stdlib.h>
#include <string.h>

#include "usb_ethernet.h"
#include "lwip/app_config.h"
#include "lwip/dispatch.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/logging.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/teardown.h"

eth_device_t eth;
struct netif *netif_list;
struct netif *netif_default;

int ethernet_test_pbuf_alloc_fail;

static lwip_app_config_t g_cfg = {
    .version = LWIP_CFG_VERSION,
    .hostname = "ethrx"
};

const lwip_app_config_t *lwip_app_config_get(void)
{
    return &g_cfg;
}

void lwip_log_event_at(uint16_t module, uint16_t module_state, uint16_t line)
{
    (void)module;
    (void)module_state;
    (void)line;
}

void lwip_teardown_abort_pcbs_on_netif(const struct netif *netif)
{
    (void)netif;
}

void lwip_dispatch_attach(lwip_dispatch_id_t id, lwip_dispatch_fn fn)
{
    (void)id;
    (void)fn;
}

void lwip_dispatch_set_period(lwip_dispatch_id_t id, uint16_t period_ticks)
{
    (void)id;
    (void)period_ticks;
}

uint16_t lwip_dispatch_period_from_ms(uint32_t ms)
{
    return (uint16_t)ms;
}

void lwip_dispatch_start(void)
{
}

void lwip_dispatch_stop(void)
{
}

void tls_secure_memzero(void *ptr, size_t len)
{
    if (ptr)
    {
        memset(ptr, 0, len);
    }
}

struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type)
{
    (void)layer;
    (void)type;
    if (ethernet_test_pbuf_alloc_fail)
    {
        return NULL;
    }

    struct pbuf *p = (struct pbuf *)calloc(1, sizeof(*p));
    if (!p)
    {
        return NULL;
    }
    p->payload = malloc(length ? length : 1);
    if (!p->payload)
    {
        free(p);
        return NULL;
    }
    p->tot_len = length;
    p->len = length;
    p->ref = 1;
    return p;
}

u8_t pbuf_free(struct pbuf *p)
{
    u8_t freed = 0;
    while (p)
    {
        struct pbuf *next = p->next;
        free(p->payload);
        free(p);
        p = next;
        freed++;
    }
    return freed;
}

err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len)
{
    if (!buf || !buf->payload || len > buf->len)
    {
        return ERR_MEM;
    }
    memcpy(buf->payload, dataptr, len);
    return ERR_OK;
}

u16_t pbuf_copy_partial(const struct pbuf *buf, void *dataptr, u16_t len, u16_t offset)
{
    if (!buf || !buf->payload || !dataptr || offset > buf->len)
    {
        return 0;
    }
    if (len > (u16_t)(buf->len - offset))
    {
        len = (u16_t)(buf->len - offset);
    }
    memcpy(dataptr, (const uint8_t *)buf->payload + offset, len);
    return len;
}

err_t pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from)
{
    if (!p_to || !p_from || !p_to->payload || !p_from->payload ||
        p_to->tot_len < p_from->tot_len)
    {
        return ERR_ARG;
    }
    memcpy(p_to->payload, p_from->payload, p_from->tot_len);
    return ERR_OK;
}

err_t etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
    (void)netif;
    (void)q;
    (void)ipaddr;
    return ERR_OK;
}

err_t ethip6_output(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr)
{
    (void)netif;
    (void)q;
    (void)ip6addr;
    return ERR_OK;
}

struct netif *netif_add_noaddr(struct netif *netif, void *state,
                               netif_init_fn init, netif_input_fn input)
{
    netif->state = state;
    netif->input = input;
    netif->next = netif_list;
    netif_list = netif;
    if (init)
    {
        init(netif);
    }
    return netif;
}

void netif_remove(struct netif *netif)
{
    struct netif **pp = &netif_list;
    while (*pp)
    {
        if (*pp == netif)
        {
            *pp = netif->next;
            break;
        }
        pp = &(*pp)->next;
    }
}

void netif_set_default(struct netif *netif)
{
    netif_default = netif;
}

void netif_set_up(struct netif *netif)
{
    netif->flags |= NETIF_FLAG_UP;
}

void netif_set_down(struct netif *netif)
{
    netif->flags &= (u8_t)~NETIF_FLAG_UP;
}

void netif_set_link_up(struct netif *netif)
{
    netif->flags |= NETIF_FLAG_LINK_UP;
}

void netif_set_link_down(struct netif *netif)
{
    netif->flags &= (u8_t)~NETIF_FLAG_LINK_UP;
}

void netif_set_link_callback(struct netif *netif, netif_status_callback_fn link_callback)
{
    netif->link_callback = link_callback;
}

void netif_set_status_callback(struct netif *netif, netif_status_callback_fn status_callback)
{
    netif->status_callback = status_callback;
}

void netif_create_ip6_linklocal_address(struct netif *netif, u8_t from_mac_48bit)
{
    (void)netif;
    (void)from_mac_48bit;
}
