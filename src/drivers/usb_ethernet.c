/****************************************************************************
 * Code for Communications Data Class (CDC)
 * for USB-Ethernet devices
 * Includes Callbacks, USB Event handlers, and netif initialization
 */

#include <sys/util.h>
#include <usbdrvce.h>

/**
 * LWIP headers for handing link layer to stack,
 * managing NETIF in USB callbacks,
 * managing packet buffers,
 * and tracking link stats
 */
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/netif.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/dhcp.h"
#include "usb_ethernet.h" /* Communications Data Class header file */
#include "mem.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/logging.h"

#define ETH_USB_MAX_RETRIES 5
#define ETH_START_DHCP_ON_ALL true
#define ETH_DO_RESTART_ON_ERROR true

/// Define Default Hostname for NETIFs
const char hostname[] = "ti84plusce";
static uint8_t ifnums_used = 0;
bool eth_disabled_with_error = false;
struct usb_configurator usb_fn = {0};
static enum mem_pressure_level g_eth_rx_throttle_level = MEM_PRESSURE_NONE;

static void log_usb_transfer_status(usb_transfer_status_t status)
{
    if (status & USB_TRANSFER_NO_DEVICE)
    {
        lwip_log_event(LWIP_LOG_MODULE_USB, LWIP_LOG_USB_ENDPOINT_NO_DEVICE);
    }
    if (status & USB_TRANSFER_STALLED)
    {
        lwip_log_event(LWIP_LOG_MODULE_USB, LWIP_LOG_USB_ENDPOINT_STALL);
    }
    if (status & (USB_TRANSFER_ERROR | USB_TRANSFER_HOST_ERROR | USB_TRANSFER_BUS_ERROR |
                  USB_TRANSFER_OVERFLOW | USB_TRANSFER_FAILED))
    {
        lwip_log_event(LWIP_LOG_MODULE_USB, LWIP_LOG_USB_ENDPOINT_ERROR);
    }
}
static bool g_eth_rx_drain_scheduled = false;
static bool g_eth_rx_sched_scheduled = false;

#define ETH_RX_RING_INIT_SIZE 512u
#define ETH_RX_RING_MAX_SIZE 2048u
#define ETH_RX_RING_STEP_SIZE 512u
#define ETH_RX_DRAIN_INTERVAL_MS 10u
#define ETH_RX_SCHED_INTERVAL_MS 20u
#define ETH_RX_DRAIN_MAX_NONE 8u
#define ETH_RX_DRAIN_MAX_MILD 4u
#define ETH_RX_DRAIN_MAX_HIGH 2u
#define ETH_RX_DRAIN_MAX_CRITICAL 1u
static uint32_t g_eth_rx_drain_interval_ms = ETH_RX_DRAIN_INTERVAL_MS;
static uint32_t g_eth_rx_sched_interval_ms = ETH_RX_SCHED_INTERVAL_MS;

static uint32_t eth_rx_schedule_interval_ms(void)
{
    uint32_t base = ETH_RX_SCHED_INTERVAL_MS;
    switch (g_eth_rx_throttle_level)
    {
    case MEM_PRESSURE_NONE:
        return base;
    case MEM_PRESSURE_MILD:
        return base * 2u;
    case MEM_PRESSURE_HIGH:
        return base * 4u;
    case MEM_PRESSURE_SEVERE:
        return base * 8u;
    case MEM_PRESSURE_CRITICAL:
        return base * 8u;
    default:
        return base * 2u;
    }
}

static uint16_t eth_drain_budget(void)
{
    enum mem_pressure_level level = mem_get_global_pressure_level();
    uint16_t budget = ETH_RX_DRAIN_MAX_NONE;
    switch (level)
    {
    case MEM_PRESSURE_NONE:
        return budget;
    case MEM_PRESSURE_MILD:
        budget = ETH_RX_DRAIN_MAX_NONE / 2u;
        break;
    case MEM_PRESSURE_HIGH:
        budget = ETH_RX_DRAIN_MAX_NONE / 4u;
        break;
    case MEM_PRESSURE_SEVERE:
        budget = ETH_RX_DRAIN_MAX_NONE / 8u;
        break;
    case MEM_PRESSURE_CRITICAL:
        return 0;
    default:
        budget = ETH_RX_DRAIN_MAX_NONE / 2u;
        break;
    }
    if (budget == 0)
    {
        budget = 1;
    }
    return budget;
}

static void eth_schedule_rx_for_netifs(void)
{
    struct netif *netif = NULL;
    NETIF_FOREACH(netif)
    {
        if (!netif || netif->name[0] != 'e' || netif->name[1] != 'n' || !netif->state)
        {
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        if (!dev->rx.callback || dev->rx_transfer_active)
        {
            continue;
        }
        size_t len = (dev->type == USB_NCM_SUBCLASS) ? NCM_RX_NTB_MAX_SIZE : ETHERNET_MTU;
        usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf, len, dev->rx.callback, dev);
        dev->rx_transfer_active = true;
    }
}

static void eth_rx_schedule_timer(void *arg)
{
    LWIP_UNUSED_ARG(arg);
    if (g_eth_rx_throttle_level == MEM_PRESSURE_CRITICAL)
    {
        g_eth_rx_sched_scheduled = false;
        return;
    }
    eth_schedule_rx_for_netifs();
    sys_timeout(g_eth_rx_sched_interval_ms, eth_rx_schedule_timer, NULL);
}

static bool eth_ring_push_frame(eth_device_t *dev, const uint8_t *data, uint16_t len)
{
    if (!dev || !dev->rx_ring || !data || len == 0)
    {
        return false;
    }
    size_t needed = (size_t)len + 2u;
    if (!mem_buffer_reserve(dev->rx_ring, needed))
    {
        return false;
    }
    uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xff)};
    if (!mem_buffer_push(dev->rx_ring, hdr, sizeof(hdr)))
    {
        return false;
    }
    if (!mem_buffer_push(dev->rx_ring, data, len))
    {
        return false;
    }
    return true;
}

static size_t eth_rx_ring_drain(struct mem_buffer *rb, void *user, size_t budget)
{
    struct netif *netif = (struct netif *)user;
    if (!rb || !netif)
    {
        return 0;
    }
    size_t drained = 0;
    while (budget > 0 && mem_buffer_len(rb) >= 2)
    {
        uint8_t hdr[2];
        if (!mem_buffer_peek(rb, 0, hdr, sizeof(hdr)))
        {
            break;
        }
        uint16_t len = (uint16_t)((hdr[0] << 8) | hdr[1]);
        if (mem_buffer_len(rb) < (size_t)len + 2u)
        {
            break;
        }
        struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (!p)
        {
            break;
        }
        mem_buffer_pop(rb, hdr, sizeof(hdr));
        size_t remaining = len;
        for (struct pbuf *q = p; q != NULL && remaining > 0; q = q->next)
        {
            size_t chunk = q->len;
            if (chunk > remaining)
            {
                chunk = remaining;
            }
            mem_buffer_pop(rb, (uint8_t *)q->payload, chunk);
            remaining -= chunk;
        }
        if (remaining != 0)
        {
            pbuf_free(p);
            break;
        }
        if (netif->input(p, netif) != ERR_OK)
        {
            pbuf_free(p);
        }
        budget--;
        drained++;
    }
    return drained;
}

static void eth_rx_drain_timer(void *arg)
{
    LWIP_UNUSED_ARG(arg);
    struct netif *netif = NULL;
    size_t budget = eth_drain_budget();
    NETIF_FOREACH(netif)
    {
        if (budget == 0)
        {
            break;
        }
        if (!netif || netif->name[0] != 'e' || netif->name[1] != 'n' || !netif->state)
        {
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        if (!dev->rx_ring || !dev->rx_ring->u.ring.drain_fn)
        {
            continue;
        }
        size_t drained = dev->rx_ring->u.ring.drain_fn(dev->rx_ring, dev->rx_ring->u.ring.drain_fn_data, budget);
        if (drained > budget)
        {
            drained = budget;
        }
        budget -= drained;
    }
    sys_timeout(g_eth_rx_drain_interval_ms, eth_rx_drain_timer, NULL);
}


static void eth_rx_ring_pressure_cb(struct mem_buffer *mb, size_t requested, enum mem_pressure_level level)
{
    (void)mb;
    (void)requested;
    eth_set_rx_throttle(level);
}

void eth_set_rx_throttle(enum mem_pressure_level level)
{
    g_eth_rx_throttle_level = level;
    g_eth_rx_sched_interval_ms = eth_rx_schedule_interval_ms();
    if (g_eth_rx_throttle_level == MEM_PRESSURE_CRITICAL)
    {
        g_eth_rx_sched_scheduled = false;
        return;
    }
    if (!g_eth_rx_sched_scheduled)
    {
        sys_timeout(g_eth_rx_sched_interval_ms, eth_rx_schedule_timer, NULL);
        g_eth_rx_sched_scheduled = true;
    }
}

void eth_set_rx_drain_interval_ms(uint32_t interval_ms)
{
    if (interval_ms == 0)
    {
        interval_ms = ETH_RX_DRAIN_INTERVAL_MS;
    }
    g_eth_rx_drain_interval_ms = interval_ms;
}

/// UTF-16 -> hex conversion
uint8_t
nibble(uint16_t c)
{
    c -= '0';
    if (c < 10)
        return c;
    c -= 'A' - '0';
    if (c < 6)
        return c + 10;
    c -= 'a' - 'A';
    if (c < 6)
        return c + 10;
    return 0xff;
}

bool eth_xmit_fatal_error(eth_device_t *dev, uint8_t retries)
{
    if (retries == ETH_USB_MAX_RETRIES)
    {
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SEVERE,
                    ("int: endpoint failure, giving up"));
        lwip_log_event(LWIP_LOG_MODULE_USB, LWIP_LOG_USB_FATAL_RETRY);
        // if it fails repeatedly, free the pbuf, disable the device,
        // and set driver error state
        usb_fn.disable_device(dev->device);
        eth_disabled_with_error = true;
        return true;
    }
    return false;
}

struct eth_tx_ctx
{
    eth_device_t *dev;
    struct pbuf *p;
};

///---------------------------------------------------
/// @brief interrupt transfer callback function
usb_error_t
interrupt_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                           usb_transfer_status_t status,
                           size_t transferred,
                           usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    uint8_t *ibuf = dev->interrupt.buf;
    static uint8_t int_retries = 0;
    if (status)
    {
        log_usb_transfer_status(status);
        // much like RX, we will retry a INT USB_CDC_MAX_RETRIES times
        if (eth_xmit_fatal_error(dev, int_retries))
            return USB_ERROR_FAILED;
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("int: endpoint failure, retry=%u", int_retries));
        // increment TX retry counter and queue the transfer again
        int_retries++;
    }
    else if ((status == USB_TRANSFER_COMPLETED) && transferred)
    {
        usb_control_setup_t *notify;
        size_t bytes_parsed = 0;
        do
        {
            notify = (usb_control_setup_t *)&ibuf[bytes_parsed];
            if (notify->bmRequestType == 0b10100001)
            {
                switch (notify->bRequest)
                {
                case NOTIFY_NETWORK_CONNECTION:
                    if (notify->wValue)
                    {
                        netif_set_link_up(&dev->iface);
                        if (ETH_START_DHCP_ON_ALL)
                            dhcp_start(&dev->iface);
                        if (netif_default == NULL)
                        {
                            netif_set_default(&dev->iface);
                        }
                    }
                    else
                    {
                        netif_set_link_down(&dev->iface);
                        if (netif_default == &dev->iface)
                        {
                            /* Find another connected netif to promote as default */
                            struct netif *candidate = netif_list;
                            struct netif *new_default = NULL;
                            while (candidate)
                            {
                                if (candidate != &dev->iface && netif_is_link_up(candidate))
                                {
                                    new_default = candidate;
                                    break;
                                }
                                candidate = candidate->next;
                            }
                            netif_set_default(new_default);
                        }
                    }
                    break;
                case NOTIFY_CONNECTION_SPEED_CHANGE:
                    // this will have no effect - calc too slow
                    break;
                }
            }
            bytes_parsed += sizeof(usb_control_setup_t) + notify->wLength;
        } while (bytes_parsed < transferred);
        int_retries = 0;
    }
    usb_fn.schedule_transfer(dev->interrupt.endpoint, dev->interrupt.buf, INTERRUPT_RX_MAX, interrupt_receive_callback, data);
    return USB_SUCCESS;
}

///---------------------------------------------------
/// @brief bulk out callback function
usb_error_t bulk_transmit_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                   usb_transfer_status_t status,
                                   __attribute__((unused)) size_t transferred,
                                   usb_transfer_data_t *data)
{
    // Handle completion or error of the transfer, if needed
    struct eth_tx_ctx *ctx = (struct eth_tx_ctx *)data;
    eth_device_t *dev = ctx->dev;
    struct pbuf *tbuf = ctx->p;
    static uint8_t tx_retries = 0;
    if (status)
    {
        log_usb_transfer_status(status);
        // much like RX, we will retry a TX USB_CDC_MAX_RETRIES times
        if (eth_xmit_fatal_error(dev, tx_retries))
        {
            pbuf_free(tbuf);
            free(ctx);
            tx_retries = 0;  // Reset retry counter on fatal error
            return USB_ERROR_FAILED;
        }
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("tx: endpoint failure, retry=%u", tx_retries));
        // increment TX retry counter and queue the transfer again
        tx_retries++;
        usb_fn.schedule_transfer(dev->tx.endpoint, tbuf->payload, tbuf->tot_len, bulk_transmit_callback, ctx);
        return USB_SUCCESS;
    }

    // Successful transmission - reset retry counter
    tx_retries = 0;

    if (tbuf)
        pbuf_free(tbuf);
    free(ctx);

    return USB_SUCCESS;
}

///------------------------------------------------------------------------
/// @brief linkinput callback function for @b Ethernet_Control_Model (ECM)
usb_error_t ecm_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                 usb_transfer_status_t status,
                                 size_t transferred,
                                 usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    uint8_t *recvbuf = dev->rx.buf;
    static uint8_t rx_retries = 0;
    dev->rx_transfer_active = false;
    if (status)
    {
        log_usb_transfer_status(status);
        if (eth_xmit_fatal_error(dev, rx_retries))
            return USB_ERROR_FAILED;

        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("ecm_rx: endpoint failure, retry=%u", rx_retries));
        rx_retries++;
        return USB_SUCCESS;
    }
    else if (transferred)
    {
        rx_retries = 0;
        bool pushed = eth_ring_push_frame(dev, recvbuf, (uint16_t)transferred);
        LINK_STATS_INC(link.recv);
        MIB2_STATS_NETIF_ADD(&dev->iface, ifinoctets, transferred);
    }
    return USB_SUCCESS;
}

///----------------------------------------------------------------
/// @brief linkoutput function for @b Ethernet_Control_Model (ECM)
err_t ecm_bulk_transmit(struct netif *netif, struct pbuf *p)
{
    eth_device_t *dev = (eth_device_t *)netif->state;
    if (p->tot_len > ETHERNET_MTU)
        return ERR_MEM;
    struct pbuf *tbuf = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
    if (tbuf == NULL)
        return ERR_MEM;
    struct eth_tx_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        pbuf_free(tbuf);
        return ERR_MEM;
    }
    LINK_STATS_INC(link.xmit);
    // Update SNMP stats(only if you use SNMP)
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
    if (pbuf_copy(tbuf, p))
    {
        pbuf_free(tbuf);
        free(ctx);
        return ERR_MEM;
    }
    ctx->dev = dev;
    ctx->p = tbuf;
    usb_fn.schedule_transfer(dev->tx.endpoint, tbuf->payload, tbuf->tot_len, bulk_transmit_callback, ctx);
    return ERR_OK;
}

/****************************************************************************
 * Code for Network Control Model (NCM)
 * for USB-Ethernet devices
 */

/* Flag Values for NCM Network Capabilities. */
enum _cdc_ncm_bm_networkcapabilities
{
    CAPABLE_ETHERNET_PACKET_FILTER,
    CAPABLE_NET_ADDRESS,
    CAPABLE_ENCAPSULATED_RESPONSE,
    CAPABLE_MAX_DATAGRAM,
    CAPABLE_NTB_INPUT_SIZE_8BYTE
};
/* Helper Macro for Returning State of Network Capabilities Flag. */
#define ncm_device_supports(dev, bm) (((dev)->class.ncm.bm_capabilities >> (bm)) & 1)

/* Data Structure for NTB Config control request. */
struct _ntb_config_data
{
    uint32_t dwNtbInMaxSize;
    uint16_t wNtbInMaxDatagrams;
    uint16_t reserved;
};

/* NCM Transfer Header (NTH) Defintion */
#define NCM_NTH_SIG 0x484D434E
struct ncm_nth
{
    uint32_t dwSignature;   // "NCMH"
    uint16_t wHeaderLength; // size of this header structure (should be 12 for NTB-16)
    uint16_t wSequence;     // counter for NTB's sent
    uint16_t wBlockLength;  // size of the NTB
    uint16_t wNdpIndex;     // offset to first NDP
};

/* NCM Datagram Pointers (NDP) Definition */
struct ncm_ndp_idx
{
    uint16_t wDatagramIndex; // offset of datagram, if 0, then is end of datagram list
    uint16_t wDatagramLen;   // length of datagram, if 0, then is end of datagram list
};
#define NCM_NDP_SIG0 0x304D434E
#define NCM_NDP_SIG1 0x314D434E
struct ncm_ndp
{
    uint32_t dwSignature;               // "NCM0"
    uint16_t wLength;                   // size of NDP16
    uint16_t wNextNdpIndex;             // offset to next NDP16
    struct ncm_ndp_idx wDatagramIdx[1]; // pointer to end of NDP
};

#define NCM_NTH_LEN sizeof(struct ncm_nth)
#define NCM_NDP_LEN sizeof(struct ncm_ndp)
#define NCM_RX_MAX_DATAGRAMS 4
#define NCM_RX_DATAGRAMS_OVERFLOW_MUL 16 // this is here in the event that max datagrams is unsupported
#define NCM_RX_QUEUE_LEN (NCM_RX_MAX_DATAGRAMS * NCM_RX_DATAGRAMS_OVERFLOW_MUL)

///------------------------------------------------------------
/// @brief control setup for @b Network_Control_Model (NCM)
usb_error_t ncm_control_setup(eth_device_t *eth)
{
    if (eth->type != USB_NCM_SUBCLASS)
        return USB_SUCCESS;
    size_t transferred;
    usb_error_t error = 0;
    usb_control_setup_t get_ntb_params = {0b10100001, REQUEST_GET_NTB_PARAMETERS, 0, 0, 0x1c};
    usb_control_setup_t ntb_config_request = {0b00100001, REQUEST_SET_NTB_INPUT_SIZE, 0, 0, ncm_device_supports(eth, CAPABLE_NTB_INPUT_SIZE_8BYTE) ? 8 : 4};
    // usb_control_setup_t multicast_filter_request = {0b00100001, REQUEST_SET_ETHERNET_MULTICAST_FILTERS, 0, 0, 0};
    usb_control_setup_t packet_filter_request = {0b00100001, REQUEST_SET_ETHERNET_PACKET_FILTER, 0x01, 0, 0};
    struct _ntb_config_data ntb_config_data = {NCM_RX_NTB_MAX_SIZE, NCM_RX_MAX_DATAGRAMS, 0};

    /* Query NTB Parameters for device (NCM devices) */
    error |= usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0), &get_ntb_params, &eth->class.ncm.ntb_params, USB_CDC_MAX_RETRIES, &transferred);

    /* Set NTB Max Input Size to 2048 (recd minimum NCM spec v 1.2) */
    error |= usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0), &ntb_config_request, &ntb_config_data, USB_CDC_MAX_RETRIES, &transferred);

    /* Reset packet filters */
    if (ncm_device_supports(eth, CAPABLE_ETHERNET_PACKET_FILTER))
        error |= usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0), &packet_filter_request, NULL, USB_CDC_MAX_RETRIES, &transferred);

    return error;
}

///------------------------------------------------------------
/// @brief linkinput function for @b Network_Control_Model (NCM)
usb_error_t ncm_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                 usb_transfer_status_t status,
                                 size_t transferred,
                                 usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    uint8_t *recvbuf = dev->rx.buf;
    static uint8_t rx_retries = 0;
    dev->rx_transfer_active = false;
    if (status)
    {
        log_usb_transfer_status(status);
        if (eth_xmit_fatal_error(dev, rx_retries))
        {
            pbuf_free(data);
            return USB_ERROR_FAILED;
        }
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("ncm_rx: endpoint failure, retry=%u", rx_retries));
        rx_retries++;
        return USB_SUCCESS;
    }
    if (transferred)
    {
        rx_retries = 0;
        bool parse_ntb = true;

        // get header and first NDP pointers
        uint8_t *ntb = (uint8_t *)recvbuf;
        struct ncm_nth *nth = (struct ncm_nth *)ntb;
        if (nth->dwSignature != NCM_NTH_SIG)
            return USB_SUCCESS; // validate NTH signature field. If invalid, fail out

        // start proc'ing first NDP
        struct ncm_ndp *ndp = (struct ncm_ndp *)&ntb[nth->wNdpIndex];

        // repeat while ndp->wNextNdpIndex is non-zero
        do
        {
            if (ndp->dwSignature != NCM_NDP_SIG0)
                return USB_SUCCESS; // validate NDP signature field, if invalid, fail out

            // set datagram number to 0 and set datagram index pointer
            uint16_t dg_num = 0;
            struct ncm_ndp_idx *idx = (struct ncm_ndp_idx *)&ndp->wDatagramIdx;

            // a null datagram index structure indicates end of NDP
            do
            {
                // attempt to allocate pbuf
                if (!eth_ring_push_frame(dev, &ntb[idx[dg_num].wDatagramIndex], idx[dg_num].wDatagramLen))
                {
                    parse_ntb = false;
                    break;
                }
                dg_num++;
            } while ((idx[dg_num].wDatagramIndex) && (idx[dg_num].wDatagramLen));
            // if next NDP is 0, NTB is done and so is my sanity
            if (ndp->wNextNdpIndex == 0)
                break;
            // set next NDP
            ndp = (struct ncm_ndp *)&ntb[ndp->wNextNdpIndex];
        } while (parse_ntb);

        LINK_STATS_INC(link.recv);
        MIB2_STATS_NETIF_ADD(&dev->iface, ifinoctets, transferred);
    }
    return USB_SUCCESS;
}

/* This code packs a single TX Ethernet frame into an NCM transfer. */
#define NCM_HBUF_SIZE 64
#define get_next_offset(offset, divisor, remainder) \
    (offset) + (divisor) - ((offset) % (divisor)) + (remainder)

///---------------------------------------------------------------
/// @brief linkoutput function for @b Network_Control_Model (NCM)
err_t ncm_bulk_transmit(struct netif *netif, struct pbuf *p)
{
    eth_device_t *dev = (eth_device_t *)netif->state;
    uint16_t offset_ndp = get_next_offset(NCM_NTH_LEN, dev->class.ncm.ntb_params.wNdpInAlignment, 0);
    if (p->tot_len > ETHERNET_MTU)
        return ERR_MEM;

    // allocate TX packet buffer
    struct pbuf *obuf = pbuf_alloc(PBUF_RAW, ETHERNET_MTU + NCM_HBUF_SIZE, PBUF_RAM);
    if (obuf == NULL)
        return ERR_MEM;
    struct eth_tx_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        pbuf_free(obuf);
        return ERR_MEM;
    }

    memset(obuf->payload, 0, ETHERNET_MTU + NCM_HBUF_SIZE);

    // declare NTH, NDP, and NDP_IDX structures
    uint8_t hdr_buf[NCM_HBUF_SIZE] = {0};
    struct ncm_nth *nth = (struct ncm_nth *)hdr_buf;
    struct ncm_ndp *ndp = (struct ncm_ndp *)&hdr_buf[offset_ndp];

    // populate structs
    nth->dwSignature = NCM_NTH_SIG;
    nth->wHeaderLength = NCM_NTH_LEN;
    nth->wSequence = dev->class.ncm.sequence++;
    nth->wBlockLength = NCM_HBUF_SIZE + ETHERNET_MTU;
    nth->wNdpIndex = offset_ndp;

    ndp->dwSignature = NCM_NDP_SIG0;
    ndp->wLength = NCM_NDP_LEN + 4;
    ndp->wNextNdpIndex = 0;

    ndp->wDatagramIdx[0].wDatagramIndex = NCM_HBUF_SIZE;
    ndp->wDatagramIdx[0].wDatagramLen = p->tot_len;
    ndp->wDatagramIdx[1].wDatagramIndex = 0;
    ndp->wDatagramIdx[1].wDatagramLen = 0;

    // absorb the populated structs into the obuf
    pbuf_take(obuf, hdr_buf, NCM_HBUF_SIZE);

    // copy the datagram to the pbuf
    pbuf_copy_partial(p, obuf->payload + NCM_HBUF_SIZE, p->tot_len, 0);
    LINK_STATS_INC(link.xmit);
    // Update SNMP stats(only if you use SNMP)
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);

    // queue the TX
    // printf("sent packet %u at time %lu\n", sequence, sys_now());
    ctx->dev = dev;
    ctx->p = obuf;
    usb_fn.schedule_transfer(dev->tx.endpoint, obuf->payload, obuf->tot_len, bulk_transmit_callback, ctx);
    return ERR_OK;
}

///----------------------------------------
/// @brief ethernet NETIF initialization
err_t eth_netif_init(struct netif *netif)
{
    eth_device_t *dev = (eth_device_t *)netif->state;
    netif->linkoutput = dev->tx.emit;
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->mtu = ETHERNET_MTU;
    netif->mtu6 = ETHERNET_MTU;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;
    MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 100000000);
    memcpy(netif->hwaddr, dev->hwaddr, NETIF_MAX_HWADDR_LEN);
    netif->hwaddr_len = NETIF_MAX_HWADDR_LEN;
    // netif_set_link_callback(netif, eth_link_callback);
    // netif_set_status_callback(netif, eth_status_callback);
    return ERR_OK;
}

/** DESCRIPTOR PARSER AWAIT STATES */
enum _descriptor_parser_await_states
{
    PARSE_HAS_CONTROL_IF = 1,
    PARSE_HAS_MAC_ADDR = (1 << 1),
    PARSE_HAS_BULK_IF_NUM = (1 << 2),
    PARSE_HAS_BULK_IF = (1 << 3),
    PARSE_HAS_ENDPOINT_INT = (1 << 4),
    PARSE_HAS_ENDPOINT_IN = (1 << 5),
    PARSE_HAS_ENDPOINT_OUT = (1 << 6)
};

/*****************************************************************************************
 * @brief Parses descriptors for a USB device and checks for a valid CDC Ethernet device.
 * @return \b True if success (with NETIF initialized), \b False if not CDC-ECM/NCM or error.
 */
#define DESCRIPTOR_MAX_LEN 256
bool init_ethernet_usb_device(usb_device_t device)
{
    eth_device_t tmp = {0};
    eth_device_t *eth = NULL;
    size_t xferd, parsed_len, desc_len;
    usb_error_t err;
    tmp.device = device;

    if (ifnums_used == 0b11111111)
    {
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_WARNING,
                    ("WARNING, device=%p, if_slots full", device));
        return false;
    }

    struct
    {
        usb_configuration_descriptor_t *addr;
        size_t len;
    } configdata;
    struct
    {
        usb_interface_descriptor_t *addr;
        size_t len;
    } if_bulk;
    struct
    {
        uint8_t in, out, interrupt;
    } endpoint_addr;
    union
    {
        uint8_t bytes[DESCRIPTOR_MAX_LEN];   // allocate 256 bytes for descriptors
        usb_descriptor_t desc;               // descriptor type aliases
        usb_device_descriptor_t dev;         // .. device descriptor alias
        usb_configuration_descriptor_t conf; // .. config descriptor alias
    } descriptor;
    err = usb_fn.get_descriptor(device, USB_DEVICE_DESCRIPTOR, 0, &descriptor.dev, sizeof(usb_device_descriptor_t), &xferd);
    if (err || (xferd != sizeof(usb_device_descriptor_t)))
        return false;

    // check for main DeviceClass being type 0x00 - composite/if-specific
    if (descriptor.dev.bDeviceClass != USB_INTERFACE_SPECIFIC_CLASS)
        return false;

    // parse both configs for the correct one
    uint8_t num_configs = descriptor.dev.bNumConfigurations;
    for (uint8_t config = 0; config < num_configs; config++)
    {
        uint8_t ifnum = 0;
        uint8_t parse_state = 0;
        desc_len = usb_fn.get_config_descriptor_len(device, config);
        parsed_len = 0;
        if (desc_len > 256)
            // if we overflow buffer, skip descriptor
            continue;
        // fetch config descriptor
        err = usb_fn.get_descriptor(device, USB_CONFIGURATION_DESCRIPTOR, config, &descriptor.conf, desc_len, &xferd);
        if (err || (xferd != desc_len))
            // if error or not full descriptor, skip
            continue;

        // set pointer to current working descriptor
        usb_descriptor_t *desc = &descriptor.desc;
        while (parsed_len < desc_len)
        {
            switch (desc->bDescriptorType)
            {
            case USB_ENDPOINT_DESCRIPTOR:
            {
                // we should only look for this IF we have found the ECM control interface,
                // and have retrieved the bulk data interface number from the CS_INTERFACE descriptor
                // see case USB_CS_INTERFACE_DESCRIPTOR and case USB_INTERFACE_DESCRIPTOR
                usb_endpoint_descriptor_t *endpoint = (usb_endpoint_descriptor_t *)desc;
                if (parse_state & PARSE_HAS_BULK_IF)
                {
                    if (endpoint->bEndpointAddress & (USB_DEVICE_TO_HOST))
                    {
                        endpoint_addr.in = endpoint->bEndpointAddress; // set out endpoint address
                        parse_state |= PARSE_HAS_ENDPOINT_IN;
                    }
                    else
                    {
                        endpoint_addr.out = endpoint->bEndpointAddress; // set in endpoint address
                        parse_state |= PARSE_HAS_ENDPOINT_OUT;
                    }
                    if ((parse_state & PARSE_HAS_ENDPOINT_IN) &&
                        (parse_state & PARSE_HAS_ENDPOINT_OUT) &&
                        (parse_state & PARSE_HAS_ENDPOINT_INT) &&
                        (parse_state & PARSE_HAS_MAC_ADDR))
                        goto init_success; // if we have both, we are done -- hard exit
                }
                else if (parse_state & PARSE_HAS_CONTROL_IF)
                {
                    endpoint_addr.interrupt = endpoint->bEndpointAddress;
                    parse_state |= PARSE_HAS_ENDPOINT_INT;
                }
            }
            break;
            case USB_INTERFACE_DESCRIPTOR:
                // we should look for this to either:
                // (1) find the CDC Control Class/ECM interface, or
                // (2) find the Interface number that matches the Interface indicated by the USB_CS_INTERFACE descriptor
                {
                    // cast to struct of type interface descriptor
                    usb_interface_descriptor_t *iface = (usb_interface_descriptor_t *)desc;
                    // if we have a control interface and ifnum is non-zero (we have an interface num to look for)
                    if (parse_state & PARSE_HAS_BULK_IF_NUM)
                    {
                        if ((iface->bInterfaceNumber == ifnum) &&
                            (iface->bNumEndpoints == 2) &&
                            (iface->bInterfaceClass == USB_CDC_DATA_CLASS))
                        {
                            if_bulk.addr = iface;
                            if_bulk.len = desc_len - parsed_len;
                            parse_state |= PARSE_HAS_BULK_IF;
                        }
                    }
                    else
                    {
                        // if we encounter another interface type after a control interface that isn't the CS_INTERFACE
                        // then we don't have the correct interface. This could be a malformed descriptor or something else
                        parse_state = 0; // reset parser state

                        // If the interface is class CDC control and subtype ECM, this might be the correct interface union
                        // the next thing we should encounter is see case USB_CS_INTERFACE_DESCRIPTOR
                        if ((iface->bInterfaceClass == USB_COMM_CLASS) &&
                            ((iface->bInterfaceSubClass == USB_ECM_SUBCLASS) ||
                             (iface->bInterfaceSubClass == USB_NCM_SUBCLASS)))
                        {
                            // use this to set configuration
                            configdata.addr = &descriptor.conf;
                            configdata.len = desc_len;
                            tmp.type = iface->bInterfaceSubClass;
                            if (usb_fn.set_configuration(device, configdata.addr, configdata.len))
                                return false;
                            parse_state |= PARSE_HAS_CONTROL_IF;
                        }
                    }
                }
                break;
            case USB_CS_INTERFACE_DESCRIPTOR:
                // this is a class-specific descriptor that specifies the interfaces used by the control interface
                {
                    usb_cs_interface_descriptor_t *cs = (usb_cs_interface_descriptor_t *)desc;
                    switch (cs->bDescriptorSubType)
                    {
                    case USB_ETHERNET_FUNCTIONAL_DESCRIPTOR:
                    {
                        usb_ethernet_functional_descriptor_t *ethdesc = (usb_ethernet_functional_descriptor_t *)cs;
                        usb_control_setup_t get_mac_addr = {0b10100001, REQUEST_GET_NET_ADDRESS, 0, 0, 6};
                        size_t xferd_tmp;
                        uint8_t string_descriptor_buf[DESCRIPTOR_MAX_LEN];
                        usb_string_descriptor_t *macaddr = (usb_string_descriptor_t *)string_descriptor_buf;
                        // Get MAC address and save for lwIP use (ETHARP header)
                        // if index for iMacAddress valid and GetStringDescriptor success, save MAC address
                        // else attempt control transfer to get mac address and save it
                        // else generate random compliant local MAC address and send control request to set the hwaddr, then save it
                        if (ethdesc->iMacAddress &&
                            (!usb_fn.get_string_descriptor(device, ethdesc->iMacAddress, 0, macaddr, DESCRIPTOR_MAX_LEN, &xferd_tmp)))
                        {
                            for (uint24_t i = 0; i < NETIF_MAX_HWADDR_LEN; i++)
                                tmp.hwaddr[i] = (nibble(macaddr->bString[2 * i]) << 4) | nibble(macaddr->bString[2 * i + 1]);

                            parse_state |= PARSE_HAS_MAC_ADDR;
                        }
                        else if (!usb_fn.control_transfer(usb_fn.get_device_endpoint(device, 0), &get_mac_addr, &tmp.hwaddr[0], ETH_USB_MAX_RETRIES, &xferd_tmp))
                        {
                            parse_state |= PARSE_HAS_MAC_ADDR;
                        }
                        else
                        {
#define RMAC_RANDOM_MAX 0xFFFFFF
                            usb_control_setup_t set_mac_addr = {0b00100001, REQUEST_SET_NET_ADDRESS, 0, 0, 6};
                            uint24_t rmac[2];
                            rmac[0] = (uint24_t)(random() & RMAC_RANDOM_MAX);
                            rmac[1] = (uint24_t)(random() & RMAC_RANDOM_MAX);
                            memcpy(&tmp.hwaddr[0], rmac, 6);
                            tmp.hwaddr[0] &= 0xFE;
                            tmp.hwaddr[0] |= 0x02;
                            if (!usb_fn.control_transfer(usb_fn.get_device_endpoint(device, 0), &set_mac_addr, &tmp.hwaddr[0], ETH_USB_MAX_RETRIES, &xferd_tmp))
                            {
                                parse_state |= PARSE_HAS_MAC_ADDR;
                            }
                        }
                    }
                    break;
                    case USB_UNION_FUNCTIONAL_DESCRIPTOR:
                    {
                        // if union functional type, this contains interface number for bulk transfer
                        usb_union_functional_descriptor_t *func = (usb_union_functional_descriptor_t *)cs;
                        ifnum = func->bInterface;
                        parse_state |= PARSE_HAS_BULK_IF_NUM;
                    }
                    break;
                    case USB_NCM_FUNCTIONAL_DESCRIPTOR:
                    {
                        usb_ncm_functional_descriptor_t *ncm = (usb_ncm_functional_descriptor_t *)cs;
                        tmp.class.ncm.bm_capabilities = ncm->bmNetworkCapabilities;
                    }
                    break;
                    }
                }
            }
            parsed_len += desc->bLength;
            desc = (usb_descriptor_t *)(((uint8_t *)desc) + desc->bLength);
        }
    }
    return false;
init_success:
    if (ncm_control_setup(&tmp))
        return false;

    tmp.rx.callback = (tmp.type == USB_NCM_SUBCLASS)   ? ncm_receive_callback
                      : (tmp.type == USB_ECM_SUBCLASS) ? ecm_receive_callback
                                                       : NULL;

    tmp.tx.emit = (tmp.type == USB_NCM_SUBCLASS)   ? ncm_bulk_transmit
                  : (tmp.type == USB_ECM_SUBCLASS) ? ecm_bulk_transmit
                                                   : NULL;

    if ((tmp.tx.emit == NULL) || (tmp.rx.callback == NULL))
        return false;

    // switch to alternate interface
    if (usb_fn.set_interface(device, if_bulk.addr, if_bulk.len))
        return false;

    // set endpoint data
    tmp.rx.endpoint = usb_fn.get_device_endpoint(device, endpoint_addr.in);
    tmp.tx.endpoint = usb_fn.get_device_endpoint(device, endpoint_addr.out);
    tmp.interrupt.endpoint = usb_fn.get_device_endpoint(device, endpoint_addr.interrupt);
    // allocate eth_device_t => contains type, usb device, metadata, and INT/RX buffers

    // better ifnum assignment
    uint8_t ifnum_assigned;
#define NETIFS_MAX_ALLOWED 8
#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))
    for (ifnum_assigned = 0; ifnum_assigned < NETIFS_MAX_ALLOWED; ifnum_assigned++)
        if (!CHECK_BIT(ifnums_used, ifnum_assigned))
            break;

#if ETH_DEBUG
    if (ifnum_assigned == NETIFS_MAX_ALLOWED)
    {
        // this is a bug because code earlier should detect this condition
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("ERROR: Interface assign err. This is a bug. File an issue on https://github.com/cagstech/lwip-ce with the following:\nusb_ethernet.c:731 ifs_used=%u, if_assign=%u", ifnums_used, ifnum_assigned));
        return false;
    }
#endif

    if (usb_fn.get_device_data(device))
    {
        // ## IF DEVICE ALREADY USED FOR NETIF ##
        // reuse existing eth_device_t address
        eth = (eth_device_t *)usb_fn.get_device_data(device);
        struct mem_buffer *saved_rx_ring = eth->rx_ring;
        // copy new usb config without destroying netif config
        memcpy(eth, &tmp, sizeof(eth_device_t) - sizeof(struct netif));
        eth->rx_ring = saved_rx_ring;
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_STATE,
                    ("RESUME, netif=%c%c%u <- device=%p", eth->iface.name[0], eth->iface.name[1], eth->iface.num, device));
        eth_netif_init(&eth->iface);
        if (netif_default == NULL)
        {
            netif_set_default(&eth->iface);
        }
    }
    else
    {
        // ## ELSE CONFIG NEW NETIF ##
        if ((eth = malloc(sizeof(eth_device_t))) == NULL)
            return false;
        memcpy(eth, &tmp, sizeof(eth_device_t));
        struct netif *iface = &eth->iface;
        // add to lwIP list of active netifs (save pointer to eth_device_t too)
        if (netif_add_noaddr(iface, eth, eth_netif_init, netif_input) == NULL)
        {
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                        ("ERROR, ? netif= <- device=%p, netif add failed", device));
            free(eth);
            return false;
        }
        if (netif_default == NULL)
        {
            netif_set_default(iface);
        }
        // fetch next available device number to use
        // set pointer to eth_device_t as associated data for usb device too
        usb_fn.set_device_data(device, eth);

        iface->name[0] = 'e';
        iface->name[1] = 'n';

        iface->num = ifnum_assigned; // use IFnum that triggered break

        // allow IPv4 and IPv6 on device
        netif_create_ip6_linklocal_address(iface, 1);
        iface->ip6_autoconfig_enabled = 1;

        ifnums_used |= 1 << ifnum_assigned;  // set flag marking the ifnum used
        netif_set_hostname(iface, hostname); // set default hostname
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_STATE,
                    ("NEW, netif=%c%c%u <- device=%p", iface->name[0], iface->name[1], iface->num, device));
    }

    if (!eth->rx_ring)
    {
        eth->rx_ring = mem_buffer_create(MEM_BUFFER_RING, ETH_RX_RING_INIT_SIZE, ETH_RX_RING_MAX_SIZE, ETH_RX_RING_STEP_SIZE, 0);
        if (!eth->rx_ring)
        {
            return false;
        }
        mem_buffer_set_drain(eth->rx_ring, eth_rx_ring_drain, &eth->iface);
        mem_buffer_set_pressure_cb(eth->rx_ring, eth_rx_ring_pressure_cb);
        mem_buffer_set_grow(eth->rx_ring, 85, ETH_RX_RING_STEP_SIZE);
        mem_buffer_set_shrink(eth->rx_ring, 30, ETH_RX_RING_STEP_SIZE);
    }
    if (!g_eth_rx_drain_scheduled)
    {
        sys_timeout(g_eth_rx_drain_interval_ms, eth_rx_drain_timer, NULL);
        g_eth_rx_drain_scheduled = true;
    }
    if (!g_eth_rx_sched_scheduled && g_eth_rx_throttle_level != MEM_PRESSURE_CRITICAL)
    {
        g_eth_rx_sched_interval_ms = eth_rx_schedule_interval_ms();
        sys_timeout(g_eth_rx_sched_interval_ms, eth_rx_schedule_timer, NULL);
        g_eth_rx_sched_scheduled = true;
    }

    netif_set_up(&eth->iface); // tell lwIP that the interface is ready to receive
    // enqueue callbacks for receiving interrupt and RX transfers from this device.
    usb_fn.schedule_transfer(eth->interrupt.endpoint, eth->interrupt.buf, INTERRUPT_RX_MAX, interrupt_receive_callback, eth);
    return true;
}

usb_error_t
eth_usb_event_callback(usb_event_t event, void *event_data,
                       __attribute__((unused)) usb_callback_data_t *callback_data)
{
    usb_device_t usb_device = event_data;
    /* Enable newly connected devices */
    switch (event)
    {
    case USB_DEVICE_CONNECTED_EVENT:
        if (!(usb_fn.get_role() & USB_ROLE_DEVICE))
            usb_fn.reset_device(usb_device);
        break;
    case USB_DEVICE_ENABLED_EVENT:
        if (usb_fn.get_device_flags(usb_device) & USB_IS_HUB)
        {
            // add handling for hubs
            union
            {
                uint8_t bytes[DESCRIPTOR_MAX_LEN];   // allocate 256 bytes for descriptors
                usb_configuration_descriptor_t conf; // .. config descriptor alias
            } descriptor;
            size_t desc_len = usb_fn.get_config_descriptor_len(usb_device, 0);
            size_t xferd;
            usb_fn.get_descriptor(usb_device, USB_CONFIGURATION_DESCRIPTOR, 0, &descriptor.conf, desc_len, &xferd);
            if (desc_len != xferd)
                break;
            usb_fn.set_configuration(usb_device, &descriptor.conf, desc_len);
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_STATE,
                        ("NEW device=%p, type=hub", usb_device));
            break;
        }
        if (init_ethernet_usb_device(usb_device))
            break;
        break;
    case USB_DEVICE_DISCONNECTED_EVENT:
    case USB_DEVICE_DISABLED_EVENT:
    {
        eth_device_t *eth_device = (eth_device_t *)usb_fn.get_device_data(usb_device);
        if (eth_device)
        {
            netif_set_link_down(&eth_device->iface);
            netif_set_down(&eth_device->iface);
            if (eth_device->rx.endpoint)
            {
                usb_fn.set_endpoint_flags(eth_device->rx.endpoint, USB_MANUAL_TERMINATE);
                usb_fn.set_endpoint_halt(eth_device->rx.endpoint);
            }
            if (eth_device->tx.endpoint)
            {
                usb_fn.set_endpoint_flags(eth_device->tx.endpoint, USB_MANUAL_TERMINATE);
                usb_fn.set_endpoint_halt(eth_device->tx.endpoint);
            }
            if (eth_device->interrupt.endpoint)
            {
                usb_fn.set_endpoint_flags(eth_device->interrupt.endpoint, USB_MANUAL_TERMINATE);
                usb_fn.set_endpoint_halt(eth_device->interrupt.endpoint);
            }
        }
        if (eth_disabled_with_error && ETH_DO_RESTART_ON_ERROR)
        {
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SEVERE,
                        ("device ptr=%p: disabled with error, resetting!", usb_device));
            usb_fn.reset_device(usb_device);
            eth_disabled_with_error = false;
            break;
        }
        if (eth_device)
        {
            ifnums_used &= ~(1 << eth_device->iface.num);
            netif_remove(&eth_device->iface);
            if (eth_device->rx_ring)
            {
                mem_buffer_destroy(eth_device->rx_ring);
                eth_device->rx_ring = NULL;
            }
            free(eth_device);
            eth_device = NULL;
            usb_fn.set_device_data(usb_device, eth_device);
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SEVERE,
                        ("device ptr=%p: disconnected", usb_device));
        }
    }
    break;
    case USB_HOST_PORT_CONNECT_STATUS_CHANGE_INTERRUPT:
        return USB_ERROR_NO_DEVICE;
        break;
    default:
        break;
    }
    return USB_SUCCESS;
}

uint8_t eth_get_interfaces(void)
{
    return ifnums_used;
}
