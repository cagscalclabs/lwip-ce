/****************************************************************************
 * Code for Communications Data Class (CDC)
 * for USB-Ethernet devices
 * Includes Callbacks, USB Event handlers, and netif initialization
 */

#include <sys/util.h>
#include <stddef.h>
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
#include "lwip/prot/dhcp.h"
#include "usb_ethernet.h" /* Communications Data Class header file */
#include "lwip-imports.h" /* fn_imports_table / usb_fn dispatch table */
#include "mem.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/logging.h"
#include "lwip/app_config.h"
#include "lwip/teardown.h"
#include "lwip/dispatch.h"

#define ETH_USB_MAX_RETRIES 5
#define ETH_DO_RESTART_ON_ERROR true
static uint8_t ifnums_used = 0;
static bool eth_driver_shutting_down = false;

static void log_usb_transfer_status(usb_transfer_status_t status)
{
    if (status & USB_TRANSFER_NO_DEVICE)
    {
        lwip_debug_emit(LWIP_DBG_MOD_USB, LWIP_DBG_USB_ENDPOINT_NO_DEVICE,
                        (int)status, 0);
    }
    if (status & USB_TRANSFER_STALLED)
    {
        lwip_debug_emit(LWIP_DBG_MOD_USB, LWIP_DBG_USB_ENDPOINT_STALL,
                        (int)status, 0);
    }
    if (status & (USB_TRANSFER_ERROR | USB_TRANSFER_HOST_ERROR | USB_TRANSFER_BUS_ERROR |
                  USB_TRANSFER_OVERFLOW | USB_TRANSFER_FAILED))
    {
        lwip_debug_emit(LWIP_DBG_MOD_USB, LWIP_DBG_USB_ENDPOINT_ERROR,
                        (int)status, 0);
    }
}
/* RX cadence (milliseconds). The dispatch layer quantizes these to
 * master ticks. There is no longer any pressure-driven slowdown — TCP's
 * own backpressure (window updates via tcp_recved) is the right way for
 * an overloaded receiver to ask the remote to slow down. Slowing our
 * own ingress just caused frame loss when the ring filled. */
#define ETH_RX_RING_INIT_SIZE 512u
#define ETH_RX_RING_MAX_SIZE 2048u
#define ETH_RX_RING_STEP_SIZE 512u
#define ETH_RX_DRAIN_INTERVAL_MS 10u
#define ETH_RX_SCHED_INTERVAL_MS 20u
#define ETH_RX_DRAIN_BUDGET 8u
/* Consecutive RX-drain invariant failures tolerated before the netif is
 * aborted. A drain-short failure means pbuf_alloc returned a chain too
 * small for a queued frame — an allocator/pool invariant violation that
 * should never happen. We drop the offending frame and resync the ring
 * (one frame lost, stream survives); if it recurs across this many
 * distinct frames the situation is systemic and we give up on the netif. */
#define ETH_RX_DRAIN_MAX_ERRORS 5u

/* Defined below; forward-declared so eth_rx_ring_drain can abort the
 * netif on repeated drain-short failures. */
static void eth_abort_netif(eth_device_t *dev, uint16_t log_state);
static bool eth_netif_is_default_candidate(const struct netif *netif);
static void eth_promote_default_if_needed(struct netif *netif);
static void eth_arm_dhcp_once(eth_device_t *dev);

/* True if netif is one of our ethernet interfaces (named "en*") with a
 * backing eth_device_t. Centralizes the guard used by every netif walk
 * and the public netif_is_link_error accessor. */
static inline bool eth_is_eth_netif(const struct netif *netif)
{
    return netif && netif->name[0] == 'e' && netif->name[1] == 'n' && netif->state;
}

static inline bool eth_is_shutting_down(const eth_device_t *dev)
{
    return eth_driver_shutting_down || (dev && (dev->shutting_down || dev->dead));
}

/* Bump the in-flight transfer count when a schedule_transfer succeeds. */
static inline void eth_transfer_began(eth_device_t *dev)
{
    if (dev && dev->pending_transfers != 0xFFFFu)
    {
        dev->pending_transfers++;
    }
}

/* Drop the in-flight transfer count at the top of a completion callback. */
static inline void eth_transfer_ended(eth_device_t *dev)
{
    if (dev && dev->pending_transfers != 0)
    {
        dev->pending_transfers--;
    }
}

/* Reap any dead devices whose in-flight transfers have fully drained. Called
 * from the RX dispatch tick (a safe, non-callback context). Walks the netif
 * list; a dead device has already been netif_remove()'d, so we instead reap
 * from a small intrusive list of dead-pending devices. */
static eth_device_t *g_dead_devices = NULL; /* singly-linked via ->dead_next */

static void eth_reap_dead_devices(void)
{
    eth_device_t **pp = &g_dead_devices;
    while (*pp)
    {
        eth_device_t *dev = *pp;
        if (dev->pending_transfers == 0)
        {
            *pp = dev->dead_next;
            if (dev->rx_ring)
            {
                mem_buffer_destroy(dev->rx_ring);
                dev->rx_ring = NULL;
            }
            free(dev);
        }
        else
        {
            pp = &dev->dead_next;
        }
    }
}

static void eth_schedule_rx_for_netifs(void)
{
    struct netif *netif = NULL;
    NETIF_FOREACH(netif)
    {
        if (!eth_is_eth_netif(netif))
        {
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        if (eth_is_shutting_down(dev) || !dev->rx.callback || dev->rx_transfer_active)
        {
            continue;
        }
        size_t len = (dev->type == USB_NCM_SUBCLASS) ? NCM_RX_NTB_MAX_SIZE : ETHERNET_MTU;
        if (usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf, len, dev->rx.callback, dev) == USB_SUCCESS)
        {
            dev->rx_transfer_active = true;
            eth_transfer_began(dev);
        }
    }
}

/* Dispatcher entry: re-arm RX transfers for every eth netif that
 * doesn't already have one in flight, then reap any unplugged devices whose
 * in-flight transfers have drained (safe, non-callback context). */
static void eth_rx_schedule_dispatch(void)
{
    eth_schedule_rx_for_netifs();
    eth_reap_dead_devices();
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
    if (!rb || !netif || !netif->state)
    {
        return 0;
    }
    eth_device_t *dev = (eth_device_t *)netif->state;
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
            /* Invariant violation: pbuf_alloc reported success but the
             * chain couldn't hold all `len` bytes. This should never
             * happen (see eth_rx_ring_drain notes / pbuf_alloc contract).
             * Fail closed but keep the stack alive: record the event for
             * diagnosis, then drop this frame and resync the ring past it
             * so the *next* frame's length header stays aligned — the
             * 2-byte header and `len - remaining` payload bytes were
             * already popped, so we discard the rest of the payload here.
             * Deliberately NOT LWIP_ASSERT: in this port that halts the
             * program (lwip_log_fatal_at), which would defeat the
             * recover-and-continue behavior below. */
            lwip_debug_emit(LWIP_DBG_MOD_USB, LWIP_DBG_USB_RX_DRAIN_SHORT,
                            -1, __LINE__);
            uint8_t skip[64];
            while (remaining > 0)
            {
                size_t n = remaining < sizeof(skip) ? remaining : sizeof(skip);
                if (mem_buffer_pop(rb, skip, n) != n)
                {
                    break;
                }
                remaining -= n;
            }
            pbuf_free(p);
            LINK_STATS_INC(link.drop);
            if (++dev->rx_drain_errors >= ETH_RX_DRAIN_MAX_ERRORS)
            {
                eth_abort_netif(dev, LWIP_DBG_USB_RX_DRAIN_FATAL);
            }
            break;
        }
        if (netif->input(p, netif) != ERR_OK)
        {
            pbuf_free(p);
        }
        /* A frame made it through cleanly: the drain-short condition (if
         * any) was transient, so clear the consecutive-error counter. */
        dev->rx_drain_errors = 0;
        budget--;
        drained++;
    }
    return drained;
}

/* Dispatcher entry: drain queued RX frames into lwIP's input path. */
static void eth_rx_drain_dispatch(void)
{
    struct netif *netif = NULL;
    size_t budget = ETH_RX_DRAIN_BUDGET;
    NETIF_FOREACH(netif)
    {
        if (budget == 0)
        {
            break;
        }
        if (!eth_is_eth_netif(netif))
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
}

void eth_halt_all_endpoints(void)
{
    struct netif *netif = NULL;
    NETIF_FOREACH(netif)
    {
        if (!eth_is_eth_netif(netif))
        {
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        if (dev->rx.endpoint)
        {
            usb_fn.set_endpoint_flags(dev->rx.endpoint, USB_MANUAL_TERMINATE);
            usb_fn.set_endpoint_halt(dev->rx.endpoint);
        }
        if (dev->tx.endpoint)
        {
            usb_fn.set_endpoint_flags(dev->tx.endpoint, USB_MANUAL_TERMINATE);
            usb_fn.set_endpoint_halt(dev->tx.endpoint);
        }
        if (dev->interrupt.endpoint)
        {
            usb_fn.set_endpoint_flags(dev->interrupt.endpoint, USB_MANUAL_TERMINATE);
            usb_fn.set_endpoint_halt(dev->interrupt.endpoint);
        }
    }
}

void eth_prepare_shutdown(void)
{
    struct netif *netif = NULL;
    eth_driver_shutting_down = true;
    NETIF_FOREACH(netif)
    {
        if (!eth_is_eth_netif(netif))
        {
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        dev->shutting_down = true;
        dev->rx_transfer_active = false;
        dev->rx_retries = 0;
        dev->tx_retries = 0;
        dev->int_retries = 0;
    }
}

void eth_finish_shutdown(void)
{
    struct netif *netif = netif_list;
    while (netif)
    {
        struct netif *next = netif->next;
        if (!eth_is_eth_netif(netif))
        {
            netif = next;
            continue;
        }
        eth_device_t *dev = (eth_device_t *)netif->state;
        dev->shutting_down = true;
        dev->rx_transfer_active = false;
        usb_fn.set_device_data(dev->device, NULL);
        if (netif->num < 8)
        {
            ifnums_used &= ~(1 << netif->num);
        }
        netif_remove(netif);
        if (dev->rx_ring)
        {
            mem_buffer_destroy(dev->rx_ring);
            dev->rx_ring = NULL;
        }
        netif = next;
    }
}

void eth_reset_shutdown(void)
{
    eth_driver_shutting_down = false;
}

/// UTF-16 -> hex conversion
static uint8_t
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

/* Abort a netif that has hit an unrecoverable fault. Brings the netif
 * down (link + admin) so consumers can react via the link callback
 * before USB tears the device down asynchronously, then disables the
 * device. The per-device disabled_with_error flag is what the disconnect
 * handler later consults to decide between "reset and resume" and "drop
 * the netif entirely." Logs the caller-supplied fatal reason so the
 * appvar log distinguishes endpoint-retry exhaustion from RX-drain
 * failure. */
static void eth_abort_netif(eth_device_t *dev, uint16_t log_state)
{
    if (!dev || eth_is_shutting_down(dev))
    {
        return;
    }

    LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SEVERE,
                ("eth: fatal fault, giving up on netif"));
    lwip_debug_emit(LWIP_DBG_MOD_USB, log_state, -1, 0);
    /* Surface the failure to lwIP first. Apps with a registered netif
     * link callback will see the down transition before the device
     * disappears, and any PCBs bound to this netif can be torn down via
     * the link callback's own walk (see eth_netif_link_callback in this
     * file). */
    netif_set_link_down(&dev->iface);
    netif_set_down(&dev->iface);
    dev->disabled_with_error = true;
    usb_fn.disable_device(dev->device);
}

/* Mark a USB endpoint as having exhausted its retry budget. */
static bool eth_xmit_fatal_error(eth_device_t *dev, uint8_t retries)
{
    if (retries == ETH_USB_MAX_RETRIES)
    {
        eth_abort_netif(dev, LWIP_DBG_USB_FATAL_RETRY);
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
static usb_error_t
interrupt_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                           usb_transfer_status_t status,
                           size_t transferred,
                           usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    /* This transfer just completed; drop the in-flight count BEFORE any early
     * return so a dead device can still be reaped (count must reach 0). The
     * count invariant guarantees dev is not yet freed here. */
    eth_transfer_ended(dev);
    if (!dev || eth_is_shutting_down(dev))
    {
        return USB_SUCCESS;
    }

    uint8_t *ibuf = dev->interrupt.buf;
    if (status)
    {
        log_usb_transfer_status(status);
        /* Per-device retry counter (not function-static). With multiple
         * USB-ethernet adapters, a function-static would interleave
         * across devices and trip a fatal threshold on the wrong one. */
        if (eth_xmit_fatal_error(dev, dev->int_retries))
            return USB_ERROR_FAILED;
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("int: endpoint failure, retry=%u", dev->int_retries));
        dev->int_retries++;
    }
    else if ((status == USB_TRANSFER_COMPLETED) && transferred)
    {
        usb_control_setup_t *notify;
        size_t bytes_parsed = 0;
        do
        {
            if (transferred - bytes_parsed < sizeof(usb_control_setup_t))
            {
                break;
            }
            notify = (usb_control_setup_t *)&ibuf[bytes_parsed];
            if ((size_t)notify->wLength > transferred - bytes_parsed - sizeof(usb_control_setup_t))
            {
                break;
            }
            if (notify->bmRequestType == 0b10100001)
            {
                switch (notify->bRequest)
                {
                case NOTIFY_NETWORK_CONNECTION:
                    if (notify->wValue)
                    {
                        netif_set_link_up(&dev->iface);
                        eth_promote_default_if_needed(&dev->iface);
                        eth_arm_dhcp_once(dev);
                    }
                    else
                    {
                        netif_set_link_down(&dev->iface);
                        if (netif_default == &dev->iface)
                        {
                            /* Promote only a candidate that is BOTH admin-up
                             * (netif_is_up) AND link-up (netif_is_link_up).
                             * Promoting an admin-down netif as default would
                             * black-hole outbound traffic. */
                            struct netif *candidate = netif_list;
                            struct netif *new_default = NULL;
                            while (candidate)
                            {
                                if (candidate != &dev->iface &&
                                    eth_netif_is_default_candidate(candidate))
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
        dev->int_retries = 0;
    }
    if (!eth_is_shutting_down(dev))
    {
        if (usb_fn.schedule_transfer(dev->interrupt.endpoint, dev->interrupt.buf,
                                     INTERRUPT_RX_MAX, interrupt_receive_callback,
                                     data) != USB_SUCCESS)
        {
            (void)eth_xmit_fatal_error(dev, ETH_USB_MAX_RETRIES);
            return USB_ERROR_FAILED;
        }
        eth_transfer_began(dev);
    }
    return USB_SUCCESS;
}

///---------------------------------------------------
/// @brief bulk out callback function
static usb_error_t bulk_transmit_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                   usb_transfer_status_t status,
                                   __attribute__((unused)) size_t transferred,
                                   usb_transfer_data_t *data)
{
    // Handle completion or error of the transfer, if needed
    struct eth_tx_ctx *ctx = (struct eth_tx_ctx *)data;
    if (!ctx)
    {
        return USB_ERROR_FAILED;
    }
    eth_device_t *dev = ctx->dev;
    struct pbuf *tbuf = ctx->p;
    /* TX transfer completed — drop the in-flight count before any early return
     * so a dead device can be reaped. */
    eth_transfer_ended(dev);
    if (eth_is_shutting_down(dev))
    {
        if (tbuf)
            pbuf_free(tbuf);
        free(ctx);
        return USB_SUCCESS;
    }

    if (status)
    {
        log_usb_transfer_status(status);
        if (eth_xmit_fatal_error(dev, dev->tx_retries))
        {
            pbuf_free(tbuf);
            free(ctx);
            dev->tx_retries = 0;
            return USB_ERROR_FAILED;
        }
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("tx: endpoint failure, retry=%u", dev->tx_retries));
        dev->tx_retries++;
        /* Same pbuf, same ctx — re-arm the OUT transfer. On schedule
         * failure the ctx + pbuf would leak; we treat a hard schedule
         * failure as another fatal endpoint failure so the per-device
         * counter eventually exhausts and we tear down cleanly. */
        if (usb_fn.schedule_transfer(dev->tx.endpoint, tbuf->payload,
                                     tbuf->tot_len, bulk_transmit_callback,
                                     ctx) != USB_SUCCESS)
        {
            pbuf_free(tbuf);
            free(ctx);
            (void)eth_xmit_fatal_error(dev, ETH_USB_MAX_RETRIES);
            return USB_ERROR_FAILED;
        }
        eth_transfer_began(dev);
        return USB_SUCCESS;
    }

    /* Successful transmission - reset retry counter */
    dev->tx_retries = 0;

    if (tbuf)
        pbuf_free(tbuf);
    free(ctx);

    return USB_SUCCESS;
}

///------------------------------------------------------------------------
/// @brief linkinput callback function for @b Ethernet_Control_Model (ECM)
static usb_error_t ecm_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                 usb_transfer_status_t status,
                                 size_t transferred,
                                 usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    if (!dev)
    {
        return USB_ERROR_FAILED;
    }
    eth_transfer_ended(dev);
    dev->rx_transfer_active = false;
    if (eth_is_shutting_down(dev))
    {
        return USB_SUCCESS;
    }

    uint8_t *recvbuf = dev->rx.buf;
    if (status)
    {
        log_usb_transfer_status(status);
        if (eth_xmit_fatal_error(dev, dev->rx_retries))
            return USB_ERROR_FAILED;

        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("ecm_rx: endpoint failure, retry=%u", dev->rx_retries));
        dev->rx_retries++;
        /* Re-arm immediately on transient errors so the next packet
         * doesn't wait for the dispatcher's RX-schedule slot to come
         * around. The dispatcher remains the safety net if this
         * synchronous re-arm fails. */
        if (usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf,
                                     ETHERNET_MTU, ecm_receive_callback,
                                     dev) == USB_SUCCESS)
        {
            dev->rx_transfer_active = true;
            eth_transfer_began(dev);
        }
        return USB_SUCCESS;
    }
    else if (transferred)
    {
        dev->rx_retries = 0;
        if (eth_ring_push_frame(dev, recvbuf, (uint16_t)transferred))
        {
            LINK_STATS_INC(link.recv);
            MIB2_STATS_NETIF_ADD(&dev->iface, ifinoctets, transferred);
        }
        else
        {
            LINK_STATS_INC(link.drop);
        }
    }
    /* Self-re-arm on every successful receive so the dispatcher is a
     * safety net rather than the sole continuity path. */
    if (!eth_is_shutting_down(dev) &&
        !dev->rx_transfer_active &&
        usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf,
                                 ETHERNET_MTU, ecm_receive_callback,
                                 dev) == USB_SUCCESS)
    {
        dev->rx_transfer_active = true;
        eth_transfer_began(dev);
    }
    return USB_SUCCESS;
}

///----------------------------------------------------------------
/// @brief linkoutput function for @b Ethernet_Control_Model (ECM)
static err_t ecm_bulk_transmit(struct netif *netif, struct pbuf *p)
{
    eth_device_t *dev = (eth_device_t *)netif->state;
    if (eth_is_shutting_down(dev))
        return ERR_IF;
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
    if (usb_fn.schedule_transfer(dev->tx.endpoint, tbuf->payload, tbuf->tot_len,
                                 bulk_transmit_callback, ctx) != USB_SUCCESS)
    {
        pbuf_free(tbuf);
        free(ctx);
        (void)eth_xmit_fatal_error(dev, ETH_USB_MAX_RETRIES);
        return ERR_IF;
    }
    eth_transfer_began(dev);
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

static bool ncm_range_fits(size_t offset, size_t len, size_t total)
{
    return offset <= total && len <= (total - offset);
}

static usb_error_t ethernet_control_setup(eth_device_t *eth)
{
    size_t transferred;
    usb_control_setup_t packet_filter_request = {
        0b00100001,
        REQUEST_SET_ETHERNET_PACKET_FILTER,
        0x1c,
        0,
        0
    };

    usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0),
                            &packet_filter_request, NULL,
                            USB_CDC_MAX_RETRIES, &transferred);
    return USB_SUCCESS;
}

///------------------------------------------------------------
/// @brief control setup for @b Network_Control_Model (NCM)
static usb_error_t ncm_control_setup(eth_device_t *eth)
{
    if (eth->type != USB_NCM_SUBCLASS)
        return USB_SUCCESS;
    size_t transferred;
    usb_error_t error = 0;
    usb_control_setup_t get_ntb_params = {0b10100001, REQUEST_GET_NTB_PARAMETERS, 0, 0, 0x1c};
    usb_control_setup_t ntb_config_request = {0b00100001, REQUEST_SET_NTB_INPUT_SIZE, 0, 0, ncm_device_supports(eth, CAPABLE_NTB_INPUT_SIZE_8BYTE) ? 8 : 4};
    struct _ntb_config_data ntb_config_data = {NCM_RX_NTB_MAX_SIZE, NCM_RX_MAX_DATAGRAMS, 0};

    /* Query NTB Parameters for device (NCM devices) */
    error |= usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0), &get_ntb_params, &eth->class.ncm.ntb_params, USB_CDC_MAX_RETRIES, &transferred);

    /* Set NTB Max Input Size to 2048 (recd minimum NCM spec v 1.2) */
    error |= usb_fn.control_transfer(usb_fn.get_device_endpoint(eth->device, 0), &ntb_config_request, &ntb_config_data, USB_CDC_MAX_RETRIES, &transferred);

    return error;
}

///------------------------------------------------------------
/// @brief linkinput function for @b Network_Control_Model (NCM)
static usb_error_t ncm_receive_callback(__attribute__((unused)) usb_endpoint_t endpoint,
                                 usb_transfer_status_t status,
                                 size_t transferred,
                                 usb_transfer_data_t *data)
{
    eth_device_t *dev = (eth_device_t *)data;
    if (!dev)
    {
        return USB_ERROR_FAILED;
    }
    eth_transfer_ended(dev);
    dev->rx_transfer_active = false;
    if (eth_is_shutting_down(dev))
    {
        return USB_SUCCESS;
    }

    uint8_t *recvbuf = dev->rx.buf;
    if (status)
    {
        log_usb_transfer_status(status);
        if (eth_xmit_fatal_error(dev, dev->rx_retries))
        {
            return USB_ERROR_FAILED;
        }
        LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                    ("ncm_rx: endpoint failure, retry=%u", dev->rx_retries));
        dev->rx_retries++;
        /* See ecm_receive_callback: synchronous re-arm beats waiting
         * for the dispatcher to come around. */
        if (usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf,
                                     NCM_RX_NTB_MAX_SIZE,
                                     ncm_receive_callback,
                                     dev) == USB_SUCCESS)
        {
            dev->rx_transfer_active = true;
            eth_transfer_began(dev);
        }
        return USB_SUCCESS;
    }
    if (transferred)
    {
        dev->rx_retries = 0;
        bool parse_ntb = true;

        /* Bail-out branches below jump to rx_rearm rather than returning
         * directly. A malformed NTB used to leave RX un-rearmed until
         * the next dispatcher tick — fine under normal pressure, but a
         * permanent stall if the dispatcher was throttled. */
        // get header and first NDP pointers
        uint8_t *ntb = (uint8_t *)recvbuf;
        if (transferred < NCM_NTH_LEN)
            goto rx_rearm;
        struct ncm_nth *nth = (struct ncm_nth *)ntb;
        if (nth->dwSignature != NCM_NTH_SIG)
            goto rx_rearm; // validate NTH signature field. If invalid, fail out
        if (nth->wHeaderLength < NCM_NTH_LEN ||
            nth->wBlockLength < NCM_NTH_LEN ||
            nth->wBlockLength > transferred ||
            !ncm_range_fits(nth->wNdpIndex, NCM_NDP_LEN, nth->wBlockLength))
            goto rx_rearm;

        // start proc'ing first NDP
        size_t ndp_offset = nth->wNdpIndex;
        struct ncm_ndp *ndp = (struct ncm_ndp *)&ntb[ndp_offset];

        // repeat while ndp->wNextNdpIndex is non-zero
        do
        {
            if (ndp->dwSignature != NCM_NDP_SIG0)
                goto rx_rearm; // validate NDP signature field, if invalid, fail out
            if (ndp->wLength < NCM_NDP_LEN ||
                !ncm_range_fits(ndp_offset, ndp->wLength, nth->wBlockLength))
                goto rx_rearm;

            // set datagram number to 0 and set datagram index pointer
            size_t idx_offset = ndp_offset + offsetof(struct ncm_ndp, wDatagramIdx);

            // a null datagram index structure indicates end of NDP
            while (ncm_range_fits(idx_offset, sizeof(struct ncm_ndp_idx), ndp_offset + ndp->wLength))
            {
                struct ncm_ndp_idx *idx = (struct ncm_ndp_idx *)&ntb[idx_offset];
                uint16_t datagram_index = idx->wDatagramIndex;
                uint16_t datagram_len = idx->wDatagramLen;

                if (datagram_index == 0 && datagram_len == 0)
                    break;
                if (datagram_index == 0 || datagram_len == 0)
                    goto rx_rearm;
                if (!ncm_range_fits(datagram_index, datagram_len, nth->wBlockLength))
                    goto rx_rearm;

                // attempt to allocate pbuf
                if (!eth_ring_push_frame(dev, &ntb[datagram_index], datagram_len))
                {
                    LINK_STATS_INC(link.drop);
                    parse_ntb = false;
                    break;
                }
                idx_offset += sizeof(struct ncm_ndp_idx);
            }
            if (parse_ntb &&
                !ncm_range_fits(idx_offset, sizeof(struct ncm_ndp_idx), ndp_offset + ndp->wLength))
                goto rx_rearm;
            // if next NDP is 0, NTB is done and so is my sanity
            if (ndp->wNextNdpIndex == 0)
                break;
            if (ndp->wNextNdpIndex <= ndp_offset ||
                !ncm_range_fits(ndp->wNextNdpIndex, NCM_NDP_LEN, nth->wBlockLength))
                goto rx_rearm;
            // set next NDP
            ndp_offset = ndp->wNextNdpIndex;
            ndp = (struct ncm_ndp *)&ntb[ndp_offset];
        } while (parse_ntb);

        LINK_STATS_INC(link.recv);
        MIB2_STATS_NETIF_ADD(&dev->iface, ifinoctets, transferred);
    }
rx_rearm:
    /* Self-re-arm on every successful or bailed-out receive so the
     * dispatcher is a safety net rather than the sole continuity path. */
    if (!eth_is_shutting_down(dev) &&
        !dev->rx_transfer_active &&
        usb_fn.schedule_transfer(dev->rx.endpoint, dev->rx.buf,
                                 NCM_RX_NTB_MAX_SIZE,
                                 ncm_receive_callback,
                                 dev) == USB_SUCCESS)
    {
        dev->rx_transfer_active = true;
        eth_transfer_began(dev);
    }
    return USB_SUCCESS;
}

/* This code packs a single TX Ethernet frame into an NCM transfer. */
#define NCM_HBUF_SIZE 64
#define get_next_offset(offset, divisor, remainder) \
    (offset) + (divisor) - ((offset) % (divisor)) + (remainder)

///---------------------------------------------------------------
/// @brief linkoutput function for @b Network_Control_Model (NCM)
static err_t ncm_bulk_transmit(struct netif *netif, struct pbuf *p)
{
    eth_device_t *dev = (eth_device_t *)netif->state;
    if (eth_is_shutting_down(dev))
        return ERR_IF;
    uint16_t offset_ndp = get_next_offset(NCM_NTH_LEN, dev->class.ncm.ntb_params.wNdpInAlignment, 0);
    if (p->tot_len > ETHERNET_MTU)
        return ERR_MEM;

    /* Size the NTB to the actual datagram, not the MTU. A 40-byte TCP ACK
     * was previously allocated and transmitted as a 1578-byte buffer; on
     * a sustained download the ACK rate is high enough that this burned
     * both pbuf memory and USB TX bandwidth, causing stalls. */
    uint16_t ntb_len = NCM_HBUF_SIZE + p->tot_len;

    // allocate TX packet buffer
    struct pbuf *obuf = pbuf_alloc(PBUF_RAW, ntb_len, PBUF_RAM);
    if (obuf == NULL)
        return ERR_MEM;
    struct eth_tx_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        pbuf_free(obuf);
        return ERR_MEM;
    }

    memset(obuf->payload, 0, ntb_len);

    // declare NTH, NDP, and NDP_IDX structures
    uint8_t hdr_buf[NCM_HBUF_SIZE] = {0};
    struct ncm_nth *nth = (struct ncm_nth *)hdr_buf;
    struct ncm_ndp *ndp = (struct ncm_ndp *)&hdr_buf[offset_ndp];

    // populate structs
    nth->dwSignature = NCM_NTH_SIG;
    nth->wHeaderLength = NCM_NTH_LEN;
    nth->wSequence = dev->class.ncm.sequence++;
    nth->wBlockLength = ntb_len;
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
    if (usb_fn.schedule_transfer(dev->tx.endpoint, obuf->payload, obuf->tot_len,
                                 bulk_transmit_callback, ctx) != USB_SUCCESS)
    {
        pbuf_free(obuf);
        free(ctx);
        (void)eth_xmit_fatal_error(dev, ETH_USB_MAX_RETRIES);
        return ERR_IF;
    }
    eth_transfer_began(dev);
    return ERR_OK;
}

/* netif link callback: lwIP invokes this whenever netif_set_link_up /
 * netif_set_link_down toggles. On the down edge we walk the stack's
 * PCB lists and abort any that were bound to this netif so the
 * application's err callbacks fire promptly. Connections that were
 * unbound (using netif_default implicitly) are left alone — they'll
 * fail their next operation on their own and may legitimately want to
 * survive a default-netif switch. */
static void eth_link_callback(struct netif *netif)
{
    if (!netif)
    {
        return;
    }
    if (eth_is_shutting_down((eth_device_t *)netif->state))
    {
        return;
    }
    if (!netif_is_link_up(netif))
    {
        lwip_teardown_abort_pcbs_on_netif(netif);
    }
}

/* netif status callback: same idea, on the admin-down edge. Together
 * with the link callback this gives apps a single point of truth for
 * "the interface I was using just went away — abandon ship." */
static void eth_status_callback(struct netif *netif)
{
    if (!netif)
    {
        return;
    }
    if (eth_is_shutting_down((eth_device_t *)netif->state))
    {
        return;
    }
    if (!netif_is_up(netif))
    {
        lwip_teardown_abort_pcbs_on_netif(netif);
    }
}

static bool eth_netif_is_external(const struct netif *netif)
{
    return netif && ((netif->flags & NETIF_FLAG_ETHERNET) != 0);
}

static bool eth_netif_is_default_candidate(const struct netif *netif)
{
    return eth_netif_is_external(netif) &&
           netif_is_up(netif) &&
           netif_is_link_up(netif);
}

static void eth_promote_default_if_needed(struct netif *netif)
{
    if (!eth_netif_is_default_candidate(netif))
    {
        return;
    }

    if (!eth_netif_is_external(netif_default) ||
        !netif_is_up(netif_default) ||
        !netif_is_link_up(netif_default))
    {
        netif_set_default(netif);
    }
}

#if LWIP_DHCP
static bool eth_dhcp_client_running(const struct netif *netif)
{
    struct dhcp *dhcp = netif ? netif_dhcp_data(netif) : NULL;
    return dhcp && dhcp->state != DHCP_STATE_OFF;
}
#endif

static void eth_arm_dhcp_once(eth_device_t *dev)
{
#if LWIP_DHCP
    if (!dev || dev->dhcp_auto_started)
    {
        return;
    }

    struct netif *netif = &dev->iface;
    if (!eth_netif_is_external(netif) ||
        !netif_is_up(netif) ||
        !netif_is_link_up(netif))
    {
        return;
    }

    dev->dhcp_auto_started = true;
    if (!eth_dhcp_client_running(netif))
    {
        err_t err = dhcp_start(netif);
        if (err != ERR_OK)
        {
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                        ("dhcp_start failed on %c%c%u: %d",
                         netif->name[0], netif->name[1], netif->num, err));
        }
    }
#else
    (void)dev;
#endif
}

///----------------------------------------
/// @brief ethernet NETIF initialization
static err_t eth_netif_init(struct netif *netif)
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
    netif_set_link_callback(netif, eth_link_callback);
    netif_set_status_callback(netif, eth_status_callback);
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
static bool init_ethernet_usb_device(usb_device_t device)
{
    if (eth_driver_shutting_down)
    {
        return false;
    }

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
            /* Reject malformed descriptors before advancing. bLength == 0
             * would infinite-loop the walker; bLength overrunning the
             * remaining buffer would walk into adjacent memory on the
             * next iteration. Either is a fatal parse error. */
            if (desc->bLength == 0 || parsed_len + desc->bLength > desc_len)
            {
                return false;
            }
            parsed_len += desc->bLength;
            desc = (usb_descriptor_t *)(((uint8_t *)desc) + desc->bLength);
        }
    }
    return false;
init_success:
    if (ethernet_control_setup(&tmp))
        return false;

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
        netif_set_hostname(iface, lwip_app_config_get()->hostname); // set hostname from config
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
        mem_buffer_set_grow(eth->rx_ring, 85, ETH_RX_RING_STEP_SIZE);
        mem_buffer_set_shrink(eth->rx_ring, 30, ETH_RX_RING_STEP_SIZE);
    }
    /* Wire RX dispatchers into the master tick (idempotent — attach is
     * safe to repeat across multiple device-init calls). Both run at
     * fixed cadence; TCP-level backpressure handles slowdown. */
    lwip_dispatch_attach(LWIP_DISPATCH_ETH_RX_DRAIN, eth_rx_drain_dispatch);
    lwip_dispatch_attach(LWIP_DISPATCH_ETH_RX_SCHEDULE, eth_rx_schedule_dispatch);
    lwip_dispatch_set_period(LWIP_DISPATCH_ETH_RX_DRAIN,
                             lwip_dispatch_period_from_ms(ETH_RX_DRAIN_INTERVAL_MS));
    lwip_dispatch_set_period(LWIP_DISPATCH_ETH_RX_SCHEDULE,
                             lwip_dispatch_period_from_ms(ETH_RX_SCHED_INTERVAL_MS));
    lwip_dispatch_start();

    netif_set_up(&eth->iface); // tell lwIP that the interface is ready to receive
    eth_promote_default_if_needed(&eth->iface);
    // enqueue callbacks for receiving interrupt and RX transfers from this device.
    if (usb_fn.schedule_transfer(eth->interrupt.endpoint, eth->interrupt.buf,
                                 INTERRUPT_RX_MAX, interrupt_receive_callback,
                                 eth) != USB_SUCCESS)
    {
        (void)eth_xmit_fatal_error(eth, ETH_USB_MAX_RETRIES);
        return false;
    }
    eth_transfer_began(eth);
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
        if (eth_driver_shutting_down)
        {
            break;
        }
        if (!(usb_fn.get_role() & USB_ROLE_DEVICE))
            usb_fn.reset_device(usb_device);
        break;
    case USB_DEVICE_ENABLED_EVENT:
        if (eth_driver_shutting_down)
        {
            break;
        }
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
            /* Mark the device dead BEFORE any teardown. eth_is_shutting_down()
             * now reports true, so every USB transfer callback and netif op
             * fast-returns and stops touching this device. The struct is NOT
             * freed here — it is reaped later by the RX dispatch tick once its
             * in-flight transfers drain (see eth_reap_dead_devices), which
             * closes the use-after-free window where a halted transfer's
             * completion callback fires after free. */
            eth_device->dead = true;
            bool shutting_down = eth_driver_shutting_down || eth_device->shutting_down;
            eth_device->shutting_down = shutting_down;
            eth_device->rx_transfer_active = false;
            /* Abort any TCP/TLS pcbs bound to this netif explicitly. The link/
             * status netif callbacks normally do this, but they now fast-return
             * on `dead`; this is a safe lwIP-side cleanup that does not touch the
             * USB device, so the unplugged interface's connections still tear
             * down instead of dangling. */
            lwip_teardown_abort_pcbs_on_netif(&eth_device->iface);
            netif_set_link_down(&eth_device->iface);
            netif_set_down(&eth_device->iface);
            if (shutting_down)
            {
                break;
            }
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
        /* If THIS device was the one that tripped the fatal-retry path,
         * try to reset it back online. Other devices that just happen
         * to disconnect at the same time keep their normal teardown
         * path. */
        if (eth_device && eth_device->disabled_with_error && ETH_DO_RESTART_ON_ERROR)
        {
            LWIP_DEBUGF(ETH_DEBUG | LWIP_DBG_LEVEL_SEVERE,
                        ("device ptr=%p: disabled with error, resetting!", usb_device));
            eth_device->disabled_with_error = false;
            eth_device->rx_retries = 0;
            eth_device->tx_retries = 0;
            eth_device->int_retries = 0;
            usb_fn.reset_device(usb_device);
            break;
        }
        if (eth_device)
        {
            ifnums_used &= ~(1 << eth_device->iface.num);
            netif_remove(&eth_device->iface);
            /* Unbind from the USB device so no later event re-finds this
             * (about-to-be-reaped) struct, then defer the free: enqueue on the
             * dead list. The RX dispatch tick frees it (and its rx_ring) once
             * pending_transfers reaches 0. Freeing synchronously here would
             * race a halted transfer's completion callback (use-after-free). */
            usb_fn.set_device_data(usb_device, NULL);
            if (eth_device->pending_transfers == 0)
            {
                /* No in-flight transfers — safe to free immediately. */
                if (eth_device->rx_ring)
                {
                    mem_buffer_destroy(eth_device->rx_ring);
                    eth_device->rx_ring = NULL;
                }
                free(eth_device);
            }
            else
            {
                eth_device->dead_next = g_dead_devices;
                g_dead_devices = eth_device;
            }
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

bool netif_is_link_error(const struct netif *netif)
{
    if (!eth_is_eth_netif(netif))
    {
        return false;
    }
    const eth_device_t *dev = (const eth_device_t *)netif->state;
    return dev->disabled_with_error;
}

#ifdef LWIP_ETHERNET_TEST_HOOKS
bool eth_test_ring_push_frame(eth_device_t *dev, const uint8_t *data, uint16_t len)
{
    return eth_ring_push_frame(dev, data, len);
}

size_t eth_test_rx_ring_drain(struct mem_buffer *rb, void *user, size_t budget)
{
    return eth_rx_ring_drain(rb, user, budget);
}

void eth_test_schedule_rx_for_netifs(void)
{
    eth_schedule_rx_for_netifs();
}

usb_error_t eth_test_ecm_receive(eth_device_t *dev, const uint8_t *frame, size_t len)
{
    if (!dev || !frame || len > sizeof(dev->rx.buf))
    {
        return USB_ERROR_FAILED;
    }
    memcpy(dev->rx.buf, frame, len);
    return ecm_receive_callback(dev->rx.endpoint, USB_TRANSFER_COMPLETED, len, dev);
}

usb_error_t eth_test_ncm_receive(eth_device_t *dev, const uint8_t *ntb, size_t len)
{
    if (!dev || !ntb || len > sizeof(dev->rx.buf))
    {
        return USB_ERROR_FAILED;
    }
    memcpy(dev->rx.buf, ntb, len);
    return ncm_receive_callback(dev->rx.endpoint, USB_TRANSFER_COMPLETED, len, dev);
}
#endif
