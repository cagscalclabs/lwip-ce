/**
 * @file lwIP.c
 * @brief App-facing connection API. See lwIP.h for the contract.
 *
 * Design notes:
 *
 *  - Every underlying pcb callback (tcp_recv / altcp_recv / udp_recv / etc.)
 *    is hooked by *this* module, not by the application. We need to own
 *    the dispatch path so we can keep conn->status coherent and translate
 *    err_t values into lwip_error_t before the app sees them.
 *
 *  - The handle is transparent (defined in the public header) so apps can
 *    inspect status / last_error without a function call. All other fields
 *    are managed exclusively here.
 *
 *  - lwip_conn_create allocates the connection handle/pcb and records any
 *    requested netif-level services. lwip_conn_connect owns transport
 *    readiness, mirroring socket-style behavior by parking the connection
 *    until the resident netif, link, address configuration, and requested
 *    services are usable.
 */

#include "lwIP.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "lwip/timeouts.h"
#include "lwip/app_config.h"
#include "lwip/logging.h"
#include "lwip/teardown.h"
#include "lwip/dispatch.h"
#include "lwip/sys.h"
#include "lwip/apps/sntp.h"
#include "lwip/sntp_time.h"
#include "drivers/usb_ethernet.h"
#include "lwip-imports.h"
#include "apps/altcp_tls/altcp_tls_ce.h"
#include "tls/includes/tls.h"

#include <usbdrvce.h>
#include <string.h>

/* Temporary teardown tracing — prints each phase tag to the home screen
 * and waits for a keypress, so on real hardware the last tag visible when
 * it crashes localizes the failing teardown phase. Set LWIP_STOP_TRACE 0
 * to disable. (dbgout-based tracing was CEmu-only and invisible on a
 * physical calculator.) */
#define LWIP_STOP_TRACE 0
#if LWIP_STOP_TRACE
#include <ti/screen.h>
#include <ti/getkey.h>
#define STOP_TRACE(msg) do { os_ClrHome(); os_PutStrFull("stop: " msg); \
                             os_PutStrFull(" [key]"); os_GetKey(); } while (0)
#else
#define STOP_TRACE(msg) ((void)0)
#endif

/* ============================================================
 * Init / poll
 * ============================================================ */

static bool g_lwip_started = false;
static bool g_lwip_stopping = false;
static lwip_app_config_t g_lwip_cfg;
static uint8_t g_requested_service_flags = 0;
static uint8_t g_lwip_start_error = 0;
static struct lwip_conn *g_conn_registry = NULL;

static void lwip_stack_cleanup(void);
static void lwip_fatal_cleanup(void);
static lwip_error_t apply_service_flags(struct netif *n, uint8_t svc_flags);
static struct netif *find_external_netif(void);
static bool netif_has_usable_ipv4(const struct netif *n);
static bool netif_has_usable_gateway(const struct netif *n);
static bool host_requires_dns(const char *host);
static bool dns_has_configured_server(void);
static void lwip_conn_detach_pcb_callbacks(struct lwip_conn *conn);
static void services_list_remove(struct lwip_conn *c);
static void services_list_cancel_all(lwip_error_t err);

#ifndef LWIP_STOP_SERVICE_SETTLE_MS
#define LWIP_STOP_SERVICE_SETTLE_MS 250u
#endif

#ifndef LWIP_STOP_TCP_CLOSE_TIMEOUT_MS
#define LWIP_STOP_TCP_CLOSE_TIMEOUT_MS LWIP_TCP_CLOSE_TIMEOUT_MS_DEFAULT
#endif

bool lwip_start(void)
{
    if (g_lwip_started)
    {
        return true;
    }

    g_lwip_start_error = 0;
    g_lwip_stopping = false;
    lwip_app_config_load(&g_lwip_cfg);
    lwip_debug_set_fatal_cleanup(lwip_fatal_cleanup);
    eth_reset_shutdown();

    if (lwip_init() != ERR_OK)
    {
        g_lwip_start_error = 1;
        return false;
    }
    /* USB init via usb_fn so the libload build resolves through
     * include_library '../usbdrvce/usbdrvce.asm' without a special case. If this
     * fails we must roll back lwip_init's side effects — leaving
     * timeouts / netifs alive after lwip_start returned false would
     * let the next start attempt see a half-initialized stack. */
    if (usb_fn.init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        g_lwip_start_error = 2;
        g_lwip_started = true;   /* let cleanup do its full sweep */
        lwip_stack_cleanup();
        return false;
    }

    g_lwip_started = true;
    return true;
}

uint8_t lwip_start_last_error(void)
{
    return g_lwip_start_error;
}

void lwip_stop(void)
{
    lwip_stack_cleanup();
}

void lwip_poll_network_events(void)
{
    if (!g_lwip_started && !g_lwip_stopping)
    {
        return;
    }
    usb_fn.handle_events();
    sys_check_timeouts();
    if (g_requested_service_flags)
    {
        (void)apply_service_flags(find_external_netif(), g_requested_service_flags);
    }
}

/* ============================================================
 * Helpers
 * ============================================================ */

static lwip_error_t lwip_err_translate(err_t e)
{
    switch (e)
    {
    case ERR_OK:               return LWIP_OK;
    case ERR_MEM:
    case ERR_BUF:
    case ERR_MEM_CONFIG_UNSET: return LWIP_ERR_MEM;
    case ERR_ARG:
    case ERR_VAL:              return LWIP_ERR_ARG;
    case ERR_RTE:
    case ERR_IF:               return LWIP_ERR_NETIF;
    case ERR_TIMEOUT:
    case ERR_ABRT:
    case ERR_CONN:             return LWIP_ERR_CONNECT;
    case ERR_INPROGRESS:
    case ERR_WOULDBLOCK:
    case ERR_USE:
    case ERR_ALREADY:
    case ERR_ISCONN:           return LWIP_ERR_STATE;
    case ERR_CLSD:
    case ERR_RST:              return LWIP_ERR_CLOSED;
    default:                   return LWIP_ERR_INTERNAL;
    }
}

static bool netif_is_external_network(const struct netif *n)
{
    return n && ((n->flags & NETIF_FLAG_ETHERNET) != 0);
}

static struct netif *find_external_netif(void)
{
    struct netif *n = NULL;

    if (netif_is_external_network(netif_default))
    {
        return netif_default;
    }

    NETIF_FOREACH(n)
    {
        if (netif_is_external_network(n))
        {
            return n;
        }
    }

    return NULL;
}

static void conn_registry_add(struct lwip_conn *conn)
{
    if (!conn) return;
    for (struct lwip_conn *cur = g_conn_registry; cur; cur = cur->registry_next)
    {
        if (cur == conn) return;
    }
    conn->registry_next = g_conn_registry;
    g_conn_registry = conn;
}

static void conn_registry_remove(struct lwip_conn *conn)
{
    if (!conn) return;
    struct lwip_conn **slot = &g_conn_registry;
    while (*slot)
    {
        if (*slot == conn)
        {
            *slot = conn->registry_next;
            conn->registry_next = NULL;
            return;
        }
        slot = &(*slot)->registry_next;
    }
}

static bool conn_registry_is_tcp_like(const struct lwip_conn *conn)
{
    if (!conn) return false;
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        return true;
#endif
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        return true;
    default:
        return false;
    }
}

static void conn_registry_close_tcp_like(void)
{
    struct lwip_conn *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_conn *next = conn->registry_next;
        if (conn_registry_is_tcp_like(conn))
        {
            services_list_remove(conn);
            (void)lwip_conn_close(conn);
            if (conn->status != LWIP_STATUS_CLOSED)
            {
                conn->status = LWIP_STATUS_CLOSING;
            }
        }
        conn = next;
    }
}

static void conn_registry_abort_tcp_like(void)
{
    struct lwip_conn *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_conn *next = conn->registry_next;
        if (conn_registry_is_tcp_like(conn))
        {
            (void)lwip_conn_abort(conn);
        }
        conn = next;
    }
}

static void conn_registry_close_udp(void)
{
    struct lwip_conn *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_conn *next = conn->registry_next;
        if ((lwip_protocol_t)conn->protocol == LWIP_PROTO_UDP)
        {
            services_list_remove(conn);
            (void)lwip_conn_close(conn);
        }
        conn = next;
    }
}

static void conn_registry_mark_closed(lwip_error_t err)
{
    while (g_conn_registry)
    {
        struct lwip_conn *conn = g_conn_registry;
        conn_registry_remove(conn);
        services_list_remove(conn);
        lwip_conn_detach_pcb_callbacks(conn);
        conn->pcb.tcp = NULL;
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
        }
        conn->status = LWIP_STATUS_CLOSED;
        conn->last_error = err;
    }
}

static void lwip_stop_pump_once(void)
{
    usb_fn.handle_events();
    sys_check_timeouts();
}

static void lwip_stop_pump_for(uint32_t duration_ms)
{
    uint32_t deadline = sys_now() + duration_ms;
    do
    {
        lwip_stop_pump_once();
    } while ((int32_t)(sys_now() - deadline) < 0);
}

static bool lwip_stop_wait_for_tcp(uint32_t timeout_ms)
{
    uint32_t deadline = sys_now() + timeout_ms;
    while (lwip_teardown_tcp_pcbs_pending())
    {
        if ((int32_t)(sys_now() - deadline) >= 0)
        {
            return false;
        }
        lwip_stop_pump_once();
    }
    return true;
}

/* Resolve the conn's resident netif: caller-supplied, else the external
 * ethernet device. lwIP's loopif installs itself at 127.0.0.1 during
 * lwip_init(), so blindly using netif_default can route public connects
 * through loopback before USB ethernet has promoted itself. */
static struct netif *resolve_netif(struct netif *requested)
{
    return requested ? requested : find_external_netif();
}

/* Track DHCP state for waiters. DHCP is armed by external netifs on link-up,
 * not by connection creation/connect; conns only wait for it when requested. */
#if LWIP_DHCP
static bool dhcp_client_running(const struct netif *n)
{
    struct dhcp *dhcp = n ? netif_dhcp_data(n) : NULL;
    return dhcp && dhcp->state != DHCP_STATE_OFF;
}
#endif

static void copy_ip4_octets(uint8_t out[4], const ip4_addr_t *addr)
{
    if (!out) return;
    if (!addr)
    {
        memset(out, 0, 4);
        return;
    }
    out[0] = ip4_addr1(addr);
    out[1] = ip4_addr2(addr);
    out[2] = ip4_addr3(addr);
    out[3] = ip4_addr4(addr);
}

bool lwip_default_netif_info(lwip_netif_info_t *info)
{
    if (!info)
    {
        return false;
    }

    memset(info, 0, sizeof(*info));

    struct netif *n = find_external_netif();
    if (!n)
    {
        return false;
    }

    info->has_netif = true;
    info->up = netif_is_up(n) != 0;
    info->link_up = netif_is_link_up(n) != 0;

#if LWIP_DHCP
    struct dhcp *dhcp = netif_dhcp_data(n);
    info->dhcp_running = dhcp && dhcp->state != DHCP_STATE_OFF;
    info->dhcp_state = dhcp ? dhcp->state : 0;
#endif

#if LWIP_IPV4
    const ip4_addr_t *ip = netif_ip4_addr(n);
    const ip4_addr_t *mask = netif_ip4_netmask(n);
    const ip4_addr_t *gw = netif_ip4_gw(n);
    info->has_ipv4 = ip && !ip4_addr_isany(ip) && !ip4_addr_isloopback(ip);
    info->has_ipv4_gateway = gw && !ip4_addr_isany(gw);
    copy_ip4_octets(info->ipv4_addr, ip);
    copy_ip4_octets(info->ipv4_netmask, mask);
    copy_ip4_octets(info->ipv4_gateway, gw);
#endif

    return true;
}

/* Explicit membuffer sweep, run during teardown AFTER USB is quiesced
 * (usb_Cleanup) so nothing can be mid-allocation. The driver RX rings are
 * freed by eth_finish_shutdown; this releases the remaining membuffers:
 *   - the TLS file-IO buffer (and other TLS-owned state) via tls_cleanup,
 *     which frees-and-NULLs g_tls_fileio_buffer.
 *   - every registered lwIP pool via mem_buffer_lwip_release_pools.
 * Each owner NULLs its buffer pointer as it frees it, so any later stray
 * reference sees NULL rather than a dangling pointer. */
static void lwip_membuffers_release(void)
{
#if LWIP_ALTCP_TLS
    tls_cleanup();
#endif
    mem_buffer_lwip_release_pools();
}

static void lwip_stack_cleanup(void)
{
    if (!g_lwip_started && !g_lwip_stopping)
    {
        return;
    }

    STOP_TRACE("P0 enter");

    /* Reject new API work and make re-entry a no-op while this blocking
     * teardown pumps USB/timeouts to finish orderly TCP/TLS closes. */
    g_lwip_started = false;
    g_lwip_stopping = true;
    g_requested_service_flags = 0;
    services_list_cancel_all(LWIP_ERR_CLOSED);

    STOP_TRACE("P1 closeTCP+FIN");
    conn_registry_close_tcp_like();
    lwip_teardown_begin_tcp_close();
    STOP_TRACE("P2 awaitTCP");
    if (!lwip_stop_wait_for_tcp(LWIP_STOP_TCP_CLOSE_TIMEOUT_MS))
    {
        STOP_TRACE("P2b abortTCP");
        conn_registry_abort_tcp_like();
        lwip_teardown_abort_tcp_pcbs();
    }
    lwip_teardown_abort_time_wait_pcbs();

#if LWIP_SNTP
    sntp_stop();
#endif

    /* Walk every netif, not just netif_default. Stop netif-owned services
     * before the non-TCP PCB sweep; DHCP/SNTP own UDP PCBs, so removing all
     * UDP first can leave their stop paths touching already-freed PCBs. */
    struct netif *n = NULL;
    NETIF_FOREACH(n)
    {
#if LWIP_DHCP
        if (dhcp_client_running(n))
        {
            dhcp_release_and_stop(n);
        }
#endif
    }

    STOP_TRACE("P3 rmNonTCP");
    lwip_stop_pump_for(LWIP_STOP_SERVICE_SETTLE_MS);
    conn_registry_close_udp();
    lwip_teardown_remove_non_tcp_pcbs();
    conn_registry_mark_closed(LWIP_ERR_CLOSED);
    STOP_TRACE("P4 dispatchStop");
    lwip_dispatch_stop();

    /* At this point the wire-side close is done: FINs have been sent and
     * awaited (or aborted on timeout), the dispatcher is stopped, and the
     * stack holds no live PCBs. eth_prepare_shutdown marks the driver
     * shutting-down so any callback that still fires during USB
     * cancellation below bails out instead of touching stack state. */
    STOP_TRACE("P5 ethPrepare");
    eth_prepare_shutdown();

    STOP_TRACE("P6 netifsDown");
    NETIF_FOREACH(n)
    {
        netif_set_link_down(n);
        netif_set_down(n);
    }

    /* NOTE: we deliberately do NOT call ti_CloseAll() here. That
     * deprecated bcall closes EVERY open fileioc handle system-wide —
     * including handles owned by the consumer program or the OS, since
     * the resident lwIP app is called from a running program rather than
     * being the active program. Closing handles we don't own corrupted
     * the OS file state and crashed on exit. The app's own fileioc use
     * (logging.c, app_config.c) already pairs every ti_Open with a
     * ti_Close in the same scope and keeps no long-lived handles, so
     * there is nothing for the teardown to mop up. */

    /* Quiesce USB FIRST, before freeing any resource a transfer callback
     * could reference. usb_Cleanup cancels every in-flight transfer
     * (firing the rx/tx/interrupt callbacks, which early-return on the
     * shutting-down flag) and disables the devices, handing the USB
     * hardware back to the OS in a clean state. We deliberately do NOT
     * stall endpoints (usb_SetEndpointHalt) — that would leave the
     * controller in a halted condition the OS must clear. After this
     * returns, no driver callback can ever fire again. */
    STOP_TRACE("P8 usbCleanup");
    usb_fn.cleanup();

    /* USB is now silent, so the teardown below is race-free: nothing can
     * call back into a resource as we free it. Release low -> high:
     *   1. driver RX rings + remove netifs (eth_finish_shutdown)
     *   2. remaining membuffers (TLS file-IO buffer, lwIP pools)
     * Each owner frees-and-NULLs its buffer so a stray future reference
     * sees NULL rather than a dangling pointer. */
    STOP_TRACE("P9 ethFinish");
    eth_finish_shutdown();
    STOP_TRACE("P10 memRelease");
    lwip_membuffers_release();

    STOP_TRACE("P11 complete");
    g_lwip_stopping = false;
}

static void lwip_fatal_cleanup(void)
{
    lwip_stack_cleanup();
}

static lwip_error_t apply_service_flags(struct netif *n, uint8_t svc_flags)
{
    if (!n) return LWIP_OK;

#if LWIP_DNS
    if (svc_flags & LWIP_CONN_SVC_DNS)
    {
        /* dns_init() runs as part of lwip_init() already; calling again
         * is a no-op but documents intent. */
        dns_init();
    }
#endif

    if (svc_flags & LWIP_CONN_SVC_SNTP)
    {
        if (!netif_is_up(n) || !netif_is_link_up(n) ||
            !netif_has_usable_ipv4(n))
        {
            return LWIP_OK;
        }
#if LWIP_DHCP
        if ((svc_flags & LWIP_CONN_SVC_DHCP) &&
            (!dhcp_client_running(n) || !netif_has_usable_gateway(n)))
        {
            return LWIP_OK;
        }
#endif
        if (!sntp_enabled())
        {
            sntp_servermode_dhcp(1);
            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_init();
        }
    }

    return LWIP_OK;
}

typedef enum
{
    LWIP_CONN_SERVICES_WAIT = 0,
    LWIP_CONN_SERVICES_READY,
    LWIP_CONN_SERVICES_FAILED,
} lwip_conn_services_state_t;

static bool lwip_conn_services_timed_out(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}

static void lwip_conn_fail(struct lwip_conn *conn, lwip_error_t err)
{
    if (!conn) return;
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                    (int)err, 0);
    conn->pending_host = NULL;
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = err;
    if (conn->on_err) conn->on_err(conn->user_arg, conn, err);
}

static bool netif_has_usable_ipv4(const struct netif *n)
{
#if LWIP_IPV4
    const ip4_addr_t *addr = n ? netif_ip4_addr(n) : NULL;
    return addr && !ip4_addr_isany(addr) && !ip4_addr_isloopback(addr);
#else
    (void)n;
    return true;
#endif
}

static bool netif_has_usable_gateway(const struct netif *n)
{
#if LWIP_IPV4
    const ip4_addr_t *gw = n ? netif_ip4_gw(n) : NULL;
    return gw && !ip4_addr_isany(gw);
#else
    (void)n;
    return true;
#endif
}

static bool host_requires_dns(const char *host)
{
    ip_addr_t parsed;

    if (!host || !*host)
    {
        return false;
    }
    if (ip4addr_aton(host, ip_2_ip4(&parsed)))
    {
        return false;
    }
#if LWIP_IPV6
    if (ip6addr_aton(host, ip_2_ip6(&parsed)))
    {
        return false;
    }
#endif
    return true;
}

static bool dns_has_configured_server(void)
{
#if LWIP_DNS
    for (uint8_t i = 0; i < DNS_MAX_SERVERS; i++)
    {
        const ip_addr_t *server = dns_getserver(i);
        if (server && !ip_addr_isany(server))
        {
            return true;
        }
    }
#endif
    return false;
}

/* Are the requested netif-level services ready for a connect? This also
 * resolves a lazily-created NULL conn->netif to netif_default once USB
 * enumeration creates it, and starts requested netif services the first
 * time a usable netif appears.
 *
 * A connection always needs an administratively-up, link-up netif with a
 * usable local address. With DHCP requested, also require a gateway before
 * attempting transport connect; public destinations otherwise commonly
 * fail immediately with ERR_RTE even though DHCP is still converging. */
static lwip_conn_services_state_t services_check(struct lwip_conn *conn,
                                                 lwip_error_t *err_out,
                                                 const char *host)
{
    lwip_error_t svc_err;

    if (err_out) *err_out = LWIP_OK;
    if (!conn) return LWIP_CONN_SERVICES_FAILED;
    if (!conn->netif)
    {
        conn->netif = resolve_netif(NULL);
    }
    if (!conn->netif)
    {
        if (err_out) *err_out = LWIP_ERR_NETIF;
        return LWIP_CONN_SERVICES_WAIT;
    }

    svc_err = apply_service_flags(conn->netif, conn->flags);
    if (svc_err != LWIP_OK)
    {
        if (err_out) *err_out = svc_err;
        return LWIP_CONN_SERVICES_FAILED;
    }

    if (!netif_is_up(conn->netif))
    {
        if (err_out) *err_out = LWIP_ERR_NETIF;
        return LWIP_CONN_SERVICES_WAIT;
    }
    if (!netif_is_link_up(conn->netif))
    {
        if (err_out) *err_out = LWIP_ERR_NETIF;
        return LWIP_CONN_SERVICES_WAIT;
    }
    if (!netif_has_usable_ipv4(conn->netif))
    {
        if (err_out) *err_out = LWIP_ERR_NETIF;
        return LWIP_CONN_SERVICES_WAIT;
    }

    if (netif_default != conn->netif)
    {
        netif_set_default(conn->netif);
    }

#if LWIP_DHCP
    if (conn->flags & LWIP_CONN_SVC_DHCP)
    {
        if (!dhcp_client_running(conn->netif))
        {
            if (err_out) *err_out = LWIP_ERR_NETIF;
            return LWIP_CONN_SERVICES_WAIT;
        }
        if (!netif_has_usable_gateway(conn->netif))
        {
            if (err_out) *err_out = LWIP_ERR_NETIF;
            return LWIP_CONN_SERVICES_WAIT;
        }
    }
#endif
#if LWIP_DNS
    if ((conn->flags & LWIP_CONN_SVC_DNS) && host_requires_dns(host) &&
        !dns_has_configured_server())
    {
        if (err_out) *err_out = LWIP_ERR_DNS;
        return LWIP_CONN_SERVICES_WAIT;
    }
#endif
    return LWIP_CONN_SERVICES_READY;
}

/* Waiting-services list. Conns enter this list when lwip_conn_connect
 * is called against a netif that isn't ready yet; the dispatcher walks
 * the list every tick and re-attempts the deferred connects. */
static struct lwip_conn *g_services_waiters = NULL;

static void services_list_add(struct lwip_conn *c)
{
    /* Prepend; iteration order doesn't matter. */
    if (!c) return;
    /* Guard against double-add. */
    for (struct lwip_conn *cur = g_services_waiters; cur; cur = cur->services_next)
    {
        if (cur == c) return;
    }
    c->services_next = g_services_waiters;
    g_services_waiters = c;
}

static void services_list_remove(struct lwip_conn *c)
{
    if (!c) return;
    struct lwip_conn **slot = &g_services_waiters;
    while (*slot)
    {
        if (*slot == c)
        {
            *slot = c->services_next;
            c->services_next = NULL;
            return;
        }
        slot = &(*slot)->services_next;
    }
}

static void services_list_cancel_all(lwip_error_t err)
{
    while (g_services_waiters)
    {
        struct lwip_conn *conn = g_services_waiters;
        services_list_remove(conn);
        conn->pending_host = NULL;
        conn->services_deadline = 0;
        conn->status = LWIP_STATUS_CLOSED;
        conn->last_error = err;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES, 0);
}

/* Forward decls so the services dispatcher can drive a connect. */
static lwip_error_t lwip_conn_connect_now(struct lwip_conn *conn,
                                          const char *host, uint16_t port);
static void services_arm(void);

static lwip_error_t lwip_conn_wait_for_services(struct lwip_conn *conn,
                                                const char *host,
                                                uint16_t port,
                                                uint32_t deadline)
{
    conn->pending_host = host;
    conn->remote_port = port;
    conn->status = LWIP_STATUS_WAITING_SERVICES;
    conn->last_error = LWIP_OK;
    conn->services_deadline = deadline;
    services_list_add(conn);
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_WAIT, 0, 0);
#if LWIP_DNS
    if ((conn->flags & LWIP_CONN_SVC_DNS) && host_requires_dns(host) &&
        !dns_has_configured_server())
    {
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_DNS_WAIT, 0, 0);
    }
#endif
    services_arm();
    return LWIP_OK;
}

static void services_dispatch(void)
{
    if (!g_services_waiters)
    {
        /* Nothing to do — disable ourselves until something gets added. */
        lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES, 0);
        return;
    }

    uint32_t now = sys_now();
    struct lwip_conn *c = g_services_waiters;
    while (c)
    {
        struct lwip_conn *next = c->services_next;
        lwip_error_t svc_err = LWIP_OK;
        lwip_conn_services_state_t svc_state = services_check(c, &svc_err,
                                                              c->pending_host);
        if (svc_state == LWIP_CONN_SERVICES_READY)
        {
            const char *host = c->pending_host;
            uint16_t port = c->remote_port;
            uint32_t deadline = c->services_deadline;
            lwip_error_t err;
            services_list_remove(c);
            c->pending_host = NULL;
            c->services_deadline = 0;
            err = lwip_conn_connect_now(c, host, port);
            if (err == LWIP_ERR_NETIF &&
                !lwip_conn_services_timed_out(now, deadline))
            {
                lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_RETRY,
                                (int)LWIP_ERR_NETIF, 0);
                (void)lwip_conn_wait_for_services(c, host, port, deadline);
            }
            else if (err != LWIP_OK && c->on_err)
            {
                c->on_err(c->user_arg, c, err);
            }
        }
        else if (svc_state == LWIP_CONN_SERVICES_FAILED)
        {
            services_list_remove(c);
            lwip_conn_fail(c, svc_err ? svc_err : LWIP_ERR_NETIF);
        }
        else if (lwip_conn_services_timed_out(now, c->services_deadline))
        {
            lwip_error_t timeout_err = svc_err ? svc_err : LWIP_ERR_NETIF;
            services_list_remove(c);
            lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_SERVICES_TIMEOUT,
                            (int)timeout_err, 0);
            lwip_conn_fail(c, timeout_err);
        }
        c = next;
    }

    if (!g_services_waiters)
    {
        lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES, 0);
    }
}

static void services_arm(void)
{
    /* 100 ms cadence: fast enough that the app sees CONNECTING soon
     * after DHCP completes, slow enough not to dominate CPU. */
    lwip_dispatch_attach(LWIP_DISPATCH_CONN_SERVICES, services_dispatch);
    lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES,
                             lwip_dispatch_period_from_ms(100));
    lwip_dispatch_start();
}

/* ============================================================
 * Callback bridges: lower-level pcb → user-facing lwip_conn cb.
 *
 * One set per protocol. Each shim:
 *   - looks up the owning lwip_conn via the pcb's arg slot,
 *   - updates conn->status,
 *   - re-dispatches to the registered user callback (if any).
 * ============================================================ */

/* --- altcp (covers ALTCP and ALTCP_TLS) --- */

static err_t conn_altcp_recv_cb(void *arg, struct altcp_pcb *pcb,
                                struct pbuf *p, err_t err)
{
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (g_lwip_stopping)
    {
        if (p) pbuf_free(p);
        else c->status = LWIP_STATUS_CLOSED;
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (p == NULL)
    {
        c->status = LWIP_STATUS_CLOSED;
        if (c->on_closed) c->on_closed(c->user_arg, c);
        return ERR_OK;
    }
    if (c->on_recv)
    {
        /* App owns both the pbuf lifetime and the ack — see lwip_conn_recved. */
        c->on_recv(c->user_arg, c, p);
        if (c->aborting) return ERR_ABRT;
    }
    else
    {
        /* No consumer registered: ack and drop. This keeps the window
         * advancing for connections the app explicitly ignores. */
        altcp_recved(pcb, p->tot_len);
        pbuf_free(p);
    }
    return ERR_OK;
}

static err_t conn_altcp_sent_cb(void *arg, struct altcp_pcb *pcb, u16_t len)
{
    (void)pcb; (void)len;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (g_lwip_stopping) return ERR_OK;
    if (c && c->on_sent) c->on_sent(c->user_arg, c, (uint16_t)len);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_altcp_poll_cb(void *arg, struct altcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (g_lwip_stopping) return ERR_OK;
    if (c && c->on_poll) c->on_poll(c->user_arg, c);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static void conn_altcp_err_cb(void *arg, err_t err)
{
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return;
    c->status = LWIP_STATUS_ERROR;
    c->last_error = lwip_err_translate(err);
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                    (int)c->last_error, 0);
    /* lower layer freed the pcb */
    c->pcb.altcp = NULL;
    if (g_lwip_stopping) return;
    if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
}

static err_t conn_altcp_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return ERR_OK;
    if (g_lwip_stopping) return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                        (int)c->last_error, 0);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_ESTABLISHED, 0, 0);
    if (c->on_connected) c->on_connected(c->user_arg, c);
    if (c->aborting) return ERR_ABRT;
    return ERR_OK;
}

/* --- UDP --- */

static void conn_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *addr, u16_t port)
{
    (void)pcb; (void)addr; (void)port;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) {
        if (p) pbuf_free(p);
        return;
    }
    if (g_lwip_stopping)
    {
        if (p) pbuf_free(p);
        return;
    }
    if (c->on_recv) c->on_recv(c->user_arg, c, p);
    else            pbuf_free(p);
}

/* --- raw TCP --- */

#if LWIP_TCP
static err_t conn_tcp_recv_cb(void *arg, struct tcp_pcb *pcb,
                              struct pbuf *p, err_t err)
{
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (g_lwip_stopping)
    {
        if (p) pbuf_free(p);
        else c->status = LWIP_STATUS_CLOSED;
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (p == NULL)
    {
        c->status = LWIP_STATUS_CLOSED;
        if (c->on_closed) c->on_closed(c->user_arg, c);
        return ERR_OK;
    }
    if (c->on_recv)
    {
        /* App owns both the pbuf lifetime and the ack — see lwip_conn_recved. */
        c->on_recv(c->user_arg, c, p);
        if (c->aborting) return ERR_ABRT;
    }
    else
    {
        tcp_recved(pcb, p->tot_len);
        pbuf_free(p);
    }
    return ERR_OK;
}

static err_t conn_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)pcb; (void)len;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (g_lwip_stopping) return ERR_OK;
    if (c && c->on_sent) c->on_sent(c->user_arg, c, (uint16_t)len);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (g_lwip_stopping) return ERR_OK;
    if (c && c->on_poll) c->on_poll(c->user_arg, c);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static void conn_tcp_err_cb(void *arg, err_t err)
{
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return;
    c->status = LWIP_STATUS_ERROR;
    c->last_error = lwip_err_translate(err);
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                    (int)c->last_error, 0);
    c->pcb.tcp = NULL;
    if (g_lwip_stopping) return;
    if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
}

static err_t conn_tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return ERR_OK;
    if (g_lwip_stopping) return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                        (int)c->last_error, 0);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_ESTABLISHED, 0, 0);
    if (c->on_connected) c->on_connected(c->user_arg, c);
    if (c->aborting) return ERR_ABRT;
    return ERR_OK;
}
#endif /* LWIP_TCP */

/* Re-bind the underlying pcb's callbacks to our shim functions. Called
 * from create() and again from set_poll() when the interval changes. */
static void rebind_pcb_callbacks(struct lwip_conn *c)
{
    if (!c) return;
    switch ((lwip_protocol_t)c->protocol)
    {
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (c->pcb.altcp)
        {
            altcp_arg(c->pcb.altcp, c);
            altcp_recv(c->pcb.altcp, conn_altcp_recv_cb);
            altcp_sent(c->pcb.altcp, conn_altcp_sent_cb);
            altcp_err(c->pcb.altcp,  conn_altcp_err_cb);
            altcp_poll(c->pcb.altcp, conn_altcp_poll_cb, 4);
        }
        break;
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (c->pcb.tcp)
        {
            tcp_arg(c->pcb.tcp, c);
            tcp_recv(c->pcb.tcp, conn_tcp_recv_cb);
            tcp_sent(c->pcb.tcp, conn_tcp_sent_cb);
            tcp_err(c->pcb.tcp,  conn_tcp_err_cb);
            tcp_poll(c->pcb.tcp, conn_tcp_poll_cb, 4);
        }
        break;
#endif
    case LWIP_PROTO_UDP:
        if (c->pcb.udp)
        {
            udp_recv(c->pcb.udp, conn_udp_recv_cb, c);
        }
        break;
    default:
        break;
    }
}

/* ============================================================
 * Lifecycle: create / destroy
 * ============================================================ */

lwip_error_t lwip_conn_create(struct lwip_conn *conn,
                              struct netif *netif,
                              lwip_protocol_t protocol,
                              uint8_t flags)
{
    if (!conn) return LWIP_ERR_ARG;
    if (!g_lwip_started || g_lwip_stopping) return LWIP_ERR_STATE;

    memset(conn, 0, sizeof(*conn));
    conn->status   = LWIP_STATUS_INIT;
    conn->protocol = (uint8_t)protocol;
    conn->flags    = flags;
    conn->netif    = resolve_netif(netif);
    g_requested_service_flags |= flags;

    switch (protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        conn->pcb.tcp = tcp_new();
        if (!conn->pcb.tcp) goto fail_mem;
        break;
#endif
    case LWIP_PROTO_UDP:
        conn->pcb.udp = udp_new();
        if (!conn->pcb.udp) goto fail_mem;
        break;
    case LWIP_PROTO_ALTCP:
        conn->pcb.altcp = altcp_new(NULL);  /* default = altcp_tcp */
        if (!conn->pcb.altcp) goto fail_mem;
        break;
    case LWIP_PROTO_ALTCP_TLS:
        /* Bring the TLS stack up lazily on the first TLS connection: alloc
         * the RSA/ECC scratch, start the RNG, and load the SPKI trust
         * store. tls_init() gates on tls_ctx.initialized, so this is
         * re-call-safe and a no-op for subsequent TLS connections. Without
         * this the handshake dereferenced NULL scratch / an unstarted RNG
         * and crashed before sending ClientHello. */
        if (!tls_ctx.initialized && !tls_init())
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            return LWIP_ERR_MEM;
        }
        /* TLS config is built in lwip_conn_connect once we know the host
         * (needed for SNI). The pcb is allocated then too. */
        conn->tls_conf = NULL;
        conn->pcb.altcp = NULL;
        break;
    default:
        return LWIP_ERR_PROTO;
    }

    rebind_pcb_callbacks(conn);
    conn_registry_add(conn);
    return LWIP_OK;

fail_mem:
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_MEM;
    return LWIP_ERR_MEM;
}

/* Detach the conn shim from every callback slot on the underlying
 * pcb. After this the pcb may still emit events (a deferred recv after
 * tcp_close, the err cb after abort, etc.) but they'll go to NULL and
 * be swallowed by lwIP instead of dereferencing into a freed conn. */
static void lwip_conn_detach_pcb_callbacks(struct lwip_conn *conn)
{
    if (!conn) return;
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            tcp_arg(conn->pcb.tcp, NULL);
            tcp_recv(conn->pcb.tcp, NULL);
            tcp_sent(conn->pcb.tcp, NULL);
            tcp_err(conn->pcb.tcp, NULL);
            tcp_poll(conn->pcb.tcp, NULL, conn->pcb.tcp->pollinterval);
        }
        break;
#endif
    case LWIP_PROTO_UDP:
        if (conn->pcb.udp)
        {
            udp_recv(conn->pcb.udp, NULL, NULL);
        }
        break;
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            altcp_arg(conn->pcb.altcp, NULL);
            altcp_recv(conn->pcb.altcp, NULL);
            altcp_sent(conn->pcb.altcp, NULL);
            altcp_err(conn->pcb.altcp, NULL);
            altcp_poll(conn->pcb.altcp, NULL, conn->pcb.altcp->pollinterval);
        }
        break;
    default:
        break;
    }
}

lwip_error_t lwip_conn_destroy(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
    conn_registry_remove(conn);
    /* Drop from the services waiter list if we were parked. Safe no-op
     * for conns that never entered WAITING_SERVICES. */
    services_list_remove(conn);
    /* Destruction is not graceful close. lwip_conn_close() owns orderly
     * FIN shutdown; destroy must leave no live pcb that can outlast this
     * transparent handle. Detach first so abort-side callbacks cannot
     * dereference the about-to-be-zeroed conn. */
    lwip_conn_detach_pcb_callbacks(conn);
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            tcp_abort(conn->pcb.tcp);
        }
        break;
#endif
    case LWIP_PROTO_UDP:
        if (conn->pcb.udp) udp_remove(conn->pcb.udp);
        break;
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            altcp_abort(conn->pcb.altcp);
        }
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
        }
        break;
    default:
        break;
    }
    memset(conn, 0, sizeof(*conn));
    conn->status = LWIP_STATUS_CLOSED;
    return LWIP_OK;
}

/* ============================================================
 * Connect (with DNS-or-IP resolution)
 * ============================================================ */

/* Issue the transport-level connect once we have a final ip_addr. Returns
 * lwip_err_t so the caller can roll status/error back on failure. */
static err_t start_transport_connect(struct lwip_conn *c)
{
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_ATTEMPT, 0, 0);

    switch ((lwip_protocol_t)c->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        tcp_bind_netif(c->pcb.tcp, c->netif);
        return tcp_connect(c->pcb.tcp, &c->remote_ip, c->remote_port,
                           conn_tcp_connected_cb);
#endif
    case LWIP_PROTO_UDP:
    {
        udp_bind_netif(c->pcb.udp, c->netif);
        err_t e = udp_connect(c->pcb.udp, &c->remote_ip, c->remote_port);
        if (e == ERR_OK)
        {
            c->status = LWIP_STATUS_CONNECTED;
            if (c->on_connected) c->on_connected(c->user_arg, c);
        }
        return e;
    }
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
    {
        struct altcp_pcb *leaf = c->pcb.altcp;
        while (leaf && leaf->inner_conn)
        {
            leaf = leaf->inner_conn;
        }
        if (leaf && leaf->state && c->netif)
        {
            tcp_bind_netif((struct tcp_pcb *)leaf->state, c->netif);
        }
        return altcp_connect(c->pcb.altcp, &c->remote_ip, c->remote_port,
                             conn_altcp_connected_cb);
    }
    default:
        return ERR_VAL;
    }
}

#if LWIP_DNS
static void conn_dns_found_cb(const char *name, const ip_addr_t *ipaddr,
                              void *callback_arg)
{
    (void)name;
    struct lwip_conn *c = (struct lwip_conn *)callback_arg;
    if (!c) return;
    if (!ipaddr)
    {
        c->pending_host = NULL;
        c->services_deadline = 0;
        c->status = LWIP_STATUS_ERROR;
        c->last_error = LWIP_ERR_DNS;
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                        (int)c->last_error, 0);
        if (c->on_err) c->on_err(c->user_arg, c, LWIP_ERR_DNS);
        return;
    }
    c->remote_ip = *ipaddr;
    c->status = LWIP_STATUS_CONNECTING;

    err_t err = start_transport_connect(c);
    if (err != ERR_OK)
    {
        lwip_error_t mapped = lwip_err_translate(err);
        if (mapped == LWIP_ERR_NETIF)
        {
            uint32_t deadline = c->services_deadline;
            if (!deadline)
            {
                deadline = sys_now() + LWIP_CONN_SERVICES_TIMEOUT_MS;
            }
            (void)lwip_conn_wait_for_services(c, c->pending_host ? c->pending_host : name,
                                              c->remote_port, deadline);
            return;
        }
        c->pending_host = NULL;
        c->services_deadline = 0;
        c->status = LWIP_STATUS_ERROR;
        c->last_error = mapped;
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                        (int)c->last_error, 0);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        return;
    }
    c->pending_host = NULL;
    c->services_deadline = 0;
}
#endif /* LWIP_DNS */

/* Internal: do the actual connect (literal-IP fast path / DNS / TLS
 * setup). Both the public entry point and the services dispatcher
 * call into this once the netif is ready. */
static lwip_error_t lwip_conn_connect_now(struct lwip_conn *conn,
                                          const char *host,
                                          uint16_t port)
{
    conn->remote_port = port;

    /* ALTCP_TLS connects need a TLS config and a wrapped pcb. We defer
     * both until connect() so the SNI hostname is in hand. */
    if (conn->protocol == LWIP_PROTO_ALTCP_TLS && conn->pcb.altcp == NULL)
    {
        conn->tls_conf = altcp_tls_ce_create_config_client_ecdhe(host);
        if (!conn->tls_conf)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            return LWIP_ERR_MEM;
        }
        conn->pcb.altcp = altcp_tls_ce_new(conn->tls_conf, IPADDR_TYPE_V4);
        if (!conn->pcb.altcp)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            return LWIP_ERR_MEM;
        }
        rebind_pcb_callbacks(conn);
    }

    /* IPv4 / IPv6 literal short-circuits DNS. Try v4 first because it
     * fails fast on anything containing ':'; v6 succeeds on either
     * '::1'-style or v4-mapped forms. */
    if (ip4addr_aton(host, ip_2_ip4(&conn->remote_ip)))
    {
        IP_SET_TYPE_VAL(conn->remote_ip, IPADDR_TYPE_V4);
        conn->status = LWIP_STATUS_CONNECTING;
        err_t err = start_transport_connect(conn);
        if (err != ERR_OK)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = lwip_err_translate(err);
            lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                            (int)conn->last_error, 0);
            return conn->last_error;
        }
        conn->pending_host = NULL;
        conn->services_deadline = 0;
        return LWIP_OK;
    }
#if LWIP_IPV6
    if (ip6addr_aton(host, ip_2_ip6(&conn->remote_ip)))
    {
        IP_SET_TYPE_VAL(conn->remote_ip, IPADDR_TYPE_V6);
        conn->status = LWIP_STATUS_CONNECTING;
        err_t err = start_transport_connect(conn);
        if (err != ERR_OK)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = lwip_err_translate(err);
            lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                            (int)conn->last_error, 0);
            return conn->last_error;
        }
        conn->pending_host = NULL;
        conn->services_deadline = 0;
        return LWIP_OK;
    }
#endif

#if LWIP_DNS
    conn->pending_host = host;
    if (!conn->services_deadline)
    {
        conn->services_deadline = sys_now() + LWIP_CONN_SERVICES_TIMEOUT_MS;
    }
    conn->status = LWIP_STATUS_RESOLVING;
    err_t derr = dns_gethostbyname(host, &conn->remote_ip,
                                   conn_dns_found_cb, conn);
    if (derr == ERR_OK)
    {
        /* Cached hit — drive the next stage synchronously. */
        conn_dns_found_cb(host, &conn->remote_ip, conn);
        return LWIP_OK;
    }
    if (derr == ERR_INPROGRESS)
    {
        return LWIP_OK;  /* async — caller polls status */
    }
    conn->pending_host = NULL;
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                    (int)conn->last_error, 0);
    return LWIP_ERR_DNS;
#else
    conn->pending_host = NULL;
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
    lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                    (int)conn->last_error, 0);
    return LWIP_ERR_DNS;
#endif
}


lwip_error_t lwip_conn_connect(struct lwip_conn *conn,
                               const char *host,
                               uint16_t port)
{
    if (!conn || !host) return LWIP_ERR_ARG;
    if (conn->status == LWIP_STATUS_CONNECTED ||
        conn->status == LWIP_STATUS_CONNECTING ||
        conn->status == LWIP_STATUS_RESOLVING ||
        conn->status == LWIP_STATUS_WAITING_SERVICES)
    {
        return LWIP_ERR_STATE;
    }

    lwip_error_t svc_err = LWIP_OK;
    uint32_t deadline = sys_now() + LWIP_CONN_SERVICES_TIMEOUT_MS;
    lwip_conn_services_state_t svc_state = services_check(conn, &svc_err, host);

    /* Fast path: services already up — drive the connect synchronously.
     * If routing still says "not yet" (ERR_RTE/ERR_IF), fall back into
     * the waiter instead of surfacing a transient connect failure. */
    if (svc_state == LWIP_CONN_SERVICES_READY)
    {
        lwip_error_t err = lwip_conn_connect_now(conn, host, port);
        if (err != LWIP_ERR_NETIF)
        {
            return err;
        }
    }
    else if (svc_state == LWIP_CONN_SERVICES_FAILED)
    {
        conn->status = LWIP_STATUS_ERROR;
        conn->last_error = svc_err ? svc_err : LWIP_ERR_NETIF;
        lwip_debug_emit(LWIP_DBG_MOD_LWIP, LWIP_DBG_LWIP_CONN_FAILED,
                        (int)conn->last_error, 0);
        return conn->last_error;
    }

    /* Slow path: park the conn on the services waiter list. The
     * services dispatcher polls every 100 ms and re-attempts the
     * connect once netif_is_up && link_up && (DHCP got an IP if
     * requested). On services timeout we transition to ERROR with
     * LWIP_ERR_NETIF.
     *
     * NOTE: `host` is borrowed; the caller must keep it alive until
     * the conn leaves WAITING_SERVICES. Callers passing string
     * literals are safe. */
    return lwip_conn_wait_for_services(conn, host, port, deadline);
}

/* ============================================================
 * Write / shutdown / close
 * ============================================================ */

lwip_error_t lwip_conn_write(struct lwip_conn *conn,
                             const uint8_t *buf,
                             size_t len)
{
    if (!conn || !buf || len == 0) return LWIP_ERR_ARG;
    if (conn->status != LWIP_STATUS_CONNECTED)
    {
        /* Distinguish "you closed me or the peer did" from "I'm not
         * ready yet." Apps in retry loops can use this to back off vs.
         * give up. */
        if (conn->status == LWIP_STATUS_CLOSING ||
            conn->status == LWIP_STATUS_CLOSED)
        {
            return LWIP_ERR_CLOSED;
        }
        return LWIP_ERR_STATE;
    }

    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
    {
        err_t e = tcp_write(conn->pcb.tcp, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK) tcp_output(conn->pcb.tcp);
        return lwip_err_translate(e);
    }
#endif
    case LWIP_PROTO_UDP:
    {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
        if (!p) return LWIP_ERR_MEM;
        memcpy(p->payload, buf, len);
        err_t e = udp_send(conn->pcb.udp, p);
        pbuf_free(p);
        return lwip_err_translate(e);
    }
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
    {
        err_t e = altcp_write(conn->pcb.altcp, buf, (u16_t)len,
                              TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK) altcp_output(conn->pcb.altcp);
        return lwip_err_translate(e);
    }
    default:
        return LWIP_ERR_PROTO;
    }
}

lwip_error_t lwip_conn_recved(struct lwip_conn *conn, size_t len)
{
    if (!conn) return LWIP_ERR_ARG;
    if (len == 0) return LWIP_OK;
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (!conn->pcb.tcp) return LWIP_ERR_STATE;
        tcp_recved(conn->pcb.tcp, (u16_t)len);
        return LWIP_OK;
#endif
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (!conn->pcb.altcp) return LWIP_ERR_STATE;
        altcp_recved(conn->pcb.altcp, (u16_t)len);
        return LWIP_OK;
    case LWIP_PROTO_UDP:
        return LWIP_OK; /* no flow control for UDP */
    default:
        return LWIP_ERR_PROTO;
    }
}

lwip_error_t lwip_conn_shutdown(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            err_t e = tcp_shutdown(conn->pcb.tcp, 0, 1);
            if (e == ERR_OK) conn->status = LWIP_STATUS_CLOSING;
            return lwip_err_translate(e);
        }
        return LWIP_ERR_STATE;
#endif
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            err_t e = altcp_shutdown(conn->pcb.altcp, 0, 1);
            if (e == ERR_OK) conn->status = LWIP_STATUS_CLOSING;
            return lwip_err_translate(e);
        }
        return LWIP_ERR_STATE;
    case LWIP_PROTO_UDP:
        return LWIP_OK;  /* UDP has no shutdown */
    default:
        return LWIP_ERR_PROTO;
    }
}

lwip_error_t lwip_conn_close(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
    /* Detach BEFORE attempting close so a deferred FIN ACK/err cb
     * doesn't reach into a half-torn-down conn. If close() then fails
     * we re-bind the callbacks below so the app keeps getting events
     * on the still-live pcb. */
    lwip_conn_detach_pcb_callbacks(conn);
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            err_t e = tcp_close(conn->pcb.tcp);
            if (e != ERR_OK)
            {
                /* Close didn't go through (typically ERR_MEM for FIN
                 * enqueue). Re-arm the callbacks so the app continues
                 * to see events, and return the error for retry. */
                if (!g_lwip_stopping)
                {
                    rebind_pcb_callbacks(conn);
                }
                conn->last_error = lwip_err_translate(e);
                return conn->last_error;
            }
            conn->pcb.tcp = NULL;
        }
        break;
#endif
    case LWIP_PROTO_UDP:
        if (conn->pcb.udp)
        {
            udp_remove(conn->pcb.udp);
            conn->pcb.udp = NULL;
        }
        break;
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            err_t e = altcp_close(conn->pcb.altcp);
            if (e != ERR_OK)
            {
                if (!g_lwip_stopping)
                {
                    rebind_pcb_callbacks(conn);
                }
                conn->last_error = lwip_err_translate(e);
                return conn->last_error;
            }
            conn->pcb.altcp = NULL;
        }
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
        }
        break;
    default:
        return LWIP_ERR_PROTO;
    }
    conn->status = LWIP_STATUS_CLOSED;
    conn_registry_remove(conn);
    return LWIP_OK;
}

lwip_error_t lwip_conn_abort(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
    conn_registry_remove(conn);
    services_list_remove(conn);
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            struct tcp_pcb *pcb = conn->pcb.tcp;
            conn->pcb.tcp = NULL;
            conn->aborting = 1;
            tcp_arg(pcb, NULL);
            tcp_recv(pcb, NULL);
            tcp_sent(pcb, NULL);
            tcp_err(pcb, NULL);
            tcp_poll(pcb, NULL, pcb->pollinterval);
            tcp_abort(pcb);
        }
        break;
#endif
    case LWIP_PROTO_UDP:
        if (conn->pcb.udp)
        {
            udp_remove(conn->pcb.udp);
            conn->pcb.udp = NULL;
        }
        break;
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            struct altcp_pcb *pcb = conn->pcb.altcp;
            conn->pcb.altcp = NULL;
            conn->aborting = 1;
            altcp_arg(pcb, NULL);
            altcp_recv(pcb, NULL);
            altcp_sent(pcb, NULL);
            altcp_err(pcb, NULL);
            altcp_poll(pcb, NULL, pcb->pollinterval);
            altcp_abort(pcb);
        }
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
        }
        break;
    default:
        return LWIP_ERR_PROTO;
    }
    conn->status = LWIP_STATUS_CLOSED;
    return LWIP_OK;
}

/* ============================================================
 * Callback setters
 * ============================================================ */

void lwip_conn_set_arg(struct lwip_conn *conn, void *arg)
{
    if (conn) conn->user_arg = arg;
}

void lwip_conn_set_connected(struct lwip_conn *conn, lwip_conn_connected_cb cb)
{
    if (conn) conn->on_connected = cb;
}

void lwip_conn_set_recv(struct lwip_conn *conn, lwip_conn_recv_cb cb)
{
    if (conn) conn->on_recv = cb;
}

void lwip_conn_set_sent(struct lwip_conn *conn, lwip_conn_sent_cb cb)
{
    if (conn) conn->on_sent = cb;
}

void lwip_conn_set_err(struct lwip_conn *conn, lwip_conn_err_cb cb)
{
    if (conn) conn->on_err = cb;
}

void lwip_conn_set_poll(struct lwip_conn *conn, lwip_conn_poll_cb cb,
                        uint8_t interval_ticks)
{
    if (!conn) return;
    conn->on_poll = cb;
    /* Re-arm the underlying poll interval (in 0.5 s ticks). */
    switch ((lwip_protocol_t)conn->protocol)
    {
    case LWIP_PROTO_ALTCP:
    case LWIP_PROTO_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            altcp_poll(conn->pcb.altcp, conn_altcp_poll_cb,
                       interval_ticks ? interval_ticks : 4);
        }
        break;
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            tcp_poll(conn->pcb.tcp, conn_tcp_poll_cb,
                     interval_ticks ? interval_ticks : 4);
        }
        break;
#endif
    default:
        break;
    }
}

void lwip_conn_set_closed(struct lwip_conn *conn, lwip_conn_closed_cb cb)
{
    if (conn) conn->on_closed = cb;
}

void lwip_conn_set_callbacks(struct lwip_conn *conn,
                             const lwip_conn_callbacks_t *cbs)
{
    if (!conn || !cbs) return;
    /* Delegate to the individual setters so the poll re-arm side effect
     * (altcp_poll / tcp_poll) stays in one place. */
    lwip_conn_set_arg(conn, cbs->arg);
    lwip_conn_set_connected(conn, cbs->connected);
    lwip_conn_set_recv(conn, cbs->recv);
    lwip_conn_set_sent(conn, cbs->sent);
    lwip_conn_set_err(conn, cbs->err);
    lwip_conn_set_poll(conn, cbs->poll, cbs->poll_interval_ticks);
    lwip_conn_set_closed(conn, cbs->closed);
}
