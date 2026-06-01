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
 *  - lwip_conn_create can request services (DHCP / SNTP / DNS) be started
 *    on the resident netif. This mirrors the policy in main.c's
 *    apply_network_config but reapplies idempotently each create.
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
#include "apps/altcp_tls/altcp_tls_ce.h"

#include <usbdrvce.h>
#include <fileioc.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Init / poll
 * ============================================================ */

static bool g_lwip_started = false;
static bool g_lwip_cleanup_registered = false;
static lwip_app_config_t g_lwip_cfg;

static void lwip_stack_cleanup(void);
static void lwip_fatal_cleanup(uint8_t type, uint8_t reason);

bool lwip_start(void)
{
    if (g_lwip_started)
    {
        return true;
    }

    lwip_app_config_load(&g_lwip_cfg);
    if (!g_lwip_cleanup_registered)
    {
        atexit(lwip_stack_cleanup);
        g_lwip_cleanup_registered = true;
    }
    lwip_log_set_fatal_handler(lwip_fatal_cleanup);

    if (lwip_init() != ERR_OK)
    {
        return false;
    }
    /* USB init via usb_fn so the libload build resolves through
     * include_library 'usbdrvce.lib' without a special case. If this
     * fails we must roll back lwip_init's side effects — leaving
     * timeouts / netifs alive after lwip_start returned false would
     * let the next start attempt see a half-initialized stack. */
    if (usb_fn.init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        g_lwip_started = true;   /* let cleanup do its full sweep */
        lwip_stack_cleanup();
        return false;
    }

    g_lwip_started = true;
    return true;
}

void lwip_poll_network_events(void)
{
    usb_fn.handle_events();
    sys_check_timeouts();
}

/* ============================================================
 * Helpers
 * ============================================================ */

static lwip_error_t lwip_err_translate(err_t e)
{
    switch (e)
    {
    case ERR_OK:    return LWIP_OK;
    case ERR_MEM:   return LWIP_ERR_MEM;
    case ERR_ARG:   return LWIP_ERR_ARG;
    case ERR_VAL:   return LWIP_ERR_ARG;
    case ERR_CLSD:
    case ERR_RST:   return LWIP_ERR_CLOSED;
    case ERR_CONN:  return LWIP_ERR_CONNECT;
    default:        return LWIP_ERR_INTERNAL;
    }
}

/* Resolve the conn's resident netif: caller-supplied, else netif_default. */
static struct netif *resolve_netif(struct netif *requested)
{
    return requested ? requested : netif_default;
}

/* Apply service-up flags on the resident netif. Idempotent — already-up
 * services are left alone. */
#if LWIP_DHCP
static bool dhcp_client_running(const struct netif *n)
{
    struct dhcp *dhcp = n ? netif_dhcp_data(n) : NULL;
    return dhcp && dhcp->state != DHCP_STATE_OFF;
}
#endif

static void lwip_stack_cleanup(void)
{
    if (!g_lwip_started)
    {
        return;
    }
    /* Mark down first so re-entry (fatal handler firing during atexit,
     * or vice versa) is a no-op. */
    g_lwip_started = false;

    /* Stop the lwIP-CE master dispatcher first so no further RX-drain
     * or RNG ticks fire against a stack we're tearing down. lwIP's own
     * cyclic timers stay running until sys_check_timeouts is drained
     * via usb_fn.cleanup's wait loop. */
    lwip_dispatch_stop();

    /* Halt USB endpoints BEFORE aborting PCBs. Without this, frames
     * currently in flight on the device could land in the rx ring
     * mid-teardown — at best a wasted pbuf_alloc, at worst a use of
     * a memory pool that lwIP is concurrently dismantling. */
    eth_halt_all_endpoints();

    lwip_teardown_abort_pcbs();

#if LWIP_SNTP
    sntp_stop();
#endif

    /* Walk every netif, not just netif_default. Apps with multiple
     * interfaces need DHCP-release + admin-down on each before USB
     * disappears — otherwise DHCP timers continue firing against a
     * dead transport. */
    struct netif *n = NULL;
    NETIF_FOREACH(n)
    {
#if LWIP_DHCP
        if (dhcp_client_running(n))
        {
            dhcp_release_and_stop(n);
        }
#endif
        netif_set_link_down(n);
        netif_set_down(n);
    }

    usb_fn.cleanup();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ti_CloseAll();
#pragma GCC diagnostic pop
}

static void lwip_fatal_cleanup(uint8_t type, uint8_t reason)
{
    (void)type;
    (void)reason;
    lwip_stack_cleanup();
}

static void apply_service_flags(struct netif *n, uint8_t svc_flags)
{
    if (!n) return;

#if LWIP_DHCP
    if ((svc_flags & LWIP_CONN_SVC_DHCP) && !dhcp_client_running(n))
    {
        dhcp_start(n);
    }
#endif

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
        if (!sntp_enabled())
        {
            sntp_servermode_dhcp(1);
            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_init();
        }
    }
}

/* Are the requested netif-level services ready for a connect? A netif
 * with DHCP requested must have a non-any IPv4 address before tcp_connect
 * will produce a meaningful packet; without DHCP we accept whatever IP
 * the user statically configured. */
static bool services_ready(const struct lwip_conn *conn)
{
    if (!conn || !conn->netif) return false;
    if (!netif_is_up(conn->netif)) return false;
    if (!netif_is_link_up(conn->netif)) return false;

#if LWIP_IPV4
    if (conn->flags & LWIP_CONN_SVC_DHCP)
    {
        if (ip4_addr_isany_val(*netif_ip4_addr(conn->netif)))
        {
            return false;
        }
    }
#endif
    return true;
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

/* Forward decls so the services dispatcher can drive a connect. */
static lwip_error_t lwip_conn_connect_now(struct lwip_conn *conn,
                                          const char *host, uint16_t port);

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
        if (services_ready(c))
        {
            const char *host = c->pending_host;
            uint16_t port = c->remote_port;
            services_list_remove(c);
            c->pending_host = NULL;
            c->services_deadline = 0;
            (void)lwip_conn_connect_now(c, host, port);
        }
        else if (now > c->services_deadline)
        {
            services_list_remove(c);
            c->pending_host = NULL;
            c->services_deadline = 0;
            c->status = LWIP_STATUS_ERROR;
            c->last_error = LWIP_ERR_NETIF;
            if (c->on_err) c->on_err(c->user_arg, c, LWIP_ERR_NETIF);
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
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (c && c->on_sent) c->on_sent(c->user_arg, c, (uint16_t)len);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_altcp_poll_cb(void *arg, struct altcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
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
    /* lower layer freed the pcb */
    c->pcb.altcp = NULL;
    if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
}

static err_t conn_altcp_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
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
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (c && c->on_sent) c->on_sent(c->user_arg, c, (uint16_t)len);
    if (c && c->aborting) return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
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
    c->pcb.tcp = NULL;
    if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
}

static err_t conn_tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (!c) return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
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
    if (!g_lwip_started) return LWIP_ERR_STATE;

    memset(conn, 0, sizeof(*conn));
    conn->status   = LWIP_STATUS_INIT;
    conn->protocol = (uint8_t)protocol;
    conn->flags    = flags;
    conn->netif    = resolve_netif(netif);

    if (!conn->netif)
    {
        conn->status = LWIP_STATUS_ERROR;
        conn->last_error = LWIP_ERR_NETIF;
        return LWIP_ERR_NETIF;
    }

    apply_service_flags(conn->netif, flags);

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
        /* TLS config is built in lwip_conn_connect once we know the host
         * (needed for SNI). The pcb is allocated then too. */
        conn->tls_conf = NULL;
        conn->pcb.altcp = NULL;
        break;
    default:
        return LWIP_ERR_PROTO;
    }

    rebind_pcb_callbacks(conn);
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
    /* Drop from the services waiter list if we were parked. Safe no-op
     * for conns that never entered WAITING_SERVICES. */
    services_list_remove(conn);
    /* Detach callbacks FIRST. If tcp_close defers the FIN (pcb is kept
     * alive by lwIP until peer ACKs) any subsequent recv/err callback
     * the pcb raises would otherwise hit our shim with arg pointing at
     * the about-to-be-zeroed conn. */
    lwip_conn_detach_pcb_callbacks(conn);
    switch ((lwip_protocol_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        if (conn->pcb.tcp)
        {
            if (tcp_close(conn->pcb.tcp) != ERR_OK)
            {
                tcp_abort(conn->pcb.tcp);
            }
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
            if (altcp_close(conn->pcb.altcp) != ERR_OK)
            {
                altcp_abort(conn->pcb.altcp);
            }
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
    switch ((lwip_protocol_t)c->protocol)
    {
#if LWIP_TCP
    case LWIP_PROTO_TCP:
        return tcp_connect(c->pcb.tcp, &c->remote_ip, c->remote_port,
                           conn_tcp_connected_cb);
#endif
    case LWIP_PROTO_UDP:
    {
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
        return altcp_connect(c->pcb.altcp, &c->remote_ip, c->remote_port,
                             conn_altcp_connected_cb);
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
        c->status = LWIP_STATUS_ERROR;
        c->last_error = LWIP_ERR_DNS;
        if (c->on_err) c->on_err(c->user_arg, c, LWIP_ERR_DNS);
        return;
    }
    c->remote_ip = *ipaddr;
    c->status = LWIP_STATUS_CONNECTING;

    err_t err = start_transport_connect(c);
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        if (c->on_err) c->on_err(c->user_arg, c, c->last_error);
    }
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
            return conn->last_error;
        }
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
            return conn->last_error;
        }
        return LWIP_OK;
    }
#endif

#if LWIP_DNS
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
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
    return LWIP_ERR_DNS;
#else
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
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

    /* Fast path: services already up — drive the connect synchronously. */
    if (services_ready(conn))
    {
        return lwip_conn_connect_now(conn, host, port);
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
    conn->pending_host = host;
    conn->remote_port = port;
    conn->status = LWIP_STATUS_WAITING_SERVICES;
    conn->services_deadline = sys_now() + LWIP_CONN_SERVICES_TIMEOUT_MS;
    services_list_add(conn);
    services_arm();
    return LWIP_OK;
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
                rebind_pcb_callbacks(conn);
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
                rebind_pcb_callbacks(conn);
                conn->last_error = lwip_err_translate(e);
                return conn->last_error;
            }
            conn->pcb.altcp = NULL;
        }
        break;
    default:
        return LWIP_ERR_PROTO;
    }
    conn->status = LWIP_STATUS_CLOSED;
    return LWIP_OK;
}

lwip_error_t lwip_conn_abort(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
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
