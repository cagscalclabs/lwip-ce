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
#include "lwip/timeouts.h"
#include "lwip/app_config.h"
#include "lwip/apps/sntp.h"
#include "lwip/sntp_time.h"
#include "drivers/usb_ethernet.h"
#include "apps/altcp_tls/altcp_tls_ce.h"

#include <usbdrvce.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Init / poll
 * ============================================================ */

static bool g_lwip_started = false;
static lwip_app_config_t g_lwip_cfg;

bool lwip_start(void)
{
    if (g_lwip_started)
    {
        return true;
    }

    lwip_app_config_load(&g_lwip_cfg);

    struct lwip_configurator conf = LWIP_CONFIGURATOR_INIT;
    conf.usb_conf.reset_device              = usb_ResetDevice;
    conf.usb_conf.disable_device            = usb_DisableDevice;
    conf.usb_conf.ref_device                = usb_RefDevice;
    conf.usb_conf.unref_device              = usb_UnrefDevice;
    conf.usb_conf.set_device_data           = usb_SetDeviceData;
    conf.usb_conf.get_device_data           = usb_GetDeviceData;
    conf.usb_conf.get_role                  = usb_GetRole;
    conf.usb_conf.get_device_flags          = usb_GetDeviceFlags;
    conf.usb_conf.schedule_transfer         = usb_ScheduleTransfer;
    conf.usb_conf.control_transfer          = usb_ControlTransfer;
    conf.usb_conf.get_config_descriptor_len = usb_GetConfigurationDescriptorTotalLength;
    conf.usb_conf.get_descriptor            = usb_GetDescriptor;
    conf.usb_conf.get_string_descriptor     = usb_GetStringDescriptor;
    conf.usb_conf.set_configuration         = usb_SetConfiguration;
    conf.usb_conf.set_interface             = usb_SetInterface;
    conf.usb_conf.get_device_endpoint       = usb_GetDeviceEndpoint;
    conf.usb_conf.set_endpoint_data         = usb_SetEndpointData;
    conf.usb_conf.get_endpoint_data         = usb_GetEndpointData;
    conf.usb_conf.set_endpoint_flags        = usb_SetEndpointFlags;
    conf.usb_conf.set_endpoint_halt         = usb_SetEndpointHalt;
    conf.usb_conf.init                      = usb_Init;
    conf.usb_conf.handle_events             = usb_HandleEvents;

    if (lwip_init(&conf) != ERR_OK)
    {
        return false;
    }
    /* Route usb_Init through usb_fn so the libload build can resolve it
     * via include_library 'usbdrvce.lib' without a special case. */
    if (usb_fn.init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
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
static void apply_service_flags(struct netif *n, uint8_t svc_flags)
{
    if (!n) return;

#if LWIP_DHCP
    if ((svc_flags & LWIP_CONN_SVC_DHCP) && !dhcp_supplied_address(n))
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
    return ERR_OK;
}

static err_t conn_altcp_poll_cb(void *arg, struct altcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (c && c->on_poll) c->on_poll(c->user_arg, c);
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
    return ERR_OK;
}

static err_t conn_tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_conn *c = (struct lwip_conn *)arg;
    if (c && c->on_poll) c->on_poll(c->user_arg, c);
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

lwip_error_t lwip_conn_destroy(struct lwip_conn *conn)
{
    if (!conn) return LWIP_ERR_ARG;
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

lwip_error_t lwip_conn_connect(struct lwip_conn *conn,
                               const char *host,
                               uint16_t port)
{
    if (!conn || !host) return LWIP_ERR_ARG;
    if (conn->status == LWIP_STATUS_CONNECTED ||
        conn->status == LWIP_STATUS_CONNECTING ||
        conn->status == LWIP_STATUS_RESOLVING)
    {
        return LWIP_ERR_STATE;
    }

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

    /* IPv4 literal short-circuits DNS. */
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

/* ============================================================
 * Write / shutdown / close
 * ============================================================ */

lwip_error_t lwip_conn_write(struct lwip_conn *conn,
                             const uint8_t *buf,
                             size_t len)
{
    if (!conn || !buf || len == 0) return LWIP_ERR_ARG;
    if (conn->status != LWIP_STATUS_CONNECTED) return LWIP_ERR_STATE;

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
    lwip_error_t rc = LWIP_OK;
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
            if (altcp_close(conn->pcb.altcp) != ERR_OK)
            {
                altcp_abort(conn->pcb.altcp);
            }
            conn->pcb.altcp = NULL;
        }
        break;
    default:
        rc = LWIP_ERR_PROTO;
        break;
    }
    conn->status = LWIP_STATUS_CLOSED;
    return rc;
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
