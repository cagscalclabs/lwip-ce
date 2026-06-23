/**
 * @file lwIP.c
 * @brief App-facing socket API. See lwIP.h for the contract.
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
 *  - lwip_socket_create allocates the socket handle/pcb and records any
 *    requested netif-level services. lwip_socket_connect owns transport
 *    readiness, mirroring socket-style behavior by parking the socket
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

#define LWIP_DBG_FILE_ID LWIP_FILE_LWIP_CE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_LWIP
#include "lwip/sntp_time.h"
#include "drivers/usb_ethernet.h"
#include "drivers/mem.h"
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
#define STOP_TRACE(msg)              \
    do                               \
    {                                \
        os_ClrHome();                \
        os_PutStrFull("stop: " msg); \
        os_PutStrFull(" [key]");     \
        os_GetKey();                 \
    } while (0)
#else
#define STOP_TRACE(msg) ((void)0)
#endif

/* ============================================================
 * Init / poll
 * ============================================================ */

/* Minimum-plausible-clock floor: if the RTC reads earlier than this at
 * startup (e.g. reset to 0/1970 by a RAM clear, or never set), it's clamped
 * forward to this value so timestamp-based checks elsewhere -- certificate
 * expiry (tls_x509_time_in_validity), PSK ticket aging -- aren't silently
 * defeated by an implausible clock before SNTP has a chance to run. This is
 * NOT a substitute for SNTP: it only rules out "clock reads before this
 * library was released," not "clock is accurate." Bump this manually each
 * release; do not try to keep it in sync with the actual build date
 * automatically. Currently: 2026-06-21T00:00:00Z. */
#define LWIP_MIN_PLAUSIBLE_CLOCK_UNIX 1782000000u

static bool g_lwip_stack_started = false;
static bool g_lwip_started = false;
static bool g_lwip_stopping = false;
static lwip_app_config_t g_lwip_cfg;
static uint8_t g_requested_service_flags = 0;
static uint8_t g_lwip_start_error = 0;
static struct lwip_socket *g_conn_registry = NULL;

/* Internal event data buffers — pointed at by ev_data in the callback.
 * Static storage; valid only for the duration of the callback dispatch. */
static lwip_socket_error_data_t lwip_socket_error_data;
static lwip_socket_state_data_t lwip_socket_state_data;
static lwip_socket_io_data_t    lwip_socket_io_data;

typedef enum
{
    CONN_PENDING_WAITING = 0,
    CONN_PENDING_RESOLVING,
    CONN_PENDING_CONNECTING,
    CONN_PENDING_CONNECTED,
    CONN_PENDING_READABLE,
    CONN_PENDING_WRITABLE,
    CONN_PENDING_POLL,
    CONN_PENDING_CLOSING,
    CONN_PENDING_CLOSED,
    CONN_PENDING_RESET,
    CONN_PENDING_ERROR,
} conn_pending_event_t;

static void lwip_stack_cleanup(void);
bool lwip_stack_init(void); /* not static: called from lwip_init_runtime_internal
                              * (core/lwip_runtime.c) at libload bootstrap time.
                              * Internal — not in the public manifest/header. */
static void lwip_fatal_cleanup(void);
static void lwip_membuffers_release(void);
static lwip_error_t apply_service_flags(struct netif *n, uint8_t svc_flags);
static struct netif *find_external_netif(void);
static bool netif_has_usable_ipv4(const struct netif *n);
static bool netif_has_usable_gateway(const struct netif *n);
static bool host_requires_dns(const char *host);
static bool dns_has_configured_server(void);
static void lwip_socket_detach_pcb_callbacks(struct lwip_socket *conn);
static void services_list_remove(struct lwip_socket *c);
static void services_list_cancel_all(lwip_error_t err);
static void netif_service_requests_cancel_all(lwip_netif_service_status_t status);
static void services_arm(void);
static void services_dispatch(void);
static void conn_registry_dispatch_events(void);
static void conn_connect_watchdog(uint32_t now);
static uint32_t conn_window_ms(const struct lwip_socket *conn);
static void conn_event_enqueue(struct lwip_socket *conn,
                               conn_pending_event_t event,
                               lwip_error_t err);
static void conn_error_enqueue(struct lwip_socket *conn,
                               lwip_socket_error_component_t component,
                               lwip_socket_error_operation_t operation,
                               int raw_error,
                               lwip_error_t err);
static void lwip_socket_rx_ring_destroy(struct lwip_socket *conn);
static struct netif *socket_find_qualifying_netif(
    lwip_socket_bind_descriptor_t bind);
static void socket_bind_netif(struct lwip_socket *conn, struct netif *netif);
static lwip_error_t socket_attach_netif(struct lwip_socket *conn,
                                        lwip_socket_bind_descriptor_t bind,
                                        const lwip_socket_addrinfo_t *addrinfo,
                                        uint32_t timeout_ms);

#ifndef LWIP_STOP_SERVICE_SETTLE_MS
#define LWIP_STOP_SERVICE_SETTLE_MS 250u
#endif

#ifndef LWIP_STOP_TCP_CLOSE_TIMEOUT_MS
#define LWIP_STOP_TCP_CLOSE_TIMEOUT_MS LWIP_TCP_CLOSE_TIMEOUT_MS_DEFAULT
#endif

#ifndef LWIP_SOCKET_CLOSE_TIMEOUT_MS
#define LWIP_SOCKET_CLOSE_TIMEOUT_MS 3000u
#endif

#ifndef LWIP_NETIF_SERVICE_REQUEST_MAX
#define LWIP_NETIF_SERVICE_REQUEST_MAX 4u
#endif

#define SOCKET_EVT_BIT(e) ((uint16_t)(1u << (uint8_t)(e)))

/* No-network bootstrap: stack memory, timers, and (RNG-only) TLS init.
 * Touches nothing USB/netif-related — see lwip_network_up() for that.
 * Dispatched once from lwip_start_with_crt() (the libload bootstrap), but
 * kept callable standalone too (e.g. re-init after lwip_stop()). This is
 * also the entry point every unit test relies on to make crypto/memory
 * primitives usable via lwip_start() alone, without bringing up
 * networking -- do not move lwip_init()/tls_init() out of here again
 * without updating every test under tests/unit/ first. */
bool lwip_stack_init(void)
{
    if (g_lwip_stack_started)
    {
        return true;
    }

    g_lwip_start_error = 0;
    g_lwip_stopping = false;
    lwip_app_config_load(&g_lwip_cfg);
    lwip_debug_set_fatal_cleanup(lwip_fatal_cleanup);
    eth_reset_shutdown();
    lwip_sntp_clamp_rtc_floor(LWIP_MIN_PLAUSIBLE_CLOCK_UNIX);

    if (lwip_init() != ERR_OK)
    {
        g_lwip_start_error = 1;
        lwip_membuffers_release();
        return false;
    }
    /* tls_init() brings up the RNG, the cert truststore, and the PSK/
     * session-ticket cache in one call -- fixed one-time setup, run here
     * rather than lazily on the first TLS socket so lwip_start() alone is
     * sufficient for crypto-only callers (every unit test under
     * tests/unit/ relies on this). Gated on the wizard's "Enable TLS"
     * setting -- skip it entirely when TLS is disabled. */
    if (g_lwip_cfg.tls_enabled && !tls_init())
    {
        g_lwip_start_error = 1;
        lwip_membuffers_release();
        return false;
    }

    g_lwip_stack_started = true;
    return true;
}

bool lwip_network_up(void)
{
    if (g_lwip_started)
    {
        return true;
    }

    if (!lwip_stack_init())
    {
        return false;
    }

    /* USB init via usb_fn so the libload build resolves through
     * include_library '../usbdrvce/usbdrvce.asm' without a special case. If this
     * fails we must roll back lwip_init's side effects — leaving
     * timeouts / netifs alive after lwip_network_up returned false would
     * let the next start attempt see a half-initialized stack. */
    if (usb_fn.init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        g_lwip_start_error = 2;
        g_lwip_started = true; /* let cleanup do its full sweep */
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

void lwip_service_events(void)
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
    if (!g_lwip_stopping)
    {
        services_dispatch();
        conn_connect_watchdog(sys_now());
        conn_registry_dispatch_events();
    }
}

uint32_t lwip_now_ms(void)
{
    return sys_now();
}

/* ============================================================
 * Helpers
 * ============================================================ */

static lwip_error_t lwip_err_translate(err_t e)
{
    switch (e)
    {
    case ERR_OK:
        return LWIP_OK;
    case ERR_MEM:
    case ERR_BUF:
    case ERR_MEM_CONFIG_UNSET:
        return LWIP_ERR_MEM;
    case ERR_ARG:
    case ERR_VAL:
        return LWIP_ERR_ARG;
    case ERR_RTE:
    case ERR_IF:
        return LWIP_ERR_NETIF;
    case ERR_TIMEOUT:
    case ERR_ABRT:
    case ERR_CONN:
        return LWIP_ERR_CONNECT;
    case ERR_INPROGRESS:
    case ERR_WOULDBLOCK:
    case ERR_USE:
    case ERR_ALREADY:
    case ERR_ISCONN:
        return LWIP_ERR_STATE;
    case ERR_CLSD:
    case ERR_RST:
        return LWIP_ERR_CLOSED;
    default:
        return LWIP_ERR_INTERNAL;
    }
}

static bool netif_is_external_network(const struct netif *n)
{
    return n && ((n->flags & NETIF_FLAG_ETHERNET) != 0);
}

static bool netif_is_loop_network(const struct netif *n)
{
    return n && n->name[0] == 'l' && n->name[1] == 'o';
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

static struct netif *find_loop_netif(void)
{
    struct netif *n = NULL;

    if (netif_is_loop_network(netif_default))
    {
        return netif_default;
    }

    NETIF_FOREACH(n)
    {
        if (netif_is_loop_network(n))
        {
            return n;
        }
    }

    return NULL;
}

static struct netif *socket_find_qualifying_netif(
    lwip_socket_bind_descriptor_t bind)
{
    switch (bind)
    {
    case LWIP_NETIF_EXT:
        return find_external_netif();
    case LWIP_NETIF_LOOP:
        return find_loop_netif();
    case LWIP_NETIF_ANY:
    default:
    {
        struct netif *n = find_external_netif();
        return n ? n : find_loop_netif();
    }
    }
}

static void conn_registry_add(struct lwip_socket *conn)
{
    if (!conn)
        return;
    for (struct lwip_socket *cur = g_conn_registry; cur; cur = cur->registry_next)
    {
        if (cur == conn)
            return;
    }
    conn->registry_next = g_conn_registry;
    g_conn_registry = conn;
}

static void conn_registry_remove(struct lwip_socket *conn)
{
    if (!conn)
        return;
    struct lwip_socket **slot = &g_conn_registry;
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

static void conn_event_enqueue(struct lwip_socket *conn,
                               conn_pending_event_t event,
                               lwip_error_t err)
{
    if (!conn || event > CONN_PENDING_ERROR)
    {
        return;
    }
    conn->pending_events |= SOCKET_EVT_BIT(event);
    if (err != LWIP_OK)
    {
        conn->pending_error = err;
    }
}

static void conn_error_enqueue(struct lwip_socket *conn,
                               lwip_socket_error_component_t component,
                               lwip_socket_error_operation_t operation,
                               int raw_error,
                               lwip_error_t err)
{
    if (!conn)
    {
        return;
    }
    conn->last_error = err;
    conn->pending_error_component = (uint16_t)component;
    conn->pending_error_operation = (uint16_t)operation;
    conn->pending_raw_error = raw_error;
    lwip_traceback_push_socket((uint16_t)component, (uint16_t)operation,
                               raw_error, (uint16_t)err,
                               (uint16_t)conn->status);
    conn_event_enqueue(conn, CONN_PENDING_ERROR, err);
}

static bool conn_event_pop(struct lwip_socket *conn,
                           conn_pending_event_t *event,
                           lwip_error_t *err)
{
    if (!conn || !conn->pending_events || !event || !err)
    {
        return false;
    }

    for (uint8_t i = 0; i <= (uint8_t)CONN_PENDING_ERROR; i++)
    {
        uint16_t bit = (uint16_t)(1u << i);
        if (conn->pending_events & bit)
        {
            conn->pending_events &= (uint16_t)~bit;
            *event = (conn_pending_event_t)i;
            *err = (i == (uint8_t)CONN_PENDING_ERROR) ?
                (conn->pending_error ? conn->pending_error : conn->last_error) :
                LWIP_OK;
            if (i == (uint8_t)CONN_PENDING_ERROR)
            {
                conn->pending_error = LWIP_OK;
            }
            return true;
        }
    }
    return false;
}

static bool conn_pending_is_state_event(conn_pending_event_t event)
{
    return event == CONN_PENDING_WAITING ||
           event == CONN_PENDING_RESOLVING ||
           event == CONN_PENDING_CONNECTING ||
           event == CONN_PENDING_CONNECTED ||
           event == CONN_PENDING_CLOSING ||
           event == CONN_PENDING_CLOSED ||
           event == CONN_PENDING_RESET;
}


static lwip_status_t conn_pending_status(conn_pending_event_t event,
                                         lwip_status_t fallback)
{
    switch (event)
    {
    case CONN_PENDING_WAITING:
        return LWIP_STATUS_WAITING_SERVICES;
    case CONN_PENDING_RESOLVING:
        return LWIP_STATUS_RESOLVING;
    case CONN_PENDING_CONNECTING:
        return LWIP_STATUS_CONNECTING;
    case CONN_PENDING_CONNECTED:
        return LWIP_STATUS_CONNECTED;
    case CONN_PENDING_CLOSING:
        return LWIP_STATUS_CLOSING;
    case CONN_PENDING_CLOSED:
        return LWIP_STATUS_CLOSED;
    case CONN_PENDING_RESET:
        return LWIP_STATUS_RESET;
    default:
        return fallback;
    }
}

static uint8_t conn_pending_io_flags(conn_pending_event_t event)
{
    switch (event)
    {
    case CONN_PENDING_READABLE:
        return LWIP_SOCKET_IO_READABLE;
    case CONN_PENDING_WRITABLE:
        return LWIP_SOCKET_IO_WRITABLE;
    case CONN_PENDING_POLL:
        return LWIP_SOCKET_IO_POLL;
    default:
        return 0;
    }
}

static lwip_socket_error_component_t conn_transport_component(
    const struct lwip_socket *conn)
{
    if (!conn)
    {
        return LWIP_SOCKET_ERR_COMP_SOCKET;
    }
    switch ((lwip_socket_type_t)conn->protocol)
    {
    case LWIP_SOCKET_TCP:
        return LWIP_SOCKET_ERR_COMP_TCP;
    case LWIP_SOCKET_UDP:
        return LWIP_SOCKET_ERR_COMP_UDP;
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        return LWIP_SOCKET_ERR_COMP_ALTCP;
    default:
        return LWIP_SOCKET_ERR_COMP_SOCKET;
    }
}

static void conn_dispatch_user_event(struct lwip_socket *conn,
                                     lwip_socket_event_type_t type,
                                     const void *data)
{
    if (!conn || !conn->on_event)
    {
        return;
    }
    uint8_t flag = (uint8_t)(1u << (uint8_t)type);
    if (conn->event_flags & flag)
    {
        conn->on_event(conn, type, data, conn->user_arg);
    }
}

static void conn_dispatch_one_event(struct lwip_socket *conn,
                                    conn_pending_event_t event,
                                    lwip_error_t err)
{
    if (!conn)
    {
        return;
    }

    if (event == CONN_PENDING_ERROR)
    {
        lwip_error_t e = err ? err : conn->last_error;
        lwip_socket_error_data.component = conn->pending_error_component;
        lwip_socket_error_data.operation = conn->pending_error_operation;
        lwip_socket_error_data.raw_error  = conn->pending_raw_error;
        lwip_socket_error_data.err        = e;
        lwip_socket_error_data.status     = conn->status;
        conn_dispatch_user_event(conn, LWIP_SOCKET_EV_ERROR,
                                 &lwip_socket_error_data);
    }
    else if (conn_pending_is_state_event(event))
    {
        lwip_status_t current = conn_pending_status(event, conn->status);
        lwip_socket_state_data.previous = conn->pending_state_previous;
        lwip_socket_state_data.current  = current;
        conn_dispatch_user_event(conn, LWIP_SOCKET_EV_STATE_CHANGE,
                                 &lwip_socket_state_data);
        conn->pending_state_previous = current;
    }
    else
    {
        uint8_t io_flags = conn_pending_io_flags(event);
        if (io_flags)
        {
            lwip_socket_io_data.flags    = io_flags;
            lwip_socket_io_data.readable = lwip_socket_available(conn);
            lwip_socket_io_data.written  = conn->last_sent_len;
            conn_dispatch_user_event(conn, LWIP_SOCKET_EV_IO,
                                     &lwip_socket_io_data);
        }
    }
}

static void conn_registry_dispatch_events(void)
{
    struct lwip_socket *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_socket *next = conn->registry_next;
        conn_pending_event_t event;
        lwip_error_t err;
        if (conn_event_pop(conn, &event, &err))
        {
            conn_dispatch_one_event(conn, event, err);
        }
        conn = next;
    }
}

static bool conn_registry_is_tcp_like(const struct lwip_socket *conn)
{
    if (!conn)
        return false;
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        return true;
#endif
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        return true;
    default:
        return false;
    }
}

static void conn_registry_close_tcp_like(void)
{
    struct lwip_socket *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_socket *next = conn->registry_next;
        if (conn_registry_is_tcp_like(conn))
        {
            services_list_remove(conn);
            (void)lwip_socket_close(conn);
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
    struct lwip_socket *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_socket *next = conn->registry_next;
        if (conn_registry_is_tcp_like(conn))
        {
            (void)lwip_socket_abort(conn);
        }
        conn = next;
    }
}

static void conn_registry_close_udp(void)
{
    struct lwip_socket *conn = g_conn_registry;
    while (conn)
    {
        struct lwip_socket *next = conn->registry_next;
        if ((lwip_socket_type_t)conn->protocol == LWIP_SOCKET_UDP)
        {
            services_list_remove(conn);
            (void)lwip_socket_close(conn);
        }
        conn = next;
    }
}

static lwip_error_t lwip_socket_set_pending_host(struct lwip_socket *conn, const char *host)
{
    if (conn->pending_host == host)
        return LWIP_OK;
    if (conn->pending_host)
        mem_free((void *)conn->pending_host);
    conn->pending_host = NULL;
    if (host)
    {
        char *copy = (char *)mem_malloc(strlen(host) + 1);
        if (!copy)
            return LWIP_ERR_MEM;
        strcpy(copy, host);
        conn->pending_host = copy;
    }
    return LWIP_OK;
}

static void conn_registry_mark_closed(lwip_error_t err)
{
    while (g_conn_registry)
    {
        struct lwip_socket *conn = g_conn_registry;
        conn_registry_remove(conn);
        services_list_remove(conn);
        lwip_socket_set_pending_host(conn, NULL);
        lwip_socket_detach_pcb_callbacks(conn);
        conn->pcb.tcp = NULL;
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
        }
        lwip_socket_rx_ring_destroy(conn);
        conn->status = LWIP_STATUS_CLOSED;
        conn->last_error = err;
    }
}

static void lwip_stop_pump_once(void)
{
    usb_fn.handle_events();
    sys_check_timeouts();
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

static bool lwip_wait_for_tcp_pcb_close(struct tcp_pcb *pcb, uint32_t timeout_ms)
{
    uint32_t deadline;

    if (!pcb)
    {
        return true;
    }

    deadline = sys_now() + timeout_ms;
    while (lwip_teardown_tcp_pcb_pending(pcb))
    {
        if ((int32_t)(sys_now() - deadline) >= 0)
        {
            return false;
        }
        lwip_stop_pump_once();
    }
    return true;
}

static struct tcp_pcb *lwip_socket_leaf_tcp_pcb(struct lwip_socket *conn)
{
    if (!conn)
    {
        return NULL;
    }

    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        return conn->pcb.tcp;
#endif
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
    {
        struct altcp_pcb *leaf = conn->pcb.altcp;
        while (leaf && leaf->inner_conn)
        {
            leaf = leaf->inner_conn;
        }
        return leaf ? (struct tcp_pcb *)leaf->state : NULL;
    }
    default:
        return NULL;
    }
}

static lwip_error_t lwip_socket_rx_ring_create(struct lwip_socket *conn)
{
    if (!conn)
    {
        return LWIP_ERR_ARG;
    }
    if (conn->rx_ring)
    {
        return LWIP_OK;
    }

    size_t init = conn->rx_ring_init ? conn->rx_ring_init :
        LWIP_SOCKET_RX_RING_INIT_SIZE;
    size_t max = conn->rx_ring_max ? conn->rx_ring_max :
        LWIP_SOCKET_RX_RING_MAX_SIZE;
    if (init > max)
    {
        init = max;
    }
    if (init == 0)
    {
        init = LWIP_SOCKET_RX_RING_INIT_SIZE;
    }

    conn->rx_ring = mem_buffer_create(MEM_BUFFER_RING, init, max,
                                      LWIP_SOCKET_RX_RING_STEP_SIZE,
                                      BUFFER_SOCKET_RING);
    if (!conn->rx_ring)
    {
        ERROR_CODE(init > 0xFFFF ? 0xFFFF : init);
        conn->last_error = LWIP_ERR_MEM;
        return LWIP_ERR_MEM;
    }
    mem_buffer_set_grow(conn->rx_ring, 75, LWIP_SOCKET_RX_RING_STEP_SIZE);
    mem_buffer_set_shrink(conn->rx_ring, 25, LWIP_SOCKET_RX_RING_STEP_SIZE);
    return LWIP_OK;
}

static void lwip_socket_rx_ring_destroy(struct lwip_socket *conn)
{
    if (conn && conn->rx_ring)
    {
        mem_buffer_destroy(conn->rx_ring);
        conn->rx_ring = NULL;
    }
}

static bool lwip_socket_buffer_pbuf(struct lwip_socket *conn, struct pbuf *p)
{
    if (!conn || !p)
    {
        return false;
    }
    if (lwip_socket_rx_ring_create(conn) != LWIP_OK)
    {
        ERROR();
        return false;
    }
    if (!mem_buffer_reserve(conn->rx_ring, p->tot_len))
    {
        ERROR_CODE(p->tot_len);
        conn->last_error = LWIP_ERR_MEM;
        return false;
    }

    for (struct pbuf *q = p; q; q = q->next)
    {
        if (q->len == 0)
        {
            continue;
        }
        if (!mem_buffer_push(conn->rx_ring,
                             (const uint8_t *)q->payload,
                             q->len))
        {
            ERROR_CODE(q->len);
            conn->last_error = LWIP_ERR_MEM;
            return false;
        }
        if (q->tot_len == q->len)
        {
            break;
        }
    }
    return true;
}

/* Track DHCP state for waiters. DHCP is armed by external netifs on link-up,
 * not by socket creation/connect; conns only wait for it when requested. */
#if LWIP_DHCP
static bool dhcp_client_running(const struct netif *n)
{
    struct dhcp *dhcp = n ? netif_dhcp_data(n) : NULL;
    return dhcp && dhcp->state != DHCP_STATE_OFF;
}
#endif

static void copy_ip4_octets(uint8_t out[4], const ip4_addr_t *addr)
{
    if (!out)
        return;
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
    if (g_lwip_cfg.tls_enabled)
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
    netif_service_requests_cancel_all(LWIP_NETIF_SERVICE_FAILED);

    /* ---- Phase A: wire-side close, USB still LIVE ------------------------
     * USB must stay up here so the FIN/ACK exchange (and a best-effort DHCP
     * RELEASE) can actually flow. This is the ONLY window where inbound frames
     * are delivered into the stack during teardown, and it is bounded by the
     * TCP-close wait. */
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

    /* DHCP RELEASE is sent synchronously here (udp_sendto schedules the TX
     * while USB is still live); usb_Cleanup below cancels it if it hasn't
     * drained. RELEASE is best-effort politeness, so we do NOT spin a settle
     * pump for it — that pump was the re-entrancy window where a freshly
     * arrived frame got delivered into a half-torn-down stack and froze us. */
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

    /* ---- Phase B: STOP USB FIRST ----------------------------------------
     * The FIN is ACK'd (or aborted) and the RELEASE is queued, so the moment
     * we no longer need the wire we cut it. eth_prepare_shutdown flags the
     * driver so the transfer-cancel callbacks usb_Cleanup fires bail out;
     * after usb_Cleanup returns NO inbound frame can ever be delivered again.
     * Everything below then runs against a fully quiescent stack — nothing can
     * race in via netif->input as we free. */
    STOP_TRACE("P3 ethPrepare");
    eth_prepare_shutdown();
    STOP_TRACE("P4 usbCleanup");
    usb_fn.cleanup();

    /* ---- Phase C: drain & free (USB silent) ------------------------------
     * Safe to free now: lwIP NULL-guards every pcb callback (TCP_EVENT_RECV/
     * ERR/SENT/POLL all test the fn pointer) and the teardown helpers detach
     * recv/errf before abort, so aborting/freeing a pcb fires nothing — even
     * the RST a tcp_abort would emit just no-ops out the dead linkoutput. */
    STOP_TRACE("P5 dispatchStop");
    lwip_dispatch_stop();
    STOP_TRACE("P6 freePCBs");
    conn_registry_close_udp();
    lwip_teardown_remove_non_tcp_pcbs();
    conn_registry_mark_closed(LWIP_ERR_CLOSED);

    STOP_TRACE("P7 netifsDown");
    NETIF_FOREACH(n)
    {
        netif_set_link_down(n);
        netif_set_down(n);
    }

    /* Do not close OS/file state owned by the consumer program. The
     * resident lwIP app runs inside that program's process context, so
     * teardown must only release lwIP-owned resources. */

    /* Release low -> high: driver RX rings + netifs (eth_finish_shutdown),
     * then remaining membuffers (TLS file-IO buffer, lwIP pools). Each owner
     * frees-and-NULLs its buffer so a stray future reference sees NULL. */
    STOP_TRACE("P8 ethFinish");
    eth_finish_shutdown();
    STOP_TRACE("P9 memRelease");
    lwip_membuffers_release();

    STOP_TRACE("P10 complete");
    g_lwip_stopping = false;
    g_lwip_stack_started = false;
}

static void lwip_fatal_cleanup(void)
{
    lwip_stack_cleanup();
}

static lwip_error_t apply_service_flags(struct netif *n, uint8_t svc_flags)
{
    if (!n)
        return LWIP_OK;

#if LWIP_DHCP
    if ((svc_flags & LWIP_SOCKET_SVC_DHCP) &&
        netif_is_up(n) && netif_is_link_up(n) &&
        !dhcp_client_running(n))
    {
        err_t err = dhcp_start(n);
        if (err != ERR_OK)
        {
            return lwip_err_translate(err);
        }
    }
#endif

#if LWIP_DNS
    if (svc_flags & LWIP_SOCKET_SVC_DNS)
    {
        /* dns_init() runs as part of lwip_init() already; calling again
         * is a no-op but documents intent. */
        dns_init();
    }
#endif

    if (svc_flags & LWIP_SOCKET_SVC_SNTP)
    {
        if (!netif_is_up(n) || !netif_is_link_up(n) ||
            !netif_has_usable_ipv4(n) ||
            !netif_has_usable_gateway(n))
        {
            return LWIP_OK;
        }
        if (netif_is_external_network(n) && netif_default != n)
        {
            netif_set_default(n);
        }
#if LWIP_DHCP
        if ((svc_flags & LWIP_SOCKET_SVC_DHCP) &&
            (!dhcp_client_running(n) || !netif_has_usable_gateway(n)))
        {
            return LWIP_OK;
        }
#endif
#if LWIP_DNS
        /* Wait for DNS to be configured (populated by DHCP) before starting
         * SNTP — otherwise the pool.ntp.org hostname lookup fails silently. */
        if (!dns_has_configured_server())
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

static bool socket_addrinfo_valid(const lwip_socket_addrinfo_t *addrinfo)
{
    if (!addrinfo)
    {
        return true;
    }
    return !ip4_addr_isany_val(addrinfo->ip) &&
           !ip4_addr_isloopback(&addrinfo->ip) &&
           !ip4_addr_isany_val(addrinfo->netmask) &&
           !ip4_addr_isany_val(addrinfo->gateway);
}

static void socket_apply_addrinfo(struct netif *netif,
                                  const lwip_socket_addrinfo_t *addrinfo)
{
#if LWIP_IPV4
    if (netif && addrinfo)
    {
        netif_set_addr(netif, &addrinfo->ip, &addrinfo->netmask,
                       &addrinfo->gateway);
    }
#else
    (void)netif;
    (void)addrinfo;
#endif
}

/* Non-blocking netif attach. Records the bind preference (and any static
 * addrinfo) on the socket and resolves a qualifying netif *if one already
 * exists*, kicking DHCP / applying the static IP eagerly in that case. It
 * never blocks waiting for the interface to come up: if no qualifying netif
 * exists yet, conn->netif stays NULL and socket_resolve_netif (driven from the
 * async connect path) finishes the job once USB/link/DHCP enumerate. The old
 * version spun a pump loop here for up to timeout_ms, which froze the calc's
 * UI for the whole DHCP-acquisition window. */
static lwip_error_t socket_attach_netif(struct lwip_socket *conn,
                                        lwip_socket_bind_descriptor_t bind,
                                        const lwip_socket_addrinfo_t *addrinfo,
                                        uint32_t timeout_ms)
{
    struct netif *netif;

    (void)timeout_ms; /* now an async connect window, applied in connect() */
    if (!conn || !socket_addrinfo_valid(addrinfo))
    {
        return LWIP_ERR_ARG;
    }

    conn->bind_descriptor = (uint8_t)bind;
    conn->has_addrinfo = addrinfo != NULL;
    conn->static_applied = false;
    if (addrinfo)
    {
        conn->addrinfo = *addrinfo;
    }

    /* Best-effort eager resolution. Absence of a netif is not an error —
     * the async path retries. */
    netif = socket_find_qualifying_netif(bind);
    if (netif)
    {
        socket_bind_netif(conn, netif);
    }
    return LWIP_OK;
}

/* Bind a resolved netif onto the socket: apply the static IP (once) or kick
 * DHCP/DNS, promote an external netif to default, and record it. Shared by the
 * eager path in socket_attach_netif and the async retry in services_check. */
static void socket_bind_netif(struct lwip_socket *conn, struct netif *netif)
{
    if (!conn || !netif)
    {
        return;
    }

    if (conn->bind_descriptor != LWIP_NETIF_LOOP &&
        !netif_is_loop_network(netif))
    {
        if (conn->has_addrinfo)
        {
            if (!conn->static_applied)
            {
                socket_apply_addrinfo(netif, &conn->addrinfo);
                conn->static_applied = true;
            }
        }
        else
        {
            (void)apply_service_flags(netif,
                                      LWIP_SOCKET_SVC_DHCP |
                                      LWIP_SOCKET_SVC_DNS);
        }
    }

    conn->netif = netif;
    if (netif_is_external_network(netif))
    {
        netif_set_default(netif);
    }
}

lwip_error_t lwip_request_services(uint8_t flags)
{
    return lwip_netif_request_services(NULL, flags, NULL, NULL);
}

typedef enum
{
    LWIP_SOCKET_SERVICES_WAIT = 0,
    LWIP_SOCKET_SERVICES_READY,
    LWIP_SOCKET_SERVICES_FAILED,
} lwip_socket_services_state_t;

static bool lwip_socket_services_timed_out(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}

static void lwip_socket_fail(struct lwip_socket *conn, lwip_error_t err)
{
    if (!conn)
        return;
    ERROR_CODE(err);
    lwip_socket_set_pending_host(conn, NULL);
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = err;
    conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_SERVICES,
                       LWIP_SOCKET_ERR_OP_SERVICE_WAIT, (int)err, err);
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

typedef struct
{
    bool active;
    struct netif *netif;
    uint8_t pending_flags;
    uint32_t deadline;
    lwip_netif_service_cb cb;
    void *cb_data;
} lwip_netif_service_request_t;

static lwip_netif_service_request_t
    g_netif_service_requests[LWIP_NETIF_SERVICE_REQUEST_MAX];

static bool netif_service_base_ready(const struct netif *netif)
{
    return netif &&
           netif_is_up(netif) &&
           netif_is_link_up(netif);
}

static bool netif_service_ready(struct netif *netif, uint8_t service_id)
{
    if (!netif_service_base_ready(netif))
    {
        return false;
    }

    switch (service_id)
    {
    case LWIP_SOCKET_SVC_DHCP:
#if LWIP_DHCP
        return dhcp_client_running(netif) &&
               dhcp_supplied_address(netif) &&
               netif_has_usable_ipv4(netif);
#else
        return netif_has_usable_ipv4(netif);
#endif
    case LWIP_SOCKET_SVC_DNS:
#if LWIP_DNS
        return netif_has_usable_ipv4(netif) && dns_has_configured_server();
#else
        return true;
#endif
    case LWIP_SOCKET_SVC_SNTP:
#if LWIP_SNTP
        return netif_has_usable_ipv4(netif) &&
               netif_has_usable_gateway(netif) &&
               sntp_enabled() != 0;
#else
        return true;
#endif
    default:
        return false;
    }
}

static void netif_service_emit(lwip_netif_service_request_t *req,
                               struct netif *netif,
                               uint8_t service_id,
                               lwip_netif_service_status_t status)
{
    if (req && req->cb)
    {
        req->cb(netif, req->cb_data, service_id, status);
    }
}

static bool netif_service_requests_active(void)
{
    for (uint8_t i = 0; i < LWIP_NETIF_SERVICE_REQUEST_MAX; i++)
    {
        if (g_netif_service_requests[i].active)
        {
            return true;
        }
    }
    return false;
}

static void netif_service_requests_cancel_all(lwip_netif_service_status_t status)
{
    (void)status;
    for (uint8_t i = 0; i < LWIP_NETIF_SERVICE_REQUEST_MAX; i++)
    {
        lwip_netif_service_request_t *req = &g_netif_service_requests[i];
        if (!req->active)
        {
            continue;
        }

        req->active = false;
        req->pending_flags = 0;
        req->netif = NULL;
        req->cb = NULL;
        req->cb_data = NULL;
    }
}

static void netif_services_dispatch(uint32_t now)
{
    for (uint8_t i = 0; i < LWIP_NETIF_SERVICE_REQUEST_MAX; i++)
    {
        lwip_netif_service_request_t *req = &g_netif_service_requests[i];
        if (!req->active)
        {
            continue;
        }

        struct netif *netif = req->netif ? req->netif : find_external_netif();
        uint8_t pending = req->pending_flags;
        lwip_error_t svc_err = apply_service_flags(netif, pending);
        bool timed_out = lwip_socket_services_timed_out(now, req->deadline);

        if (svc_err != LWIP_OK)
        {
            req->active = false;
            req->pending_flags = 0;
            if (pending & LWIP_SOCKET_SVC_DHCP)
            {
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DHCP,
                                   LWIP_NETIF_SERVICE_FAILED);
            }
            if (pending & LWIP_SOCKET_SVC_DNS)
            {
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DNS,
                                   LWIP_NETIF_SERVICE_FAILED);
            }
            if (pending & LWIP_SOCKET_SVC_SNTP)
            {
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_SNTP,
                                   LWIP_NETIF_SERVICE_FAILED);
            }
            continue;
        }

        if (pending & LWIP_SOCKET_SVC_DHCP)
        {
            if (netif_service_ready(netif, LWIP_SOCKET_SVC_DHCP))
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_DHCP;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DHCP,
                                   LWIP_NETIF_SERVICE_UP);
            }
            else if (timed_out)
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_DHCP;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DHCP,
                                   LWIP_NETIF_SERVICE_TIMEOUT);
            }
        }
        if (pending & LWIP_SOCKET_SVC_DNS)
        {
            if (netif_service_ready(netif, LWIP_SOCKET_SVC_DNS))
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_DNS;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DNS,
                                   LWIP_NETIF_SERVICE_UP);
            }
            else if (timed_out)
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_DNS;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_DNS,
                                   LWIP_NETIF_SERVICE_TIMEOUT);
            }
        }
        if (pending & LWIP_SOCKET_SVC_SNTP)
        {
            if (netif_service_ready(netif, LWIP_SOCKET_SVC_SNTP))
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_SNTP;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_SNTP,
                                   LWIP_NETIF_SERVICE_UP);
            }
            else if (timed_out)
            {
                req->pending_flags &= (uint8_t)~LWIP_SOCKET_SVC_SNTP;
                netif_service_emit(req, netif, LWIP_SOCKET_SVC_SNTP,
                                   LWIP_NETIF_SERVICE_TIMEOUT);
            }
        }

        if (req->pending_flags == 0)
        {
            req->active = false;
        }
    }
}

lwip_error_t lwip_netif_request_services(struct netif *netif,
                                         uint8_t flags,
                                         lwip_netif_service_cb cb,
                                         void *cb_data)
{
    flags &= (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS | LWIP_SOCKET_SVC_SNTP);
    if (!flags)
    {
        return LWIP_ERR_ARG;
    }
    if (!g_lwip_started || g_lwip_stopping)
    {
        return LWIP_ERR_STATE;
    }

    g_requested_service_flags |= flags;
    lwip_error_t err = apply_service_flags(netif ? netif : find_external_netif(),
                                           flags);
    if (err != LWIP_OK || !cb)
    {
        return err;
    }

    for (uint8_t i = 0; i < LWIP_NETIF_SERVICE_REQUEST_MAX; i++)
    {
        lwip_netif_service_request_t *req = &g_netif_service_requests[i];
        if (req->active && req->netif == netif && req->cb == cb &&
            req->cb_data == cb_data)
        {
            req->pending_flags |= flags;
            req->deadline = sys_now() + LWIP_SOCKET_SERVICES_TIMEOUT_MS;
            services_arm();
            return LWIP_OK;
        }
    }

    for (uint8_t i = 0; i < LWIP_NETIF_SERVICE_REQUEST_MAX; i++)
    {
        lwip_netif_service_request_t *req = &g_netif_service_requests[i];
        if (!req->active)
        {
            req->active = true;
            req->netif = netif;
            req->pending_flags = flags;
            req->deadline = sys_now() + LWIP_SOCKET_SERVICES_TIMEOUT_MS;
            req->cb = cb;
            req->cb_data = cb_data;
            services_arm();
            return LWIP_OK;
        }
    }

    return LWIP_ERR_MEM;
}

/* Are the requested netif-level services ready for a connect? This also
 * resolves a lazily-created NULL conn->netif to netif_default once USB
 * enumeration creates it, and starts requested netif services the first
 * time a usable netif appears.
 *
 * A socket always needs an administratively-up, link-up netif with a
 * usable local address. With DHCP requested, also require a gateway before
 * attempting transport connect; public destinations otherwise commonly
 * fail immediately with ERR_RTE even though DHCP is still converging. */
static lwip_socket_services_state_t services_check(struct lwip_socket *conn,
                                                 lwip_error_t *err_out,
                                                 const char *host)
{
    lwip_error_t svc_err;

    if (err_out)
        *err_out = LWIP_OK;
    if (!conn)
        return LWIP_SOCKET_SERVICES_FAILED;
    /* create() is non-blocking, so the qualifying netif may not have existed
     * yet. Re-resolve it here (and apply static IP / kick DHCP) once it shows
     * up; until then, keep waiting. */
    if (!conn->netif)
    {
        struct netif *netif = socket_find_qualifying_netif(
            (lwip_socket_bind_descriptor_t)conn->bind_descriptor);
        if (netif)
        {
            socket_bind_netif(conn, netif);
        }
    }
    if (!conn->netif)
    {
        if (err_out)
            *err_out = LWIP_ERR_NETIF;
        return LWIP_SOCKET_SERVICES_WAIT;
    }

    svc_err = apply_service_flags(conn->netif, conn->flags);
    if (svc_err != LWIP_OK)
    {
        if (err_out)
            *err_out = svc_err;
        return LWIP_SOCKET_SERVICES_FAILED;
    }

    if (!netif_is_up(conn->netif))
    {
        if (err_out)
            *err_out = LWIP_ERR_NETIF;
        return LWIP_SOCKET_SERVICES_WAIT;
    }
    if (netif_is_loop_network(conn->netif))
    {
        return LWIP_SOCKET_SERVICES_READY;
    }
    if (!netif_is_link_up(conn->netif))
    {
        if (err_out)
            *err_out = LWIP_ERR_NETIF;
        return LWIP_SOCKET_SERVICES_WAIT;
    }
    if (!netif_has_usable_ipv4(conn->netif))
    {
        if (err_out)
            *err_out = LWIP_ERR_NETIF;
        return LWIP_SOCKET_SERVICES_WAIT;
    }

    if (netif_default != conn->netif)
    {
        netif_set_default(conn->netif);
    }

#if LWIP_DHCP
    if (conn->flags & LWIP_SOCKET_SVC_DHCP)
    {
        if (!dhcp_client_running(conn->netif))
        {
            if (err_out)
                *err_out = LWIP_ERR_NETIF;
            return LWIP_SOCKET_SERVICES_WAIT;
        }
        if (!dhcp_supplied_address(conn->netif))
        {
            if (err_out)
                *err_out = LWIP_ERR_NETIF;
            return LWIP_SOCKET_SERVICES_WAIT;
        }
        if (!netif_has_usable_gateway(conn->netif))
        {
            if (err_out)
                *err_out = LWIP_ERR_NETIF;
            return LWIP_SOCKET_SERVICES_WAIT;
        }
    }
#endif
#if LWIP_DNS
    if ((conn->flags & LWIP_SOCKET_SVC_DNS) && host_requires_dns(host) &&
        !dns_has_configured_server())
    {
        if (err_out)
            *err_out = LWIP_ERR_DNS;
        return LWIP_SOCKET_SERVICES_WAIT;
    }
#endif
    return LWIP_SOCKET_SERVICES_READY;
}

/* Waiting-services list. Conns enter this list when lwip_socket_connect
 * is called against a netif that isn't ready yet; the dispatcher walks
 * the list every tick and re-attempts the deferred connects. */
static struct lwip_socket *g_services_waiters = NULL;

static void services_list_add(struct lwip_socket *c)
{
    /* Prepend; iteration order doesn't matter. */
    if (!c)
        return;
    /* Guard against double-add. */
    for (struct lwip_socket *cur = g_services_waiters; cur; cur = cur->services_next)
    {
        if (cur == c)
            return;
    }
    c->services_next = g_services_waiters;
    g_services_waiters = c;
}

static void services_list_remove(struct lwip_socket *c)
{
    if (!c)
        return;
    struct lwip_socket **slot = &g_services_waiters;
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
        struct lwip_socket *conn = g_services_waiters;
        services_list_remove(conn);
        lwip_socket_set_pending_host(conn, NULL);
        conn->services_deadline = 0;
        conn->status = LWIP_STATUS_CLOSED;
        conn->last_error = err;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES, 0);
}

/* Forward decls so the services dispatcher can drive a connect. */
static lwip_error_t lwip_socket_connect_now(struct lwip_socket *conn,
                                          const char *host, uint16_t port);
static void services_arm(void);

static lwip_error_t lwip_socket_wait_for_services(struct lwip_socket *conn,
                                                const char *host,
                                                uint16_t port,
                                                uint32_t deadline)
{
    /* Deferring a connect requires owning the host string. If we already
     * owned one from a previous attempt, free it first. */
    lwip_error_t host_err = lwip_socket_set_pending_host(conn, host);
    if (host_err != LWIP_OK)
        return host_err;

    conn->remote_port = port;
    conn->status = LWIP_STATUS_WAITING_SERVICES;
    conn->last_error = LWIP_OK;
    conn->services_deadline = deadline;
    services_list_add(conn);
    conn_event_enqueue(conn, CONN_PENDING_WAITING, LWIP_OK);
    DEBUG();
#if LWIP_DNS
    if ((conn->flags & LWIP_SOCKET_SVC_DNS) && host_requires_dns(host) &&
        !dns_has_configured_server())
    {
        DEBUG();
    }
#endif
    services_arm();
    return LWIP_OK;
}

static void services_dispatch(void)
{
    if (!g_services_waiters && !netif_service_requests_active())
    {
        /* Nothing to do — disable ourselves until something gets added. */
        lwip_dispatch_set_period(LWIP_DISPATCH_CONN_SERVICES, 0);
        return;
    }

    uint32_t now = sys_now();
    netif_services_dispatch(now);

    struct lwip_socket *c = g_services_waiters;
    while (c)
    {
        struct lwip_socket *next = c->services_next;
        lwip_error_t svc_err = LWIP_OK;
        lwip_socket_services_state_t svc_state = services_check(c, &svc_err,
                                                              c->pending_host);
        if (svc_state == LWIP_SOCKET_SERVICES_READY)
        {
            uint16_t port = c->remote_port;
            uint32_t deadline = c->services_deadline;
            lwip_error_t err;

            /* We must NOT free pending_host yet. If connect_now starts
             * DNS resolution, it needs this pointer to remain valid. */
            services_list_remove(c);
            c->services_deadline = 0;

            err = lwip_socket_connect_now(c, c->pending_host, port);

            if (err == LWIP_ERR_NETIF)
            {
                WARN_CODE(LWIP_ERR_NETIF);
                /* Transient routing (ERR_RTE/IF) — re-park and let the
                 * inactivity watchdog, not a fixed deadline, decide when to
                 * give up. Preserves the existing pending_host. */
                (void)lwip_socket_wait_for_services(c, c->pending_host, port, deadline);
            }
            else if (err != LWIP_OK)
            {
                lwip_socket_set_pending_host(c, NULL);
                c->status = LWIP_STATUS_ERROR;
                c->last_error = err;
                conn_error_enqueue(c, conn_transport_component(c),
                                   LWIP_SOCKET_ERR_OP_CONNECT, (int)err, err);
            }
            /* If err == LWIP_OK, either it's connected or resolving.
             * If resolving, pending_host is now owned by the DNS state. */
        }
        else if (svc_state == LWIP_SOCKET_SERVICES_FAILED)
        {
            services_list_remove(c);
            lwip_socket_set_pending_host(c, NULL);
            lwip_socket_fail(c, svc_err ? svc_err : LWIP_ERR_NETIF);
        }
        /* Still WAITING: stay parked. conn_connect_watchdog owns the
         * inactivity timeout (it covers RESOLVING/CONNECTING too). */
        c = next;
    }

    if (!g_services_waiters && !netif_service_requests_active())
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
 * Connect/handshake inactivity watchdog
 *
 * A socket in WAITING_SERVICES / RESOLVING / CONNECTING is failed only
 * after `connect_window` ms of NO inbound line activity (eth_last_rx_activity_ms
 * stops advancing). Any received frame pushes the deadline forward, so a
 * slow-but-progressing DNS lookup or TLS handshake is never killed — only a
 * genuinely quiet line is. This replaces the old fixed wall-clock services
 * deadline and also covers the post-resolve phases the deadline never watched.
 * ============================================================ */

static uint32_t conn_window_ms(const struct lwip_socket *conn)
{
    if (conn && conn->connect_timeout_ms)
    {
        return conn->connect_timeout_ms;
    }
    return LWIP_SOCKET_SERVICES_TIMEOUT_MS;
}

static bool conn_in_connect_phase(const struct lwip_socket *conn)
{
    return conn && (conn->status == LWIP_STATUS_WAITING_SERVICES ||
                    conn->status == LWIP_STATUS_RESOLVING ||
                    conn->status == LWIP_STATUS_CONNECTING);
}

/* Fail a socket that went quiet mid-connect. Aborts the underlying
 * connecting pcb so SYN/handshake retransmits stop, but leaves the handle in
 * the registry (status ERROR) so the queued ERROR event still reaches the app;
 * the app then destroys it. */
static void conn_connect_fail_timeout(struct lwip_socket *conn)
{
    if (!conn)
    {
        return;
    }
    services_list_remove(conn);
    lwip_socket_set_pending_host(conn, NULL);
    conn->services_deadline = 0;
    lwip_socket_detach_pcb_callbacks(conn);
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        if (conn->pcb.tcp)
        {
            struct tcp_pcb *pcb = conn->pcb.tcp;
            conn->pcb.tcp = NULL;
            tcp_abort(pcb);
        }
        break;
#endif
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            struct altcp_pcb *pcb = conn->pcb.altcp;
            conn->pcb.altcp = NULL;
            altcp_abort(pcb);
        }
        if (conn->tls_conf)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
        }
        break;
    default:
        break;
    }
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_CONNECT;
    ERROR_CODE(LWIP_ERR_CONNECT);
    conn_error_enqueue(conn, conn_transport_component(conn),
                       LWIP_SOCKET_ERR_OP_CONNECT, (int)ERR_TIMEOUT,
                       LWIP_ERR_CONNECT);
}

static void conn_connect_watchdog(uint32_t now)
{
    uint32_t activity = eth_last_rx_activity_ms();
    struct lwip_socket *conn = g_conn_registry;

    while (conn)
    {
        struct lwip_socket *next = conn->registry_next;

        if (!conn_in_connect_phase(conn))
        {
            /* Not connecting: keep the deadline disarmed and the activity
             * snapshot current so the next connect attempt arms cleanly. */
            conn->services_deadline = 0;
            conn->activity_seen = activity;
            conn = next;
            continue;
        }

        if (conn->services_deadline == 0)
        {
            /* Just entered a connect phase — arm a fresh idle window. */
            conn->services_deadline = now + conn_window_ms(conn);
            conn->activity_seen = activity;
        }
        else if (activity != conn->activity_seen)
        {
            /* Inbound line activity since last tick: the connect is making
             * progress, so push the idle deadline forward. */
            conn->activity_seen = activity;
            conn->services_deadline = now + conn_window_ms(conn);
        }
        else if (lwip_socket_services_timed_out(now, conn->services_deadline))
        {
            conn_connect_fail_timeout(conn);
        }

        conn = next;
    }
}

/* ============================================================
 * Callback bridges: lower-level pcb → user-facing lwip_socket cb.
 *
 * One set per protocol. Each shim:
 *   - looks up the owning lwip_socket via the pcb's arg slot,
 *   - updates conn->status,
 *   - re-dispatches to the registered user callback (if any).
 * ============================================================ */

/* --- altcp (covers ALTCP and ALTCP_TLS) --- */

static err_t conn_altcp_recv_cb(void *arg, struct altcp_pcb *pcb,
                                struct pbuf *p, err_t err)
{
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
    {
        if (p)
            pbuf_free(p);
        return ERR_OK;
    }
    if (g_lwip_stopping)
    {
        if (p)
            pbuf_free(p);
        else
            c->status = LWIP_STATUS_CLOSED;
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_ALTCP,
                           LWIP_SOCKET_ERR_OP_RECV, (int)err,
                           c->last_error);
        if (p)
            pbuf_free(p);
        return ERR_OK;
    }
    if (p == NULL)
    {
        c->status = LWIP_STATUS_CLOSED;
        conn_event_enqueue(c, CONN_PENDING_CLOSED, LWIP_OK);
        return ERR_OK;
    }
    if (!lwip_socket_buffer_pbuf(c, p))
    {
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_MEM,
                           LWIP_SOCKET_ERR_OP_RECV, (int)ERR_MEM,
                           LWIP_ERR_MEM);
        return ERR_MEM;
    }
    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    conn_event_enqueue(c, CONN_PENDING_READABLE, LWIP_OK);
    return ERR_OK;
}

static err_t conn_altcp_sent_cb(void *arg, struct altcp_pcb *pcb, u16_t len)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (g_lwip_stopping)
        return ERR_OK;
    if (c)
    {
        c->last_sent_len = (uint16_t)len;
        conn_event_enqueue(c, CONN_PENDING_WRITABLE, LWIP_OK);
    }
    if (c && c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_altcp_poll_cb(void *arg, struct altcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (g_lwip_stopping)
        return ERR_OK;
    if (c)
        conn_event_enqueue(c, CONN_PENDING_POLL, LWIP_OK);
    if (c && c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}

static void conn_altcp_err_cb(void *arg, err_t err)
{
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
        return;
    /* Distinguish a peer RST (clean reset) from a stack abort/error so the
     * app can tell "remote end hung up abruptly" from "something broke". */
    if (err == ERR_RST)
    {
        c->status = LWIP_STATUS_RESET;
        c->last_error = LWIP_ERR_CLOSED;
    }
    else
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
    }
    ERROR_CODE(c->last_error);
    c->pcb.altcp = NULL; /* lower layer freed the pcb */
    if (g_lwip_stopping)
        return;
    if (err == ERR_RST)
    {
        conn_event_enqueue(c, CONN_PENDING_RESET, LWIP_OK);
    }
    else
    {
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_ALTCP,
                           LWIP_SOCKET_ERR_OP_RECV, (int)err, c->last_error);
    }
}

static err_t conn_altcp_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
        return ERR_OK;
    if (g_lwip_stopping)
        return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        ERROR_CODE(c->last_error);
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_ALTCP,
                           LWIP_SOCKET_ERR_OP_CONNECT, (int)err,
                           c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
    STATE_CHG(c, LWIP_STATE_CONN_ESTABLISHED);
    conn_event_enqueue(c, CONN_PENDING_CONNECTED, LWIP_OK);
    if (c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}

/* --- UDP --- */

static void conn_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *addr, u16_t port)
{
    (void)pcb;
    (void)addr;
    (void)port;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
    {
        if (p)
            pbuf_free(p);
        return;
    }
    if (g_lwip_stopping)
    {
        if (p)
            pbuf_free(p);
        return;
    }
    if (p)
    {
        if (lwip_socket_buffer_pbuf(c, p))
        {
            conn_event_enqueue(c, CONN_PENDING_READABLE, LWIP_OK);
        }
        else
        {
            conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_MEM,
                               LWIP_SOCKET_ERR_OP_RECV, (int)ERR_MEM,
                               LWIP_ERR_MEM);
        }
        pbuf_free(p);
    }
}

/* --- raw TCP --- */

#if LWIP_TCP
static err_t conn_tcp_recv_cb(void *arg, struct tcp_pcb *pcb,
                              struct pbuf *p, err_t err)
{
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
    {
        if (p)
            pbuf_free(p);
        return ERR_OK;
    }
    if (g_lwip_stopping)
    {
        if (p)
            pbuf_free(p);
        else
            c->status = LWIP_STATUS_CLOSED;
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_TCP,
                           LWIP_SOCKET_ERR_OP_RECV, (int)err,
                           c->last_error);
        if (p)
            pbuf_free(p);
        return ERR_OK;
    }
    if (p == NULL)
    {
        c->status = LWIP_STATUS_CLOSED;
        conn_event_enqueue(c, CONN_PENDING_CLOSED, LWIP_OK);
        return ERR_OK;
    }
    if (!lwip_socket_buffer_pbuf(c, p))
    {
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_MEM,
                           LWIP_SOCKET_ERR_OP_RECV, (int)ERR_MEM,
                           LWIP_ERR_MEM);
        return ERR_MEM;
    }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    conn_event_enqueue(c, CONN_PENDING_READABLE, LWIP_OK);
    return ERR_OK;
}

static err_t conn_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (g_lwip_stopping)
        return ERR_OK;
    if (c)
    {
        c->last_sent_len = (uint16_t)len;
        conn_event_enqueue(c, CONN_PENDING_WRITABLE, LWIP_OK);
    }
    if (c && c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}

static err_t conn_tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (g_lwip_stopping)
        return ERR_OK;
    if (c)
        conn_event_enqueue(c, CONN_PENDING_POLL, LWIP_OK);
    if (c && c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}

static void conn_tcp_err_cb(void *arg, err_t err)
{
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
        return;
    if (err == ERR_RST)
    {
        c->status = LWIP_STATUS_RESET;
        c->last_error = LWIP_ERR_CLOSED;
    }
    else
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
    }
    ERROR_CODE(c->last_error);
    c->pcb.tcp = NULL;
    if (g_lwip_stopping)
        return;
    if (err == ERR_RST)
        conn_event_enqueue(c, CONN_PENDING_RESET, LWIP_OK);
    else
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_TCP,
                           LWIP_SOCKET_ERR_OP_RECV, (int)err, c->last_error);
}

static err_t conn_tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    struct lwip_socket *c = (struct lwip_socket *)arg;
    if (!c)
        return ERR_OK;
    if (g_lwip_stopping)
        return ERR_OK;
    if (err != ERR_OK)
    {
        c->status = LWIP_STATUS_ERROR;
        c->last_error = lwip_err_translate(err);
        ERROR_CODE(c->last_error);
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_TCP,
                           LWIP_SOCKET_ERR_OP_CONNECT, (int)err,
                           c->last_error);
        return ERR_OK;
    }
    c->status = LWIP_STATUS_CONNECTED;
    STATE_CHG(c, LWIP_STATE_CONN_ESTABLISHED);
    conn_event_enqueue(c, CONN_PENDING_CONNECTED, LWIP_OK);
    if (c->aborting)
        return ERR_ABRT;
    return ERR_OK;
}
#endif /* LWIP_TCP */

/* Re-bind the underlying pcb's callbacks to our shim functions. Called
 * from create() and again from set_poll() when the interval changes. */
static void rebind_pcb_callbacks(struct lwip_socket *c)
{
    if (!c)
        return;
    switch ((lwip_socket_type_t)c->protocol)
    {
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        if (c->pcb.altcp)
        {
            altcp_arg(c->pcb.altcp, c);
            altcp_recv(c->pcb.altcp, conn_altcp_recv_cb);
            altcp_sent(c->pcb.altcp, conn_altcp_sent_cb);
            altcp_err(c->pcb.altcp, conn_altcp_err_cb);
            altcp_poll(c->pcb.altcp, conn_altcp_poll_cb, 4);
        }
        break;
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        if (c->pcb.tcp)
        {
            tcp_arg(c->pcb.tcp, c);
            tcp_recv(c->pcb.tcp, conn_tcp_recv_cb);
            tcp_sent(c->pcb.tcp, conn_tcp_sent_cb);
            tcp_err(c->pcb.tcp, conn_tcp_err_cb);
            tcp_poll(c->pcb.tcp, conn_tcp_poll_cb, 4);
        }
        break;
#endif
    case LWIP_SOCKET_UDP:
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

lwip_error_t lwip_socket_create(struct lwip_socket *conn,
                                lwip_socket_type_t protocol,
                                lwip_socket_bind_descriptor_t bind,
                                const lwip_socket_addrinfo_t *addrinfo,
                                uint32_t timeout_ms)
{
    return lwip_socket_create_ex(conn, protocol, bind, addrinfo, timeout_ms,
                                 LWIP_SOCKET_RX_RING_MAX_SIZE);
}

lwip_error_t lwip_socket_create_ex(struct lwip_socket *conn,
                                   lwip_socket_type_t protocol,
                                   lwip_socket_bind_descriptor_t bind,
                                   const lwip_socket_addrinfo_t *addrinfo,
                                   uint32_t timeout_ms,
                                   size_t rx_ring_max)
{
    lwip_error_t attach_err;
    uint8_t flags;

    if (!conn)
        return LWIP_ERR_ARG;
    if (!g_lwip_started || g_lwip_stopping)
        return LWIP_ERR_STATE;
    if (bind != LWIP_NETIF_ANY &&
        bind != LWIP_NETIF_LOOP &&
        bind != LWIP_NETIF_EXT)
    {
        return LWIP_ERR_ARG;
    }

    memset(conn, 0, sizeof(*conn));
    conn->status = LWIP_STATUS_INIT;
    conn->protocol = (uint8_t)protocol;
    conn->connect_timeout_ms = timeout_ms;
    flags = addrinfo || bind == LWIP_NETIF_LOOP ?
        LWIP_SOCKET_SVC_DNS :
        (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS);
    conn->flags = flags;
    conn->rx_ring_init = LWIP_SOCKET_RX_RING_INIT_SIZE;
    conn->rx_ring_max = rx_ring_max ? rx_ring_max : LWIP_SOCKET_RX_RING_MAX_SIZE;
    g_requested_service_flags |= flags;

    attach_err = socket_attach_netif(conn, bind, addrinfo, timeout_ms);
    if (attach_err != LWIP_OK)
    {
        conn->last_error = attach_err;
        conn->status = LWIP_STATUS_ERROR;
        return attach_err;
    }

    if (lwip_socket_rx_ring_create(conn) != LWIP_OK)
    {
        ERROR();
        return LWIP_ERR_MEM;
    }

    switch (protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        conn->pcb.tcp = tcp_new();
        if (!conn->pcb.tcp)
            goto fail_mem;
        break;
#endif
    case LWIP_SOCKET_UDP:
        conn->pcb.udp = udp_new();
        if (!conn->pcb.udp)
            goto fail_mem;
        break;
    case LWIP_SOCKET_ALTCP:
        conn->pcb.altcp = altcp_new(NULL); /* default = altcp_tcp */
        if (!conn->pcb.altcp)
            goto fail_mem;
        break;
    case LWIP_SOCKET_ALTCP_TLS:
        /* tls_init() now runs eagerly in lwip_stack_init() (called from
         * lwip_start()); this is a defensive fallback only (tls_init()
         * gates on tls_ctx.initialized, so it's re-call-safe and a no-op
         * if already initialized there). Refuse outright if the wizard
         * has TLS disabled. */
        if (!g_lwip_cfg.tls_enabled ||
            (!tls_ctx.initialized && !tls_init()))
        {
            lwip_socket_rx_ring_destroy(conn);
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TLS,
                               LWIP_SOCKET_ERR_OP_TLS_INIT, (int)ERR_MEM,
                               LWIP_ERR_MEM);
            return LWIP_ERR_MEM;
        }
        /* TLS config is built in lwip_socket_connect once we know the host
         * (needed for SNI). The pcb is allocated then too. */
        conn->tls_conf = NULL;
        conn->pcb.altcp = NULL;
        break;
    default:
        lwip_socket_rx_ring_destroy(conn);
        return LWIP_ERR_PROTO;
    }

    rebind_pcb_callbacks(conn);
    conn_registry_add(conn);
    return LWIP_OK;

fail_mem:
    ERROR();
    lwip_socket_rx_ring_destroy(conn);
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_MEM;
    return LWIP_ERR_MEM;
}

/* Detach the conn shim from every callback slot on the underlying
 * pcb. After this the pcb may still emit events (a deferred recv after
 * tcp_close, the err cb after abort, etc.) but they'll go to NULL and
 * be swallowed by lwIP instead of dereferencing into a freed conn. */
static void lwip_socket_detach_pcb_callbacks(struct lwip_socket *conn)
{
    if (!conn)
        return;
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
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
    case LWIP_SOCKET_UDP:
        if (conn->pcb.udp)
        {
            udp_recv(conn->pcb.udp, NULL, NULL);
        }
        break;
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
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

lwip_error_t lwip_socket_destroy(struct lwip_socket *conn)
{
    if (!conn)
        return LWIP_ERR_ARG;
    conn_registry_remove(conn);
    /* Drop from the services waiter list if we were parked. Safe no-op
     * for conns that never entered WAITING_SERVICES. */
    services_list_remove(conn);
    lwip_socket_set_pending_host(conn, NULL);
    /* Destruction is not graceful close. lwip_socket_close() owns orderly
     * FIN shutdown; destroy must leave no live pcb that can outlast this
     * transparent handle. Detach first so abort-side callbacks cannot
     * dereference the about-to-be-zeroed conn. */
    lwip_socket_detach_pcb_callbacks(conn);
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        if (conn->pcb.tcp)
        {
            tcp_abort(conn->pcb.tcp);
        }
        break;
#endif
    case LWIP_SOCKET_UDP:
        if (conn->pcb.udp)
            udp_remove(conn->pcb.udp);
        break;
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
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
    lwip_socket_rx_ring_destroy(conn);
    memset(conn, 0, sizeof(*conn));
    conn->status = LWIP_STATUS_CLOSED;
    return LWIP_OK;
}

/* ============================================================
 * Connect (with DNS-or-IP resolution)
 * ============================================================ */

/* Issue the transport-level connect once we have a final ip_addr. Returns
 * lwip_err_t so the caller can roll status/error back on failure. */
static err_t start_transport_connect(struct lwip_socket *c)
{
    STATE_CHG(c, LWIP_STATE_CONN_CONNECTING);

    switch ((lwip_socket_type_t)c->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        tcp_bind_netif(c->pcb.tcp, c->netif);
        return tcp_connect(c->pcb.tcp, &c->remote_ip, c->remote_port,
                           conn_tcp_connected_cb);
#endif
    case LWIP_SOCKET_UDP:
    {
        udp_bind_netif(c->pcb.udp, c->netif);
        err_t e = udp_connect(c->pcb.udp, &c->remote_ip, c->remote_port);
        if (e == ERR_OK)
        {
            c->status = LWIP_STATUS_CONNECTED;
            conn_event_enqueue(c, CONN_PENDING_CONNECTED, LWIP_OK);
        }
        return e;
    }
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
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
    struct lwip_socket *c = (struct lwip_socket *)callback_arg;
    if (!c)
        return;
    /* The lookup may complete after the inactivity watchdog already failed and
     * aborted this conn (status != RESOLVING, pcb torn down). Acting on it then
     * would re-enter connect on a dead pcb — drop the stale result. */
    if (c->status != LWIP_STATUS_RESOLVING)
        return;
    if (!ipaddr)
    {
        lwip_socket_set_pending_host(c, NULL);
        c->services_deadline = 0;
        c->status = LWIP_STATUS_ERROR;
        c->last_error = LWIP_ERR_DNS;
        ERROR_CODE(c->last_error);
        conn_error_enqueue(c, LWIP_SOCKET_ERR_COMP_DNS,
                           LWIP_SOCKET_ERR_OP_DNS_LOOKUP, (int)ERR_VAL,
                           LWIP_ERR_DNS);
        return;
    }
    c->remote_ip = *ipaddr;
    c->status = LWIP_STATUS_CONNECTING;
    conn_event_enqueue(c, CONN_PENDING_CONNECTING, LWIP_OK);

    err_t err = start_transport_connect(c);
    if (err != ERR_OK)
    {
        lwip_error_t mapped = lwip_err_translate(err);
        if (mapped == LWIP_ERR_NETIF)
        {
            uint32_t deadline = c->services_deadline;
            if (!deadline)
            {
                deadline = sys_now() + LWIP_SOCKET_SERVICES_TIMEOUT_MS;
            }
            (void)lwip_socket_wait_for_services(c, c->pending_host ? c->pending_host : name,
                                              c->remote_port, deadline);
            return;
        }
        lwip_socket_set_pending_host(c, NULL);
        c->services_deadline = 0;
        c->status = LWIP_STATUS_ERROR;
        c->last_error = mapped;
        ERROR_CODE(c->last_error);
        conn_error_enqueue(c, conn_transport_component(c),
                           LWIP_SOCKET_ERR_OP_CONNECT, (int)err,
                           c->last_error);
        return;
    }
    lwip_socket_set_pending_host(c, NULL);
    c->services_deadline = 0;
}
#endif /* LWIP_DNS */

/* Internal: do the actual connect (literal-IP fast path / DNS / TLS
 * setup). Both the public entry point and the services dispatcher
 * call into this once the netif is ready. */
static lwip_error_t lwip_socket_connect_now(struct lwip_socket *conn,
                                          const char *host,
                                          uint16_t port)
{
    conn->remote_port = port;

    /* ALTCP_TLS connects need a TLS config and a wrapped pcb. We defer
     * both until connect() so the SNI hostname is in hand. */
    if (conn->protocol == LWIP_SOCKET_ALTCP_TLS && conn->pcb.altcp == NULL)
    {
        conn->tls_conf = altcp_tls_ce_create_config_client_ecdhe(host);
        if (!conn->tls_conf)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TLS,
                               LWIP_SOCKET_ERR_OP_TLS_CONFIG, (int)ERR_MEM,
                               LWIP_ERR_MEM);
            return LWIP_ERR_MEM;
        }
        conn->pcb.altcp = altcp_tls_ce_new(conn->tls_conf, IPADDR_TYPE_V4);
        if (!conn->pcb.altcp)
        {
            altcp_tls_ce_free_config(conn->tls_conf);
            conn->tls_conf = NULL;
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = LWIP_ERR_MEM;
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TLS,
                               LWIP_SOCKET_ERR_OP_CREATE, (int)ERR_MEM,
                               LWIP_ERR_MEM);
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
        conn_event_enqueue(conn, CONN_PENDING_CONNECTING, LWIP_OK);
        err_t err = start_transport_connect(conn);
        if (err != ERR_OK)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = lwip_err_translate(err);
            ERROR_CODE(conn->last_error);
            conn_error_enqueue(conn, conn_transport_component(conn),
                               LWIP_SOCKET_ERR_OP_CONNECT, (int)err,
                               conn->last_error);
            return conn->last_error;
        }
        lwip_socket_set_pending_host(conn, NULL);
        conn->services_deadline = 0;
        return LWIP_OK;
    }
#if LWIP_IPV6
    if (ip6addr_aton(host, ip_2_ip6(&conn->remote_ip)))
    {
        IP_SET_TYPE_VAL(conn->remote_ip, IPADDR_TYPE_V6);
        conn->status = LWIP_STATUS_CONNECTING;
        conn_event_enqueue(conn, CONN_PENDING_CONNECTING, LWIP_OK);
        err_t err = start_transport_connect(conn);
        if (err != ERR_OK)
        {
            conn->status = LWIP_STATUS_ERROR;
            conn->last_error = lwip_err_translate(err);
            ERROR_CODE(conn->last_error);
            conn_error_enqueue(conn, conn_transport_component(conn),
                               LWIP_SOCKET_ERR_OP_CONNECT, (int)err,
                               conn->last_error);
            return conn->last_error;
        }
        lwip_socket_set_pending_host(conn, NULL);
        conn->services_deadline = 0;
        return LWIP_OK;
    }
#endif

#if LWIP_DNS
    lwip_error_t host_err = lwip_socket_set_pending_host(conn, host);
    if (host_err != LWIP_OK)
        return host_err;

    if (!conn->services_deadline)
    {
        conn->services_deadline = sys_now() + LWIP_SOCKET_SERVICES_TIMEOUT_MS;
    }
    conn->status = LWIP_STATUS_RESOLVING;
    conn_event_enqueue(conn, CONN_PENDING_RESOLVING, LWIP_OK);
    err_t derr = dns_gethostbyname(conn->pending_host, &conn->remote_ip,
                                   conn_dns_found_cb, conn);
    if (derr == ERR_OK)
    {
        /* Cached hit — drive the next stage synchronously. conn_dns_found_cb
         * may itself fail (e.g. tcp_connect() returning ERR_MEM) and set
         * conn->status/last_error accordingly; surface that instead of
         * blindly reporting success. WAITING_SERVICES is the one non-error,
         * non-connected outcome (conn_dns_found_cb parked us on the
         * services waiter after an ERR_NETIF) — also fine to report OK. */
        conn_dns_found_cb(host, &conn->remote_ip, conn);
        if (conn->status == LWIP_STATUS_ERROR)
        {
            return conn->last_error;
        }
        return LWIP_OK;
    }
    if (derr == ERR_INPROGRESS)
    {
        return LWIP_OK; /* async — caller polls status */
    }
    lwip_socket_set_pending_host(conn, NULL);
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
    ERROR_CODE(conn->last_error);
    conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_DNS,
                       LWIP_SOCKET_ERR_OP_DNS_LOOKUP, (int)derr,
                       LWIP_ERR_DNS);
    return LWIP_ERR_DNS;
#else
    conn->pending_host = NULL;
    conn->services_deadline = 0;
    conn->status = LWIP_STATUS_ERROR;
    conn->last_error = LWIP_ERR_DNS;
    ERROR_CODE(conn->last_error);
    conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_DNS,
                       LWIP_SOCKET_ERR_OP_DNS_LOOKUP, (int)ERR_VAL,
                       LWIP_ERR_DNS);
    return LWIP_ERR_DNS;
#endif
}

lwip_error_t lwip_socket_connect(struct lwip_socket *conn,
                               const char *host,
                               uint16_t port)
{
    if (!conn || !host)
        return LWIP_ERR_ARG;
    if (conn->status == LWIP_STATUS_CONNECTED ||
        conn->status == LWIP_STATUS_CONNECTING ||
        conn->status == LWIP_STATUS_RESOLVING ||
        conn->status == LWIP_STATUS_WAITING_SERVICES)
    {
        return LWIP_ERR_STATE;
    }

    lwip_error_t svc_err = LWIP_OK;
    uint32_t deadline = sys_now() + conn_window_ms(conn);
    lwip_socket_services_state_t svc_state = services_check(conn, &svc_err, host);

    /* Fast path: services already up — drive the connect synchronously.
     * If routing still says "not yet" (ERR_RTE/ERR_IF), fall back into
     * the waiter instead of surfacing a transient connect failure. */
    if (svc_state == LWIP_SOCKET_SERVICES_READY)
    {
        lwip_error_t err = lwip_socket_connect_now(conn, host, port);
        if (err != LWIP_ERR_NETIF)
        {
            return err;
        }
    }
    else if (svc_state == LWIP_SOCKET_SERVICES_FAILED)
    {
        conn->status = LWIP_STATUS_ERROR;
        conn->last_error = svc_err ? svc_err : LWIP_ERR_NETIF;
        ERROR_CODE(conn->last_error);
        conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_SERVICES,
                           LWIP_SOCKET_ERR_OP_SERVICE_WAIT,
                           (int)conn->last_error, conn->last_error);
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
    return lwip_socket_wait_for_services(conn, host, port, deadline);
}

/* ============================================================
 * Write / shutdown / close
 * ============================================================ */

lwip_error_t lwip_socket_write(struct lwip_socket *conn,
                             const uint8_t *buf,
                             size_t len)
{
    if (!conn || !buf || len == 0)
        return LWIP_ERR_ARG;
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

    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
    {
        err_t e = tcp_write(conn->pcb.tcp, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK)
        {
            e = tcp_output(conn->pcb.tcp);
        }
        if (e != ERR_OK)
        {
            lwip_error_t mapped = lwip_err_translate(e);
            if (mapped == LWIP_ERR_MEM)
            {
                return mapped;
            }
            ERROR_CODE(-e);
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TCP,
                               LWIP_SOCKET_ERR_OP_WRITE, (int)e, mapped);
            return mapped;
        }
        return LWIP_OK;
    }
#endif
    case LWIP_SOCKET_UDP:
    {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
        if (!p)
        {
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_MEM,
                               LWIP_SOCKET_ERR_OP_ALLOC, (int)ERR_MEM,
                               LWIP_ERR_MEM);
            return LWIP_ERR_MEM;
        }
        memcpy(p->payload, buf, len);
        err_t e = udp_send(conn->pcb.udp, p);
        pbuf_free(p);
        if (e != ERR_OK)
        {
            lwip_error_t mapped = lwip_err_translate(e);
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_UDP,
                               LWIP_SOCKET_ERR_OP_SEND, (int)e, mapped);
            return mapped;
        }
        return LWIP_OK;
    }
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
    {
        err_t e = altcp_write(conn->pcb.altcp, buf, (u16_t)len,
                              TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK)
        {
            e = altcp_output(conn->pcb.altcp);
        }
        if (e != ERR_OK)
        {
            lwip_error_t mapped = lwip_err_translate(e);
            if (mapped == LWIP_ERR_MEM)
            {
                return mapped;
            }
            conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_ALTCP,
                               LWIP_SOCKET_ERR_OP_WRITE, (int)e, mapped);
            return mapped;
        }
        return LWIP_OK;
    }
    default:
        return LWIP_ERR_PROTO;
    }
}

size_t lwip_socket_available(const struct lwip_socket *conn)
{
    return (conn && conn->rx_ring) ? mem_buffer_len(conn->rx_ring) : 0;
}

size_t lwip_socket_read(struct lwip_socket *conn, uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0 || !conn->rx_ring)
    {
        return 0;
    }
    /* mem_buffer_pop requires len <= bytes available; clamp to what's there. */
    size_t avail = mem_buffer_len(conn->rx_ring);
    if (avail == 0)
    {
        return 0;
    }
    if (len > avail)
    {
        len = avail;
    }
    return mem_buffer_pop(conn->rx_ring, buf, len);
}

lwip_status_t lwip_socket_status(const struct lwip_socket *conn)
{
    return conn ? conn->status : LWIP_STATUS_ERROR;
}

lwip_error_t lwip_socket_shutdown(struct lwip_socket *conn)
{
    if (!conn)
        return LWIP_ERR_ARG;
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
        if (conn->pcb.tcp)
        {
            err_t e = tcp_shutdown(conn->pcb.tcp, 0, 1);
            if (e == ERR_OK)
            {
                conn->status = LWIP_STATUS_CLOSING;
                conn_event_enqueue(conn, CONN_PENDING_CLOSING, LWIP_OK);
            }
            if (e != ERR_OK)
            {
                lwip_error_t mapped = lwip_err_translate(e);
                conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TCP,
                                   LWIP_SOCKET_ERR_OP_SHUTDOWN, (int)e,
                                   mapped);
                return mapped;
            }
            return LWIP_OK;
        }
        return LWIP_ERR_STATE;
#endif
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            err_t e = altcp_shutdown(conn->pcb.altcp, 0, 1);
            if (e == ERR_OK)
            {
                conn->status = LWIP_STATUS_CLOSING;
                conn_event_enqueue(conn, CONN_PENDING_CLOSING, LWIP_OK);
            }
            if (e != ERR_OK)
            {
                lwip_error_t mapped = lwip_err_translate(e);
                conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_ALTCP,
                                   LWIP_SOCKET_ERR_OP_SHUTDOWN, (int)e,
                                   mapped);
                return mapped;
            }
            return LWIP_OK;
        }
        return LWIP_ERR_STATE;
    case LWIP_SOCKET_UDP:
        return LWIP_OK; /* UDP has no shutdown */
    default:
        return LWIP_ERR_PROTO;
    }
}

lwip_error_t lwip_socket_close(struct lwip_socket *conn)
{
    struct tcp_pcb *closing_tcp;
    bool wait_for_tcp;

    if (!conn)
        return LWIP_ERR_ARG;
    closing_tcp = lwip_socket_leaf_tcp_pcb(conn);
    wait_for_tcp = closing_tcp && !g_lwip_stopping;

    /* Cancel any pending service work (DHCP/DNS) and free the host string
     * before clearing the handle. This prevents memory leaks and
     * use-after-free during deferred connects. */
    services_list_remove(conn);
    lwip_socket_set_pending_host(conn, NULL);

    /* Detach BEFORE attempting close so a deferred FIN ACK/err cb
     * doesn't reach into a half-torn-down conn. If close() then fails
     * we re-bind the callbacks below so the app keeps getting events
     * on the still-live pcb. */
    lwip_socket_detach_pcb_callbacks(conn);
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
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
                conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_TCP,
                                   LWIP_SOCKET_ERR_OP_CLOSE, (int)e,
                                   lwip_err_translate(e));
                return conn->last_error;
            }
            conn->pcb.tcp = NULL;
        }
        break;
#endif
    case LWIP_SOCKET_UDP:
        if (conn->pcb.udp)
        {
            udp_remove(conn->pcb.udp);
            conn->pcb.udp = NULL;
        }
        break;
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
        if (conn->pcb.altcp)
        {
            err_t e = altcp_close(conn->pcb.altcp);
            if (e != ERR_OK)
            {
                if (!g_lwip_stopping)
                {
                    rebind_pcb_callbacks(conn);
                }
                conn_error_enqueue(conn, LWIP_SOCKET_ERR_COMP_ALTCP,
                                   LWIP_SOCKET_ERR_OP_CLOSE, (int)e,
                                   lwip_err_translate(e));
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
    conn_event_enqueue(conn, CONN_PENDING_CLOSED, LWIP_OK);
    conn_registry_remove(conn);
    if (wait_for_tcp &&
        !lwip_wait_for_tcp_pcb_close(closing_tcp, LWIP_SOCKET_CLOSE_TIMEOUT_MS))
    {
        lwip_teardown_abort_tcp_pcb(closing_tcp);
        conn->last_error = LWIP_ERR_CLOSED;
        return LWIP_ERR_CLOSED;
    }
    return LWIP_OK;
}

lwip_error_t lwip_socket_abort(struct lwip_socket *conn)
{
    if (!conn)
        return LWIP_ERR_ARG;
    conn_registry_remove(conn);
    lwip_socket_set_pending_host(conn, NULL);
    services_list_remove(conn);
    switch ((lwip_socket_type_t)conn->protocol)
    {
#if LWIP_TCP
    case LWIP_SOCKET_TCP:
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
    case LWIP_SOCKET_UDP:
        if (conn->pcb.udp)
        {
            udp_remove(conn->pcb.udp);
            conn->pcb.udp = NULL;
        }
        break;
    case LWIP_SOCKET_ALTCP:
    case LWIP_SOCKET_ALTCP_TLS:
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
 * Callback + status helpers
 * ============================================================ */

void lwip_socket_on_event(struct lwip_socket *conn,
                          uint8_t event_flags,
                          lwip_socket_event_cb cb,
                          void *arg)
{
    if (!conn)
        return;
    conn->on_event    = cb;
    conn->user_arg    = arg;
    conn->event_flags = cb ?
        (uint8_t)((event_flags | LWIP_SOCKET_EVENTF_ERROR) &
                  LWIP_SOCKET_EVENTF_ALL) :
        0;
}

bool lwip_socket_is_active(const struct lwip_socket *conn)
{
    if (!conn)
        return false;
    switch (conn->status)
    {
    case LWIP_STATUS_INIT:
    case LWIP_STATUS_WAITING_SERVICES:
    case LWIP_STATUS_RESOLVING:
    case LWIP_STATUS_CONNECTING:
    case LWIP_STATUS_CONNECTED:
    case LWIP_STATUS_CLOSING:
        return true;
    default:
        return false;
    }
}

lwip_error_t lwip_socket_set_rx_limits(struct lwip_socket *conn,
                                     size_t initial_size,
                                     size_t max_size)
{
    if (!conn || initial_size == 0 || max_size == 0 || initial_size > max_size)
    {
        return LWIP_ERR_ARG;
    }
    if (conn->rx_ring && mem_buffer_len(conn->rx_ring) != 0)
    {
        return LWIP_ERR_STATE;
    }
    if (conn->rx_ring)
    {
        mem_buffer_destroy(conn->rx_ring);
        conn->rx_ring = NULL;
    }
    conn->rx_ring_init = initial_size;
    conn->rx_ring_max = max_size;
    return lwip_socket_rx_ring_create(conn);
}

lwip_error_t lwip_socket_set_connect_timeout(struct lwip_socket *conn,
                                           uint32_t timeout_ms)
{
    if (!conn)
    {
        return LWIP_ERR_ARG;
    }
    conn->connect_timeout_ms = timeout_ms; /* 0 ⇒ default window */
    /* Re-arm: the watchdog recomputes services_deadline from the new window
     * on its next tick (services_deadline==0 ⇒ fresh arm) when connecting. */
    if (conn_in_connect_phase(conn))
    {
        conn->services_deadline = 0;
    }
    return LWIP_OK;
}
