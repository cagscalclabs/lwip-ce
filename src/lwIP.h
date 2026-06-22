/**
 * @file lwIP.h
 * @brief App-facing socket API.
 *
 * Hides the altcp / altcp_tls_ce / raw tcp / udp factoring behind a single
 * socket handle and a fixed verb set. Intended for application code
 * that just wants to open a socket-like endpoint, attach a single event
 * callback, and send/recv bytes. The TLS and altcp layers are still directly
 * usable for anyone who needs them — this is an additive convenience layer.
 *
 * Lifecycle:
 *   lwip_start()                — once at load time (libload bootstrap +
 *                                  app config; makes exported functions
 *                                  callable, but no stack memory/timers/RNG
 *                                  or networking yet)
 *   lwip_network_up()           — bring up stack memory/timers/pools, TLS
 *                                  (RNG + truststore/PSK cache), and
 *                                  USB/netif; call once before networking.
 *                                  Crypto needing fresh entropy requires
 *                                  this to have run; for the RNG without
 *                                  full networking, call
 *                                  tls_random_init_entropy() directly.
 *   lwip_service_events()  — every main-loop iteration (drives callbacks)
 *   lwip_socket_create()        — allocate handle, bind netif, kick DHCP
 *   lwip_socket_on_event()      — register single event callback + arg
 *   lwip_socket_connect()       — initiate connect; completion fires STATE_CHANGE
 *   lwip_socket_available() / lwip_socket_read() — data path in main loop
 *   lwip_socket_write()         — send data (from CONNECTED callback or loop)
 *   lwip_socket_shutdown() / close / abort — teardown
 *   lwip_socket_destroy()       — free handle
 *   lwip_stop()                 — stack shutdown
 *
 * Typical main loop:
 *   while (lwip_socket_is_active(&sock) && !done) {
 *       lwip_service_events();
 *       size_t n = lwip_socket_available(&sock);
 *       if (n) lwip_socket_read(&sock, buf, n);
 *   }
 */

#ifndef LWIP_HDR_LWIP_APP_H
#define LWIP_HDR_LWIP_APP_H

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/logging.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct netif;
struct tcp_pcb;
struct udp_pcb;
struct altcp_pcb;
struct altcp_tls_ce_config;
struct mem_buffer;
struct lwip_socket;   /* forward decl for callback typedefs */

/** API result codes. */
typedef enum
{
    LWIP_OK = 0,
    LWIP_ERR_ARG,        /**< NULL / out-of-range argument */
    LWIP_ERR_STATE,      /**< called in wrong lifecycle state */
    LWIP_ERR_MEM,        /**< allocation failed */
    LWIP_ERR_NETIF,      /**< no netif available / not up */
    LWIP_ERR_DNS,        /**< DNS resolution failed / unavailable */
    LWIP_ERR_CONNECT,    /**< connect() failed at transport layer */
    LWIP_ERR_PROTO,      /**< unsupported protocol for this op */
    LWIP_ERR_CLOSED,     /**< peer has closed (or local close pending) */
    LWIP_ERR_INTERNAL,   /**< lwIP returned an unexpected err_t */
} lwip_error_t;

/** Transport selector for lwip_socket_create. */
typedef enum
{
    LWIP_SOCKET_TCP = 0,      /**< raw TCP via tcp_*  */
    LWIP_SOCKET_UDP,          /**< UDP via udp_*      */
    LWIP_SOCKET_ALTCP,        /**< altcp (default TCP allocator) */
    LWIP_SOCKET_ALTCP_TLS,    /**< altcp wrapped in TLS 1.3 (altcp_tls_ce) */
} lwip_socket_type_t;

/** Which netif a socket attaches to at create(). */
typedef enum
{
    LWIP_NETIF_ANY = 0,  /**< first usable netif (loopback or external) */
    LWIP_NETIF_LOOP,     /**< loopback only */
    LWIP_NETIF_EXT,      /**< external Ethernet only */
} lwip_socket_bind_descriptor_t;

/** Optional static IPv4 configuration. Pass NULL for DHCP. */
typedef struct
{
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gateway;
} lwip_socket_addrinfo_t;

/** Socket lifecycle status. Poll via socket->status or STATE_CHANGE events. */
typedef enum
{
    LWIP_STATUS_INIT = 0,         /**< handle created, not connecting yet */
    LWIP_STATUS_WAITING_SERVICES, /**< deferred: netif/link/DHCP/DNS not ready */
    LWIP_STATUS_RESOLVING,        /**< DNS lookup in flight */
    LWIP_STATUS_CONNECTING,       /**< TCP / TLS handshake in flight */
    LWIP_STATUS_CONNECTED,        /**< ready for write/read */
    LWIP_STATUS_CLOSING,          /**< local shutdown / close issued */
    LWIP_STATUS_CLOSED,           /**< peer sent FIN, clean close */
    LWIP_STATUS_RESET,            /**< peer sent RST, connection immediately gone */
    LWIP_STATUS_ERROR,            /**< stack error (timeout, OOM, abort) */
} lwip_status_t;

/** Socket event types delivered to the event callback.
 *
 *  ERROR is always delivered if a callback is registered, regardless of flags.
 *  For STATE_CHANGE, ev_data is lwip_socket_state_data_t* (previous + current
 *  status). For IO, ev_data is lwip_socket_io_data_t*. For ERROR, ev_data is
 *  lwip_socket_error_data_t* with the full component/operation/raw breakdown.
 *  All ev_data pointers are valid only for the duration of the callback. */
typedef enum
{
    LWIP_SOCKET_EV_ERROR = 0,
    LWIP_SOCKET_EV_STATE_CHANGE,
    LWIP_SOCKET_EV_IO,
} lwip_socket_event_type_t;

#define LWIP_SOCKET_EVENTF_ERROR        (1u << LWIP_SOCKET_EV_ERROR)
#define LWIP_SOCKET_EVENTF_STATE_CHANGE (1u << LWIP_SOCKET_EV_STATE_CHANGE)
#define LWIP_SOCKET_EVENTF_IO           (1u << LWIP_SOCKET_EV_IO)
#define LWIP_SOCKET_EVENTF_ALL          (LWIP_SOCKET_EVENTF_ERROR | \
                                         LWIP_SOCKET_EVENTF_STATE_CHANGE | \
                                         LWIP_SOCKET_EVENTF_IO)

/** IO event flags within lwip_socket_io_data_t.flags. */
typedef enum
{
    LWIP_SOCKET_IO_READABLE = 1u << 0,  /**< data in ring; call lwip_socket_read */
    LWIP_SOCKET_IO_WRITABLE = 1u << 1,  /**< peer ACKed sent data */
    LWIP_SOCKET_IO_POLL     = 1u << 2,  /**< periodic poll tick */
} lwip_socket_io_flags_t;

/** Error component — which subsystem reported the error. */
typedef enum
{
    LWIP_SOCKET_ERR_COMP_SOCKET = 0,
    LWIP_SOCKET_ERR_COMP_NETIF,
    LWIP_SOCKET_ERR_COMP_SERVICES,
    LWIP_SOCKET_ERR_COMP_DNS,
    LWIP_SOCKET_ERR_COMP_TCP,
    LWIP_SOCKET_ERR_COMP_UDP,
    LWIP_SOCKET_ERR_COMP_ALTCP,
    LWIP_SOCKET_ERR_COMP_TLS,
    LWIP_SOCKET_ERR_COMP_MEM,
} lwip_socket_error_component_t;

/** Error operation — what was being attempted when the error occurred. */
typedef enum
{
    LWIP_SOCKET_ERR_OP_NONE = 0,
    LWIP_SOCKET_ERR_OP_CREATE,
    LWIP_SOCKET_ERR_OP_CONNECT,
    LWIP_SOCKET_ERR_OP_DNS_LOOKUP,
    LWIP_SOCKET_ERR_OP_SERVICE_WAIT,
    LWIP_SOCKET_ERR_OP_SERVICE_START,
    LWIP_SOCKET_ERR_OP_RECV,
    LWIP_SOCKET_ERR_OP_SEND,
    LWIP_SOCKET_ERR_OP_WRITE,
    LWIP_SOCKET_ERR_OP_CLOSE,
    LWIP_SOCKET_ERR_OP_SHUTDOWN,
    LWIP_SOCKET_ERR_OP_TLS_INIT,
    LWIP_SOCKET_ERR_OP_TLS_CONFIG,
    LWIP_SOCKET_ERR_OP_ALLOC,
} lwip_socket_error_operation_t;

/** ev_data for LWIP_SOCKET_EV_ERROR events. */
typedef struct
{
    uint16_t      component;   /**< lwip_socket_error_component_t */
    uint16_t      operation;   /**< lwip_socket_error_operation_t */
    int           raw_error;   /**< raw err_t / module code */
    lwip_error_t  err;         /**< mapped app-facing result */
    lwip_status_t status;      /**< socket status at time of error */
} lwip_socket_error_data_t;

/** ev_data for LWIP_SOCKET_EV_STATE_CHANGE events. */
typedef struct
{
    lwip_status_t previous;
    lwip_status_t current;
} lwip_socket_state_data_t;

/** ev_data for LWIP_SOCKET_EV_IO events. */
typedef struct
{
    uint8_t  flags;    /**< lwip_socket_io_flags_t bitmap */
    size_t   readable; /**< bytes in ring for lwip_socket_read */
    uint16_t written;  /**< bytes peer ACKed (WRITABLE flag set) */
} lwip_socket_io_data_t;

/** Single typed event callback.
 *
 *  sock     — the socket that generated the event.
 *  type     — LWIP_SOCKET_EV_ERROR / STATE_CHANGE / IO.
 *  ev_data  — typed payload (cast to the matching _data_t* for the event type).
 *             Valid only for the duration of the callback.
 *  arg      — user pointer supplied to lwip_socket_on_event(). */
typedef void (*lwip_socket_event_cb)(struct lwip_socket *sock,
                                     lwip_socket_event_type_t type,
                                     const void *ev_data,
                                     void *arg);

/** Service wait flags. */
#define LWIP_SOCKET_SVC_DHCP   (1u << 0)
#define LWIP_SOCKET_SVC_SNTP   (1u << 1)
#define LWIP_SOCKET_SVC_DNS    (1u << 2)

typedef enum
{
    LWIP_NETIF_SERVICE_UP = 0,
    LWIP_NETIF_SERVICE_FAILED,
    LWIP_NETIF_SERVICE_TIMEOUT,
} lwip_netif_service_status_t;

typedef void (*lwip_netif_service_cb)(struct netif *netif,
                                      void *arg,
                                      uint8_t service_id,
                                      lwip_netif_service_status_t status);

/** Snapshot of the default lwIP netif. */
typedef struct
{
    bool    has_netif;
    bool    up;
    bool    link_up;
    bool    dhcp_running;
    uint8_t dhcp_state;
    bool    has_ipv4;
    bool    has_ipv4_gateway;
    uint8_t ipv4_addr[4];
    uint8_t ipv4_netmask[4];
    uint8_t ipv4_gateway[4];
} lwip_netif_info_t;

/** Timing constants. */
#define LWIP_SOCKET_SERVICES_TIMEOUT_MS  30000u
#define LWIP_SOCKET_RX_RING_INIT_SIZE    512u
#define LWIP_SOCKET_RX_RING_STEP_SIZE    512u
#define LWIP_SOCKET_RX_RING_MAX_SIZE     4096u

/** Socket handle. status and last_error are app-readable; all other fields
 *  are managed by the implementation — do not write them. */
struct lwip_socket
{
    /* Public, app-readable. */
    lwip_status_t  status;
    lwip_error_t   last_error;

    /* App-supplied (written by lwip_socket_on_event). */
    void                *user_arg;
    lwip_socket_event_cb on_event;
    uint8_t              event_flags;

    /* Internal. */
    uint8_t   protocol;       /**< lwip_socket_type_t */
    uint8_t   flags;          /**< service flags */
    uint8_t   aborting;
    uint16_t  remote_port;
    ip_addr_t remote_ip;
    struct netif *netif;

    /* Netif bind preference (recorded non-blocking at create). */
    uint8_t                bind_descriptor;
    bool                   has_addrinfo;
    bool                   static_applied;
    lwip_socket_addrinfo_t addrinfo;

    union {
        struct tcp_pcb   *tcp;
        struct udp_pcb   *udp;
        struct altcp_pcb *altcp;
    } pcb;
    struct altcp_tls_ce_config *tls_conf;
    struct mem_buffer          *rx_ring;
    size_t                      rx_ring_init;
    size_t                      rx_ring_max;
    uint16_t                    last_sent_len;
    uint16_t                    pending_events;
    lwip_error_t                pending_error;
    int                         pending_raw_error;
    uint16_t                    pending_error_component;
    uint16_t                    pending_error_operation;
    lwip_status_t               pending_state_previous;

    /* Deferred-connect / inactivity watchdog state. */
    const char *pending_host;
    uint32_t    services_deadline;
    uint32_t    connect_timeout_ms;
    uint32_t    activity_seen;

    struct lwip_socket *services_next;
    struct lwip_socket *registry_next;
};

/* ------------------------------------------------------------------ */

uint8_t  lwip_start_last_error(void);
void     lwip_stop(void);
bool     lwip_init_runtime_internal(const void *imports_src, size_t imports_len);

/* Bring the network up: stack memory/timers/pools (lwip_init()), TLS (RNG
 * bootstrap, truststore, PSK cache), and USB/netif init, in that order.
 * Requires lwip_start() to have run first (lwip_start_with_crt(), aliased
 * to lwip_start() for the caller's own CRT, does this automatically at
 * load time) — lwip_network_up() only assumes app config/exported
 * functions are in place, not that the stack itself is live yet. */
bool     lwip_network_up(void);
void     lwip_service_events(void);
uint32_t lwip_now_ms(void);
bool     lwip_default_netif_info(lwip_netif_info_t *info);

lwip_error_t lwip_request_services(uint8_t flags);
lwip_error_t lwip_netif_request_services(struct netif *netif,
                                         uint8_t flags,
                                         lwip_netif_service_cb cb,
                                         void *cb_data);

/** Create a socket handle. Non-blocking: returns immediately after binding
 *  the netif preference and kicking DHCP/static-IP. Readiness is awaited
 *  asynchronously by lwip_socket_connect.
 *
 *  @param socket     Caller-allocated handle. Zeroed by this call.
 *  @param type       Transport selector (lwip_socket_type_t).
 *  @param bind       Netif preference (lwip_socket_bind_descriptor_t).
 *  @param addrinfo   NULL for DHCP; non-NULL for static IPv4.
 *  @param timeout_ms Inactivity watchdog window for connect/handshake (ms);
 *                    0 = default (LWIP_SOCKET_SERVICES_TIMEOUT_MS). */
lwip_error_t lwip_socket_create(struct lwip_socket *socket,
                                lwip_socket_type_t type,
                                lwip_socket_bind_descriptor_t bind,
                                const lwip_socket_addrinfo_t *addrinfo,
                                uint32_t timeout_ms);

/** Like lwip_socket_create but with an explicit RX ring maximum.
 *  rx_ring_max == 0 uses LWIP_SOCKET_RX_RING_MAX_SIZE. */
lwip_error_t lwip_socket_create_ex(struct lwip_socket *socket,
                                   lwip_socket_type_t type,
                                   lwip_socket_bind_descriptor_t bind,
                                   const lwip_socket_addrinfo_t *addrinfo,
                                   uint32_t timeout_ms,
                                   size_t rx_ring_max);

lwip_error_t lwip_socket_destroy(struct lwip_socket *socket);

lwip_error_t lwip_socket_connect(struct lwip_socket *socket,
                                 const char *host,
                                 uint16_t port);

/** Register the single event callback.
 *
 *  flags    — bitwise OR of LWIP_SOCKET_EVENTF_* to subscribe to; ERROR is
 *             always delivered regardless.
 *  cb       — callback: void cb(sock, type, ev_data, arg)
 *  arg      — user pointer passed as the last argument to cb.
 *
 *  Call before lwip_socket_connect. Only one callback is supported per socket;
 *  calling again replaces the previous registration. */
void lwip_socket_on_event(struct lwip_socket *socket,
                          uint8_t event_flags,
                          lwip_socket_event_cb cb,
                          void *arg);

/** True while the socket is in a pre-terminal lifecycle state
 *  (INIT / WAITING / RESOLVING / CONNECTING / CONNECTED / CLOSING).
 *  Returns false once the socket reaches CLOSED, RESET, or ERROR — use this
 *  as the main-loop exit condition. */
bool lwip_socket_is_active(const struct lwip_socket *socket);

lwip_error_t lwip_socket_set_connect_timeout(struct lwip_socket *socket,
                                             uint32_t timeout_ms);
lwip_error_t lwip_socket_write(struct lwip_socket *socket,
                               const uint8_t *buf,
                               size_t len);
size_t       lwip_socket_available(const struct lwip_socket *socket);
/** Read up to len bytes from the socket ring. Returns bytes actually read
 *  (clamped to available); never blocks. */
size_t       lwip_socket_read(struct lwip_socket *socket,
                              uint8_t *buf,
                              size_t len);
lwip_status_t lwip_socket_status(const struct lwip_socket *socket);
lwip_error_t  lwip_socket_shutdown(struct lwip_socket *socket);
lwip_error_t  lwip_socket_close(struct lwip_socket *socket);
lwip_error_t  lwip_socket_abort(struct lwip_socket *socket);

lwip_error_t lwip_socket_set_rx_limits(struct lwip_socket *socket,
                                       size_t initial_size,
                                       size_t max_size);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_LWIP_APP_H */
