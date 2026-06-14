/**
 * @file lwIP.h
 * @brief App-facing connection API.
 *
 * Hides the altcp / altcp_tls_ce / raw tcp / udp factoring behind a single
 * connection handle and a fixed verb set. Intended for application code
 * that just wants to open a socket-like endpoint, attach callbacks, and
 * send/recv bytes. The TLS and altcp layers are still directly usable for
 * anyone who needs them — this is an additive convenience layer.
 *
 * Lifecycle:
 *   lwip_start()                  — once at startup
 *   lwip_poll_network_events()   — in the app's main loop, every iteration
 *   lwip_conn_create()           — per connection
 *   lwip_conn_set_*()            — register any callbacks before connect
 *   lwip_conn_connect()          — host (IPv4 string or DNS name) + port
 *   lwip_conn_write() / recv     — once connected (recv is callback-driven)
 *   lwip_conn_shutdown() / close — graceful half-close or orderly teardown
 *   lwip_conn_abort()            — immediate forced teardown
 *   lwip_conn_destroy()          — free the handle
 *   lwip_stop()                  — before app exit when done with networking
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
struct lwip_conn;   /* defined further down; forward decl for callback typedefs */

/** API result codes. Distinct from lwIP's err_t to keep the app surface
 *  small and stable. */
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

/** Transport selector for lwip_conn_create. */
typedef enum
{
    LWIP_PROTO_TCP = 0,      /**< raw TCP via tcp_*  */
    LWIP_PROTO_UDP,          /**< UDP via udp_*      */
    LWIP_PROTO_ALTCP,        /**< altcp (default TCP allocator) */
    LWIP_PROTO_ALTCP_TLS,    /**< altcp wrapped in TLS 1.3 (altcp_tls_ce) */
} lwip_protocol_t;

/** Status the app polls after async operations (connect / TLS handshake /
 *  peer close). Single value, no callback registration required. */
typedef enum
{
    LWIP_STATUS_INIT = 0,            /**< created but not connecting yet */
    LWIP_STATUS_WAITING_SERVICES,    /**< connect deferred: netif not yet
                                          enumerated, link not up, or requested
                                          service (DHCP/DNS) not yet ready.
                                          transitions automatically to
                                          RESOLVING/CONNECTING when ready, or
                                          to ERROR on timeout. */
    LWIP_STATUS_RESOLVING,           /**< DNS lookup in flight */
    LWIP_STATUS_CONNECTING,          /**< TCP / TLS handshake in flight */
    LWIP_STATUS_CONNECTED,           /**< ready for write/recv */
    LWIP_STATUS_CLOSING,             /**< local shutdown / close issued */
    LWIP_STATUS_CLOSED,              /**< peer closed cleanly */
    LWIP_STATUS_ERROR,               /**< fatal error; check last_error */
} lwip_status_t;

/** Service wait flags for lwip_conn_create. These are *netif-level* — they
 *  request that this connection wait until the service is usable on the
 *  resident interface, not that this connection owns it privately. */
#define LWIP_CONN_SVC_DHCP        (1u << 0)  /**< DHCP on resident netif */
#define LWIP_CONN_SVC_SNTP        (1u << 1)  /**< SNTP started against DHCP/server */
#define LWIP_CONN_SVC_DNS         (1u << 2)  /**< DNS resolver initialized */

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

/** Snapshot of the default lwIP netif. IPv4 octets are stored in display
 *  order: index 0 is the dotted-quad's first octet. */
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

/** Per-connection application callbacks. All optional; set via the
 *  lwip_conn_set_* helpers below before lwip_conn_connect. */
typedef void (*lwip_conn_connected_cb)(void *arg, struct lwip_conn *conn);
typedef void (*lwip_conn_recv_cb)(void *arg, struct lwip_conn *conn,
                                  struct pbuf *p);
typedef void (*lwip_conn_sent_cb)(void *arg, struct lwip_conn *conn,
                                  uint16_t len);
typedef void (*lwip_conn_err_cb)(void *arg, struct lwip_conn *conn,
                                 lwip_error_t err);
typedef void (*lwip_conn_poll_cb)(void *arg, struct lwip_conn *conn);
typedef void (*lwip_conn_closed_cb)(void *arg, struct lwip_conn *conn);

/** Bundle of all per-connection callbacks, for setting them in one call
 *  via lwip_conn_set_callbacks(). Any field may be NULL to clear that
 *  callback. Zero-initialize (e.g. `lwip_conn_callbacks_t cbs = {0};`)
 *  then fill the ones you want — this is equivalent to calling each
 *  lwip_conn_set_* helper individually. */
typedef struct
{
    void                  *arg;          /**< user_arg passed to every callback */
    lwip_conn_connected_cb connected;
    lwip_conn_recv_cb      recv;
    lwip_conn_sent_cb      sent;
    lwip_conn_err_cb       err;
    lwip_conn_poll_cb      poll;
    uint8_t                poll_interval_ticks; /**< poll period in 0.5s ticks; 0 ⇒ default (4) */
    lwip_conn_closed_cb    closed;
} lwip_conn_callbacks_t;

/** Maximum time (ms) lwip_conn_connect will wait in
 *  LWIP_STATUS_WAITING_SERVICES before giving up with LWIP_ERR_NETIF.
 *  Covers USB enumeration, link-up, and DHCP-on-cold-boot latency. */
#define LWIP_CONN_SERVICES_TIMEOUT_MS  30000u

/** Connection state. Transparent on purpose — apps may inspect `status`
 *  and `last_error` directly. All other fields are managed by the
 *  implementation; do not write them. */
struct lwip_conn
{
    /* Public, app-readable. */
    lwip_status_t        status;
    lwip_error_t         last_error;

    /* App-supplied. */
    void                *user_arg;
    lwip_conn_connected_cb on_connected;
    lwip_conn_recv_cb      on_recv;
    lwip_conn_sent_cb      on_sent;
    lwip_conn_err_cb       on_err;
    lwip_conn_poll_cb      on_poll;
    lwip_conn_closed_cb    on_closed;

    /* Internal — written by the implementation only. */
    uint8_t              protocol;       /**< lwip_protocol_t */
    uint8_t              flags;          /**< service flags actually applied */
    uint8_t              aborting;       /**< abort issued from callback */
    uint16_t             remote_port;
    ip_addr_t            remote_ip;
    struct netif        *netif;          /**< resident interface */
    union {
        struct tcp_pcb           *tcp;
        struct udp_pcb           *udp;
        struct altcp_pcb         *altcp;
    } pcb;
    struct altcp_tls_ce_config  *tls_conf;  /**< owned by conn, only for ALTCP_TLS */

    /* Deferred-connect state for LWIP_STATUS_WAITING_SERVICES. Set by
     * lwip_conn_connect when the netif/link/IP/services aren't ready yet;
     * cleared once the deferred connect fires (or times out). */
    const char          *pending_host;       /**< borrowed pointer; caller must keep alive */
    uint32_t             services_deadline;  /**< sys_now() in ms; 0 = unused */
    struct lwip_conn    *services_next;      /**< intrusive list of waiters */
    struct lwip_conn    *registry_next;      /**< intrusive list of live handles */
};

/** Boot the network stack. Loads the persisted lwip_app_config appvar,
 *  brings up the memory subsystem and USB driver, registers the ethernet
 *  netif callback. Idempotent — calls after the first return LWIP_OK
 *  without reinitializing.
 *
 *  Designed for the simple case where the app has no opinion about the
 *  configurator. Apps that need custom usb hooks should call lwip_init()
 *  directly instead. */
bool lwip_start(void);

/** Reason for the last lwip_start() failure.
 *  0 = none, 1 = lwip_init/memory init, 2 = USB driver init. */
uint8_t lwip_start_last_error(void);

/** Tear down the network stack started by lwip_start(). Safe to call when the
 *  stack is not running. */
void lwip_stop(void);

/** App-side init invoked by lwip_init_runtime_opaque after the export
 *  trampolines are patched. Zeroes lwIP's BSS, copies its .data from LMA
 *  to VMA, and copies the libload-side imports table into the app's
 *  fn_imports_table so app code can dispatch through usb_fn / the host
 *  CRT pointers. Consumers do not call this directly. */
void lwip_init_runtime_internal(const void *imports_src, size_t imports_len);

/** Pump network events. Calls usb_HandleEvents() and sys_check_timeouts().
 *  The app should call this every iteration of its main loop. */
void lwip_poll_network_events(void);

/** Fill `info` with the current default netif state. Returns true if a
 *  default netif exists. The function is safe to poll immediately after
 *  lwip_start(); USB enumeration, link-up, and DHCP can all complete later. */
bool lwip_default_netif_info(lwip_netif_info_t *info);

/** Request netif-level services without allocating a connection.
 *
 *  This is useful for apps that need the stack online before they create
 *  transport PCBs. Flags use LWIP_CONN_SVC_* and are applied immediately if
 *  the external netif already exists; otherwise lwip_poll_network_events()
 *  applies them once USB/link enumeration creates the netif. */
lwip_error_t lwip_request_services(uint8_t flags);

/** Request netif-level services and get per-service completion callbacks.
 *
 *  `netif == NULL` means the external Ethernet netif once it exists. The
 *  callback fires once per requested LWIP_CONN_SVC_* bit with service_id set
 *  to that bit and status set to UP, FAILED, or TIMEOUT. If `cb` is NULL, this
 *  behaves like lwip_request_services().
 */
lwip_error_t lwip_netif_request_services(struct netif *netif,
                                         uint8_t flags,
                                         lwip_netif_service_cb cb,
                                         void *cb_data);

/** Initialize a connection handle.
 *
 *  @param conn      Caller-allocated handle. Zeroed by this call.
 *  @param netif     Resident interface. NULL means "use netif_default".
 *                   If no default netif exists yet, create still succeeds;
 *                   lwip_conn_connect queues until USB/link/DHCP are ready.
 *  @param protocol  Transport selector (see lwip_protocol_t).
 *  @param flags     Service wait flags (LWIP_CONN_SVC_*). */
lwip_error_t lwip_conn_create(struct lwip_conn *conn,
                              struct netif *netif,
                              lwip_protocol_t protocol,
                              uint8_t flags);

/** Free any resources owned by the handle (pcb, TLS config). Safe to call
 *  on a handle in any state. Zeroes the handle on return. */
lwip_error_t lwip_conn_destroy(struct lwip_conn *conn);

/** Connect to host:port. `host` may be either a dotted-quad IPv4 string
 *  ("192.168.1.10") or a DNS name ("example.com"). DNS resolution is
 *  attempted only when LWIP_DNS is configured *and* DNS has been started
 *  on the netif — request it via LWIP_CONN_SVC_DNS at create time.
 *
 *  Returns LWIP_OK once the connect attempt has been *initiated*. Apps
 *  must poll `conn->status` for completion (or register on_connected). */
lwip_error_t lwip_conn_connect(struct lwip_conn *conn,
                               const char *host,
                               uint16_t port);

/** Send bytes. For TCP/altcp/altcp_tls this enqueues into the send buffer
 *  (TCP_WRITE_FLAG_COPY semantics). For UDP this sends as a single dgram
 *  to the previously-connected remote.
 *
 *  Returns LWIP_OK on success, LWIP_ERR_MEM if the lower layer's send
 *  buffer is full (caller should retry), LWIP_ERR_STATE if not connected. */
lwip_error_t lwip_conn_write(struct lwip_conn *conn,
                             const uint8_t *buf,
                             size_t len);

/** Acknowledge `len` consumed bytes from a previous on_recv callback.
 *
 *  This module hands the recv pbuf to the app and does NOT auto-ack — the
 *  app is responsible for calling this once it has consumed (or queued
 *  for consumption) the data. Without the call, the TCP receive window
 *  will not advance and the peer will eventually stall, which is the
 *  intended backpressure signal for slow consumers.
 *
 *  UDP has no flow-control concept here; the call returns LWIP_OK and
 *  does nothing. The pbuf returned by on_recv is the caller's to free
 *  (this call does not free it). */
lwip_error_t lwip_conn_recved(struct lwip_conn *conn, size_t len);

/** Half-close (TCP/altcp/altcp_tls only). Sends FIN (+ TLS close_notify
 *  for the TLS variant) and transitions the handle to CLOSING. The app
 *  may still receive data until the peer closes. */
lwip_error_t lwip_conn_shutdown(struct lwip_conn *conn);

/** Orderly close. For TCP/altcp/altcp_tls this asks the lower layer to
 *  close cleanly, then pumps the stack for a bounded interval until that
 *  TCP PCB leaves the active close lists. If lwIP cannot enqueue the close
 *  immediately (for example because memory is unavailable for a FIN), the
 *  pcb is left intact and the error is returned so the app can retry or
 *  call lwip_conn_abort(). If the close was enqueued but does not drain
 *  before the timeout, the remaining TCP PCB is aborted and LWIP_ERR_CLOSED
 *  is returned.
 *
 *  For UDP this removes the pcb. On success, no callbacks will fire and
 *  the handle is in CLOSED state. */
lwip_error_t lwip_conn_close(struct lwip_conn *conn);

/** Immediate forced teardown. This detaches the wrapper callbacks first so
 *  lwIP stops delivering receive traffic to this connection, then aborts
 *  TCP/altcp/altcp_tls without attempting an orderly close. For UDP this
 *  removes the pcb. After this returns, no callbacks will fire and the
 *  handle is in CLOSED state. */
lwip_error_t lwip_conn_abort(struct lwip_conn *conn);

/* ------------------------------------------------------------------
 * Callback setters — register before lwip_conn_connect.
 *
 * The conn module hooks every underlying pcb callback itself (so it can
 * own the polling state machine) and re-dispatches to these app-facing
 * callbacks. Apps therefore set these helpers, never the raw pcb fields.
 * ------------------------------------------------------------------ */
void lwip_conn_set_arg(struct lwip_conn *conn, void *arg);
void lwip_conn_set_connected(struct lwip_conn *conn, lwip_conn_connected_cb cb);
void lwip_conn_set_recv(struct lwip_conn *conn, lwip_conn_recv_cb cb);
void lwip_conn_set_sent(struct lwip_conn *conn, lwip_conn_sent_cb cb);
void lwip_conn_set_err(struct lwip_conn *conn, lwip_conn_err_cb cb);
void lwip_conn_set_poll(struct lwip_conn *conn, lwip_conn_poll_cb cb, uint8_t interval_ticks);
void lwip_conn_set_closed(struct lwip_conn *conn, lwip_conn_closed_cb cb);

/** Set every per-connection callback at once. Equivalent to calling each
 *  lwip_conn_set_* helper in turn (including the poll re-arm); fields left
 *  NULL clear the corresponding callback. Call before lwip_conn_connect. */
void lwip_conn_set_callbacks(struct lwip_conn *conn,
                             const lwip_conn_callbacks_t *cbs);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_LWIP_APP_H */
