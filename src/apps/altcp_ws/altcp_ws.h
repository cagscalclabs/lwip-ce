#ifndef ALTCP_WS_H
#define ALTCP_WS_H

#include "lwip/opt.h"
#if LWIP_ALTCP

#include "lwip/altcp.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file altcp_ws.h
 * @brief WebSocket altcp layer (RFC 6455, client-side only).
 *
 * Wraps a plain TCP or TLS altcp_pcb with a WebSocket framing layer.
 * From the application's perspective the socket behaves like a normal altcp
 * connection: write sends binary frames, recv delivers payload bytes only.
 * Fragment payloads may be delivered separately; message boundaries are not
 * exposed. Each received frame, including its header, must fit TCP_WND and
 * a 16-bit pbuf length. Larger frames are rejected.
 *
 * Usage (WS):
 *   altcp_ws_config_t *cfg = altcp_ws_create_config("example.com", "/ws", NULL);
 *   struct altcp_pcb  *pcb = altcp_ws_new(cfg, IPADDR_TYPE_V4);
 *   altcp_connect(pcb, &ip, port, connected_cb);
 *
 * Usage (WSS — WS over TLS):
 *   struct altcp_tls_ce_config *tls = altcp_tls_ce_create_config_client_ecdhe(host);
 *   altcp_ws_config_t          *cfg = altcp_ws_create_config(host, "/", NULL);
 *   struct altcp_pcb           *pcb = altcp_ws_new_tls(cfg, tls, IPADDR_TYPE_V4);
 *   altcp_connect(pcb, &ip, port, connected_cb);
 *
 * Or use the lwip_socket layer with LWIP_SOCKET_ALTCP_WS / LWIP_SOCKET_ALTCP_WSS.
 */

struct altcp_tls_ce_config;

/** Configuration for a WebSocket connection. Strings are borrowed — caller
 *  must keep them alive for the lifetime of the connection. */
typedef struct altcp_ws_config
{
    const char *host;        /**< HTTP Host header value (e.g. "example.com")  */
    const char *path;        /**< HTTP request path (e.g. "/ws")               */
    const char *subprotocol; /**< Sec-WebSocket-Protocol value; NULL to omit   */
} altcp_ws_config_t;

/** Create a config. Strings are borrowed; no copies are made. */
altcp_ws_config_t *altcp_ws_create_config(const char *host,
                                           const char *path,
                                           const char *subprotocol);

/** Free a config created by altcp_ws_create_config. */
void altcp_ws_free_config(altcp_ws_config_t *conf);

/** Wrap an existing inner_pcb (plain TCP or TLS-wrapped altcp_pcb) with a
 *  WebSocket framing layer. On success, inner_pcb is owned by the returned
 *  pcb. On failure, inner_pcb is left untouched (caller must free it). */
struct altcp_pcb *altcp_ws_wrap(altcp_ws_config_t *conf,
                                struct altcp_pcb  *inner_pcb);

/** Allocate a plain TCP inner pcb and wrap it with the WS layer (WS scheme). */
struct altcp_pcb *altcp_ws_new(altcp_ws_config_t *conf, u8_t ip_type);

/** Allocate a TLS inner pcb using tls_conf and wrap it with the WS layer
 *  (WSS scheme). Takes ownership of tls_conf on success. */
struct altcp_pcb *altcp_ws_new_tls(altcp_ws_config_t          *conf,
                                   struct altcp_tls_ce_config  *tls_conf,
                                   u8_t                         ip_type);

/** altcp_allocator_t-compatible shim. arg must be an altcp_ws_config_t *. */
struct altcp_pcb *altcp_ws_alloc(void *arg, u8_t ip_type);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP */
#endif /* ALTCP_WS_H */
