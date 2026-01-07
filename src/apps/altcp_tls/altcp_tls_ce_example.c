/**
 * @file altcp_tls_ce_example.c
 * @brief Example usage of TLS 1.3 with lwIP's altcp layer
 *
 * This file demonstrates how to create TLS client and server connections
 * using the CE-optimized TLS 1.3 implementation.
 */

#include "lwip/opt.h"

#if LWIP_ALTCP

#include "lwip/altcp.h"
#include "altcp_tls_ce.h"
#include "lwip/ip_addr.h"
#include <string.h>

/* ========== Example 1: TLS Client with PSK ========== */

static err_t tls_client_recv(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err);
static err_t tls_client_connected(void *arg, struct altcp_pcb *conn, err_t err);

/**
 * @brief Create a TLS client connection using PSK
 *
 * This example shows how to:
 * 1. Configure PSK and identity
 * 2. Create TLS configuration
 * 3. Create TLS connection
 * 4. Connect to remote server
 */
void example_tls_client_connect(void)
{
    struct altcp_tls_ce_config *tls_config;
    struct altcp_pcb *tls_conn;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];
    ip4_addr_t server_ipv4;
    ip_addr_t server_ip;
    err_t err;

    /* Set up PSK (in real application, load from secure storage) */
    memset(psk, 0xAA, 32); /* Example key */
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0x01; /* Example identity */
    psk_identity.identity_len = 1;

    /* Create TLS configuration for PSK client */
    tls_config = altcp_tls_ce_create_config_psk_client(psk, &psk_identity);
    if (tls_config == NULL) {
        /* Failed to create configuration */
        return;
    }

    /* Create TLS connection (IPv4) */
    tls_conn = altcp_tls_ce_new(tls_config, IPADDR_TYPE_V4);
    if (tls_conn == NULL) {
        altcp_tls_ce_free_config(tls_config);
        return;
    }

    /* Set up callbacks */
    altcp_recv(tls_conn, tls_client_recv);
    altcp_arg(tls_conn, NULL); /* Application context */

    /* Connect to server */
    IP4_ADDR(&server_ipv4, 192, 168, 1, 100); /* Example server IP */
    ip_addr_copy_from_ip4(server_ip, server_ipv4);
    err = altcp_connect(tls_conn, &server_ip, 443, tls_client_connected);

    if (err != ERR_OK) {
        altcp_close(tls_conn);
        altcp_tls_ce_free_config(tls_config);
    }
}

static err_t tls_client_connected(void *arg, struct altcp_pcb *conn, err_t err)
{
    LWIP_UNUSED_ARG(arg);

    if (err != ERR_OK) {
        /* Connection failed */
        return ERR_ABRT;
    }

    /* TLS handshake completed successfully */
    /* Send application data */
    const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    altcp_write(conn, request, strlen(request), TCP_WRITE_FLAG_COPY);
    altcp_output(conn);

    return ERR_OK;
}

static err_t tls_client_recv(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    if (p == NULL) {
        /* Connection closed */
        altcp_close(conn);
        return ERR_OK;
    }

    /* Process received data (already decrypted) */
    /* ... application logic ... */

    /* Acknowledge received data */
    altcp_recved(conn, p->tot_len);

    /* Free the pbuf */
    pbuf_free(p);

    return ERR_OK;
}

/* ========== Example 2: TLS Server with PSK ========== */

static err_t tls_server_accept(void *arg, struct altcp_pcb *newconn, err_t err);
static err_t tls_server_recv(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err);

/**
 * @brief Create a TLS server listening on port 443
 *
 * This example shows how to:
 * 1. Configure server PSK
 * 2. Create listening TLS server
 * 3. Accept incoming connections
 */
void example_tls_server_listen(void)
{
    struct altcp_tls_ce_config *tls_config;
    struct altcp_pcb *listen_pcb;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];
    err_t err;

    /* Set up server PSK */
    memset(psk, 0xBB, 32); /* Example key */
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0x02; /* Example identity */
    psk_identity.identity_len = 1;

    /* Create TLS configuration for PSK server */
    tls_config = altcp_tls_ce_create_config_psk_server(psk, &psk_identity);
    if (tls_config == NULL) {
        return;
    }

    /* Create TLS listening pcb (IPv4) */
    listen_pcb = altcp_tls_ce_new(tls_config, IPADDR_TYPE_V4);
    if (listen_pcb == NULL) {
        altcp_tls_ce_free_config(tls_config);
        return;
    }

    /* Bind to port 443 (HTTPS) */
    err = altcp_bind(listen_pcb, IP_ADDR_ANY, 443);
    if (err != ERR_OK) {
        altcp_close(listen_pcb);
        altcp_tls_ce_free_config(tls_config);
        return;
    }

    /* Start listening */
    listen_pcb = altcp_listen(listen_pcb);
    if (listen_pcb == NULL) {
        altcp_tls_ce_free_config(tls_config);
        return;
    }

    /* Set accept callback */
    altcp_accept(listen_pcb, tls_server_accept);
}

static err_t tls_server_accept(void *arg, struct altcp_pcb *newconn, err_t err)
{
    LWIP_UNUSED_ARG(arg);

    if (err != ERR_OK || newconn == NULL) {
        return ERR_VAL;
    }

    /* Set up callbacks for new connection */
    altcp_recv(newconn, tls_server_recv);
    altcp_arg(newconn, NULL); /* Application context */

    /* TLS handshake will complete automatically */
    return ERR_OK;
}

static err_t tls_server_recv(void *arg, struct altcp_pcb *conn, struct pbuf *p, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    if (p == NULL) {
        /* Connection closed */
        altcp_close(conn);
        return ERR_OK;
    }

    /* Process received data (already decrypted) */
    /* ... application logic ... */

    /* Send encrypted response */
    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    altcp_write(conn, response, strlen(response), TCP_WRITE_FLAG_COPY);
    altcp_output(conn);

    /* Acknowledge received data */
    altcp_recved(conn, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

/* ========== Example 3: Using with HTTP Client ========== */

#if LWIP_ALTCP_TLS

/**
 * @brief Use TLS with lwIP's HTTP client
 *
 * This example shows how to integrate with existing lwIP applications
 * that use altcp (like http_client, mqtt, etc.)
 */
void example_https_request(void)
{
    struct altcp_tls_ce_config *tls_config;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];

    /* Configure PSK */
    memset(psk, 0xCC, 32);
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0x03;
    psk_identity.identity_len = 1;

    tls_config = altcp_tls_ce_create_config_psk_client(psk, &psk_identity);
    if (tls_config == NULL) {
        return;
    }

    /* Use with http_client or other altcp-based applications */
    /* Example (pseudo-code):
     *   httpc_connection_t settings;
     *   settings.use_tls = 1;
     *   settings.altcp_allocator = altcp_tls_ce_alloc;
     *   settings.altcp_allocator_arg = tls_config;
     *   httpc_get_file(&server_addr, 443, "/api/data", &settings, ...);
     */
}

#endif /* LWIP_ALTCP_TLS */

/* ========== Example 4: Session Resumption (Future) ========== */

/**
 * @brief Example of session resumption with PSK tickets
 *
 * When X25519 is implemented, this will show:
 * 1. Saving session after first connection
 * 2. Resuming session on reconnect
 * 3. Benefits: faster handshake, reduced computation
 *
 * Note: This is a placeholder for future functionality
 */
void example_session_resumption(void)
{
    /* @todo: Implement after X25519 KEX is available */
    /* Will use PSK with DHE for forward secrecy */
    /* Session tickets will allow fast reconnection */
}

#endif /* LWIP_ALTCP */
