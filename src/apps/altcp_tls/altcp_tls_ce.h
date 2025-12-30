/**
 * @file altcp_tls_ce.h
 * @brief ALTCP TLS Layer for TI-84+ CE
 *
 * TLS 1.3 integration for lwIP's altcp layer using custom CE-optimized
 * cryptographic primitives (AES-GCM, SHA-256, X25519, RSA).
 */

#ifndef LWIP_ALTCP_TLS_CE_H
#define LWIP_ALTCP_TLS_CE_H

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/altcp.h"
#include "../../tls/includes/handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TLS connection state for CE implementation
 */
typedef struct altcp_tls_ce_state {
    void *conf;                              /* Configuration handle */
    struct tls_handshake_context tls_ctx;    /* TLS 1.3 handshake context */
    struct pbuf *rx;                         /* Encrypted RX data from TCP */
    struct pbuf *rx_app;                     /* Decrypted application data */
    int rx_passed_unrecved;                  /* Data passed to app but not recved */
    int bio_bytes_read;                      /* Bytes read from TCP */
    int bio_bytes_appl;                      /* Application data bytes */
    int overhead_bytes_adjust;               /* TLS overhead tracking */
    u8_t flags;                              /* State flags */
} altcp_tls_ce_state_t;

/* State flags */
#define ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE    0x01
#define ALTCP_TLS_CE_FLAGS_UPPER_CALLED      0x02
#define ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED   0x04
#define ALTCP_TLS_CE_FLAGS_RX_CLOSED         0x08

/**
 * @brief TLS configuration for CE implementation
 */
struct altcp_tls_ce_config {
    u8_t is_server;                          /* Server mode flag */

    /* PSK configuration */
    u8_t psk[32];                            /* Pre-shared key */
    struct tls_psk_identity psk_identity;    /* PSK identity */

    /* Certificate/key for RSA mode (future) */
    const u8_t *cert;
    size_t cert_len;
    const u8_t *privkey;
    size_t privkey_len;
};

/**
 * @brief Create TLS configuration for PSK client
 *
 * @param psk Pre-shared key (32 bytes)
 * @param psk_identity PSK identity structure
 * @return Configuration handle or NULL on failure
 */
struct altcp_tls_ce_config *altcp_tls_ce_create_config_psk_client(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity
);

/**
 * @brief Create TLS configuration for PSK server
 *
 * @param psk Pre-shared key (32 bytes)
 * @param psk_identity PSK identity structure
 * @return Configuration handle or NULL on failure
 */
struct altcp_tls_ce_config *altcp_tls_ce_create_config_psk_server(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity
);

/**
 * @brief Free TLS configuration
 *
 * @param conf Configuration to free
 */
void altcp_tls_ce_free_config(struct altcp_tls_ce_config *conf);

/**
 * @brief Wrap existing altcp_pcb with TLS layer
 *
 * @param config TLS configuration
 * @param inner_pcb Inner connection (e.g., TCP)
 * @return New TLS-wrapped pcb or NULL on failure
 */
struct altcp_pcb *altcp_tls_ce_wrap(
    struct altcp_tls_ce_config *config,
    struct altcp_pcb *inner_pcb
);

/**
 * @brief Create new TLS connection with inner TCP
 *
 * @param config TLS configuration
 * @param ip_type IP version (IPADDR_TYPE_V4/V6)
 * @return New TLS pcb or NULL on failure
 */
struct altcp_pcb *altcp_tls_ce_new(
    struct altcp_tls_ce_config *config,
    u8_t ip_type
);

/**
 * @brief Allocator function for use with altcp_new
 *
 * @param arg Must contain struct altcp_tls_ce_config *
 * @param ip_type IP version
 * @return New TLS pcb or NULL on failure
 */
struct altcp_pcb *altcp_tls_ce_alloc(void *arg, u8_t ip_type);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_ALTCP */
#endif /* LWIP_ALTCP_TLS_CE_H */
