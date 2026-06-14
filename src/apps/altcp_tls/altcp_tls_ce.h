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
#include "../../drivers/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cap on the per-record plaintext scratch buffer the TLS layer allocates
 * during handshake-message decryption. RFC 8446 §5.1 caps TLS 1.3
 * plaintext records at 16384 bytes; the inner parser receives at most
 * that many bytes (plus the inner content-type byte, see the +1 sites). */
#ifndef ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT
#define ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT 16384
#endif

/**
 * @brief TLS connection state for CE implementation
 */
typedef struct altcp_tls_ce_state {
    void *conf;                              /* Configuration handle */
    struct tls_handshake_context tls_ctx;    /* TLS 1.3 handshake context */
    struct altcp_pcb *conn;                  /* Owning altcp pcb */
    struct pbuf *rx;                         /* Encrypted RX data from TCP */
    size_t rx_acked_len;                     /* Bytes at the front of rx already
                                              * acked to the lower TCP (so the
                                              * consume path never re-acks them) */
    struct pbuf *rx_app;                     /* Decrypted application data */
    int rx_passed_unrecved;                  /* Data passed to app but not recved */
    int overhead_bytes_adjust;               /* TLS overhead tracking */
    size_t rx_throttle_pending;              /* Pending bytes to recved */
    struct altcp_tls_ce_state *next;         /* Linked list of states */
    u8_t flags;                              /* State flags */
    /* Pending ClientHello record awaiting a free lower send buffer. Generated
     * once (transcript hash is updated at generation, so it must NOT be
     * regenerated on retry); the write is retried on each recv/poll tick until
     * the lower TCP accepts it, then this buffer is freed. NULL when none
     * pending. See altcp_tls_ce_send_client_hello. */
    uint8_t *pending_chello;
    uint16_t pending_chello_len;
} altcp_tls_ce_state_t;

/* State flags */
#define ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE    0x01
#define ALTCP_TLS_CE_FLAGS_UPPER_CALLED      0x02
#define ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED   0x04
#define ALTCP_TLS_CE_FLAGS_RX_CLOSED         0x08
/* close_notify has been emitted to the peer. Set the moment we hand it
 * off; a retried close() (because the TCP-level close came back ERR_MEM)
 * skips re-sending the alert. The peer has already seen it. */
#define ALTCP_TLS_CE_FLAGS_CLOSE_NOTIFY_SENT 0x10

/**
 * @brief TLS configuration for CE implementation
 */
struct altcp_tls_ce_config {
    u8_t is_server;                          /* Server mode flag */
    u8_t psk_mode;                           /* 1 = PSK/PSK+ECDHE, 0 = pure ECDHE */

    /* PSK configuration (only used when psk_mode == 1) */
    u8_t psk[32];                            /* Pre-shared key */
    struct tls_psk_identity psk_identity;    /* PSK identity */
    enum tls_psk_type psk_type;              /* Resumption vs external PSK */

    /* SNI hostname (pointer to caller-owned string, must outlive config) */
    const char *hostname;

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
 * @brief Create TLS configuration for ECDHE-only client (no PSK)
 *
 * Used for connecting to standard HTTPS servers with certificate validation.
 * @param hostname Server hostname for SNI (caller must keep string alive)
 * @return Configuration handle or NULL on failure
 */
struct altcp_tls_ce_config *altcp_tls_ce_create_config_client_ecdhe(
    const char *hostname
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

void altcp_tls_ce_set_rx_throttle(enum mem_pressure_level level);

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
