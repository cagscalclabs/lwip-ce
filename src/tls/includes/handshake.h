/**
 * @file handshake.h
 * @brief TLS 1.3 Handshake Protocol
 * @author Anthony Cagliano
 * @author Claude Code
 * @author OpenAI Codex
 *
 * @note Implements TLS 1.3 handshake with PSK and/or ECDHE (X25519) key exchange.
 * @note Certificate validation uses SPKI pinning against a compiled-in truststore.
 */

/*
 * Known constraints:
 * - Only x25519 key exchange is supported. HelloRetryRequest is detected
 *   and aborted gracefully since no alternative groups are available.
 * - Cross-record handshake message reassembly is bounded at
 *   TLS_HS_REASSEMBLY_MAX bytes (16KB). Anything larger is fatal.
 * - The ALTCP CE transport keeps encrypted input as pbufs and passes complete
 *   records into this layer. Very large cross-record handshake messages are
 *   bounded by TLS_HS_REASSEMBLY_MAX.
 */

#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hash.h"
#include "lwip/logging.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* TLS 1.3 Constants */
#define TLS_VERSION_1_3 0x0304
#define TLS_LEGACY_VERSION 0x0303 /* TLS 1.2 for compatibility */
#define TLS_PSK_IDENTITY_MAX_LEN 256

/* Cipher Suites */
#define TLS_AES_128_GCM_SHA256 0x1301

/* Extension Types */
#define TLS_EXT_SUPPORTED_GROUPS 0x000a
#define TLS_EXT_KEY_SHARE 0x0033
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES 0x002d
#define TLS_EXT_PRE_SHARED_KEY 0x0029

/* Named Groups */
#define TLS_NAMED_GROUP_X25519 0x001d

/* PSK Key Exchange Modes */
#define TLS_PSK_MODE_KE 0x00     /* PSK-only */
#define TLS_PSK_MODE_DHE_KE 0x01 /* PSK with ECDHE */

/* Handshake Message Types */
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_HANDSHAKE_SERVER_HELLO 0x02
#define TLS_HANDSHAKE_CERTIFICATE 0x0b
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 0x0d
#define TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS 0x08
#define TLS_HANDSHAKE_FINISHED 0x14
#define TLS_HANDSHAKE_KEY_UPDATE 0x18
    /* Server-side handshake message types across TLS versions */
    enum tls_server_handshake_type
    {
        TLS_SERVER_HANDSHAKE_HELLO_REQUEST = 0x00, /* TLS 1.2 and earlier */
        TLS_SERVER_HANDSHAKE_SERVER_HELLO = 0x02,
        TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET = 0x04,
        TLS_SERVER_HANDSHAKE_ENCRYPTED_EXTENSIONS = 0x08,
        TLS_SERVER_HANDSHAKE_CERTIFICATE = 0x0b,
        TLS_SERVER_HANDSHAKE_SERVER_KEY_EXCHANGE = 0x0c, /* TLS 1.2 and earlier */
        TLS_SERVER_HANDSHAKE_CERTIFICATE_REQUEST = 0x0d,
        TLS_SERVER_HANDSHAKE_SERVER_HELLO_DONE = 0x0e, /* TLS 1.2 and earlier */
        TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY = 0x0f,
        TLS_SERVER_HANDSHAKE_FINISHED = 0x14,
        TLS_SERVER_HANDSHAKE_KEY_UPDATE = 0x18,
        TLS_SERVER_HANDSHAKE_MESSAGE_HASH = 0xfe /* TLS 1.3 HRR transcript */
    };

/* Content Types */
#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 0x14
#define TLS_CONTENT_TYPE_ALERT 0x15
#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_CONTENT_TYPE_APPLICATION_DATA 0x17

/* Alert Levels */
#define TLS_ALERT_LEVEL_WARNING 0x01
#define TLS_ALERT_LEVEL_FATAL 0x02

/* Alert Descriptions */
#define TLS_ALERT_CLOSE_NOTIFY 0x00
#define TLS_ALERT_UNEXPECTED_MESSAGE 0x0A
#define TLS_ALERT_BAD_RECORD_MAC 0x14
#define TLS_ALERT_RECORD_OVERFLOW 0x16
#define TLS_ALERT_HANDSHAKE_FAILURE 0x28
#define TLS_ALERT_DECODE_ERROR 0x32
#define TLS_ALERT_DECRYPT_ERROR 0x33
#define TLS_ALERT_PROTOCOL_VERSION 0x46
#define TLS_ALERT_INTERNAL_ERROR 0x50

/* Bound on cross-record handshake message reassembly. Any handshake message
 * larger than this is treated as fatal (record_overflow). 16KB matches the
 * TLS 1.3 max plaintext record size and accommodates realistic cert chains. */
#define TLS_HS_REASSEMBLY_MAX 16384

    /**
     * @brief Transport write callback used by tls_send_alert / close_notify.
     *
     * altcp_tls_ce sets this on the context during setup so handshake.c can
     * push encrypted records out without depending on lwIP/altcp directly.
     * Implementations should hand the bytes to the transport and return true
     * iff the write was accepted.
     */
    typedef bool (*tls_transport_write_fn)(void *transport_arg,
                                           const uint8_t *data, size_t len);

    /**
     * @brief TLS 1.3 PSK Identity
     */
    struct tls_psk_identity
    {
        uint8_t identity[TLS_PSK_IDENTITY_MAX_LEN]; /* PSK identity (e.g., session ticket) */
        size_t identity_len;                        /* Length of identity */
        uint32_t obfuscated_ticket_age;             /* Obfuscated age for resumption */
    };

    enum tls_psk_type
    {
        TLS_PSK_TYPE_RESUMPTION = 0, /* NewSessionTicket/resumption PSK: "res binder" */
        TLS_PSK_TYPE_EXTERNAL = 1    /* Caller-provisioned external PSK: "ext binder" */
    };

    /**
     * @brief TLS 1.3 Traffic Keys
     */
    struct tls_traffic_keys
    {
        /* Key schedule secrets */
        uint8_t handshake_secret[32];
        uint8_t master_secret[32];
        uint8_t resumption_master_secret[32];

        /* Traffic secrets */
        uint8_t client_handshake_traffic_secret[32];
        uint8_t server_handshake_traffic_secret[32];
        uint8_t client_application_traffic_secret[32];
        uint8_t server_application_traffic_secret[32];

        /* Derived keys for AES-GCM */
        uint8_t client_handshake_key[16];
        uint8_t client_handshake_iv[12];
        uint8_t server_handshake_key[16];
        uint8_t server_handshake_iv[12];
        uint8_t client_application_key[16];
        uint8_t client_application_iv[12];
        uint8_t server_application_key[16];
        uint8_t server_application_iv[12];
    };

    /**
     * @brief TLS 1.3 Handshake Context
     */
    struct tls_handshake_context
    {
        /* PSK Configuration */
        uint8_t psk[32]; /* Pre-shared key */
        struct tls_psk_identity psk_identity;
        bool psk_mode;              /* true = PSK/PSK+ECDHE, false = pure ECDHE */
        enum tls_psk_type psk_type; /* Binder label selector for offered PSK */

        /* Handshake State */
        uint8_t client_random[32];
        uint8_t server_random[32];
        uint16_t cipher_suite; /* TLS_AES_128_GCM_SHA256 */

        /* Transcript Hash (running hash of all handshake messages) */
        struct tls_hash_context transcript_hash_storage; /* Embedded storage */
        struct tls_hash_context *transcript_hash;        /* Pointer to storage or NULL */

        /* Derived Keys */
        struct tls_traffic_keys keys;

        /* Sequence Numbers (for record layer) */
        uint64_t client_seq_num;
        uint64_t server_seq_num;
        uint64_t client_hs_seq_num; /* Handshake traffic sequence numbers */
        uint64_t server_hs_seq_num;

        /* Connection State */
        enum
        {
            TLS_STATE_INIT,
            TLS_STATE_CLIENT_HELLO_SENT,
            TLS_STATE_SERVER_HELLO_RECEIVED,
            TLS_STATE_HANDSHAKE_KEYS_DERIVED,
            TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED,
            TLS_STATE_CERTIFICATE_RECEIVED,
            TLS_STATE_CERTIFICATE_VERIFY_RECEIVED,
            TLS_STATE_SERVER_FINISHED_RECEIVED,
            TLS_STATE_HANDSHAKE_COMPLETE,
            TLS_STATE_ERROR
        } state;

        /* ECDHE (X25519) key exchange state */
        uint8_t ecdhe_private[32];   /* Ephemeral X25519 private key */
        uint8_t ecdhe_shared[32];    /* Computed shared secret */
        uint8_t ecdhe_public[32];    /* Our ephemeral public key */
        bool ecdhe_negotiated;       /* True if server selected PSK+ECDHE */
        bool client_certificate_requested; /* True if server sent TLS 1.3 CertificateRequest */
        uint32_t ticket_age_add;     /* NST ticket_age_add */
        uint32_t ticket_received_ms; /* sys_now() when last ticket was accepted */
        uint32_t ticket_lifetime;    /* NST ticket_lifetime, seconds (RFC 8446 4.6.1) */

        /* SNI hostname for server_name extension */
        const char *hostname;

        /* Transport plumbing for outbound records (alerts, close_notify). Set by
         * the altcp layer before the handshake begins. NULL means tls_send_alert
         * just updates local state without emitting on the wire. */
        tls_transport_write_fn transport_write;
        void *transport_arg;

        /* Cross-record handshake message reassembly buffer. Allocated on demand
         * from the custom heap when an inner handshake message exceeds the
         * current decrypted record; freed once the message is consumed.
         * Certificate messages bypass this buffer: body bytes stream through
         * cert_walker (declared below) so only one cert at a time is held
         * flat, regardless of chain depth. hs_reasm_buf still holds the
         * 4-byte handshake header for the in-flight Certificate so the
         * dispatch path can read msg_type uniformly. */
        uint8_t *hs_reasm_buf;
        size_t hs_reasm_cap;
        size_t hs_reasm_len;
        size_t hs_reasm_expected; /* Total bytes expected (4 + body), 0 = idle */
        size_t hs_reasm_body_fed; /* Body bytes routed through cert_walker so far */

        /* Lazy-allocated walker for in-flight Certificate message body.
         * NULL when no Certificate is being received. Struct definition is
         * private to handshake.c. */
        struct tls_cert_walker *cert_walker;

        /* True once close_notify has been sent so we don't send it twice. */
        bool close_notify_sent;

        /* True once a close_notify alert has been received from the peer
         * (RFC 8446 6.1). The altcp layer checks this to delivery an EOF to
         * the application the same way it would for a TCP FIN, instead of
         * silently discarding the alert and leaving the application hanging
         * on a read that never completes. */
        bool peer_close_notify_received;

        /* Leaf cert SPKI (SubjectPublicKeyInfo) captured during
         * Certificate-receive. Used by tls_recv_certificate_verify to
         * RSA-verify the CertificateVerify signature against the leaf's
         * public key, which is the live proof-of-possession that pins
         * the server to its leaf private key. Heap-allocated on first
         * cert, freed in tls_handshake_cleanup. NULL if the chain was
         * empty or the leaf had no extractable SPKI. */
        uint8_t *leaf_spki;
        size_t leaf_spki_len;
    };

    /**
     * @brief Initialize a TLS 1.3 PSK handshake context
     *
     * @param ctx Handshake context to initialize
     * @param psk Pre-shared key (32 bytes)
     * @param psk_identity PSK identity
     * @return true on success, false on failure
     */
    bool tls_handshake_init(
        struct tls_handshake_context *ctx,
        const uint8_t psk[32],
        const struct tls_psk_identity *psk_identity);

    /**
     * @brief Generate ClientHello message
     *
     * Creates a TLS 1.3 ClientHello with PSK extension for resumption or
     * PSK-only mode. The message includes:
     * - Random nonce
     * - Cipher suite (TLS_AES_128_GCM_SHA256)
     * - Extensions (supported_versions, psk_key_exchange_modes, pre_shared_key)
     * - PSK binder (HMAC of transcript)
     *
     * @param ctx Handshake context
     * @param out Output buffer for ClientHello
     * @param out_len Size of output buffer
     * @param written Number of bytes written
     * @return true on success, false on failure
     *
     * TODO: Implement ClientHello generation
     */
    bool tls_send_client_hello(
        struct tls_handshake_context *ctx,
        uint8_t *out,
        size_t out_len,
        size_t *written);

    /**
     * @brief Process ServerHello message
     *
     * Parses and validates ServerHello from server:
     * - Extracts server random
     * - Verifies cipher suite selection
     * - Processes extensions (supported_versions, pre_shared_key)
     * - Updates transcript hash
     *
     * @param ctx Handshake context
     * @param data ServerHello message data
     * @param data_len Length of ServerHello
     * @return true on success, false on failure
     *
     * TODO: Implement ServerHello parsing
     */
    bool tls_recv_server_hello(
        struct tls_handshake_context *ctx,
        const uint8_t *data,
        size_t data_len);

    /**
     * @brief Derive handshake keys from PSK
     *
     * Performs TLS 1.3 key schedule for PSK-only mode:
     * 1. Early Secret = HKDF-Extract(0, PSK)
     * 2. Handshake Secret = HKDF-Extract(Early Secret, 0)
     * 3. Derive handshake traffic secrets
     * 4. Derive handshake keys and IVs
     *
     * @param ctx Handshake context
     * @return true on success, false on failure
     *
     * TODO: Wire in HKDF implementation
     */
    bool tls_derive_handshake_keys(struct tls_handshake_context *ctx);

    /**
     * @brief Derive application keys
     *
     * Derives application traffic keys from master secret:
     * 1. Master Secret = HKDF-Extract(Handshake Secret, 0)
     * 2. Derive application traffic secrets
     * 3. Derive application keys and IVs
     *
     * @param ctx Handshake context
     * @return true on success, false on failure
     *
     * TODO: Wire in HKDF implementation
     */
    bool tls_derive_application_keys(struct tls_handshake_context *ctx);

    /**
     * @brief Generate Finished message
     *
     * Creates Finished message with HMAC verification:
     * finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
     * verify_data = HMAC(finished_key, transcript_hash)
     *
     * @param ctx Handshake context
     * @param is_client true for client Finished, false for server Finished
     * @param out Output buffer for Finished message
     * @param out_len Size of output buffer
     * @param written Number of bytes written
     * @return true on success, false on failure
     *
     * TODO: Implement Finished message generation
     */
    bool tls_send_finished(
        struct tls_handshake_context *ctx,
        bool is_client,
        uint8_t *out,
        size_t out_len,
        size_t *written);

    /**
     * @brief Generate an empty TLS 1.3 client Certificate message.
     *
     * Used when a server sent CertificateRequest but the client has no
     * configured client identity. TLS 1.3 clients reply with an empty
     * Certificate message, then send Finished.
     *
     * @param ctx Handshake context
     * @param out Output buffer for Certificate message
     * @param out_len Size of output buffer
     * @param written Number of bytes written
     * @return true on success, false on failure
     */
    bool tls_send_empty_certificate(
        struct tls_handshake_context *ctx,
        uint8_t *out,
        size_t out_len,
        size_t *written);

    /**
     * @brief Process decrypted inner plaintext from a pbuf chain.
     *
     * Post-AEAD dispatch entry called by the altcp layer's streaming record
     * decrypter. Walks the decrypted pbuf chain segment-by-segment and feeds
     * each segment into the cross-record handshake-message reassembler.
     *
     * @param ctx Handshake context
     * @param inner_content_type Decrypted TLSInnerPlaintext content type
     * @param plaintext Decrypted-plaintext pbuf chain
     * @param plaintext_len Total bytes of plaintext to walk (<= chain length)
     * @return true on success, false on fatal protocol/parse failure
     */
    struct pbuf;
    bool tls_process_inner_plaintext_pbuf(
        struct tls_handshake_context *ctx,
        uint8_t inner_content_type,
        const struct pbuf *plaintext,
        size_t plaintext_len);

    /**
     * @brief Register a transport write callback for outbound records.
     *
     * Used by the altcp_tls_ce layer to give the handshake code a way to send
     * alerts/close_notify without including lwIP. Must be called after
     * tls_handshake_init and before any operation that might emit a record.
     */
    void tls_set_transport(
        struct tls_handshake_context *ctx,
        tls_transport_write_fn write_fn,
        void *transport_arg);

    /**
     * @brief Send a close_notify alert (warning level) and remember that we did.
     *
     * Idempotent: subsequent calls are no-ops. Intended to be called from the
     * altcp close path before the TCP FIN.
     *
     * @return true if close_notify was sent (or already sent), false on failure.
     */
    bool tls_send_close_notify(struct tls_handshake_context *ctx);

    /**
     * @brief Clean up handshake context
     *
     * Securely zeroes sensitive data.
     *
     * @param ctx Handshake context to clean
     */
    void tls_handshake_cleanup(struct tls_handshake_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* TLS_HANDSHAKE_H */
