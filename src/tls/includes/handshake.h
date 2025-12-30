/**
 * @file handshake.h
 * @brief TLS 1.3 Handshake Protocol - PSK Mode
 *
 * Implements TLS 1.3 handshake with Pre-Shared Key (PSK) authentication.
 * This avoids expensive ECDHE operations while maintaining security.
 */

#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.3 Constants */
#define TLS_VERSION_1_3         0x0304
#define TLS_LEGACY_VERSION      0x0303  /* TLS 1.2 for compatibility */

/* Cipher Suites */
#define TLS_AES_128_GCM_SHA256  0x1301

/* Extension Types */
#define TLS_EXT_SUPPORTED_VERSIONS      0x002b
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES  0x002d
#define TLS_EXT_PRE_SHARED_KEY          0x0029

/* PSK Key Exchange Modes */
#define TLS_PSK_MODE_KE         0x00  /* PSK-only */
#define TLS_PSK_MODE_DHE_KE     0x01  /* PSK with ECDHE */

/* Handshake Message Types */
#define TLS_HANDSHAKE_CLIENT_HELLO      0x01
#define TLS_HANDSHAKE_SERVER_HELLO      0x02
#define TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS 0x08
#define TLS_HANDSHAKE_FINISHED          0x14

/* Content Types */
#define TLS_CONTENT_TYPE_HANDSHAKE      0x16
#define TLS_CONTENT_TYPE_APPLICATION_DATA 0x17
#define TLS_CONTENT_TYPE_ALERT          0x15

/* Alert Levels */
#define TLS_ALERT_LEVEL_WARNING         0x01
#define TLS_ALERT_LEVEL_FATAL           0x02

/* Alert Descriptions */
#define TLS_ALERT_CLOSE_NOTIFY          0x00
#define TLS_ALERT_UNEXPECTED_MESSAGE    0x0A
#define TLS_ALERT_BAD_RECORD_MAC        0x14
#define TLS_ALERT_DECRYPT_ERROR         0x33
#define TLS_ALERT_PROTOCOL_VERSION      0x46
#define TLS_ALERT_INTERNAL_ERROR        0x50

/**
 * @brief TLS 1.3 PSK Identity
 */
struct tls_psk_identity {
    uint8_t identity[32];          /* PSK identity (e.g., session ticket) */
    size_t identity_len;           /* Length of identity */
    uint32_t obfuscated_ticket_age;  /* Obfuscated age for resumption */
};

/**
 * @brief TLS 1.3 Traffic Keys
 */
struct tls_traffic_keys {
    /* Key schedule secrets */
    uint8_t handshake_secret[32];

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
struct tls_handshake_context {
    /* PSK Configuration */
    uint8_t psk[32];                    /* Pre-shared key */
    struct tls_psk_identity psk_identity;

    /* Handshake State */
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint16_t cipher_suite;              /* TLS_AES_128_GCM_SHA256 */

    /* Transcript Hash (running hash of all handshake messages) */
    struct tls_hash_context transcript_hash_storage;  /* Embedded storage */
    struct tls_hash_context *transcript_hash;  /* Pointer to storage or NULL */

    /* Derived Keys */
    struct tls_traffic_keys keys;

    /* Sequence Numbers (for record layer) */
    uint64_t client_seq_num;
    uint64_t server_seq_num;

    /* Connection State */
    enum {
        TLS_STATE_INIT,
        TLS_STATE_CLIENT_HELLO_SENT,
        TLS_STATE_SERVER_HELLO_RECEIVED,
        TLS_STATE_HANDSHAKE_COMPLETE,
        TLS_STATE_ERROR
    } state;
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
    const struct tls_psk_identity *psk_identity
);

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
bool tls_generate_client_hello(
    struct tls_handshake_context *ctx,
    uint8_t *out,
    size_t out_len,
    size_t *written
);

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
bool tls_process_server_hello(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len
);

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
bool tls_generate_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    uint8_t *out,
    size_t out_len,
    size_t *written
);

/**
 * @brief Verify Finished message
 *
 * Verifies peer's Finished message by computing expected HMAC
 * and comparing with received value.
 *
 * @param ctx Handshake context
 * @param is_client true if verifying client Finished, false for server
 * @param data Finished message data
 * @param data_len Length of Finished message
 * @return true if valid, false if invalid
 *
 * TODO: Implement Finished message verification
 */
bool tls_verify_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    const uint8_t *data,
    size_t data_len
);

/**
 * @brief Encrypt application data
 *
 * Encrypts plaintext using AES-128-GCM with application traffic keys.
 * Uses TLS 1.3 record layer format with sequence numbers.
 *
 * @param ctx Handshake context
 * @param plaintext Input plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output buffer for ciphertext + tag
 * @param ciphertext_len Size of output buffer (must be >= plaintext_len + 16)
 * @param written Number of bytes written
 * @return true on success, false on failure
 *
 * TODO: Wire in AES-GCM implementation
 */
bool tls_encrypt_data(
    struct tls_handshake_context *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    size_t *written
);

/**
 * @brief Decrypt application data
 *
 * Decrypts ciphertext using AES-128-GCM with application traffic keys.
 * Verifies authentication tag and sequence number.
 *
 * @param ctx Handshake context
 * @param ciphertext Input ciphertext + tag
 * @param ciphertext_len Length of ciphertext (includes 16-byte tag)
 * @param plaintext Output buffer for plaintext
 * @param plaintext_len Size of output buffer
 * @param written Number of bytes written
 * @return true on success, false on failure
 *
 * TODO: Wire in AES-GCM implementation
 */
bool tls_decrypt_data(
    struct tls_handshake_context *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len,
    size_t *written
);

/**
 * @brief Send alert message
 *
 * @param ctx Handshake context
 * @param level Alert level (warning/fatal)
 * @param description Alert description
 * @return true on success, false on failure
 */
bool tls_send_alert(
    struct tls_handshake_context *ctx,
    uint8_t level,
    uint8_t description
);

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
