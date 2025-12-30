/**
 * @file handshake.c
 * @brief TLS 1.3 Handshake Protocol - PSK Mode Implementation
 *
 * This implements the TLS 1.3 handshake flow using Pre-Shared Keys (PSK).
 * TODOs mark functions that need implementation or optimization.
 */

#include "handshake.h"
#include "hash.h"
#include "hmac.h"
#include "aes.h"
#include "random.h"
#include "hkdf.h"
#include <string.h>

/*
 * ============================================================================
 * Transcript Hash Management
 * ============================================================================
 * The transcript hash is a running SHA-256 hash of all handshake messages.
 * It's used in key derivation and Finished message verification.
 */

/**
 * @brief Initialize transcript hash
 */
static bool transcript_hash_init(struct tls_hash_context *ctx) {
    return tls_hash_context_init(ctx, TLS_HASH_SHA256);
}

/**
 * @brief Update transcript hash with message data
 */
static void transcript_hash_update(struct tls_hash_context *ctx,
                                   const uint8_t *data, size_t len) {
    tls_hash_update(ctx, data, len);
}

/**
 * @brief Get current transcript hash value
 */
static void transcript_hash_digest(struct tls_hash_context *ctx,
                                   uint8_t digest[32]) {
    /* Make a copy to get digest without destroying context */
    struct tls_hash_context ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(ctx_copy));
    tls_hash_digest(&ctx_copy, digest);
}

/*
 * ============================================================================
 * Handshake Functions
 * ============================================================================
 */

/**
 * @brief Initialize TLS 1.3 PSK handshake context
 */
bool tls_handshake_init(
    struct tls_handshake_context *ctx,
    const uint8_t psk[32],
    const struct tls_psk_identity *psk_identity
) {
    if (!ctx || !psk || !psk_identity) {
        return false;
    }

    /* Clear context */
    memset(ctx, 0, sizeof(*ctx));

    /* Copy PSK and identity */
    memcpy(ctx->psk, psk, 32);
    memcpy(&ctx->psk_identity, psk_identity, sizeof(*psk_identity));

    /* Set cipher suite */
    ctx->cipher_suite = TLS_AES_128_GCM_SHA256;

    /* Initialize state */
    ctx->state = TLS_STATE_INIT;
    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;

    /* Generate client random */
    for (size_t i = 0; i < 4; i++) {
        uint64_t rand = tls_random();
        memcpy(&ctx->client_random[i * 8], &rand, 8);
    }

    /* TODO: Allocate and initialize transcript_hash
     * Need: struct tls_hash_context allocation
     * Wire in: tls_hash_context_init(ctx->transcript_hash, TLS_HASH_SHA256)
     */

    return true;
}

/**
 * @brief Generate ClientHello message
 *
 * Message structure:
 * - HandshakeType (1 byte): 0x01 (ClientHello)
 * - Length (3 bytes): Total message length
 * - ProtocolVersion (2 bytes): 0x0303 (legacy TLS 1.2)
 * - Random (32 bytes): Client random nonce
 * - SessionID (1 byte length + data): Empty for TLS 1.3
 * - CipherSuites (2 byte length + data): TLS_AES_128_GCM_SHA256
 * - CompressionMethods (1 byte length + data): null compression
 * - Extensions: supported_versions, psk_key_exchange_modes, pre_shared_key
 */
bool tls_generate_client_hello(
    struct tls_handshake_context *ctx,
    uint8_t *out,
    size_t out_len,
    size_t *written
) {
    if (!ctx || !out || !written) {
        return false;
    }

    size_t offset = 0;

    /* TODO: Implement ClientHello generation
     *
     * Structure:
     * 1. Handshake header (type=0x01, length=calculated)
     * 2. Legacy version (0x0303)
     * 3. Client random (32 bytes from ctx->client_random)
     * 4. Session ID (0 length for TLS 1.3)
     * 5. Cipher suites (2 bytes: TLS_AES_128_GCM_SHA256)
     * 6. Compression methods (1 byte: 0x00 for null)
     * 7. Extensions:
     *    a. supported_versions (0x002b): TLS 1.3 (0x0304)
     *    b. psk_key_exchange_modes (0x002d): psk_ke (0x00)
     *    c. pre_shared_key (0x0029): identity + binder
     *
     * PSK Binder Calculation:
     * - Compute transcript hash of ClientHello up to binders
     * - binder_key = HKDF-Expand-Label(early_secret, "res binder", "", 32)
     * - finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
     * - binder = HMAC(finished_key, transcript_hash)
     *
     * Dependencies:
     * - HKDF-Extract, HKDF-Expand-Label (from hkdf.c - NEEDS IMPLEMENTATION)
     * - HMAC (available in hmac.c)
     * - SHA-256 (available in hash.c)
     * - Transcript hash update
     */

    *written = 0;
    /* Placeholder - return error until implemented */
    ctx->state = TLS_STATE_ERROR;
    return false;

    /* After implementation, update state */
    // ctx->state = TLS_STATE_CLIENT_HELLO_SENT;
    // return true;
}

/**
 * @brief Process ServerHello message
 *
 * Expected structure:
 * - HandshakeType (1 byte): 0x02 (ServerHello)
 * - Length (3 bytes)
 * - ProtocolVersion (2 bytes): 0x0303 (legacy)
 * - Random (32 bytes): Server random
 * - SessionID: Echo of client's (or empty)
 * - CipherSuite (2 bytes): Selected suite
 * - CompressionMethod (1 byte): 0x00
 * - Extensions: supported_versions, pre_shared_key
 */
bool tls_process_server_hello(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len
) {
    if (!ctx || !data || ctx->state != TLS_STATE_CLIENT_HELLO_SENT) {
        return false;
    }

    size_t offset = 0;

    /* TODO: Implement ServerHello parsing
     *
     * Steps:
     * 1. Verify handshake type (0x02)
     * 2. Parse length field
     * 3. Verify legacy version (0x0303)
     * 4. Extract server random (32 bytes) -> ctx->server_random
     * 5. Skip session ID
     * 6. Parse cipher suite -> verify matches ctx->cipher_suite
     * 7. Verify compression method (0x00)
     * 8. Parse extensions:
     *    a. supported_versions: verify 0x0304 (TLS 1.3)
     *    b. pre_shared_key: extract selected PSK identity
     * 9. Update transcript hash with ServerHello
     *
     * Dependencies:
     * - Extension parsing (new code needed)
     * - Transcript hash update
     */

    /* Placeholder - return error until implemented */
    ctx->state = TLS_STATE_ERROR;
    return false;

    /* After implementation, update state */
    // ctx->state = TLS_STATE_SERVER_HELLO_RECEIVED;
    // return true;
}

/**
 * @brief Derive handshake keys from PSK
 *
 * TLS 1.3 Key Schedule (PSK-only mode):
 *
 * Early Secret = HKDF-Extract(salt=0, IKM=PSK)
 * Handshake Secret = HKDF-Extract(salt=Derive-Secret(Early Secret, "derived", ""),
 *                                 IKM=0)
 * client_handshake_traffic_secret = Derive-Secret(Handshake Secret,
 *                                                  "c hs traffic",
 *                                                  ClientHello...ServerHello)
 * server_handshake_traffic_secret = Derive-Secret(Handshake Secret,
 *                                                  "s hs traffic",
 *                                                  ClientHello...ServerHello)
 *
 * Then derive keys and IVs from traffic secrets:
 * key = HKDF-Expand-Label(secret, "key", "", 16)
 * iv = HKDF-Expand-Label(secret, "iv", "", 12)
 */
bool tls_derive_handshake_keys(struct tls_handshake_context *ctx) {
    if (!ctx || ctx->state != TLS_STATE_SERVER_HELLO_RECEIVED) {
        return false;
    }

    uint8_t early_secret[32];
    uint8_t handshake_secret[32];
    uint8_t derived_secret[32];
    uint8_t empty_hash[32];
    uint8_t transcript_hash[32];
    uint8_t zero_ikm[32] = {0};
    struct tls_hash_context hash_ctx;

    /* Step 1: Compute early_secret from PSK
     * early_secret = HKDF-Extract(salt=0, IKM=PSK)
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, early_secret)) {
        return false;
    }

    /* Step 2: Compute empty hash for "derived" secret
     * empty_hash = SHA-256("")
     */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256)) {
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 3: Derive "derived" secret from early_secret
     * derived = Derive-Secret(early_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, early_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret)) {
        return false;
    }

    /* Step 4: Compute handshake_secret (PSK-only mode, no ECDHE)
     * handshake_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          zero_ikm, 32, handshake_secret)) {
        return false;
    }

    /* Step 5: Get transcript hash (ClientHello...ServerHello)
     * TODO: Extract from ctx->transcript_hash when implemented
     * For now, use placeholder zeros for testing
     */
    memset(transcript_hash, 0, 32);
    if (ctx->transcript_hash) {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }

    /* Step 6: Derive client handshake traffic secret
     * client_handshake_traffic_secret =
     *     Derive-Secret(handshake_secret, "c hs traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, handshake_secret, 32,
                           "c hs traffic", 12, transcript_hash, 32,
                           ctx->keys.client_handshake_traffic_secret)) {
        return false;
    }

    /* Step 7: Derive server handshake traffic secret
     * server_handshake_traffic_secret =
     *     Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, handshake_secret, 32,
                           "s hs traffic", 12, transcript_hash, 32,
                           ctx->keys.server_handshake_traffic_secret)) {
        return false;
    }

    /* Step 8: Derive client handshake key and IV
     * key = HKDF-Expand-Label(secret, "key", "", 16)
     * iv = HKDF-Expand-Label(secret, "iv", "", 12)
     */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_handshake_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.client_handshake_key, 16)) {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_handshake_iv, 12)) {
        return false;
    }

    /* Step 9: Derive server handshake key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_handshake_key, 16)) {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_handshake_iv, 12)) {
        return false;
    }

    /* Store handshake_secret for later use in application key derivation */
    memcpy(ctx->keys.handshake_secret, handshake_secret, 32);

    return true;
}

/**
 * @brief Derive application keys
 *
 * Continues key schedule to derive application traffic keys:
 * Master Secret = HKDF-Extract(Handshake Secret, 0)
 * client_application_traffic_secret = Derive-Secret(Master Secret,
 *                                                    "c ap traffic",
 *                                                    ClientHello...Finished)
 * server_application_traffic_secret = Derive-Secret(Master Secret,
 *                                                    "s ap traffic",
 *                                                    ClientHello...Finished)
 */
bool tls_derive_application_keys(struct tls_handshake_context *ctx) {
    if (!ctx) {
        return false;
    }

    uint8_t master_secret[32];
    uint8_t derived_secret[32];
    uint8_t empty_hash[32];
    uint8_t transcript_hash[32];
    uint8_t zero_ikm[32] = {0};
    struct tls_hash_context hash_ctx;

    /* Step 1: Compute empty hash for "derived" secret
     * empty_hash = SHA-256("")
     */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256)) {
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 2: Derive "derived" secret from handshake_secret
     * derived = Derive-Secret(handshake_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, ctx->keys.handshake_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret)) {
        return false;
    }

    /* Step 3: Compute master_secret
     * master_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          zero_ikm, 32, master_secret)) {
        return false;
    }

    /* Step 4: Get transcript hash (ClientHello...server Finished)
     * TODO: Extract from ctx->transcript_hash when implemented
     * For now, use placeholder zeros for testing
     */
    memset(transcript_hash, 0, 32);
    if (ctx->transcript_hash) {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }

    /* Step 5: Derive client application traffic secret
     * client_application_traffic_secret =
     *     Derive-Secret(master_secret, "c ap traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, master_secret, 32,
                           "c ap traffic", 12, transcript_hash, 32,
                           ctx->keys.client_application_traffic_secret)) {
        return false;
    }

    /* Step 6: Derive server application traffic secret
     * server_application_traffic_secret =
     *     Derive-Secret(master_secret, "s ap traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, master_secret, 32,
                           "s ap traffic", 12, transcript_hash, 32,
                           ctx->keys.server_application_traffic_secret)) {
        return false;
    }

    /* Step 7: Derive client application key and IV
     * key = HKDF-Expand-Label(secret, "key", "", 16)
     * iv = HKDF-Expand-Label(secret, "iv", "", 12)
     */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_application_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.client_application_key, 16)) {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_application_iv, 12)) {
        return false;
    }

    /* Step 8: Derive server application key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_application_key, 16)) {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_application_iv, 12)) {
        return false;
    }

    return true;
}

/**
 * @brief Generate Finished message
 *
 * Finished = HMAC(finished_key, transcript_hash)
 * where finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
 */
bool tls_generate_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    uint8_t *out,
    size_t out_len,
    size_t *written
) {
    if (!ctx || !out || !written) {
        return false;
    }

    /* TODO: Implement Finished message generation
     *
     * Steps:
     * 1. Select appropriate traffic secret:
     *    secret = is_client ? client_handshake_traffic_secret
     *                       : server_handshake_traffic_secret
     *
     * 2. Derive finished_key:
     *    finished_key = HKDF-Expand-Label(secret, "finished", "", 32)
     *
     * 3. Get transcript hash up to this point
     *
     * 4. Compute verify_data:
     *    verify_data = HMAC-SHA256(finished_key, transcript_hash)
     *
     * 5. Build Finished message:
     *    - Handshake type (1 byte): 0x14
     *    - Length (3 bytes): 32
     *    - verify_data (32 bytes)
     *
     * Wire in: tls_hmac_context_init(), tls_hmac_update(), tls_hmac_digest()
     */

    *written = 0;
    return false;
}

/**
 * @brief Verify Finished message
 */
bool tls_verify_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    const uint8_t *data,
    size_t data_len
) {
    if (!ctx || !data) {
        return false;
    }

    /* TODO: Implement Finished verification
     *
     * Steps:
     * 1. Parse Finished message (extract verify_data)
     * 2. Compute expected verify_data (same as generation)
     * 3. Constant-time compare with received value
     * 4. Update transcript hash with received Finished
     *
     * Security: Use constant-time comparison to prevent timing attacks
     */

    return false;
}

/**
 * @brief Encrypt application data
 *
 * TLS 1.3 record format:
 * - ContentType (1 byte): 0x17 (application_data)
 * - LegacyVersion (2 bytes): 0x0303
 * - Length (2 bytes): ciphertext length
 * - Encrypted data: TLS13PlaintextRecord encrypted with AES-128-GCM
 *
 * AES-GCM nonce construction:
 * nonce = iv XOR sequence_number (padded to 12 bytes)
 */
bool tls_encrypt_data(
    struct tls_handshake_context *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    size_t *written
) {
    if (!ctx || !plaintext || !ciphertext || !written) {
        return false;
    }

    if (ciphertext_len < plaintext_len + 16) {  /* Need space for auth tag */
        return false;
    }

    /* TODO: Wire in AES-GCM encryption
     *
     * Available: src/tls/core/aes.c
     * - struct tls_aes_context
     * - tls_aes_init(ctx, TLS_AES_GCM, key, 16, iv, 12)
     * - tls_aes_encrypt(ctx, plaintext, ciphertext, len)
     * - tls_aes_add_aad(ctx, aad, aad_len)  // For TLS record header
     *
     * Steps:
     * 1. Construct nonce:
     *    - XOR iv with sequence number
     *    - Increment ctx->client_seq_num
     *
     * 2. Build AAD (additional authenticated data):
     *    - TLS record header (5 bytes)
     *
     * 3. Encrypt plaintext:
     *    - Initialize AES-GCM with key and nonce
     *    - Add AAD
     *    - Encrypt plaintext -> ciphertext + tag
     *
     * PERFORMANCE NOTE:
     * - AES-GCM is the critical path for bulk data transfer
     * - Current implementation in aes.c is C-based (~47KB)
     * - OPTIMIZATION TARGET: Assembly implementation of AES-GCM
     * - Consider: AES-NI instructions (if ez80 equivalent exists)
     * -          Table-based lookups for S-box
     * -          Optimized GF(2^128) multiplication for GHASH
     */

    *written = 0;
    return false;
}

/**
 * @brief Decrypt application data
 */
bool tls_decrypt_data(
    struct tls_handshake_context *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len,
    size_t *written
) {
    if (!ctx || !ciphertext || !plaintext || !written) {
        return false;
    }

    if (ciphertext_len < 16) {  /* Must have at least auth tag */
        return false;
    }

    /* TODO: Wire in AES-GCM decryption
     *
     * Similar to encryption, but:
     * - Use tls_aes_decrypt()
     * - Verify authentication tag
     * - Return false if tag verification fails
     * - Increment ctx->server_seq_num
     *
     * PERFORMANCE NOTE:
     * - Same optimization targets as encryption
     * - Tag verification is constant-time (important for security)
     */

    *written = 0;
    return false;
}

/**
 * @brief Send alert message
 */
bool tls_send_alert(
    struct tls_handshake_context *ctx,
    uint8_t level,
    uint8_t description
) {
    if (!ctx) {
        return false;
    }

    /* TODO: Implement alert sending
     *
     * Alert structure:
     * - Content type (1 byte): 0x15 (alert)
     * - Legacy version (2 bytes): 0x0303
     * - Length (2 bytes): 2
     * - Level (1 byte): warning/fatal
     * - Description (1 byte): specific alert
     *
     * For fatal alerts, update state to ERROR
     */

    if (level == TLS_ALERT_LEVEL_FATAL) {
        ctx->state = TLS_STATE_ERROR;
    }

    return false;
}

/**
 * @brief Clean up handshake context
 */
void tls_handshake_cleanup(struct tls_handshake_context *ctx) {
    if (!ctx) {
        return;
    }

    /* Securely zero sensitive data */
    memset(ctx->psk, 0, sizeof(ctx->psk));
    memset(&ctx->keys, 0, sizeof(ctx->keys));
    memset(ctx, 0, sizeof(*ctx));
}

/*
 * ============================================================================
 * TODO SUMMARY - What Needs Implementation/Optimization
 * ============================================================================
 *
 * CRITICAL PATH (needed for PSK handshake to work):
 * --------------------------------------------------
 * 1. [HIGH] HKDF implementation (hkdf.c)
 *    - tls_hkdf_extract()
 *    - tls_hkdf_expand()
 *    - tls_hkdf_expand_label()
 *    - tls_derive_secret()
 *    Status: Partially implemented, needs testing
 *    Dependencies: HMAC (✓), SHA-256 (✓)
 *
 * 2. [HIGH] ClientHello generation
 *    - Message formatting
 *    - Extension encoding
 *    - PSK binder calculation
 *    Status: Not started
 *    Dependencies: HKDF, HMAC, transcript hash
 *
 * 3. [HIGH] ServerHello parsing
 *    - Message parsing
 *    - Extension parsing
 *    - Validation
 *    Status: Not started
 *    Dependencies: Transcript hash
 *
 * 4. [HIGH] Key derivation wiring
 *    - tls_derive_handshake_keys()
 *    - tls_derive_application_keys()
 *    Status: Stubbed
 *    Dependencies: HKDF
 *
 * 5. [HIGH] Finished message handling
 *    - Generation
 *    - Verification
 *    Status: Stubbed
 *    Dependencies: HKDF, HMAC
 *
 * 6. [MEDIUM] Record layer encryption/decryption
 *    - AES-GCM wiring
 *    - Nonce construction
 *    - Sequence number management
 *    Status: Stubbed
 *    Dependencies: AES-GCM (✓)
 *
 * OPTIMIZATION TARGETS (for speed improvements):
 * ----------------------------------------------
 * 1. [CRITICAL] AES-GCM implementation
 *    Current: C implementation (~47KB in aes.c)
 *    Target: Assembly-optimized GCM mode
 *    Impact: HUGE - this is the bulk data encryption path
 *    Candidates for optimization:
 *    - AES rounds (table lookups vs. computation)
 *    - GHASH (GF(2^128) multiplication)
 *    - Key schedule caching
 *
 * 2. [HIGH] SHA-256 (for HKDF/HMAC)
 *    Current: Assembly implementation (sha256.asm)
 *    Status: Already optimized
 *    Impact: MEDIUM - used in key derivation and Finished messages
 *
 * 3. [MEDIUM] HMAC operations
 *    Current: C wrapper around SHA-256
 *    Target: Inline assembly for tight loops
 *    Impact: MEDIUM - used in key derivation
 *
 * 4. [LOW] Memory management
 *    - Stack usage optimization
 *    - Buffer reuse
 *    Impact: LOW - not performance critical
 *
 * PERFORMANCE ESTIMATES:
 * ---------------------
 * PSK Handshake (one-time per connection):
 * - ClientHello generation: ~10ms (mostly HMAC)
 * - Key derivation: ~50ms (multiple HKDF operations)
 * - Finished messages: ~20ms (HMAC)
 * Total handshake: ~100ms (acceptable for one-time cost)
 *
 * Application Data Encryption (per message):
 * - AES-GCM encrypt (1KB): ~5-10ms (NEEDS OPTIMIZATION)
 * - Target: <1ms for 1KB
 * - Speedup needed: 10x
 *
 * COMMUNITY HELP NEEDED:
 * ---------------------
 * 1. ez80 assembly experts:
 *    - Optimize AES-GCM (highest impact)
 *    - Review SHA-256 assembly
 *    - Optimize HMAC loops
 *
 * 2. Protocol experts:
 *    - Review TLS 1.3 compliance
 *    - Test against real servers
 *    - Security audit
 *
 * 3. Testing:
 *    - Hardware performance testing
 *    - Interoperability testing
 *    - Stress testing
 */
