/**
 * @file handshake.c
 * @brief TLS 1.3 Handshake Protocol - PSK Mode Implementation
 *
 * This implements the TLS 1.3 handshake flow using Pre-Shared Keys (PSK).
 * TODOs mark functions that need implementation or optimization.
 */

#include "../includes/handshake.h"
#include "../includes/hash.h"
#include "../includes/hmac.h"
#include "../includes/aes.h"
#include "../includes/random.h"
#include "../includes/hkdf.h"
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
static bool transcript_hash_init(struct tls_hash_context *ctx)
{
    return tls_hash_context_init(ctx, TLS_HASH_SHA256);
}

/**
 * @brief Update transcript hash with message data
 */
static void transcript_hash_update(struct tls_hash_context *ctx,
                                   const uint8_t *data, size_t len)
{
    tls_hash_update(ctx, data, len);
}

/**
 * @brief Get current transcript hash value
 */
static void transcript_hash_digest(struct tls_hash_context *ctx,
                                   uint8_t digest[32])
{
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
    const struct tls_psk_identity *psk_identity)
{
    if (!ctx || !psk || !psk_identity)
    {
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
    for (size_t i = 0; i < 4; i++)
    {
        uint64_t rand = tls_random();
        memcpy(&ctx->client_random[i * 8], &rand, 8);
    }

    /* Initialize transcript hash (using embedded storage) */
    ctx->transcript_hash = &ctx->transcript_hash_storage;
    if (!transcript_hash_init(ctx->transcript_hash))
    {
        ctx->transcript_hash = NULL;
        return false;
    }

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
    size_t *written)
{
    if (!ctx || !out || !written)
    {
        return false;
    }

    uint8_t early_secret[32];
    uint8_t binder_key[32];
    uint8_t finished_key[32];
    uint8_t binder[32];
    uint8_t partial_hash[32];
    struct tls_hash_context hash_ctx;
    struct tls_hmac_context hmac_ctx;
    size_t offset = 0;
    size_t msg_start = 4; /* After handshake header */
    size_t binder_offset;

    /* Reserve space for handshake header (will fill in later) */
    if (offset + 4 > out_len)
        return false;
    offset += 4;

    /* Legacy protocol version: 0x0303 (TLS 1.2) */
    out[offset++] = 0x03;
    out[offset++] = 0x03;

    /* Client random (32 bytes) */
    if (offset + 32 > out_len)
        return false;
    memcpy(out + offset, ctx->client_random, 32);
    offset += 32;

    /* Session ID (empty for TLS 1.3) */
    out[offset++] = 0x00;

    /* Cipher suites length (2 bytes) */
    out[offset++] = 0x00;
    out[offset++] = 0x02; /* 2 bytes total */

    /* Cipher suite: TLS_AES_128_GCM_SHA256 (0x1301) */
    out[offset++] = 0x13;
    out[offset++] = 0x01;

    /* Compression methods length (1 byte) */
    out[offset++] = 0x01;

    /* Compression method: null (0x00) */
    out[offset++] = 0x00;

    /* Extensions total length (placeholder, will calculate) */
    size_t ext_len_offset = offset;
    offset += 2;

    size_t ext_start = offset;

    /* Extension 1: supported_versions */
    out[offset++] = 0x00;
    out[offset++] = 0x2b; /* Extension type */
    out[offset++] = 0x00;
    out[offset++] = 0x03; /* Extension length */
    out[offset++] = 0x02; /* Versions length */
    out[offset++] = 0x03;
    out[offset++] = 0x04; /* TLS 1.3 */

    /* Extension 2: psk_key_exchange_modes */
    out[offset++] = 0x00;
    out[offset++] = 0x2d; /* Extension type */
    out[offset++] = 0x00;
    out[offset++] = 0x02; /* Extension length */
    out[offset++] = 0x01; /* Modes length */
    out[offset++] = 0x00; /* psk_ke (PSK-only, no ECDHE) */

    /* Extension 3: pre_shared_key (MUST be last extension) */
    size_t psk_ext_offset = offset;
    out[offset++] = 0x00;
    out[offset++] = 0x29; /* Extension type */

    size_t psk_ext_len_offset = offset;
    offset += 2; /* Extension length (fill later) */

    size_t psk_ext_start = offset;

    /* PSK identities */
    size_t identities_len_offset = offset;
    offset += 2; /* Identities length (fill later) */

    size_t identities_start = offset;

    /* PSK identity */
    out[offset++] = (uint8_t)(ctx->psk_identity.identity_len >> 8);
    out[offset++] = (uint8_t)(ctx->psk_identity.identity_len & 0xFF);
    if (offset + ctx->psk_identity.identity_len > out_len)
        return false;
    memcpy(out + offset, ctx->psk_identity.identity, ctx->psk_identity.identity_len);
    offset += ctx->psk_identity.identity_len;

    /* Obfuscated ticket age (4 bytes) */
    out[offset++] = (uint8_t)(ctx->psk_identity.obfuscated_ticket_age >> 24);
    out[offset++] = (uint8_t)(ctx->psk_identity.obfuscated_ticket_age >> 16);
    out[offset++] = (uint8_t)(ctx->psk_identity.obfuscated_ticket_age >> 8);
    out[offset++] = (uint8_t)(ctx->psk_identity.obfuscated_ticket_age & 0xFF);

    /* Fill in identities length */
    size_t identities_len = offset - identities_start;
    out[identities_len_offset] = (uint8_t)(identities_len >> 8);
    out[identities_len_offset + 1] = (uint8_t)(identities_len & 0xFF);

    /* PSK binders */
    binder_offset = offset;
    size_t binders_len_offset = offset;
    offset += 2; /* Binders length (fill later) */

    /* Binder length (SHA-256 = 32 bytes) */
    out[offset++] = 32;

    /* Calculate PSK binder:
     * 1. Compute early_secret from PSK
     * 2. Derive binder_key = HKDF-Expand-Label(early_secret, "res binder", "", 32)
     * 3. Derive finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
     * 4. Hash ClientHello up to (but not including) binder value
     * 5. binder = HMAC(finished_key, partial_hash)
     */

    /* Compute early_secret */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, early_secret))
    {
        return false;
    }

    /* Derive binder_key */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256, early_secret, 32,
                               "res binder", 10, NULL, 0, binder_key, 32))
    {
        return false;
    }

    /* Derive finished_key */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256, binder_key, 32,
                               "finished", 8, NULL, 0, finished_key, 32))
    {
        return false;
    }

    /* Hash ClientHello up to binders (but with correct length fields filled) */
    /* First, fill in all length fields temporarily */
    size_t total_msg_len = offset + 32 - msg_start; /* +32 for binder value */
    out[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    out[1] = (uint8_t)(total_msg_len >> 16);
    out[2] = (uint8_t)(total_msg_len >> 8);
    out[3] = (uint8_t)(total_msg_len & 0xFF);

    size_t ext_len = offset + 32 + 2 - ext_start; /* +32 binder +2 binders_len */
    out[ext_len_offset] = (uint8_t)(ext_len >> 8);
    out[ext_len_offset + 1] = (uint8_t)(ext_len & 0xFF);

    size_t psk_ext_len = offset + 32 + 2 - psk_ext_start; /* +32 binder +2 binders_len */
    out[psk_ext_len_offset] = (uint8_t)(psk_ext_len >> 8);
    out[psk_ext_len_offset + 1] = (uint8_t)(psk_ext_len & 0xFF);

    size_t binders_len = 1 + 32; /* length byte + binder value */
    out[binders_len_offset] = (uint8_t)(binders_len >> 8);
    out[binders_len_offset + 1] = (uint8_t)(binders_len & 0xFF);

    /* Compute transcript hash of ClientHello truncated before binders */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_update(&hash_ctx, out, binder_offset + 3); /* Up to and including binder length */
    tls_hash_digest(&hash_ctx, partial_hash);

    /* Compute binder = HMAC(finished_key, partial_hash) */
    if (!tls_hmac_context_init(&hmac_ctx, TLS_HASH_SHA256, finished_key, 32))
    {
        return false;
    }
    tls_hmac_update(&hmac_ctx, partial_hash, 32);
    tls_hmac_digest(&hmac_ctx, binder);

    /* Write binder value */
    if (offset + 32 > out_len)
        return false;
    memcpy(out + offset, binder, 32);
    offset += 32;

    *written = offset;

    /* Update transcript hash with full ClientHello */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, out, offset);
    }

    ctx->state = TLS_STATE_CLIENT_HELLO_SENT;
    return true;
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
    size_t data_len)
{
    if (!ctx || !data || ctx->state != TLS_STATE_CLIENT_HELLO_SENT)
    {
        return false;
    }

    size_t offset = 0;
    bool found_supported_versions = false;
    bool found_psk = false;

    /* Step 1: Verify handshake type */
    if (data[offset++] != TLS_HANDSHAKE_SERVER_HELLO)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Step 2: Parse length */
    uint32_t msg_len = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    offset += 3;

    if (offset + msg_len > data_len)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    size_t msg_end = offset + msg_len;

    /* Step 3: Verify legacy version (0x0303) */
    if (data[offset] != 0x03 || data[offset + 1] != 0x03)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    offset += 2;

    /* Step 4: Extract server random */
    if (offset + 32 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    memcpy(ctx->server_random, data + offset, 32);
    offset += 32;

    /* Step 5: Skip session ID */
    if (offset >= msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    uint8_t session_id_len = data[offset++];
    if (offset + session_id_len > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    offset += session_id_len;

    /* Step 6: Parse cipher suite */
    if (offset + 2 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    uint16_t cipher_suite = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (cipher_suite != ctx->cipher_suite)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Step 7: Verify compression method */
    if (offset >= msg_end || data[offset++] != 0x00)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Step 8: Parse extensions */
    if (offset + 2 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    uint16_t ext_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    size_t ext_end = offset + ext_len;
    if (ext_end > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    while (offset < ext_end)
    {
        if (offset + 4 > ext_end)
        {
            ctx->state = TLS_STATE_ERROR;
            return false;
        }

        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_data_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_data_len > ext_end)
        {
            ctx->state = TLS_STATE_ERROR;
            return false;
        }

        switch (ext_type)
        {
        case TLS_EXT_SUPPORTED_VERSIONS:
            /* Verify TLS 1.3 (0x0304) */
            if (ext_data_len != 2)
            {
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            if (data[offset] != 0x03 || data[offset + 1] != 0x04)
            {
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            found_supported_versions = true;
            break;

        case TLS_EXT_PRE_SHARED_KEY:
            /* Extract selected PSK identity (2 bytes, should be 0 for first PSK) */
            if (ext_data_len != 2)
            {
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            uint16_t selected_identity = (data[offset] << 8) | data[offset + 1];
            if (selected_identity != 0)
            {
                /* Server selected a PSK identity we didn't offer */
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            found_psk = true;
            break;

        default:
            /* Skip unknown extensions */
            break;
        }

        offset += ext_data_len;
    }

    /* Verify required extensions were present */
    if (!found_supported_versions || !found_psk)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Step 9: Update transcript hash with ServerHello */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, msg_end);
    }

    ctx->state = TLS_STATE_SERVER_HELLO_RECEIVED;
    return true;
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
bool tls_derive_handshake_keys(struct tls_handshake_context *ctx)
{
    if (!ctx || ctx->state != TLS_STATE_SERVER_HELLO_RECEIVED)
    {
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
    if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, early_secret))
    {
        return false;
    }

    /* Step 2: Compute empty hash for "derived" secret
     * empty_hash = SHA-256("")
     */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 3: Derive "derived" secret from early_secret
     * derived = Derive-Secret(early_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, early_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret))
    {
        return false;
    }

    /* Step 4: Compute handshake_secret (PSK-only mode, no ECDHE)
     * handshake_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          zero_ikm, 32, handshake_secret))
    {
        return false;
    }

    /* Step 5: Get transcript hash (ClientHello...ServerHello)
     * TODO: Extract from ctx->transcript_hash when implemented
     * For now, use placeholder zeros for testing
     */
    memset(transcript_hash, 0, 32);
    if (ctx->transcript_hash)
    {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }

    /* Step 6: Derive client handshake traffic secret
     * client_handshake_traffic_secret =
     *     Derive-Secret(handshake_secret, "c hs traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, handshake_secret, 32,
                           "c hs traffic", 12, transcript_hash, 32,
                           ctx->keys.client_handshake_traffic_secret))
    {
        return false;
    }

    /* Step 7: Derive server handshake traffic secret
     * server_handshake_traffic_secret =
     *     Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, handshake_secret, 32,
                           "s hs traffic", 12, transcript_hash, 32,
                           ctx->keys.server_handshake_traffic_secret))
    {
        return false;
    }

    /* Step 8: Derive client handshake key and IV
     * key = HKDF-Expand-Label(secret, "key", "", 16)
     * iv = HKDF-Expand-Label(secret, "iv", "", 12)
     */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_handshake_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.client_handshake_key, 16))
    {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_handshake_iv, 12))
    {
        return false;
    }

    /* Step 9: Derive server handshake key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_handshake_key, 16))
    {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_handshake_iv, 12))
    {
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
bool tls_derive_application_keys(struct tls_handshake_context *ctx)
{
    if (!ctx)
    {
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
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 2: Derive "derived" secret from handshake_secret
     * derived = Derive-Secret(handshake_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, ctx->keys.handshake_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret))
    {
        return false;
    }

    /* Step 3: Compute master_secret
     * master_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          zero_ikm, 32, master_secret))
    {
        return false;
    }

    /* Step 4: Get transcript hash (ClientHello...server Finished)
     * TODO: Extract from ctx->transcript_hash when implemented
     * For now, use placeholder zeros for testing
     */
    memset(transcript_hash, 0, 32);
    if (ctx->transcript_hash)
    {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }

    /* Step 5: Derive client application traffic secret
     * client_application_traffic_secret =
     *     Derive-Secret(master_secret, "c ap traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, master_secret, 32,
                           "c ap traffic", 12, transcript_hash, 32,
                           ctx->keys.client_application_traffic_secret))
    {
        return false;
    }

    /* Step 6: Derive server application traffic secret
     * server_application_traffic_secret =
     *     Derive-Secret(master_secret, "s ap traffic", transcript_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, master_secret, 32,
                           "s ap traffic", 12, transcript_hash, 32,
                           ctx->keys.server_application_traffic_secret))
    {
        return false;
    }

    /* Step 7: Derive client application key and IV
     * key = HKDF-Expand-Label(secret, "key", "", 16)
     * iv = HKDF-Expand-Label(secret, "iv", "", 12)
     */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_application_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.client_application_key, 16))
    {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_application_iv, 12))
    {
        return false;
    }

    /* Step 8: Derive server application key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_application_key, 16))
    {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_application_iv, 12))
    {
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
    size_t *written)
{
    if (!ctx || !out || !written)
    {
        return false;
    }

    if (out_len < 36)
    { /* 4 byte header + 32 byte verify_data */
        return false;
    }

    uint8_t finished_key[32];
    uint8_t verify_data[32];
    uint8_t transcript_hash[32];
    struct tls_hmac_context hmac_ctx;
    const uint8_t *traffic_secret;

    /* Step 1: Select appropriate traffic secret */
    if (is_client)
    {
        traffic_secret = ctx->keys.client_handshake_traffic_secret;
    }
    else
    {
        traffic_secret = ctx->keys.server_handshake_traffic_secret;
    }

    /* Step 2: Derive finished_key
     * finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
     */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256, traffic_secret, 32,
                               "finished", 8, NULL, 0, finished_key, 32))
    {
        return false;
    }

    /* Step 3: Get transcript hash up to this point */
    if (ctx->transcript_hash)
    {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }
    else
    {
        memset(transcript_hash, 0, 32);
    }

    /* Step 4: Compute verify_data = HMAC(finished_key, transcript_hash) */
    if (!tls_hmac_context_init(&hmac_ctx, TLS_HASH_SHA256, finished_key, 32))
    {
        return false;
    }
    tls_hmac_update(&hmac_ctx, transcript_hash, 32);
    tls_hmac_digest(&hmac_ctx, verify_data);

    /* Step 5: Build Finished message */
    size_t offset = 0;

    /* Handshake type: Finished (0x14) */
    out[offset++] = TLS_HANDSHAKE_FINISHED;

    /* Length: 32 bytes */
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x20;

    /* Verify data */
    memcpy(out + offset, verify_data, 32);
    offset += 32;

    *written = offset;

    /* Update transcript hash with this Finished message */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, out, offset);
    }

    return true;
}

/**
 * @brief Verify Finished message
 */
bool tls_verify_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 36)
    {
        return false;
    }

    uint8_t finished_key[32];
    uint8_t expected_verify_data[32];
    uint8_t transcript_hash[32];
    struct tls_hmac_context hmac_ctx;
    const uint8_t *traffic_secret;
    size_t offset = 0;

    /* Step 1: Parse Finished message */
    /* Verify handshake type */
    if (data[offset++] != TLS_HANDSHAKE_FINISHED)
    {
        return false;
    }

    /* Parse length */
    uint32_t msg_len = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    offset += 3;

    if (msg_len != 32 || offset + 32 > data_len)
    {
        return false;
    }

    const uint8_t *received_verify_data = data + offset;

    /* Step 2: Compute expected verify_data */
    /* Select appropriate traffic secret (opposite of generation) */
    if (is_client)
    {
        /* Client is verifying server's Finished */
        traffic_secret = ctx->keys.server_handshake_traffic_secret;
    }
    else
    {
        /* Server is verifying client's Finished */
        traffic_secret = ctx->keys.client_handshake_traffic_secret;
    }

    /* Derive finished_key */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256, traffic_secret, 32,
                               "finished", 8, NULL, 0, finished_key, 32))
    {
        return false;
    }

    /* Get transcript hash (before this Finished message) */
    if (ctx->transcript_hash)
    {
        transcript_hash_digest(ctx->transcript_hash, transcript_hash);
    }
    else
    {
        memset(transcript_hash, 0, 32);
    }

    /* Compute expected verify_data */
    if (!tls_hmac_context_init(&hmac_ctx, TLS_HASH_SHA256, finished_key, 32))
    {
        return false;
    }
    tls_hmac_update(&hmac_ctx, transcript_hash, 32);
    tls_hmac_digest(&hmac_ctx, expected_verify_data);

    /* Step 3: Constant-time compare */
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++)
    {
        diff |= received_verify_data[i] ^ expected_verify_data[i];
    }

    if (diff != 0)
    {
        return false;
    }

    /* Step 4: Update transcript hash with received Finished */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, offset + 32);
    }

    return true;
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
    size_t *written)
{
    if (!ctx || !plaintext || !ciphertext || !written)
    {
        return false;
    }

    if (ciphertext_len < plaintext_len + 16)
    { /* Need space for auth tag */
        return false;
    }

    struct tls_aes_context aes_ctx;
    uint8_t nonce[12];
    uint8_t aad[5]; /* TLS record header for AAD */
    uint8_t auth_tag[16];

    /* Step 1: Construct nonce = IV XOR sequence_number
     * TLS 1.3 nonce is IV XOR sequence number (pad seq to 12 bytes)
     */
    memcpy(nonce, ctx->keys.client_application_iv, 12);

    /* XOR sequence number into last 8 bytes of nonce */
    for (size_t i = 0; i < 8; i++)
    {
        nonce[12 - 8 + i] ^= (uint8_t)((ctx->client_seq_num >> (56 - i * 8)) & 0xFF);
    }

    /* Step 2: Build AAD (TLS record header)
     * In TLS 1.3, AAD is just the record header:
     * - Content type (1 byte): 0x17 (application_data)
     * - Legacy version (2 bytes): 0x0303
     * - Length (2 bytes): ciphertext length (plaintext + tag)
     */
    aad[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
    aad[1] = 0x03; /* TLS 1.2 legacy version */
    aad[2] = 0x03;
    aad[3] = (uint8_t)((plaintext_len + 16) >> 8); /* Length includes tag */
    aad[4] = (uint8_t)((plaintext_len + 16) & 0xFF);

    /* Step 3: Initialize AES-GCM with key and nonce */
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM,
                      ctx->keys.client_application_key, 16,
                      nonce, 12))
    {
        return false;
    }

    /* Step 4: Add AAD */
    if (!tls_aes_update_aad(&aes_ctx, aad, 5))
    {
        return false;
    }

    /* Step 5: Encrypt plaintext */
    if (!tls_aes_encrypt(&aes_ctx, plaintext, plaintext_len, ciphertext))
    {
        return false;
    }

    /* Step 6: Get authentication tag */
    if (!tls_aes_digest(&aes_ctx, auth_tag))
    {
        return false;
    }

    /* Step 7: Append tag to ciphertext */
    memcpy(ciphertext + plaintext_len, auth_tag, 16);

    /* Step 8: Increment sequence number */
    ctx->client_seq_num++;

    *written = plaintext_len + 16;
    return true;
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
    size_t *written)
{
    if (!ctx || !ciphertext || !plaintext || !written)
    {
        return false;
    }

    if (ciphertext_len < 16)
    { /* Must have at least auth tag */
        return false;
    }

    /* Ciphertext length minus tag is actual plaintext length */
    size_t actual_plaintext_len = ciphertext_len - 16;

    if (plaintext_len < actual_plaintext_len)
    {
        return false;
    }

    struct tls_aes_context aes_ctx;
    uint8_t nonce[12];
    uint8_t aad[5]; /* TLS record header for AAD */
    uint8_t computed_tag[16];
    const uint8_t *received_tag = ciphertext + actual_plaintext_len;

    /* Step 1: Construct nonce = IV XOR sequence_number
     * Same as encryption but using server IV and sequence number
     */
    memcpy(nonce, ctx->keys.server_application_iv, 12);

    /* XOR sequence number into last 8 bytes of nonce */
    for (size_t i = 0; i < 8; i++)
    {
        nonce[12 - 8 + i] ^= (uint8_t)((ctx->server_seq_num >> (56 - i * 8)) & 0xFF);
    }

    /* Step 2: Build AAD (TLS record header) */
    aad[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
    aad[1] = 0x03; /* TLS 1.2 legacy version */
    aad[2] = 0x03;
    aad[3] = (uint8_t)(ciphertext_len >> 8); /* Length includes tag */
    aad[4] = (uint8_t)(ciphertext_len & 0xFF);

    /* Step 3: Initialize AES-GCM with key and nonce */
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM,
                      ctx->keys.server_application_key, 16,
                      nonce, 12))
    {
        return false;
    }

    /* Step 4: Add AAD */
    if (!tls_aes_update_aad(&aes_ctx, aad, 5))
    {
        return false;
    }

    /* Step 5: Decrypt ciphertext */
    if (!tls_aes_decrypt(&aes_ctx, ciphertext, actual_plaintext_len, plaintext))
    {
        return false;
    }

    /* Step 6: Compute authentication tag */
    if (!tls_aes_digest(&aes_ctx, computed_tag))
    {
        return false;
    }

    /* Step 7: Verify authentication tag (constant-time comparison)
     * CRITICAL: This must be constant-time to prevent timing attacks
     */
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++)
    {
        diff |= computed_tag[i] ^ received_tag[i];
    }

    if (diff != 0)
    {
        /* Tag verification failed - possible tampering or decryption error */
        memset(plaintext, 0, actual_plaintext_len); /* Clear plaintext */
        return false;
    }

    /* Step 8: Increment sequence number */
    ctx->server_seq_num++;

    *written = actual_plaintext_len;
    return true;
}

/**
 * @brief Send alert message
 */
bool tls_send_alert(
    struct tls_handshake_context *ctx,
    uint8_t level,
    uint8_t description)
{
    if (!ctx)
    {
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

    if (level == TLS_ALERT_LEVEL_FATAL)
    {
        ctx->state = TLS_STATE_ERROR;
    }

    return false;
}

/**
 * @brief Clean up handshake context
 */
void tls_handshake_cleanup(struct tls_handshake_context *ctx)
{
    if (!ctx)
    {
        return;
    }

    /* Transcript hash uses embedded storage, no need to free */

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
