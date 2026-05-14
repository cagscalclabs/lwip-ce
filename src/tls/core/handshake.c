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
#include "../includes/asn1.h"
#include "../includes/truststore.h"
#include "../includes/bytes.h"
#include "../includes/x509.h"
#include "../contrib/x25519/src/x25519.h"
#include <string.h>
#include <usbdrvce.h>
#include "../../drivers/mem.h"
#include "lwip/timeouts.h"
#include "lwip/logging.h"
#include "lwip/sntp_time.h"
#include "lwip/app_config.h"
#include "lwip/sys.h"

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

static size_t tls_padded_id_len(const uint8_t *id, size_t max_len)
{
    size_t len = 0;

    if (!id)
    {
        return 0;
    }
    while (len < max_len && id[len] != 0)
    {
        len++;
    }
    return len;
}

static bool tls_subject_cn_matches_owner_id(const struct tls_asn1_serialization *subject_cn,
                                            const uint8_t owner_id[TLS_SPKI_OWNER_ID_LEN])
{
    size_t owner_len;

    if (!subject_cn || !subject_cn->data || !owner_id)
    {
        return false;
    }

    owner_len = tls_padded_id_len(owner_id, TLS_SPKI_OWNER_ID_LEN);
    if (owner_len == 0 || subject_cn->len != owner_len)
    {
        return false;
    }

    return memcmp(subject_cn->data, owner_id, owner_len) == 0;
}

/* enum tls_server_handshake_type {
 *     TLS_SERVER_HANDSHAKE_HELLO_REQUEST = 0x00,
 *     TLS_SERVER_HANDSHAKE_SERVER_HELLO = 0x02,
 *     TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET = 0x04,
 *     TLS_SERVER_HANDSHAKE_ENCRYPTED_EXTENSIONS = 0x08,
 *     TLS_SERVER_HANDSHAKE_CERTIFICATE = 0x0b,
 *     TLS_SERVER_HANDSHAKE_SERVER_KEY_EXCHANGE = 0x0c,
 *     TLS_SERVER_HANDSHAKE_CERTIFICATE_REQUEST = 0x0d,
 *     TLS_SERVER_HANDSHAKE_SERVER_HELLO_DONE = 0x0e,
 *     TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY = 0x0f,
 *     TLS_SERVER_HANDSHAKE_FINISHED = 0x14,
 *     TLS_SERVER_HANDSHAKE_KEY_UPDATE = 0x18,
 *     TLS_SERVER_HANDSHAKE_MESSAGE_HASH = 0xfe
 * };
 */

bool tls_process_record(struct tls_handshake_context *ctx,
                        const uint8_t *data,
                        size_t data_len)
{
    if (!ctx || !data || data_len < 5)
    {
        return false;
    }

    uint8_t content_type = data[0];
    size_t record_len = ((size_t)data[3] << 8) | (size_t)data[4];

    if (data_len != 5 + record_len)
    {
        return false;
    }

    switch (content_type)
    {
    case TLS_CONTENT_TYPE_HANDSHAKE:
    {
        const uint8_t *payload = data + 5;
        size_t offset = 0;

        while (offset + 4 <= record_len)
        {
            uint8_t msg_type = payload[offset];
            size_t msg_len = ((size_t)payload[offset + 1] << 16) |
                             ((size_t)payload[offset + 2] << 8) |
                             (size_t)payload[offset + 3];
            size_t msg_end = offset + 4 + msg_len;

            if (msg_end > record_len)
            {
                return false;
            }

            switch (msg_type)
            {
            case TLS_HANDSHAKE_SERVER_HELLO:
                if (ctx->state != TLS_STATE_CLIENT_HELLO_SENT)
                {
                    ctx->state = TLS_STATE_ERROR;
                    return false;
                }
                if (!tls_recv_server_hello(ctx, payload + offset, msg_end - offset))
                {
                    return false;
                }
                break;
            case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
            case TLS_HANDSHAKE_CERTIFICATE:
            case TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY:
            case TLS_HANDSHAKE_FINISHED:
            case TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET:
                /* Post-ServerHello TLS 1.3 handshake messages must arrive via
                 * encrypted application_data records, not plaintext handshake
                 * records. Reject them here to preserve the record-layer boundary. */
                ctx->state = TLS_STATE_ERROR;
                return false;
            default:
                /* Unknown message type - skip it */
                break;
            }

            offset = msg_end;
        }

        return (offset == record_len);
    }
    case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        /* TLS 1.3 middlebox compatibility: ignore CCS records */
        return true;

    case TLS_CONTENT_TYPE_ALERT:
    {
        const uint8_t *payload = data + 5;
        if (record_len >= 2)
        {
            /* payload[0] = level (1=warning, 2=fatal), payload[1] = description */
            if (payload[0] == 2)
            {
                ctx->state = TLS_STATE_ERROR;
            }
        }
        return true;
    }

    case TLS_CONTENT_TYPE_APPLICATION_DATA:
    {
        /* Encrypted record — decrypt and process inner content */
        bool use_hs_keys = (ctx->state >= TLS_STATE_HANDSHAKE_KEYS_DERIVED &&
                            ctx->state < TLS_STATE_HANDSHAKE_COMPLETE);

        /* Allocate decryption buffer on heap — records can be up to ~16KB */
        size_t dec_buf_size = record_len; /* plaintext <= ciphertext */
        uint8_t *dec_buf = (uint8_t *)mem_buffer_custom_malloc(dec_buf_size);
        if (!dec_buf)
        {
            ctx->state = TLS_STATE_ERROR;
            return false;
        }
        size_t dec_len = 0;
        uint8_t inner_type = 0;

        if (!tls_decrypt_record(ctx, use_hs_keys,
                                data, data_len,
                                dec_buf, dec_buf_size,
                                &dec_len, &inner_type))
        {
            mem_buffer_custom_free(dec_buf);
            ctx->state = TLS_STATE_ERROR;
            return false;
        }

        if (inner_type == TLS_CONTENT_TYPE_HANDSHAKE)
        {
            /* Process decrypted handshake messages.
             *
             * LIMITATION: Each handshake message must fit entirely within a
             * single TLS record. Cross-record handshake message fragmentation
             * (where a message spans two encrypted records) is not supported.
             * In practice, servers fit handshake messages within the 16KB
             * record limit. If a message spans records, the handshake will
             * fail at the msg_end > dec_len check below. */
            size_t offset = 0;
            while (offset + 4 <= dec_len)
            {
                uint8_t msg_type = dec_buf[offset];
                size_t msg_len = ((size_t)dec_buf[offset + 1] << 16) |
                                 ((size_t)dec_buf[offset + 2] << 8) |
                                 (size_t)dec_buf[offset + 3];
                size_t msg_end = offset + 4 + msg_len;

                if (msg_end > dec_len)
                {
                    mem_buffer_custom_free(dec_buf);
                    return false;
                }

                switch (msg_type)
                {
                case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
                    if (!tls_recv_encrypted_extensions(ctx, dec_buf + offset, msg_end - offset))
                    {
                        mem_buffer_custom_free(dec_buf);
                        return false;
                    }
                    break;
                case TLS_HANDSHAKE_CERTIFICATE:
                    if (!tls_recv_certificate(ctx, dec_buf + offset, msg_end - offset))
                    {
                        mem_buffer_custom_free(dec_buf);
                        return false;
                    }
                    break;
                case TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY:
                    if (!tls_recv_certificate_verify(ctx, dec_buf + offset, msg_end - offset))
                    {
                        mem_buffer_custom_free(dec_buf);
                        return false;
                    }
                    break;
                case TLS_HANDSHAKE_FINISHED:
                    if (!tls_recv_finished(ctx, true, dec_buf + offset, msg_end - offset))
                    {
                        mem_buffer_custom_free(dec_buf);
                        return false;
                    }
                    break;
                case TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET:
                    if (!tls_recv_new_session_ticket(ctx, dec_buf + offset, msg_end - offset))
                    {
                        mem_buffer_custom_free(dec_buf);
                        return false;
                    }
                    break;
                default:
                    break;
                }

                offset = msg_end;
            }
            mem_buffer_custom_free(dec_buf);
            return (offset == dec_len);
        }
        else if (inner_type == TLS_CONTENT_TYPE_ALERT)
        {
            if (dec_len >= 2 && dec_buf[0] == 2)
            {
                ctx->state = TLS_STATE_ERROR;
            }
            mem_buffer_custom_free(dec_buf);
            return true;
        }

        /* Application data during handshake is unexpected */
        mem_buffer_custom_free(dec_buf);
        return false;
    }

    default:
        return false;
    }
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
    if (!ctx)
    {
        return false;
    }

    /* Clear context */
    tls_secure_memzero(ctx, sizeof(*ctx));

    /* Copy PSK and identity (NULL = pure ECDHE mode, PSK stays zeroed) */
    if (psk && psk_identity)
    {
        memcpy(ctx->psk, psk, 32);
        memcpy(&ctx->psk_identity, psk_identity, sizeof(*psk_identity));
        ctx->psk_mode = true;
    }
    else
    {
        ctx->psk_mode = false;
    }

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

    /* Generate ephemeral X25519 keypair for ECDHE */
    for (size_t i = 0; i < 4; i++)
    {
        uint64_t rand = tls_random();
        memcpy(&ctx->ecdhe_private[i * 8], &rand, 8);
    }

    if (!tls_x25519_publickey(ctx->ecdhe_public, ctx->ecdhe_private,
                              NULL, NULL))
    {
        tls_secure_memzero(ctx->ecdhe_private, 32);
        return false;
    }

    ctx->ecdhe_negotiated = false;
    ctx->hostname = NULL;

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
bool tls_send_client_hello(
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

    /* Extension 2: supported_groups */
    out[offset++] = 0x00;
    out[offset++] = 0x0a; /* Extension type: supported_groups */
    out[offset++] = 0x00;
    out[offset++] = 0x04; /* Extension length */
    out[offset++] = 0x00;
    out[offset++] = 0x02; /* Named group list length */
    out[offset++] = 0x00;
    out[offset++] = 0x1d; /* x25519 */

    /* Extension 3: key_share */
    out[offset++] = 0x00;
    out[offset++] = 0x33; /* Extension type: key_share */
    out[offset++] = 0x00;
    out[offset++] = 0x26; /* Extension length: 38 */
    out[offset++] = 0x00;
    out[offset++] = 0x24; /* Client shares length: 36 */
    out[offset++] = 0x00;
    out[offset++] = 0x1d; /* Named group: x25519 */
    out[offset++] = 0x00;
    out[offset++] = 0x20; /* Key exchange length: 32 */
    if (offset + 32 > out_len)
        return false;
    memcpy(out + offset, ctx->ecdhe_public, 32);
    offset += 32;

    /* Extension 4: signature_algorithms (required for ECDHE) */
    out[offset++] = 0x00;
    out[offset++] = 0x0d; /* Extension type: signature_algorithms */
    out[offset++] = 0x00;
    out[offset++] = 0x0a; /* Extension length: 10 */
    out[offset++] = 0x00;
    out[offset++] = 0x08; /* Signature algorithms list length: 8 */
    out[offset++] = 0x04;
    out[offset++] = 0x03; /* ecdsa_secp256r1_sha256 */
    out[offset++] = 0x08;
    out[offset++] = 0x04; /* rsa_pss_rsae_sha256 */
    out[offset++] = 0x04;
    out[offset++] = 0x01; /* rsa_pkcs1_sha256 */
    out[offset++] = 0x08;
    out[offset++] = 0x09; /* rsa_pss_rsae_sha384 */

    /* Extension 5: server_name (SNI) */
    if (ctx->hostname)
    {
        size_t hostname_len = strlen(ctx->hostname);
        if (offset + 9 + hostname_len > out_len)
            return false;
        out[offset++] = 0x00;
        out[offset++] = 0x00; /* Extension type: server_name */
        /* Extension length = hostname_len + 5 */
        size_t sni_ext_len = hostname_len + 5;
        out[offset++] = (uint8_t)(sni_ext_len >> 8);
        out[offset++] = (uint8_t)(sni_ext_len & 0xFF);
        /* Server name list length = hostname_len + 3 */
        size_t sni_list_len = hostname_len + 3;
        out[offset++] = (uint8_t)(sni_list_len >> 8);
        out[offset++] = (uint8_t)(sni_list_len & 0xFF);
        out[offset++] = 0x00; /* Host name type */
        out[offset++] = (uint8_t)(hostname_len >> 8);
        out[offset++] = (uint8_t)(hostname_len & 0xFF);
        memcpy(out + offset, ctx->hostname, hostname_len);
        offset += hostname_len;
    }

    if (ctx->psk_mode)
    {
        /* Extension 4: psk_key_exchange_modes */
        out[offset++] = 0x00;
        out[offset++] = 0x2d; /* Extension type */
        out[offset++] = 0x00;
        out[offset++] = 0x03; /* Extension length */
        out[offset++] = 0x02; /* Modes length */
        out[offset++] = 0x01; /* psk_dhe_ke (PSK with ECDHE) */
        out[offset++] = 0x00; /* psk_ke (PSK-only fallback) */

        /* Extension 5: pre_shared_key (MUST be last extension) */
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
        uint32_t ticket_age = ctx->psk_identity.obfuscated_ticket_age;
        if (ctx->ticket_received_ms != 0)
        {
            uint32_t elapsed = sys_now() - ctx->ticket_received_ms;
            ticket_age = ctx->ticket_age_add + elapsed;
        }
        out[offset++] = (uint8_t)(ticket_age >> 24);
        out[offset++] = (uint8_t)(ticket_age >> 16);
        out[offset++] = (uint8_t)(ticket_age >> 8);
        out[offset++] = (uint8_t)(ticket_age & 0xFF);

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

        /* Calculate PSK binder */
        if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, early_secret))
            return false;

        if (!tls_hkdf_expand_label(TLS_HASH_SHA256, early_secret, 32,
                                   "res binder", 10, NULL, 0, binder_key, 32))
            return false;

        if (!tls_hkdf_expand_label(TLS_HASH_SHA256, binder_key, 32,
                                   "finished", 8, NULL, 0, finished_key, 32))
            return false;

        /* Fill in length fields for binder hash computation */
        size_t total_msg_len = offset + 32 - msg_start;
        out[0] = TLS_HANDSHAKE_CLIENT_HELLO;
        out[1] = (uint8_t)(total_msg_len >> 16);
        out[2] = (uint8_t)(total_msg_len >> 8);
        out[3] = (uint8_t)(total_msg_len & 0xFF);

        size_t ext_len = offset + 32 + 2 - ext_start;
        out[ext_len_offset] = (uint8_t)(ext_len >> 8);
        out[ext_len_offset + 1] = (uint8_t)(ext_len & 0xFF);

        size_t psk_ext_len = offset + 32 + 2 - psk_ext_start;
        out[psk_ext_len_offset] = (uint8_t)(psk_ext_len >> 8);
        out[psk_ext_len_offset + 1] = (uint8_t)(psk_ext_len & 0xFF);

        size_t binders_len = 1 + 32;
        out[binders_len_offset] = (uint8_t)(binders_len >> 8);
        out[binders_len_offset + 1] = (uint8_t)(binders_len & 0xFF);

        /* Compute transcript hash of ClientHello truncated before binders */
        if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
            return false;
        tls_hash_update(&hash_ctx, out, binder_offset + 3);
        tls_hash_digest(&hash_ctx, partial_hash);

        /* Compute binder = HMAC(finished_key, partial_hash) */
        if (!tls_hmac_context_init(&hmac_ctx, TLS_HASH_SHA256, finished_key, 32))
            return false;
        tls_hmac_update(&hmac_ctx, partial_hash, 32);
        tls_hmac_digest(&hmac_ctx, binder);

        /* Write binder value */
        if (offset + 32 > out_len)
            return false;
        memcpy(out + offset, binder, 32);
        offset += 32;
    }
    else
    {
        /* Pure ECDHE mode: no PSK extensions, just finalize lengths */
        size_t ext_len = offset - ext_start;
        out[ext_len_offset] = (uint8_t)(ext_len >> 8);
        out[ext_len_offset + 1] = (uint8_t)(ext_len & 0xFF);

        size_t total_msg_len = offset - msg_start;
        out[0] = TLS_HANDSHAKE_CLIENT_HELLO;
        out[1] = (uint8_t)(total_msg_len >> 16);
        out[2] = (uint8_t)(total_msg_len >> 8);
        out[3] = (uint8_t)(total_msg_len & 0xFF);
    }

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
bool tls_recv_server_hello(
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
    size_t msg_len = ((size_t)data[offset] << 16) |
                     ((size_t)data[offset + 1] << 8) |
                     (size_t)data[offset + 2];
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

    /* Check for HelloRetryRequest (RFC 8446 Section 4.1.3):
     * HRR is signaled by a special server_random value = SHA-256("HelloRetryRequest") */
    {
        static const uint8_t hrr_random[32] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};
        if (memcmp(ctx->server_random, hrr_random, 32) == 0)
        {
            /* Server requested HelloRetryRequest.
             * We only support x25519, so if the server doesn't accept it,
             * there's nothing we can do — abort gracefully. */
            ctx->state = TLS_STATE_ERROR;
            return false;
        }
    }

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

        case TLS_EXT_KEY_SHARE:
        {
            /* ServerHello key_share: named_group (2) + key_exchange_length (2) + key_exchange */
            if (ext_data_len < 4)
            {
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            uint16_t group = (data[offset] << 8) | data[offset + 1];
            uint16_t ke_len = (data[offset + 2] << 8) | data[offset + 3];
            if (group != TLS_NAMED_GROUP_X25519 || ke_len != 32 ||
                ext_data_len != (size_t)(4 + ke_len))
            {
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            /* Compute shared secret from server's public key */
            if (!tls_x25519_secret(ctx->ecdhe_shared, ctx->ecdhe_private,
                                   data + offset + 4,
                                   NULL, NULL))
            {
                tls_secure_memzero(ctx->ecdhe_private, 32);
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
            /* Securely erase private key immediately */
            tls_secure_memzero(ctx->ecdhe_private, 32);
            ctx->ecdhe_negotiated = true;
            break;
        }

        case TLS_EXT_PRE_SHARED_KEY:
        {
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
        }

        default:
            /* Skip unknown extensions */
            break;
        }

        offset += ext_data_len;
    }

    /* Verify required extensions were present */
    if (!found_supported_versions || (ctx->psk_mode && !found_psk))
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Step 9: Update transcript hash with ServerHello */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, msg_end);
    }

    /* TODO(cert-chain): For full (non-PSK) handshakes, parse the incoming
     * Certificate message after ServerHello/EncryptedExtensions.
     * When you have that handshake message buffer, the certificate bytes start at:
     * cert_msg + 4 (handshake header) + 1 (context len) + 3 (cert_list_len).
     */
    ctx->state = TLS_STATE_SERVER_HELLO_RECEIVED;
    return true;
}

/**
 * @brief Process Certificate message (server -> client)
 *
 * TLS 1.3 Certificate message structure:
 * - HandshakeType (1 byte): 0x0b (Certificate)
 * - Length (3 bytes): total message length
 * - certificate_request_context (1 byte length + data)
 * - certificate_list (3 byte length):
 *   - For each certificate:
 *     - cert_data (3 byte length + DER-encoded X.509 certificate)
 *     - extensions (2 byte length + extension data)
 *
 * This function:
 * 1. Parses the certificate chain
 * 2. Extracts SPKI from each certificate
 * 3. Computes SHA-256 hash of SPKI
 * 4. Validates against truststore (SPKI pinning)
 */
bool tls_recv_certificate(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 8)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    size_t offset = 0;

    /* Verify handshake type */
    if (data[offset++] != TLS_HANDSHAKE_CERTIFICATE)
    {
        return false;
    }

    /* Parse message length (3 bytes, big-endian) */
    size_t msg_len = ((size_t)data[offset] << 16) |
                     ((size_t)data[offset + 1] << 8) |
                     (size_t)data[offset + 2];
    offset += 3;

    if (offset + msg_len > data_len)
    {
        return false;
    }

    /* Parse certificate_request_context (should be empty for server cert) */
    size_t context_len = data[offset++];
    offset += context_len;
    if (offset > data_len)
    {
        return false;
    }

    /* Parse certificate_list length (3 bytes) */
    if (offset + 3 > data_len)
    {
        return false;
    }
    size_t cert_chain_len = ((size_t)data[offset] << 16) |
                            ((size_t)data[offset + 1] << 8) |
                            (size_t)data[offset + 2];
    offset += 3;

    if (offset + cert_chain_len > data_len)
    {
        return false;
    }

    /* Parse certificate chain */
    size_t chain_offset = 0;
    bool first_cert = true;
    bool chain_validated = false;

    while (chain_offset < cert_chain_len)
    {
        /* Parse certificate entry length (3 bytes) */
        if (chain_offset + 3 > cert_chain_len)
        {
            return false;
        }
        size_t cert_len = ((size_t)data[offset + chain_offset] << 16) |
                          ((size_t)data[offset + chain_offset + 1] << 8) |
                          (size_t)data[offset + chain_offset + 2];
        chain_offset += 3;

        if (chain_offset + cert_len > cert_chain_len)
        {
            return false;
        }

        const uint8_t *cert_der = &data[offset + chain_offset];
        chain_offset += cert_len;

        /* Parse certificate extensions length (2 bytes) - TLS 1.3 specific */
        if (chain_offset + 2 > cert_chain_len)
        {
            return false;
        }
        size_t ext_len = ((size_t)data[offset + chain_offset] << 8) |
                         (size_t)data[offset + chain_offset + 1];
        if (chain_offset + 2 + ext_len > cert_chain_len)
        {
            return false;
        }
        chain_offset += 2 + ext_len;

        /* Process the first (end-entity) certificate */
        if (first_cert)
        {
            first_cert = false;
            struct tls_asn1_serialization cert_fields[13];
            struct tls_x509_parse_result cert_parsed = {0};
            bool constraints_check_pass = false;
            if (!tls_x509_parse_certificate(cert_der, cert_len, cert_fields, &cert_parsed))
            {
                return false;
            }
            if (!cert_parsed.extensions || !cert_parsed.extensions->data || cert_parsed.extensions->len == 0)
            {
                return false;
            }
            constraints_check_pass = tls_x509_has_valid_constraints(cert_parsed.extensions->data,
                                                                    cert_parsed.extensions->len);
            if (!cert_parsed.spki_raw || !cert_parsed.spki_raw->data || cert_parsed.spki_raw->len == 0)
            {
                return false;
            }

            /* Compute SHA-256 hash of SPKI for pinning */
            struct tls_hash_context hash_ctx;
            if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
            {
                return false;
            }
            tls_hash_update(&hash_ctx, cert_parsed.spki_raw->data, cert_parsed.spki_raw->len);
            tls_hash_digest(&hash_ctx, ctx->cert_state.server_cert_spki_hash);

            /* Validate SPKI hash against truststore */
            struct tls_spki_entry spki_entry;
            if (tls_truststore_lookup(ctx->cert_state.server_cert_spki_hash, &spki_entry))
            {
                const lwip_app_config_t *app_cfg = lwip_app_config_get();
                bool date_check_pass = true;
                bool owner_check_pass = true;

                /* Check validity period if configured and time is available */
                if (app_cfg && (app_cfg->flags & LWIP_CFG_CERT_CHECK_DATES))
                {
                    uint32_t current_time = lwip_sntp_get_unix_time();
                    if (current_time > 0)
                    {
                        /* Verify we're within the validity window */
                        if (current_time < spki_entry.not_before ||
                            current_time > spki_entry.not_after)
                        {
                            date_check_pass = false;
                        }
                    }
                    /* If time not available, skip date check */
                }

                /* Check owner if configured */
                if (app_cfg && (app_cfg->flags & LWIP_CFG_CERT_CHECK_OWNER))
                {
                    owner_check_pass = tls_subject_cn_matches_owner_id(cert_parsed.subject_cn,
                                                                       spki_entry.owner_id);
                }

                if (date_check_pass && owner_check_pass && constraints_check_pass)
                {
                    chain_validated = true;
                }
            }
        }
    }

    /* Store validation result */
    ctx->cert_state.certificate_validated = chain_validated;
    if (!chain_validated)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    /* Update transcript hash with the Certificate message */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }

    /* Update state */
    ctx->state = TLS_STATE_CERTIFICATE_RECEIVED;

    return true;
}

/**
 * @brief Process EncryptedExtensions message (server -> client)
 *
 * TLS 1.3 EncryptedExtensions message structure:
 * - HandshakeType (1 byte): 0x08 (EncryptedExtensions)
 * - Length (3 bytes): total message length
 * - extensions_length (2 bytes)
 * - extensions (variable): list of Extension structures
 *
 * For PSK mode, this message is typically empty or contains
 * minimal extensions. We parse it for completeness and update
 * the transcript hash.
 */
bool tls_recv_encrypted_extensions(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 6)
    {
        return false;
    }

    size_t offset = 0;

    /* Verify handshake type */
    if (data[offset++] != TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS)
    {
        return false;
    }

    /* Parse message length (3 bytes, big-endian) */
    size_t msg_len = ((size_t)data[offset] << 16) |
                     ((size_t)data[offset + 1] << 8) |
                     (size_t)data[offset + 2];
    offset += 3;

    if (offset + msg_len > data_len)
    {
        return false;
    }

    /* Parse extensions length (2 bytes) */
    if (offset + 2 > data_len)
    {
        return false;
    }
    size_t ext_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;

    /* Verify extensions fit in message */
    if (offset + ext_len > data_len)
    {
        return false;
    }

    /* Parse extensions (for now we just skip them, but could process
     * server_name, supported_groups, etc. if needed) */
    size_t ext_offset = 0;
    while (ext_offset + 4 <= ext_len)
    {
        /* Extension type (2 bytes) */
        uint16_t ext_type = ((uint16_t)data[offset + ext_offset] << 8) |
                            (uint16_t)data[offset + ext_offset + 1];
        ext_offset += 2;

        /* Extension data length (2 bytes) */
        uint16_t ext_data_len = ((uint16_t)data[offset + ext_offset] << 8) |
                                (uint16_t)data[offset + ext_offset + 1];
        ext_offset += 2;

        if (ext_offset + ext_data_len > ext_len)
        {
            return false;
        }

        /* Skip extension data - we don't process any extensions currently */
        (void)ext_type;
        ext_offset += ext_data_len;
    }
    if (ext_offset != ext_len)
    {
        return false;
    }

    /* Update transcript hash with the EncryptedExtensions message */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }

    /* Update state */
    ctx->state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;

    return true;
}

/**
 * @brief Process CertificateVerify message (server -> client)
 *
 * TLS 1.3 CertificateVerify message structure:
 * - HandshakeType (1 byte): 0x0f (CertificateVerify)
 * - Length (3 bytes): total message length
 * - algorithm (2 bytes): signature algorithm
 * - signature (2 byte length + signature data)
 *
 * Note: CertificateVerify signature verification is intentionally omitted
 * for now because the currently-available signature implementations are not
 * fast enough for this platform. This is a short-term tradeoff, not full
 * TLS 1.3 certificate authentication. We still require the message to be
 * present and well-formed so the state machine does not silently skip it.
 */
bool tls_recv_certificate_verify(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 8)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_CERTIFICATE_RECEIVED ||
        !ctx->cert_state.certificate_validated)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    size_t offset = 0;

    /* Verify handshake type */
    if (data[offset++] != TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY)
    {
        return false;
    }

    /* Parse message length (3 bytes, big-endian) */
    size_t msg_len = ((size_t)data[offset] << 16) |
                     ((size_t)data[offset + 1] << 8) |
                     (size_t)data[offset + 2];
    offset += 3;

    if (offset + msg_len > data_len)
    {
        return false;
    }

    /* Parse signature algorithm (2 bytes) - we don't verify but need to parse */
    if (offset + 2 > data_len)
    {
        return false;
    }
    offset += 2; /* Skip algorithm */

    /* Parse signature length (2 bytes) */
    if (offset + 2 > data_len)
    {
        return false;
    }
    size_t sig_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;

    /* Verify signature data fits */
    if (offset + sig_len > data_len)
    {
        return false;
    }
    if (offset + sig_len != 4 + msg_len)
    {
        return false;
    }

    /* Intentional short-term tradeoff:
     * We do not verify the signature here because an acceptably fast
     * certificate signature verification path is not available yet on this
     * platform. SPKI pinning is therefore treated as the current trust
     * decision, but this remains weaker than full certificate authentication.
     */

    /* Update transcript hash with the CertificateVerify message */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }

    /* Update state */
    ctx->state = TLS_STATE_CERTIFICATE_VERIFY_RECEIVED;

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

    /* Step 4: Compute handshake_secret
     * PSK+ECDHE: handshake_secret = HKDF-Extract(salt=derived, IKM=ecdhe_shared)
     * PSK-only:  handshake_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    {
        const uint8_t *ecdhe_ikm = ctx->ecdhe_negotiated ? ctx->ecdhe_shared : zero_ikm;
        if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                              ecdhe_ikm, 32, handshake_secret))
        {
            return false;
        }
        /* Securely erase shared secret after use */
        if (ctx->ecdhe_negotiated)
        {
            tls_secure_memzero(ctx->ecdhe_shared, 32);
        }
    }

    /* Step 5: Get transcript hash (ClientHello...ServerHello). */
    tls_secure_memzero(transcript_hash, 32);
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

    /* Advance state so this function is not called again */
    ctx->state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;

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
    memcpy(ctx->keys.master_secret, master_secret, 32);

    /* Step 4: Get transcript hash (ClientHello...server Finished). */
    tls_secure_memzero(transcript_hash, 32);
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
bool tls_send_finished(
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
        tls_secure_memzero(transcript_hash, 32);
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

    /* Client Finished completes transcript needed for resumption master secret. */
    if (is_client && ctx->transcript_hash)
    {
        uint8_t transcript_hash_full[32];
        transcript_hash_digest(ctx->transcript_hash, transcript_hash_full);
        if (!tls_derive_secret(TLS_HASH_SHA256, ctx->keys.master_secret, 32,
                               "res master", 10, transcript_hash_full, 32,
                               ctx->keys.resumption_master_secret))
        {
            return false;
        }
    }

    return true;
}

/**
 * @brief Verify Finished message
 */
bool tls_recv_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 36)
    {
        return false;
    }
    if (is_client)
    {
        uint8_t required_state = ctx->psk_mode ? TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED
                                               : TLS_STATE_CERTIFICATE_VERIFY_RECEIVED;
        if (ctx->state != required_state)
        {
            ctx->state = TLS_STATE_ERROR;
            return false;
        }
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
    size_t msg_len = ((size_t)data[offset] << 16) |
                     ((size_t)data[offset + 1] << 8) |
                     (size_t)data[offset + 2];
    offset += 3;

    if (msg_len != 32 || offset + 32 > data_len)
    {
        return false;
    }
    if (offset + 32 != data_len)
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
        tls_secure_memzero(transcript_hash, 32);
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

    /* Step 5: Update state */
    if (is_client)
    {
        /* Client verified server's Finished */
        ctx->state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    }

    return true;
}

bool tls_recv_new_session_ticket(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    size_t offset = 0;
    size_t msg_len;
    size_t msg_end;
    uint32_t ticket_lifetime;
    uint32_t ticket_age_add;
    uint8_t nonce_len;
    const uint8_t *nonce;
    uint16_t ticket_len;
    const uint8_t *ticket;
    uint16_t ext_len;

    if (!ctx || !data || data_len < 4)
    {
        return false;
    }

    if (data[offset++] != TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET)
    {
        return false;
    }

    msg_len = ((size_t)data[offset] << 16) |
              ((size_t)data[offset + 1] << 8) |
              (size_t)data[offset + 2];
    offset += 3;

    if (offset + msg_len > data_len)
    {
        return false;
    }
    msg_end = offset + msg_len;

    if (offset + 8 > msg_end)
    {
        return false;
    }
    ticket_lifetime = ((uint32_t)data[offset] << 24) |
                      ((uint32_t)data[offset + 1] << 16) |
                      ((uint32_t)data[offset + 2] << 8) |
                      (uint32_t)data[offset + 3];
    offset += 4;
    ticket_age_add = ((uint32_t)data[offset] << 24) |
                     ((uint32_t)data[offset + 1] << 16) |
                     ((uint32_t)data[offset + 2] << 8) |
                     (uint32_t)data[offset + 3];
    offset += 4;

    if (ticket_lifetime == 0)
    {
        return false;
    }

    if (offset + 1 > msg_end)
    {
        return false;
    }
    nonce_len = data[offset++];
    if (offset + nonce_len > msg_end)
    {
        return false;
    }
    nonce = data + offset;
    offset += nonce_len;

    if (offset + 2 > msg_end)
    {
        return false;
    }
    ticket_len = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;
    if (offset + ticket_len > msg_end)
    {
        return false;
    }
    ticket = data + offset;
    offset += ticket_len;

    if (offset + 2 > msg_end)
    {
        return false;
    }
    ext_len = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;
    if (offset + ext_len != msg_end)
    {
        return false;
    }

    if (ticket_len == 0 || ticket_len > TLS_PSK_IDENTITY_MAX_LEN)
    {
        return false;
    }
    if (nonce_len == 0)
    {
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.resumption_master_secret, 32,
                               "resumption", 10,
                               nonce, nonce_len,
                               ctx->psk, 32))
    {
        return false;
    }

    memcpy(ctx->psk_identity.identity, ticket, ticket_len);
    ctx->psk_identity.identity_len = ticket_len;
    ctx->psk_identity.obfuscated_ticket_age = ticket_age_add;
    ctx->ticket_age_add = ticket_age_add;
    ctx->ticket_received_ms = sys_now();
    ctx->psk_mode = true;
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
        tls_secure_memzero(plaintext, actual_plaintext_len); /* Clear plaintext */
        return false;
    }

    /* Step 8: Increment sequence number */
    ctx->server_seq_num++;

    *written = actual_plaintext_len;
    return true;
}

/**
 * @brief Decrypt a TLS 1.3 record (handshake or application phase)
 *
 * In TLS 1.3, encrypted records have outer content type 0x17.
 * The actual content type is appended after the plaintext inside the
 * encrypted payload: [plaintext || content_type || padding_zeros]
 *
 * @param record     Full TLS record (5-byte header + encrypted payload)
 * @param record_len Length of full record
 * @param use_handshake_keys  true = handshake keys, false = application keys
 */
bool tls_decrypt_record(
    struct tls_handshake_context *ctx,
    bool use_handshake_keys,
    const uint8_t *record, size_t record_len,
    uint8_t *plaintext, size_t plaintext_len,
    size_t *written, uint8_t *inner_content_type)
{
    if (!ctx || !record || !plaintext || !written || !inner_content_type)
        return false;

    /* Record must have at least 5-byte header + 16-byte tag + 1 content type */
    if (record_len < 5 + 16 + 1)
        return false;

    const uint8_t *header = record;
    const uint8_t *ciphertext = record + 5;
    size_t ciphertext_len = record_len - 5;
    size_t actual_plaintext_len = ciphertext_len - 16;

    if (plaintext_len < actual_plaintext_len)
        return false;

    /* Select keys based on phase */
    const uint8_t *key, *iv;
    uint64_t *seq_num;
    if (use_handshake_keys)
    {
        key = ctx->keys.server_handshake_key;
        iv = ctx->keys.server_handshake_iv;
        seq_num = &ctx->server_hs_seq_num;
    }
    else
    {
        key = ctx->keys.server_application_key;
        iv = ctx->keys.server_application_iv;
        seq_num = &ctx->server_seq_num;
    }

    /* Construct nonce = IV XOR sequence_number */
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
        nonce[12 - 8 + i] ^= (uint8_t)((*seq_num >> (56 - i * 8)) & 0xFF);

    /* AAD is the 5-byte record header */
    struct tls_aes_context aes_ctx;
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, 12))
        return false;
    if (!tls_aes_update_aad(&aes_ctx, header, 5))
        return false;
    if (!tls_aes_decrypt(&aes_ctx, ciphertext, actual_plaintext_len, plaintext))
        return false;

    /* Verify authentication tag */
    uint8_t computed_tag[16];
    if (!tls_aes_digest(&aes_ctx, computed_tag))
        return false;

    const uint8_t *received_tag = ciphertext + actual_plaintext_len;
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++)
        diff |= computed_tag[i] ^ received_tag[i];
    if (diff != 0)
    {
        tls_secure_memzero(plaintext, actual_plaintext_len);
        return false;
    }

    (*seq_num)++;

    /* Extract inner content type: last non-zero byte of decrypted payload */
    size_t pt_end = actual_plaintext_len;
    while (pt_end > 0 && plaintext[pt_end - 1] == 0)
        pt_end--;

    if (pt_end == 0)
        return false; /* No content type found */

    *inner_content_type = plaintext[pt_end - 1];
    *written = pt_end - 1; /* Exclude the content type byte */
    return true;
}

/**
 * @brief Encrypt a TLS 1.3 record (handshake or application phase)
 *
 * Builds a complete TLS record with 5-byte header, encrypted payload,
 * and authentication tag. The inner content type is appended to the
 * plaintext before encryption.
 *
 * @param record     Output buffer for full TLS record
 * @param record_len Size of output buffer
 */
bool tls_encrypt_record(
    struct tls_handshake_context *ctx,
    bool use_handshake_keys,
    uint8_t inner_content_type,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *record, size_t record_len,
    size_t *written)
{
    if (!ctx || !plaintext || !record || !written)
        return false;

    /* Need: 5 header + plaintext + 1 content_type + 16 tag */
    size_t inner_len = plaintext_len + 1; /* plaintext + content type byte */
    size_t total_len = 5 + inner_len + 16;
    if (record_len < total_len)
        return false;

    /* Select keys based on phase */
    const uint8_t *key, *iv;
    uint64_t *seq_num;
    if (use_handshake_keys)
    {
        key = ctx->keys.client_handshake_key;
        iv = ctx->keys.client_handshake_iv;
        seq_num = &ctx->client_hs_seq_num;
    }
    else
    {
        key = ctx->keys.client_application_key;
        iv = ctx->keys.client_application_iv;
        seq_num = &ctx->client_seq_num;
    }

    /* Build record header */
    record[0] = TLS_CONTENT_TYPE_APPLICATION_DATA; /* 0x17 */
    record[1] = 0x03;
    record[2] = 0x03; /* Legacy TLS 1.2 */
    record[3] = (uint8_t)((inner_len + 16) >> 8);
    record[4] = (uint8_t)((inner_len + 16) & 0xFF);

    /* Construct nonce */
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
        nonce[12 - 8 + i] ^= (uint8_t)((*seq_num >> (56 - i * 8)) & 0xFF);

    /* Build inner plaintext: [plaintext || content_type] in a temp buffer
     * We'll encrypt directly from plaintext, then handle the content type byte */
    uint8_t *enc_output = record + 5;

    struct tls_aes_context aes_ctx;
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, 12))
        return false;
    if (!tls_aes_update_aad(&aes_ctx, record, 5))
        return false;

    /* We need to encrypt [plaintext || content_type] as one stream.
     * Build it in enc_output temporarily, then encrypt in-place. */
    memcpy(enc_output, plaintext, plaintext_len);
    enc_output[plaintext_len] = inner_content_type;

    if (!tls_aes_encrypt(&aes_ctx, enc_output, inner_len, enc_output))
        return false;

    uint8_t auth_tag[16];
    if (!tls_aes_digest(&aes_ctx, auth_tag))
        return false;

    memcpy(enc_output + inner_len, auth_tag, 16);

    (*seq_num)++;
    *written = total_len;
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
        lwip_log_event(LWIP_LOG_MODULE_TLS, LWIP_LOG_TLS_FATAL_ALERT);
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
    tls_secure_memzero(ctx->psk, sizeof(ctx->psk));
    tls_secure_memzero(ctx->ecdhe_private, sizeof(ctx->ecdhe_private));
    tls_secure_memzero(ctx->ecdhe_shared, sizeof(ctx->ecdhe_shared));
    tls_secure_memzero(ctx->ecdhe_public, sizeof(ctx->ecdhe_public));
    tls_secure_memzero(&ctx->keys, sizeof(ctx->keys));
    tls_secure_memzero(ctx, sizeof(*ctx));
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
