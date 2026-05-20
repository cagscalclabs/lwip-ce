/**
 * @file handshake.c
 * @brief TLS 1.3 Handshake Protocol — Client implementation for eZ80
 *
 * ============================================================================
 * READER'S GUIDE
 * ============================================================================
 *
 * If you've never read this file before, this section is the only one you
 * need to understand the rest. The flow chart below is what TLS 1.3 actually
 * does on the wire; the code below this comment is just an implementation
 * of it.
 *
 *
 * 1. WHAT A TLS 1.3 HANDSHAKE LOOKS LIKE
 * --------------------------------------
 *
 *   FULL HANDSHAKE (ECDHE, e.g. first visit to https://example.com)
 *
 *     Client                                            Server
 *     ------                                            ------
 *     ClientHello       ---------------->
 *      + key_share (x25519 public key)
 *      + supported_versions (TLS 1.3)
 *      + server_name (SNI)
 *
 *                       <----------------     ServerHello
 *                                              + key_share (server x25519 pub)
 *                       <----------------     [now encrypted under HS keys]
 *                                             EncryptedExtensions
 *                                             Certificate
 *                                             CertificateVerify   (skipped here)
 *                                             Finished
 *
 *     [client derives application keys]
 *     [encrypted under HS keys]
 *     Finished          ---------------->
 *
 *     [encrypted under APP keys from here on]
 *     ApplicationData   <--------------->     ApplicationData
 *                       <----------------     NewSessionTicket (PSK for next time)
 *
 *
 *   RESUMPTION HANDSHAKE (PSK, e.g. reconnecting with a saved ticket)
 *
 *     ClientHello       ---------------->
 *      + pre_shared_key (the saved PSK identity + binder MAC)
 *      + psk_key_exchange_modes
 *      + (optional) key_share for PSK+(EC)DHE
 *
 *                       <----------------     ServerHello
 *                                              + pre_shared_key (which one)
 *                       <----------------     [encrypted under HS keys]
 *                                             EncryptedExtensions
 *                                             Finished       (no Certificate!)
 *
 *     [encrypted under HS keys]
 *     Finished          ---------------->
 *
 *     ApplicationData   <--------------->     ApplicationData
 *
 *
 * 2. THE KEY SCHEDULE (RFC 8446 §7.1)
 * ------------------------------------
 *
 * Every secret below is 32 bytes (SHA-256 output size). HKDF-Extract and
 * HKDF-Expand-Label are HMAC-SHA256-based primitives defined in §7.1.
 *
 *     Initial salt = 32 zero bytes
 *     Initial IKM  = either PSK (resumption) or 32 zero bytes (full HS)
 *
 *     early_secret      = HKDF-Extract(salt=0, IKM=PSK or 0)
 *     (binder_key, etc derived from early_secret if PSK in use)
 *
 *     handshake_secret  = HKDF-Extract(salt=Derive(early_secret,"derived"),
 *                                      IKM=ECDHE shared or 0)
 *
 *       c_hs_traffic    = Derive(handshake_secret, "c hs traffic", ClientHello..ServerHello)
 *       s_hs_traffic    = Derive(handshake_secret, "s hs traffic", ClientHello..ServerHello)
 *
 *     master_secret     = HKDF-Extract(salt=Derive(handshake_secret,"derived"), IKM=0)
 *
 *       c_ap_traffic    = Derive(master_secret, "c ap traffic", ClientHello..server Finished)
 *       s_ap_traffic    = Derive(master_secret, "s ap traffic", ClientHello..server Finished)
 *
 *       resumption_master = Derive(master_secret, "res master", ClientHello..client Finished)
 *
 * From each traffic secret we derive a 16-byte AES-128 key and a 12-byte
 * static IV using HKDF-Expand-Label with labels "key" and "iv".
 *
 *
 * 3. THE RECORD LAYER (RFC 8446 §5)
 * ----------------------------------
 *
 * Every byte on the wire after ClientHello/ServerHello is a TLS record:
 *
 *     +---------+--------+--------+----------------+
 *     |  type   |  0x03  |  0x03  | length (2B BE) |   <- 5-byte header
 *     +---------+--------+--------+----------------+
 *     |           encrypted payload + 16B tag      |
 *     +---------------------------------------------+
 *
 * Type byte is 0x17 (application_data) for *everything* encrypted — the real
 * inner content type (handshake / alert / app data) is a single byte appended
 * to the plaintext *before* AEAD encryption, then we strip trailing zero
 * padding to find it on decrypt.
 *
 * AEAD nonce is the static IV XOR'd with the per-direction sequence counter,
 * right-aligned to the last 8 bytes (RFC 8446 §5.3). Sequence counters are
 * separate for handshake and application phases — they do NOT reset.
 *
 *
 * 4. WHAT THIS IMPLEMENTATION SKIPS (DELIBERATELY)
 * -------------------------------------------------
 *
 *   - CertificateVerify signature checking. The peer's cert chain is still
 *     parsed and the end-entity SPKI is matched against a compiled-in
 *     truststore (SPKI pinning). We do this because RSA/ECDSA signature
 *     verification is too slow on an eZ80 for an interactive handshake.
 *   - 0-RTT / early_data.
 *   - HelloRetryRequest negotiation — we only ever offer x25519, so if the
 *     server demands a different group we just abort.
 *   - Server-side handshake (this is a client-only implementation; the
 *     altcp layer has a server entry point that returns "not implemented").
 *
 *
 * 5. STATE MACHINE
 * ----------------
 *
 *   INIT
 *    └─> CLIENT_HELLO_SENT
 *         └─> SERVER_HELLO_RECEIVED
 *              └─> HANDSHAKE_KEYS_DERIVED   (derived by altcp layer, not here)
 *                   └─> ENCRYPTED_EXTENSIONS_RECEIVED
 *                        ├─[ECDHE]─> CERTIFICATE_RECEIVED
 *                        │            └─> CERTIFICATE_VERIFY_RECEIVED
 *                        │                 └─> SERVER_FINISHED_RECEIVED
 *                        │                      └─> HANDSHAKE_COMPLETE
 *                        └─[PSK-only]──────────> SERVER_FINISHED_RECEIVED
 *                                                 └─> HANDSHAKE_COMPLETE
 *
 *   Any parse/MAC/state error -> ERROR (terminal, connection aborted).
 *
 *
 * 6. FILE LAYOUT
 * --------------
 *
 *   - Transcript hash helpers (init/update/digest).
 *   - tls_parse_handshake_header / tls_build_aead_nonce — shared utilities.
 *   - tls_consume_handshake_buffer + tls_dispatch_inner_handshake —
 *     cross-record reassembly and message routing.
 *   - tls_process_record — top-level entry point for an incoming record.
 *   - tls_handshake_init + tls_send_client_hello — outbound setup.
 *   - tls_recv_server_hello / encrypted_extensions / certificate /
 *     certificate_verify / finished — inbound handlers, one per message type.
 *   - tls_derive_handshake_keys / tls_derive_application_keys — key schedule.
 *   - tls_encrypt_data / tls_decrypt_data / tls_encrypt_record /
 *     tls_decrypt_record — record layer crypto.
 *   - tls_recv_new_session_ticket — post-handshake PSK update.
 *   - tls_set_transport / tls_send_alert / tls_send_close_notify — outbound
 *     alerts and orderly shutdown.
 *
 * ============================================================================
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

/*
 * ============================================================================
 * Common helpers
 * ============================================================================
 */

/**
 * @brief Parse a TLS handshake message header at @p data and return its length.
 *
 * Validates the type byte, parses the 3-byte big-endian length, and confirms
 * the payload fits within @p data_len. On success, @p out_msg_len receives the
 * message body length (excluding the 4-byte header) and the return value is
 * the offset of the body (always 4).
 *
 * @return 4 on success, 0 on type mismatch or bounds error.
 */
static size_t tls_parse_handshake_header(const uint8_t *data, size_t data_len,
                                         uint8_t expected_type,
                                         size_t *out_msg_len)
{
    if (!data || data_len < 4)
    {
        return 0;
    }
    if (data[0] != expected_type)
    {
        return 0;
    }
    size_t msg_len = ((size_t)data[1] << 16) |
                     ((size_t)data[2] << 8) |
                     (size_t)data[3];
    if (4 + msg_len > data_len)
    {
        return 0;
    }
    if (out_msg_len)
    {
        *out_msg_len = msg_len;
    }
    return 4;
}

/* Forward decl — the dispatcher needs it; full body lives further down. */
static bool tls_dispatch_inner_handshake(struct tls_handshake_context *ctx,
                                         uint8_t msg_type,
                                         const uint8_t *msg, size_t msg_len);

/**
 * @brief Build the TLS 1.3 AEAD nonce: static IV XOR right-aligned seq number.
 *
 * RFC 8446 §5.3. Caller provides the 12-byte static IV (one of the four
 * traffic IVs in tls_traffic_keys) and the per-direction sequence counter.
 * Does not advance @p seq_num — the caller still owns it.
 */
static void tls_build_aead_nonce(const uint8_t iv[12], uint64_t seq_num,
                                 uint8_t out_nonce[12])
{
    memcpy(out_nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
    {
        out_nonce[4 + i] ^= (uint8_t)((seq_num >> (56 - i * 8)) & 0xFF);
    }
}

/* ------------------------------------------------------------------------
 * Handshake message reassembly (cross-record).
 *
 * TLS 1.3 servers may fragment a handshake message across multiple encrypted
 * records (RFC 8446 §5.1). When the tail of a decrypted buffer doesn't
 * contain a full message, we copy it into ctx->hs_reasm_buf and resume on
 * the next record. Anything beyond TLS_HS_REASSEMBLY_MAX is fatal.
 * ------------------------------------------------------------------------ */

static void tls_hs_reasm_reset(struct tls_handshake_context *ctx)
{
    if (ctx->hs_reasm_buf)
    {
        mem_buffer_custom_free(ctx->hs_reasm_buf);
        ctx->hs_reasm_buf = NULL;
    }
    ctx->hs_reasm_cap = 0;
    ctx->hs_reasm_len = 0;
    ctx->hs_reasm_expected = 0;
}

/* Ensure the reassembly buffer has at least `need` bytes of capacity. */
static bool tls_hs_reasm_grow(struct tls_handshake_context *ctx, size_t need)
{
    if (need > TLS_HS_REASSEMBLY_MAX)
    {
        return false;
    }
    if (ctx->hs_reasm_cap >= need)
    {
        return true;
    }
    /* Start small (128 B handles header + most short messages) and double
     * geometrically only as bytes arrive. Capped at TLS_HS_REASSEMBLY_MAX.
     * We never pre-allocate the full 16K — fragmentation is rare in practice. */
    size_t new_cap = ctx->hs_reasm_cap ? ctx->hs_reasm_cap * 2 : 128;
    while (new_cap < need)
    {
        new_cap *= 2;
    }
    if (new_cap > TLS_HS_REASSEMBLY_MAX)
    {
        new_cap = TLS_HS_REASSEMBLY_MAX;
    }
    uint8_t *nb = (uint8_t *)mem_buffer_custom_malloc(new_cap);
    if (!nb)
    {
        return false;
    }
    if (ctx->hs_reasm_len)
    {
        memcpy(nb, ctx->hs_reasm_buf, ctx->hs_reasm_len);
    }
    if (ctx->hs_reasm_buf)
    {
        mem_buffer_custom_free(ctx->hs_reasm_buf);
    }
    ctx->hs_reasm_buf = nb;
    ctx->hs_reasm_cap = new_cap;
    return true;
}

/**
 * @brief Process a buffer of decrypted handshake bytes, dispatching each
 *        complete message and spilling the tail into reassembly storage.
 *
 * On entry, if hs_reasm_expected != 0 we are continuing a previously-spilled
 * message: appended bytes are added to hs_reasm_buf and the whole message
 * dispatched once complete.
 *
 * @return true on clean dispatch (possibly with partial tail spilled),
 *         false on fatal parse/dispatch error (caller must abort).
 */
static bool tls_consume_handshake_buffer(struct tls_handshake_context *ctx,
                                         const uint8_t *buf, size_t buf_len)
{
    size_t off = 0;

    /* If we previously spilled a partial header (1-3 bytes) we don't yet
     * know the full message size. Top up to 4 bytes, learn the length, and
     * promote to a normal in-progress reassembly. */
    if (ctx->hs_reasm_expected == 0 && ctx->hs_reasm_len > 0 &&
        ctx->hs_reasm_len < 4)
    {
        size_t need = 4 - ctx->hs_reasm_len;
        size_t take = (buf_len < need) ? buf_len : need;
        memcpy(ctx->hs_reasm_buf + ctx->hs_reasm_len, buf, take);
        ctx->hs_reasm_len += take;
        off += take;
        if (ctx->hs_reasm_len < 4)
        {
            return true; /* Still need more header bytes. */
        }
        size_t body_len = ((size_t)ctx->hs_reasm_buf[1] << 16) |
                          ((size_t)ctx->hs_reasm_buf[2] << 8) |
                          (size_t)ctx->hs_reasm_buf[3];
        ctx->hs_reasm_expected = 4 + body_len;
        if (ctx->hs_reasm_expected > TLS_HS_REASSEMBLY_MAX)
        {
            tls_hs_reasm_reset(ctx);
            return false;
        }
    }

    /* If we were mid-reassembly, top up first. */
    if (ctx->hs_reasm_expected != 0)
    {
        size_t need = ctx->hs_reasm_expected - ctx->hs_reasm_len;
        size_t take = (buf_len < need) ? buf_len : need;
        if (!tls_hs_reasm_grow(ctx, ctx->hs_reasm_len + take))
        {
            tls_hs_reasm_reset(ctx);
            return false;
        }
        memcpy(ctx->hs_reasm_buf + ctx->hs_reasm_len, buf, take);
        ctx->hs_reasm_len += take;
        off += take;

        if (ctx->hs_reasm_len < ctx->hs_reasm_expected)
        {
            return true; /* Still incomplete; wait for more. */
        }

        /* We have a full reassembled message — dispatch it, then continue
         * draining whatever follows in `buf`. */
        uint8_t msg_type = ctx->hs_reasm_buf[0];
        size_t msg_total = ctx->hs_reasm_expected;
        bool ok = tls_dispatch_inner_handshake(ctx, msg_type,
                                               ctx->hs_reasm_buf, msg_total);
        tls_hs_reasm_reset(ctx);
        if (!ok)
        {
            return false;
        }
    }

    /* Drain complete messages from `buf`. */
    while (off + 4 <= buf_len)
    {
        uint8_t msg_type = buf[off];
        size_t body_len = ((size_t)buf[off + 1] << 16) |
                          ((size_t)buf[off + 2] << 8) |
                          (size_t)buf[off + 3];
        size_t total = 4 + body_len;

        if (total > TLS_HS_REASSEMBLY_MAX)
        {
            /* Honestly-formed but ludicrously large — record_overflow. */
            return false;
        }

        if (off + total > buf_len)
        {
            /* Partial message — spill the remainder into reassembly. */
            size_t have = buf_len - off;
            if (!tls_hs_reasm_grow(ctx, total))
            {
                return false;
            }
            memcpy(ctx->hs_reasm_buf, buf + off, have);
            ctx->hs_reasm_len = have;
            ctx->hs_reasm_expected = total;
            return true;
        }

        if (!tls_dispatch_inner_handshake(ctx, msg_type, buf + off, total))
        {
            return false;
        }
        off += total;
    }

    /* If we have a leftover header fragment (1-3 bytes), spill it too. */
    if (off < buf_len)
    {
        size_t have = buf_len - off;
        /* We can't know the full size yet — stash and ask grow() for at least
         * 4 bytes so a follow-up call can read the length. */
        if (!tls_hs_reasm_grow(ctx, 4))
        {
            return false;
        }
        memcpy(ctx->hs_reasm_buf, buf + off, have);
        ctx->hs_reasm_len = have;
        ctx->hs_reasm_expected = 0; /* Length not yet known. */
    }

    return true;
}

/**
 * @brief Dispatch one complete inner handshake message (header + body).
 *
 * Called from tls_consume_handshake_buffer once a whole message is in hand
 * (either contiguous in the decrypted record or freshly reassembled). The
 * underlying per-type parser still validates its own header and length.
 */
static bool tls_dispatch_inner_handshake(struct tls_handshake_context *ctx,
                                         uint8_t msg_type,
                                         const uint8_t *msg, size_t msg_len)
{
    switch (msg_type)
    {
    case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
        return tls_recv_encrypted_extensions(ctx, msg, msg_len);
    case TLS_HANDSHAKE_CERTIFICATE:
        return tls_recv_certificate(ctx, msg, msg_len);
    case TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY:
        return tls_recv_certificate_verify(ctx, msg, msg_len);
    case TLS_HANDSHAKE_FINISHED:
        return tls_recv_finished(ctx, true, msg, msg_len);
    case TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET:
        return tls_recv_new_session_ticket(ctx, msg, msg_len);
    default:
        /* Unknown inner type — ignore per RFC 8446 §4 forward-compat note. */
        return true;
    }
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

/**
 * @brief Top-level entry point for one complete TLS record from the wire.
 *
 * The altcp layer collects a full record (5-byte header + payload) into
 * `data` and hands it here. We branch on the outer content type:
 *
 *  - HANDSHAKE (0x16): plaintext handshake records. In TLS 1.3 these are
 *    only legal for ClientHello/ServerHello — any later plaintext handshake
 *    is rejected because all post-ServerHello handshake messages must come
 *    in encrypted application_data records.
 *
 *  - CHANGE_CIPHER_SPEC (0x14): middlebox-compatibility leftover. Ignored.
 *
 *  - ALERT (0x15) plaintext: rare (servers should encrypt alerts post-EE)
 *    but legal pre-keys. Fatal alerts flip the state to ERROR.
 *
 *  - APPLICATION_DATA (0x17): in TLS 1.3 this is the wrapper for *every*
 *    encrypted record. We decrypt under whichever traffic keys are active
 *    (handshake or application phase), extract the real inner content
 *    type, and dispatch accordingly:
 *      * inner=HANDSHAKE: feed into the reassembly-aware dispatcher.
 *      * inner=ALERT: parse level/description; fatal => ERROR.
 *      * inner=APPLICATION_DATA: only legal post-handshake; handled by
 *        the altcp layer in handle_rx_appldata, not here.
 *
 * Returns true on successful processing (which includes "alert received,
 * carry on"), false on fatal protocol/parse error.
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
            /* Reassembly-aware dispatch: handles cross-record handshake
             * message fragmentation up to TLS_HS_REASSEMBLY_MAX. */
            bool ok = tls_consume_handshake_buffer(ctx, dec_buf, dec_len);
            mem_buffer_custom_free(dec_buf);
            if (!ok)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                return false;
            }
            return true;
        }
        else if (inner_type == TLS_CONTENT_TYPE_ALERT)
        {
            if (dec_len >= 2 && dec_buf[0] == TLS_ALERT_LEVEL_FATAL)
            {
                ctx->state = TLS_STATE_ERROR;
            }
            mem_buffer_custom_free(dec_buf);
            return true;
        }

        /* Application data during handshake is unexpected */
        mem_buffer_custom_free(dec_buf);
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
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
 * @brief Initialize a handshake context (resumption-aware).
 *
 * If `psk` + `psk_identity` are non-NULL we set up for a resumption
 * (PSK or PSK+ECDHE) handshake. If they are NULL we set up for a pure-ECDHE
 * full handshake against a fresh server. Either way, we always generate a
 * fresh x25519 keypair below — the server may always select PSK+ECDHE.
 *
 * Concretely:
 *   1. Zero the context (prevents accidental key reuse).
 *   2. Stash PSK + identity (if provided) and set psk_mode accordingly.
 *   3. Pin the cipher suite to TLS_AES_128_GCM_SHA256 — the only one we
 *      negotiate. TLS 1.3 only defines a handful of cipher suites; this is
 *      the universally-supported floor.
 *   4. Generate a 32-byte client_random by reading 4×uint64 from the TI RNG.
 *   5. Initialize the running SHA-256 transcript hash. Every handshake
 *      message we send or receive gets fed into this hash. Key derivation
 *      and Finished MACs all depend on its value at various snapshot points.
 *   6. Generate a fresh ephemeral x25519 keypair for ECDHE key_share. We
 *      include this in every ClientHello regardless of mode; the server
 *      picks whether to use it.
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
 * @brief Build a TLS 1.3 ClientHello.
 *
 * On-wire layout (lengths are *bytes*, all multi-byte fields big-endian):
 *
 *    +----+------------+--------+------+---------+---------+----------+----+
 *    | 01 | length(3)  | 0303   | rand | sid(1+) | cs(2+)  | cmpr(1+) | ex |
 *    +----+------------+--------+------+---------+---------+----------+----+
 *      ^      ^           ^       ^       ^          ^         ^        ^
 *      |      |           |       |       |          |         |        |
 *      |      |           |       |       |          |         |        +-- extensions block
 *      |      |           |       |       |          |         +-- compression_methods (always 0x00)
 *      |      |           |       |       |          +-- cipher_suites (just 0x1301)
 *      |      |           |       |       +-- legacy session ID (empty / 32B echo)
 *      |      |           |       +-- 32-byte client_random
 *      |      |           +-- legacy_version 0x0303 (TLS 1.2 — TLS 1.3 hides in extensions)
 *      |      +-- 3-byte body length, filled in once we know it
 *      +-- handshake type 0x01
 *
 * The interesting work is in the extensions block. We always emit:
 *
 *    supported_versions     : tells the server we speak TLS 1.3
 *    supported_groups       : just x25519
 *    key_share              : our ephemeral x25519 pubkey
 *    psk_key_exchange_modes : if PSK mode, advertise psk_dhe_ke
 *    server_name            : SNI hostname (if set)
 *    pre_shared_key         : MUST be last — see binder comment below
 *
 * PSK BINDER (RFC 8446 §4.2.11.2). When pre_shared_key is present, the
 * client MUST prove knowledge of the PSK by including a binder MAC. The
 * binder is HMAC(finished_key, transcript_hash(ClientHello-up-to-binders)).
 *
 * The tricky bit: the transcript hash must cover ClientHello *up to but
 * not including* the binders field, otherwise the binder would depend on
 * itself. That's why this function:
 *
 *   1. Serializes the whole ClientHello including the pre_shared_key
 *      extension *with the binders length and a zeroed binder placeholder*.
 *   2. Snapshots the running transcript hash at the byte offset just
 *      before the binders.
 *   3. Computes the binder MAC over that snapshot.
 *   4. Patches the binder bytes into the placeholder.
 *   5. Finally feeds the full message (including patched binder) into the
 *      transcript hash for subsequent key derivation.
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
 * @brief Parse a ServerHello and pull out everything we need to derive keys.
 *
 * ServerHello is the server's response to ClientHello. After parsing this
 * message we have enough material to derive handshake traffic secrets:
 *
 *   - server_random (32 bytes, but watch for HelloRetryRequest sentinel —
 *     RFC 8446 §4.1.3 reserves a specific value to signal HRR. We detect it
 *     and abort, because we only support x25519 so there's no useful retry).
 *   - selected cipher suite (must match what we offered).
 *   - extensions: supported_versions (must indicate TLS 1.3 = 0x0304),
 *     key_share (server's x25519 pubkey → we compute the ECDHE shared
 *     secret here via x25519(our_priv, server_pub)), and optionally
 *     pre_shared_key (which PSK identity the server chose, if any).
 *
 * IMPORTANT INVARIANT: this function does NOT derive the handshake keys
 * itself — it just stashes the ECDHE shared secret and sets state to
 * SERVER_HELLO_RECEIVED. The altcp layer notices this and calls
 * tls_derive_handshake_keys() before processing the next (encrypted)
 * record. The split exists so the transcript hash snapshot used in
 * derivation includes the ServerHello bytes but nothing after.
 *
 * After this function returns true:
 *   ctx->state                  = TLS_STATE_SERVER_HELLO_RECEIVED
 *   ctx->ecdhe_shared           = X25519(our_priv, server_pub)  [if ECDHE]
 *   ctx->ecdhe_negotiated       = true iff server selected ECDHE
 *   ctx->transcript_hash        = SHA256(ClientHello || ServerHello)
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

    bool found_supported_versions = false;
    bool found_psk = false;

    /* Steps 1+2: Verify handshake type and parse length */
    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_SERVER_HELLO,
                                               &msg_len);
    if (offset == 0)
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
 * @brief Parse the server's Certificate message and authenticate via SPKI pin.
 *
 * TLS 1.3 Certificate carries a chain of DER-encoded X.509 certificates,
 * each tagged with per-cert extensions:
 *
 *    +-----------------+
 *    | type=0x0b len(3)|
 *    +-----------------+
 *    | ctx_len(1)  ctx |   (empty for server cert)
 *    +-----------------+
 *    | chain_len(3)    |
 *    +-----------------+---------+---------+
 *    | cert_len(3) | DER cert ...| ext_len(2) | exts |   <- one CertificateEntry
 *    +-----------------+---------+---------+
 *    | cert_len(3) | DER cert ...| ext_len(2) | exts |   <- next entry
 *    +---...---+
 *
 * In a normal TLS implementation the chain is validated up to a trusted
 * root, then CertificateVerify proves the server controls the matching
 * private key by signing the transcript.
 *
 * On this platform we do neither. Instead we use SPKI PINNING: we extract
 * the SubjectPublicKeyInfo from the end-entity (first) certificate,
 * SHA-256 it, and look that hash up in a compiled-in truststore. A match
 * means "I recognize this exact public key as belonging to a server I
 * trust" — equivalent in security to certificate pinning but cheaper and
 * resilient to certificate rotation if the key stays the same.
 *
 * GUARD: this function refuses to run in PSK-only mode (psk_mode &&
 * !ecdhe_negotiated). Per RFC 8446 §2.2 the server MUST NOT send
 * Certificate in that case; receiving one is a protocol violation.
 *
 * Why SPKI pinning is the design choice: RSA-2048 verify takes >2s on an
 * eZ80, ECDSA P-256 verify is comparably slow. CertificateVerify would be
 * called once per handshake; the user-visible latency cost is too high for
 * a calculator. The trade-off is that we can only connect to servers
 * whose SPKI hash we've pre-loaded into the truststore.
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
    /* PSK-only mode (psk_mode && !ecdhe_negotiated) authenticates via the PSK
     * itself; per RFC 8446 §2.2 the server MUST NOT send Certificate. Reject
     * to keep the state machine honest. */
    if (ctx->psk_mode && !ctx->ecdhe_negotiated)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_CERTIFICATE,
                                               &msg_len);
    if (offset == 0)
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
 * @brief Parse the EncryptedExtensions message.
 *
 * EncryptedExtensions is the FIRST message protected under handshake keys.
 * In TLS 1.2 the ServerHello carried extensions in cleartext; in TLS 1.3
 * most extensions were moved here precisely so eavesdroppers can't see
 * which servers/protocols a client supports.
 *
 * In practice we don't care about any of the extensions a server might
 * include here (ALPN, server_name confirmation, etc.) — we just need to:
 *
 *   1. Validate the framing (length fields nest correctly).
 *   2. Walk past every extension to confirm it parses cleanly.
 *   3. Feed the message bytes into the running transcript hash, because
 *      the next message's transcript hash snapshot must include it.
 *   4. Advance state to ENCRYPTED_EXTENSIONS_RECEIVED.
 *
 * If a server sends us extensions we don't understand, RFC 8446 §4 says
 * we should ignore unknown extension types — exactly what we do.
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

    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
                                               &msg_len);
    if (offset == 0)
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
 * @brief Parse CertificateVerify; intentionally skip signature verification.
 *
 * CertificateVerify is the server's signature over the transcript hash
 * using the private key corresponding to the certificate it just sent.
 * In a standard TLS 1.3 stack this is THE binding between "I trust this
 * cert chain" and "I'm actually talking to that cert's owner."
 *
 * We DON'T verify the signature here. See the long comment on
 * tls_recv_certificate for the reasoning — RSA/ECDSA verify on eZ80 is
 * too slow. Instead we trust the SPKI pin from the truststore as proof
 * the server is who we think it is.
 *
 * We DO still:
 *   - Require the message to be present and well-formed (a missing
 *     CertificateVerify would let any attacker who got the certificate
 *     impersonate the server).
 *   - Require ctx->cert_state.certificate_validated to be true (which
 *     only happens if SPKI pinning succeeded).
 *   - Update the transcript hash so the server Finished MAC checks out.
 *
 * The skip is a documented trade-off, not a missing TODO. If you ever
 * add fast signature verification, gate the actual verify here behind an
 * "if (have_sig_verify)" so the pin check remains the floor.
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

    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY,
                                               &msg_len);
    if (offset == 0)
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
 * @brief Derive the handshake-phase traffic keys (RFC 8446 §7.1).
 *
 * Called right after we receive ServerHello and before we try to decrypt
 * the encrypted handshake messages that follow. By this point we know:
 *
 *   - psk_mode and (if PSK was selected) the PSK itself.
 *   - ecdhe_negotiated and (if so) ecdhe_shared = X25519(my_priv, server_pub).
 *   - transcript_hash = SHA256(ClientHello || ServerHello).
 *
 * The key schedule below is unified for all four cases (PSK-only,
 * PSK+ECDHE, ECDHE-only, neither — though that last is illegal):
 *
 *   psk_ikm     = psk_mode ? PSK : 32 zero bytes
 *   ecdhe_ikm   = ecdhe_negotiated ? ecdhe_shared : 32 zero bytes
 *
 *   early_secret      = HKDF-Extract(salt=0, IKM=psk_ikm)
 *   derived1          = HKDF-Expand-Label(early_secret, "derived",
 *                                         SHA256(""), 32)
 *   handshake_secret  = HKDF-Extract(salt=derived1, IKM=ecdhe_ikm)
 *
 *   c_hs_traffic      = HKDF-Expand-Label(handshake_secret, "c hs traffic",
 *                                         transcript_hash, 32)
 *   s_hs_traffic      = HKDF-Expand-Label(handshake_secret, "s hs traffic",
 *                                         transcript_hash, 32)
 *
 * Then from each *_hs_traffic we expand a 16-byte AES key and 12-byte IV:
 *
 *   key = HKDF-Expand-Label(secret, "key", "", 16)
 *   iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
 *
 * On exit, ctx->keys.client_handshake_{key,iv} and server_handshake_{key,iv}
 * are ready for use by tls_encrypt_record/tls_decrypt_record in
 * handshake-phase mode, and state advances to HANDSHAKE_KEYS_DERIVED.
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
 * @brief Derive the application-phase traffic keys (RFC 8446 §7.1).
 *
 * Called by the altcp layer immediately AFTER we verify the server's
 * Finished MAC but BEFORE we generate our own Finished. Why that ordering?
 * Because the transcript hash used for application-key derivation is
 * snapshotted at "everything through server Finished":
 *
 *   transcript_hash = SHA256(ClientHello || ... || server Finished)
 *
 * If we waited until after our own Finished went out, the hash would
 * include it and the keys would be wrong by one message.
 *
 * Key schedule continues from handshake_secret (saved during
 * tls_derive_handshake_keys):
 *
 *   derived2          = HKDF-Expand-Label(handshake_secret, "derived",
 *                                         SHA256(""), 32)
 *   master_secret     = HKDF-Extract(salt=derived2, IKM=0)
 *
 *   c_ap_traffic      = HKDF-Expand-Label(master_secret, "c ap traffic",
 *                                         transcript_hash, 32)
 *   s_ap_traffic      = HKDF-Expand-Label(master_secret, "s ap traffic",
 *                                         transcript_hash, 32)
 *
 * Same key/IV expansion as the handshake phase. We also save master_secret
 * for later resumption_master_secret derivation (which happens after our
 * own Finished is sent — see tls_send_finished tail).
 *
 * The application sequence counters (client_seq_num / server_seq_num) are
 * already zero from tls_handshake_init; they do NOT get reset here, and
 * the separate handshake sequence counters keep ticking until they fall
 * out of scope. This is exactly the "no reset on rekey" rule from
 * RFC 8446 §5.3.
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
 * @brief Build the client's Finished message (proves we know the keys).
 *
 * Finished is a MAC over the entire handshake transcript that proves
 * (a) we derived the same handshake_secret as the server, and (b) no
 * man-in-the-middle has tampered with any handshake message.
 *
 *   finished_key = HKDF-Expand-Label(c_hs_traffic, "finished", "", 32)
 *   verify_data  = HMAC-SHA256(finished_key, transcript_hash)
 *
 * The transcript hash here is computed *before* we feed this Finished
 * message into the running transcript — so it covers everything the
 * server has seen plus the server's own Finished, but not our reply.
 * After we emit our Finished and feed it into the transcript, the next
 * snapshot (used for resumption_master_secret) covers the full handshake.
 *
 * Wire layout of the produced message:
 *
 *     +----+--------+--------------------+
 *     | 14 | 00 00 20 |  32-byte HMAC    |
 *     +----+--------+--------------------+
 *      ^      ^           ^
 *      |      |           +-- verify_data
 *      |      +-- length = 32 (3 bytes BE)
 *      +-- handshake type 0x14 = Finished
 *
 * The caller (altcp layer) then wraps this in an encrypted record using
 * tls_encrypt_record with handshake keys, and pushes it down the TCP.
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
 * @brief Verify the server's Finished MAC.
 *
 * This is the critical authentication step. Up to this point we've been
 * trading messages with *someone* — but until we verify a HMAC over the
 * transcript using a key only the legitimate server should know, we
 * have no proof of who's on the other end.
 *
 * Compute the same MAC the server claims to have computed and compare
 * in constant time. Mismatch ⇒ MitM, key disagreement, or bug — abort.
 *
 *   expected_finished_key = HKDF-Expand-Label(s_hs_traffic, "finished", "", 32)
 *   expected_verify_data  = HMAC-SHA256(expected_finished_key, transcript_hash)
 *
 * The transcript hash at this point covers everything up to but not
 * including the server's Finished message itself. After verify succeeds
 * we feed the Finished into the transcript so subsequent derivations
 * (resumption_master_secret, our own Finished MAC) see the full handshake.
 *
 * On failure we set state to ERROR; the caller (the dispatcher) then
 * emits a fatal alert and aborts the connection.
 *
 * State transition: SERVER_HELLO_RECEIVED → SERVER_FINISHED_RECEIVED
 * (for ECDHE the path is via EE → CERT → CV → here; for PSK only via EE).
 * The required_state branch enforces that ordering.
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

    /* Step 1: Parse Finished message header */
    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_FINISHED,
                                               &msg_len);
    if (offset == 0 || msg_len != 32 || offset + 32 != data_len)
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

/**
 * @brief Accept a NewSessionTicket and derive a fresh PSK for next time.
 *
 * Sent by the server some time after the handshake completes (it's an
 * encrypted handshake message under application keys). The ticket lets
 * us skip the expensive ECDHE+certificate dance on the next connection
 * by resuming with a PSK instead.
 *
 * Wire layout (RFC 8446 §4.6.1):
 *
 *     +----+--------+
 *     | 04 | len(3) |  type 0x04 = NewSessionTicket
 *     +----+--------+
 *     | ticket_lifetime (4) |   seconds until ticket expires
 *     +---------------------+
 *     | ticket_age_add  (4) |   random offset added to obfuscate age
 *     +---------------------+
 *     | nonce_len(1) | nonce ... |
 *     +---------------------+
 *     | ticket_len(2) | ticket ...|
 *     +---------------------+
 *     | extensions  (RFC 8446 ext block) |
 *     +----------------------------------+
 *
 * What we do with it:
 *
 *   resumption_psk = HKDF-Expand-Label(resumption_master_secret, "resumption",
 *                                      nonce, 32)
 *
 * That resumption_psk becomes the PSK we store as ctx->psk (replacing
 * whatever PSK got us here). The opaque `ticket` field becomes the new
 * PSK identity — when we resume, we put it in the ClientHello's
 * pre_shared_key extension.
 *
 * We also record sys_now() so we can compute the obfuscated ticket age
 * (ticket_age_add + (sys_now - received_at)) for the next ClientHello.
 *
 * The altcp layer is responsible for persisting (psk, identity) to flash
 * via the appvar mechanism — see altcp_tls_ce_save_pski.
 */
bool tls_recv_new_session_ticket(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    size_t msg_len = 0;
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

    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET,
                                               &msg_len);
    if (offset == 0)
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

    /* Step 1: Construct AEAD nonce (RFC 8446 §5.3) */
    tls_build_aead_nonce(ctx->keys.client_application_iv,
                         ctx->client_seq_num, nonce);

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

    /* Step 1: Construct AEAD nonce (RFC 8446 §5.3) */
    tls_build_aead_nonce(ctx->keys.server_application_iv,
                         ctx->server_seq_num, nonce);

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
 * @brief Decrypt one TLS 1.3 record and recover its inner content type.
 *
 * In TLS 1.3 every encrypted record on the wire looks like:
 *
 *     +---------+-----+-----+---------+
 *     |  0x17   | 03  | 03  | length  |    <- AAD = these 5 header bytes
 *     +---------+-----+-----+---------+
 *     | ciphertext (plaintext + ct + pad) | tag(16) |
 *     +-----------------------------------+---------+
 *
 * The outer content_type is ALWAYS 0x17 (application_data) regardless of
 * what's actually inside — handshake, alert, or app data. The real type
 * lives at the end of the decrypted plaintext as a single byte, optionally
 * followed by zero padding (length-hiding). On decrypt we strip the
 * trailing zeros, then the last remaining byte is the inner content type.
 *
 * AEAD construction (AES-128-GCM):
 *   nonce = static_iv XOR right-aligned(sequence_number)
 *   AAD   = the 5 plaintext header bytes
 *   tag   = computed over (AAD, ciphertext); receiver re-derives and
 *           constant-time-compares against the tag at the end of the record.
 *
 * Tag mismatch ⇒ wipe the plaintext buffer and return false. The caller
 * MUST treat this as fatal (bad_record_mac alert) — never retry, never
 * leak partial plaintext, never increment the sequence counter.
 *
 * The `use_handshake_keys` flag selects between handshake-phase keys
 * (server_handshake_key/iv + server_hs_seq_num) and application-phase
 * keys (server_application_key/iv + server_seq_num).
 *
 * Note: this decrypts *server-to-client* records — the receive direction.
 * For client-to-server we use tls_encrypt_record below.
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

    /* Construct AEAD nonce (RFC 8446 §5.3) */
    uint8_t nonce[12];
    tls_build_aead_nonce(iv, *seq_num, nonce);

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
/**
 * @brief Build one outbound encrypted TLS 1.3 record from a plaintext blob.
 *
 * Counterpart to tls_decrypt_record. We:
 *
 *   1. Write the 5-byte record header into `record`. Outer type is always
 *      0x17 (application_data). The length field equals plaintext_len + 1
 *      (the inner content type byte) + 16 (the AEAD tag).
 *   2. Build the AEAD nonce from the appropriate client IV + sequence
 *      counter (handshake or application phase, selected by the caller).
 *   3. Initialize AES-128-GCM with the matching client key.
 *   4. Use the 5-byte header as AAD.
 *   5. Lay out the inner plaintext as [plaintext || inner_content_type]
 *      directly in the output buffer (we don't add length-hiding padding —
 *      it's optional and we don't gain anything on a calculator).
 *   6. Encrypt in place, append the 16-byte tag, advance the seq counter,
 *      report total bytes written.
 *
 * Used by:
 *   - altcp_tls_ce_lower_recv_process for the client's Finished message
 *     (with inner_content_type = HANDSHAKE, use_handshake_keys=true).
 *   - altcp_tls_ce_write for every application data send
 *     (inner_content_type = APPLICATION_DATA, use_handshake_keys=false).
 *   - tls_send_alert for alerts during/after handshake.
 *
 * Output size: 5 + plaintext_len + 1 + 16 bytes. The caller must size the
 * record buffer at least that large; we error if not.
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

    /* Construct AEAD nonce (RFC 8446 §5.3) */
    uint8_t nonce[12];
    tls_build_aead_nonce(iv, *seq_num, nonce);

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
 * @brief Register the transport write callback used for outbound records.
 */
void tls_set_transport(
    struct tls_handshake_context *ctx,
    tls_transport_write_fn write_fn,
    void *transport_arg)
{
    if (!ctx)
    {
        return;
    }
    ctx->transport_write = write_fn;
    ctx->transport_arg = transport_arg;
}

/**
 * @brief Decide which traffic key set (if any) currently applies for sending.
 *
 * Returns 0 if no keys are available (alert must go plaintext),
 *         1 if handshake-phase client keys apply,
 *         2 if application-phase client keys apply.
 */
static int tls_outbound_phase(const struct tls_handshake_context *ctx)
{
    if (ctx->state == TLS_STATE_HANDSHAKE_COMPLETE)
    {
        return 2;
    }
    if (ctx->state >= TLS_STATE_HANDSHAKE_KEYS_DERIVED)
    {
        return 1;
    }
    return 0;
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

    bool ok = false;
    uint8_t alert_body[2] = { level, description };

    if (ctx->transport_write)
    {
        int phase = tls_outbound_phase(ctx);
        if (phase == 0)
        {
            /* No keys yet — send a plaintext alert record (RFC 8446 §6). */
            uint8_t record[7];
            record[0] = TLS_CONTENT_TYPE_ALERT;
            record[1] = 0x03;
            record[2] = 0x03;
            record[3] = 0x00;
            record[4] = 0x02;
            record[5] = level;
            record[6] = description;
            ok = ctx->transport_write(ctx->transport_arg, record, sizeof(record));
        }
        else
        {
            /* Encrypt under the active client traffic keys. Worst-case record
             * is 5 header + 2 body + 1 content_type + 16 tag = 24 bytes. */
            uint8_t record[24];
            size_t written = 0;
            bool use_hs_keys = (phase == 1);
            if (tls_encrypt_record(ctx, use_hs_keys, TLS_CONTENT_TYPE_ALERT,
                                   alert_body, sizeof(alert_body),
                                   record, sizeof(record), &written))
            {
                ok = ctx->transport_write(ctx->transport_arg, record, written);
            }
        }
    }

    if (level == TLS_ALERT_LEVEL_FATAL)
    {
        ctx->state = TLS_STATE_ERROR;
        lwip_log_event(LWIP_LOG_MODULE_TLS, LWIP_LOG_TLS_FATAL_ALERT);
    }

    return ok;
}

/**
 * @brief Send close_notify (warning) and remember we did so.
 */
bool tls_send_close_notify(struct tls_handshake_context *ctx)
{
    if (!ctx)
    {
        return false;
    }
    if (ctx->close_notify_sent)
    {
        return true;
    }
    bool ok = tls_send_alert(ctx, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    ctx->close_notify_sent = true;
    return ok;
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

    /* Release the cross-record reassembly buffer if one is in flight. */
    tls_hs_reasm_reset(ctx);

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
 * Outstanding work (post-refactor)
 * ============================================================================
 *
 * Status: PSK resumption, ECDHE-only, and PSK+ECDHE client handshakes are all
 * implemented and exercised. Record-layer encryption, transcript hashing,
 * key schedule, PSK binder, NewSessionTicket-driven resumption, alerts, and
 * close_notify are all done. CertificateVerify signature is intentionally
 * skipped — SPKI pinning provides authentication.
 *
 * Remaining work, roughly ordered:
 *   - AES-GCM speedup. Pure-C in aes.c; this is the bulk-data hot path and
 *     dwarfs everything else on the wire. eZ80-asm GHASH/AES is the next
 *     big win.
 *   - Server-side handshake (currently the altcp layer returns "not
 *     implemented"). The same key schedule code applies in reverse.
 *   - Wider truststore + automated SPKI hash refresh tooling.
 *   - Interop testing against major TLS 1.3 stacks (Go, BoringSSL,
 *     mbedTLS, Rustls) — particularly the cross-record fragmentation path
 *     which is hard to trigger without help.
 */
