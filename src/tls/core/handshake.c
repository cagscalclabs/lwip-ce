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
 *                                             CertificateVerify   (RSA-PSS-SHA256
 *                                                                  verified against
 *                                                                  leaf SPKI)
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
 * separate for handshake and application phases and reset when their
 * corresponding traffic keys are updated.
 *
 *
 * 4. WHAT THIS IMPLEMENTATION SKIPS (DELIBERATELY)
 * -------------------------------------------------
 *
 *   - Signature algorithms other than rsa_pss_rsae_sha256 in
 *     CertificateVerify. The leaf SPKI must be an RSA key with modulus
 *     between 1024 and 2048 bits; ECDSA and the wider RSA-PSS hashes are
 *     rejected. CertificateVerify itself is always required and verified
 *     against the chain's leaf SPKI.
 *   - 0-RTT / early_data.
 *   - HelloRetryRequest negotiation of a different key-exchange group — we
 *     only support x25519, so a request for another group aborts.
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
 *   - tls_process_inner_plaintext_pbuf — post-AEAD dispatch entry called by
 *     the altcp layer's streaming decrypter.
 *   - tls_handshake_init + tls_send_client_hello — outbound setup.
 *   - tls_recv_server_hello / encrypted_extensions / certificate /
 *     certificate_verify / finished — inbound handlers, one per message type.
 *   - tls_derive_handshake_keys / tls_derive_application_keys — key schedule.
 *   - tls_recv_new_session_ticket — post-handshake PSK update.
 *   - tls_set_transport / tls_send_alert / tls_send_close_notify — outbound
 *     alerts and orderly shutdown. Record-layer AEAD encrypt/decrypt
 *     lives in altcp_tls_ce.c as pbuf-walking streaming helpers.
 *
 * ============================================================================
 */

#include "ip_identity.h"
#include "../includes/handshake.h"
#include "../includes/hash.h"
#include "../includes/hmac.h"
#include "../includes/aes.h"
#include "../includes/random.h"
#include "../includes/hkdf.h"
#include "../includes/asn1.h"
#include "../includes/rsa.h"
#include "x509_internal.h"
#include "../includes/truststore.h"
#include "../includes/bytes.h"
#include "../includes/crypto_guard.h"
#include "../includes/x509.h"
#include "../contrib/x25519/src/x25519.h"
#include <string.h>
#include <usbdrvce.h>
#include "../../drivers/mem.h"
#include "lwip/timeouts.h"
#include "lwip/sntp_time.h"
#include "lwip/app_config.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_HANDSHAKE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

/* Cleanup helpers for TLS_AUTOZERO_BUF/TLS_AUTOZERO_STRUCT (bytes.h):
 * every stack-local secret buffer in this file is one of these two
 * shapes, so one helper per shape covers the whole file. */
TLS_AUTOZERO_DECL(uint8_t, 32)
TLS_AUTOZERO_DECL_STRUCT(tls_hmac_context)
TLS_AUTOZERO_DECL_STRUCT(tls_aes_context)

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

/* X25519 maps low-order public inputs to an all-zero shared secret. Keep this
 * check separate from the assembly primitive so every byte is examined before
 * the caller branches on the result. */
static bool tls_x25519_shared_is_nonzero(const uint8_t shared[32])
{
    uint8_t value = 0;
    for (size_t i = 0; i < 32; i++)
    {
        value |= shared[i];
    }
    return value != 0;
}

/* Forward decl — the dispatcher needs it; full body lives further down. */
static bool tls_dispatch_inner_handshake(struct tls_handshake_context *ctx,
                                         uint8_t msg_type,
                                         const uint8_t *msg, size_t msg_len);
/* Internal handshake-message handlers. These were once exposed via
 * handshake.h but are only invoked from the dispatcher in this file. */
static bool tls_recv_encrypted_extensions(struct tls_handshake_context *ctx,
                                          const uint8_t *data, size_t data_len);
static bool tls_recv_certificate_request(struct tls_handshake_context *ctx,
                                         const uint8_t *data, size_t data_len);
static bool tls_recv_certificate_verify(struct tls_handshake_context *ctx,
                                        const uint8_t *data, size_t data_len);
static bool tls_recv_finished(struct tls_handshake_context *ctx, bool is_client,
                              const uint8_t *data, size_t data_len);
static bool tls_recv_new_session_ticket(struct tls_handshake_context *ctx,
                                        const uint8_t *data, size_t data_len);
static bool tls_recv_key_update(struct tls_handshake_context *ctx,
                                const uint8_t *data, size_t data_len);
static bool tls_send_alert(struct tls_handshake_context *ctx,
                           uint8_t level, uint8_t description);
static bool tls_send_key_update_record(struct tls_handshake_context *ctx);

#define TLS_AES_GCM_RECORD_LIMIT (1ULL << 24)
#define TLS_MAX_KEY_UPDATES 32u

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
 * the next record. Non-Certificate messages beyond TLS_HS_REASSEMBLY_MAX are
 * fatal; Certificate messages use the streaming walker instead.
 * ------------------------------------------------------------------------ */

static void tls_hs_reasm_reset(struct tls_handshake_context *ctx)
{
    if (ctx->hs_reasm_buf)
    {
        mem_stats_tls_direct_release(ctx->hs_reasm_cap, ctx->hs_reasm_cap);
        mem_buffer_custom_free(ctx->hs_reasm_buf);
        ctx->hs_reasm_buf = NULL;
    }
    ctx->hs_reasm_cap = 0;
    ctx->hs_reasm_len = 0;
    ctx->hs_reasm_expected = 0;
    /* hs_reasm_body_fed tracks body bytes fed to the cert walker — reset
     * it here so callers don't need a separate assignment. */
    ctx->hs_reasm_body_fed = 0;
}

/* Ensure the reassembly buffer has at least `need` bytes of capacity. */
static bool tls_hs_reasm_grow(struct tls_handshake_context *ctx, size_t need)
{
    if (need > TLS_HS_REASSEMBLY_MAX)
    {
        ERROR_CODE(0x01);
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
        ERROR_CODE(0x02);
        return false;
    }
    if (ctx->hs_reasm_len)
    {
        memcpy(nb, ctx->hs_reasm_buf, ctx->hs_reasm_len);
    }
    if (ctx->hs_reasm_buf)
    {
        mem_stats_tls_direct_release(ctx->hs_reasm_cap, ctx->hs_reasm_cap);
        mem_buffer_custom_free(ctx->hs_reasm_buf);
    }
    mem_stats_tls_direct_add(new_cap, new_cap);
    ctx->hs_reasm_buf = nb;
    ctx->hs_reasm_cap = new_cap;
    return true;
}

/* ------------------------------------------------------------------------
 * Certificate-message streaming walker.
 *
 * The TLS 1.3 Certificate message body can be 3-16 KiB for realistic
 * cert chains. Buffering the whole thing in hs_reasm_buf is wasteful
 * when our per-cert work is bounded: parse one cert at a time, do its
 * per-cert work, drop the cert, move on. Peak alloc per cert is the
 * cert's own size (~1-3 KiB), not the chain's total.
 *
 * The walker is fed body bytes by tls_consume_handshake_buffer when the
 * in-flight message is TLS_HANDSHAKE_CERTIFICATE. It maintains its own
 * state machine over the Certificate body framing:
 *
 *   opaque certificate_request_context<0..255>;
 *   opaque cert_data<1..2^24-1>;
 *   opaque extensions<0..2^16-1>;
 *   CertificateEntry = {cert_data, extensions};
 *   Certificate = {request_context, CertificateEntry list<0..2^24-1>}
 *
 * When CS_CERT_BODY completes, the walker invokes tls_cert_walker_validate_one
 * on that cert: verify-leaf-first (capture the leaf SPKI that CertificateVerify
 * will authenticate against), then walk the chain link-by-link. The per-link
 * signature check dispatches using the signed certificate's algorithm.
 * Once a cert is processed its buffer is freed; only its digest, signature,
 * and scheme survive until the issuer arrives.
 * ------------------------------------------------------------------------ */

enum tls_cert_walk_state
{
    CW_REQ_CTX_LEN = 0,
    CW_REQ_CTX_BODY,
    CW_CHAIN_LEN,
    CW_CERT_LEN,
    CW_CERT_BODY,
    CW_EXT_LEN,
    CW_EXT_BODY,
    CW_DONE,
    CW_ERROR
};

struct tls_cert_walker
{
    enum tls_cert_walk_state state;
    /* Multi-byte length scratch (3 bytes max for chain/cert len, 2 for ext) */
    uint8_t len_scratch[3];
    uint8_t len_have;
    uint8_t len_need;
    /* Bytes left in the current variable-length field */
    size_t field_remaining;
    /* Bytes left in the CertificateEntry list */
    size_t chain_remaining;
    /* Per-cert capture buffer (sized to cert_len at CS_CERT_LEN end) */
    uint8_t *cert_buf;
    size_t cert_buf_cap;
    size_t cert_buf_len;
    /* True once the leaf SPKI has been captured (so CertificateVerify can run)
     * and every cert walked so far was accepted by the chain policy. Invalid
     * signatures for supported operations fail closed; known unsupported
     * operations and RSA keys wider than this platform supports warn and
     * proceed temporarily.
     * Leaf proof of possession is established separately
     * by the mandatory CertificateVerify record against the captured leaf
     * SPKI. */
    bool chain_validated;
    /* Index of the cert currently in cert_buf within the chain — 0 means
     * leaf. Used by tls_cert_walker_validate_one to know when to capture
     * the leaf public key into ctx->leaf_pubkey. */
    uint16_t cert_index;
    /* Owning handshake context, so per-cert callbacks can reach back for
     * leaf SPKI capture etc. Set by the caller via tls_cert_walker_new. */
    struct tls_handshake_context *ctx;

    /* Deferred adjacent-link verification state.
     *
     * A cert is signed by the NEXT cert in the wire chain (cert N signed-by
     * cert N+1), but N+1 arrives only after N. So when a cert finishes we
     * stash the material needed to verify it — the SHA-256 digest of its
     * tbsCertificate and a copy of its signatureValue — and run the actual
     * verification once the next cert's public key is in hand. The topmost
     * cert is checked against the truststore when an issuer entry is found.
     * RSA PKCS#1 v1.5 and PSS with SHA-256 are implemented. */
    bool pending_link;             /* a prior cert is awaiting its issuer key */
    bool pending_sig_omitted;      /* unsupported algorithm/width; bytes omitted */
    tls_alg_t pending_sig_alg;     /* scheme from the signed certificate */
    uint8_t pending_tbs_digest[32];/* SHA-256(tbsCertificate) of prior cert    */
    uint8_t pending_issuer_name_digest[32]; /* DER Name named by prior cert    */
    uint8_t *pending_sig;          /* signatureValue of prior cert (heap copy) */
    size_t pending_sig_len;

    /* Issuer CN of the last (topmost) cert walked, for truststore root lookup.
     * Overwritten on each cert; after CW_DONE it holds the topmost cert's
     * issuer_cn bytes (the root CA subject we should find in the truststore). */
    uint8_t topmost_issuer_cn[TLS_TRUSTSTORE_SUBJECT_LEN];
    uint8_t topmost_issuer_cn_len;
};

static struct tls_cert_walker *tls_cert_walker_new(struct tls_handshake_context *ctx)
{
    struct tls_cert_walker *w = (struct tls_cert_walker *)
        mem_buffer_custom_malloc(sizeof(*w));
    if (!w)
    {
        return NULL;
    }
    mem_stats_tls_direct_add(sizeof(*w), sizeof(*w));
    memset(w, 0, sizeof(*w));
    w->state = CW_REQ_CTX_LEN;
    w->len_need = 1;
    w->ctx = ctx;
    return w;
}

static void tls_cert_walker_free(struct tls_cert_walker *w)
{
    if (!w)
    {
        return;
    }
    if (w->cert_buf)
    {
        mem_stats_tls_direct_release(w->cert_buf_cap, w->cert_buf_cap);
        mem_buffer_custom_free(w->cert_buf);
    }
    if (w->pending_sig)
    {
        mem_stats_tls_direct_release(w->pending_sig_len, w->pending_sig_len);
        mem_buffer_custom_free(w->pending_sig);
    }
    mem_stats_tls_direct_release(sizeof(*w), sizeof(*w));
    mem_buffer_custom_free(w);
}

/* Pull the bits needed to verify a cert's issuer signature out of its DER:
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 * Captures the full tbsCertificate TLV bytes (what the signature covers),
 * the validated signature scheme, and the raw
 * signature bytes (BIT STRING content, unused-bits byte stripped).
 * Returns false on malformed DER or unsupported signature parameters. */
static bool tls_cert_extract_sig_material(const uint8_t *der, size_t der_len,
                                          const uint8_t **tbs_out,
                                          size_t *tbs_len_out,
                                          tls_alg_t *sig_alg_out,
                                          const uint8_t **sig_out,
                                          size_t *sig_len_out)
{
    struct tls_asn1_cursor top, items;
    struct tls_asn1_tlv cert_seq, tbs, sig_alg, sig_val;

    *sig_alg_out = TLS_ALG_UNKNOWN;

    if (!tls_asn1_cursor_init(&top, der, der_len) ||
        !tls_asn1_next(&top, &cert_seq) ||
        tls_asn1_tag_number(cert_seq.tag) != ASN1_SEQUENCE ||
        !tls_asn1_tag_constructed(cert_seq.tag))
    {
        ERROR_CODE(0x03);
        return false;
    }
    if (!tls_asn1_child_cursor(&cert_seq, &items) ||
        !tls_asn1_next(&items, &tbs) ||
        !tls_asn1_next(&items, &sig_alg) ||
        !tls_asn1_next(&items, &sig_val))
    {
        ERROR_CODE(0x04);
        return false;
    }
    if (!tls_asn1_tag_constructed(tbs.tag) ||
        tls_asn1_tag_number(tbs.tag) != ASN1_SEQUENCE ||
        tls_asn1_tag_number(sig_val.tag) != ASN1_BITSTRING)
    {
        ERROR_CODE(0x05);
        return false;
    }

    /* The signature covers the whole tbsCertificate TLV (tag+len+value). */
    *tbs_out = tbs.tlv;
    *tbs_len_out = tbs.header_len + tbs.len;

    if (!tls_x509_signature_algorithm(&sig_alg, sig_alg_out))
    {
        ERROR_CODE(0x06);
        return false;
    }

    /* The signed inner AlgorithmIdentifier must agree with the outer one. */
    struct tls_asn1_cursor body;
    struct tls_asn1_tlv serial, inner_alg;
    if (!tls_asn1_child_cursor(&tbs, &body) || !tls_asn1_next(&body, &serial))
    {
        ERROR_CODE(0x07);
        return false;
    }
    if (serial.tag == 0xa0 && !tls_asn1_next(&body, &serial))
    {
        ERROR_CODE(0x08);
        return false;
    }
    if (serial.tag != ASN1_INTEGER || !tls_asn1_next(&body, &inner_alg) ||
        inner_alg.tag != sig_alg.tag || inner_alg.len != sig_alg.len ||
        memcmp(inner_alg.value, sig_alg.value, sig_alg.len))
    {
        ERROR_CODE(0x09);
        return false;
    }

    /* signatureValue BIT STRING: first content byte is the unused-bits count
     * (0 for a byte-aligned signature); the rest is the signature. */
    if (sig_val.len < 2 || sig_val.value[0] != 0x00)
    {
        ERROR_CODE(0x0a);
        return false;
    }
    *sig_out = sig_val.value + 1;
    *sig_len_out = sig_val.len - 1;
    return true;
}

/* Bind the certificate's signature scheme to a compatible issuer key.
 * The issuer's key algorithm does not choose the child's signature padding. */
static tls_key_op_result_t tls_cert_verify_digest(tls_alg_t scheme,
                                                 const struct tls_key *issuer,
                                                 const uint8_t digest[32],
                                                 const uint8_t *sig, size_t sig_len)
{
    return tls_x509_signature_verify_digest(digest, sig, sig_len, issuer, scheme);
}

/* Verify a deferred chain link while preserving the temporary compatibility
 * policy: a known-but-unimplemented operation, including an otherwise valid
 * RSA signature whose issuer key is wider than our 2048-bit arithmetic, is
 * distinguishable from a bad signature for an operation we do support. */
static tls_key_op_result_t tls_cert_verify_pending_link(
    const struct tls_cert_walker *w, const struct tls_key *issuer)
{
    if (!w || !issuer || !w->pending_link)
        return TLS_KEY_OP_INVALID;

    /* The AlgorithmIdentifier was structurally valid and matched the signed
     * tbsCertificate, but its OID is not implemented by this build. */
    if (w->pending_sig_alg == TLS_ALG_UNKNOWN)
        return w->pending_sig_omitted ? TLS_KEY_OP_UNSUPPORTED
                                      : TLS_KEY_OP_INVALID;

    bool rsa_scheme = (w->pending_sig_alg == TLS_ALG_RSA_PKCS1_SHA256 ||
                       w->pending_sig_alg == TLS_ALG_RSA_PSS_RSAE_SHA256);
    if (rsa_scheme && issuer->type == TLS_KEY_TYPE_RSA &&
        issuer->rsa.mod_len > RSA_MODULUS_MAX_SUPPORTED)
    {
        /* RSA signatures are exactly one modulus-width block. A different
         * length is invalid even though the key itself is unsupported. */
        return (w->pending_sig_omitted &&
                w->pending_sig_len == issuer->rsa.mod_len)
            ? TLS_KEY_OP_UNSUPPORTED : TLS_KEY_OP_INVALID;
    }

    /* An omitted oversized signature is only acceptable with the matching
     * oversized RSA issuer handled above. */
    if (w->pending_sig_omitted || !w->pending_sig)
        return TLS_KEY_OP_INVALID;

    return tls_cert_verify_digest(w->pending_sig_alg, issuer,
                                  w->pending_tbs_digest, w->pending_sig,
                                  w->pending_sig_len);
}

/* Verify the deferred child with this issuer, then retain this certificate's
 * signature scheme, SHA-256 digest and signature for the next issuer/root. */
static bool tls_cert_chain_verify_one(struct tls_cert_walker *w,
                                      const struct tls_x509_object *cert,
                                      bool is_leaf)
{
    const uint8_t *tbs, *sig;
    size_t tbs_len, sig_len;
    tls_alg_t sig_alg;

    /* Step 1: if a prior cert is awaiting its issuer key, THIS cert is that
     * issuer — verify the pending link now. */
    if (w->pending_link)
    {
        uint8_t subject_name_digest[32];
        struct tls_hash_context name_hash;
        if (!cert->subject_name || cert->subject_name_len == 0 ||
            !tls_hash_context_init(&name_hash, TLS_HASH_SHA256))
            return false;
        tls_hash_update(&name_hash, cert->subject_name, cert->subject_name_len);
        tls_hash_digest(&name_hash, subject_name_digest);
        if (memcmp(subject_name_digest, w->pending_issuer_name_digest,
                   sizeof(subject_name_digest)) != 0)
        {
            ERROR_CODE(0x15);
            return false;
        }
        tls_key_op_result_t verify_result =
            tls_cert_verify_pending_link(w, &cert->pubkey);
        if (verify_result == TLS_KEY_OP_UNSUPPORTED)
        {
            /* Interim compatibility pinhole: retain all structural/name/path
             * checks but allow a link this platform cannot verify. */
            WARN();
        }
        else if (verify_result != TLS_KEY_OP_OK)
        {
            /* A supported verification operation produced a bad signature,
             * or the signature/key pairing is structurally incompatible. */
            ERROR();
            return false;
        }

        /* Stash consumed. */
        if (w->pending_sig)
        {
            mem_stats_tls_direct_release(w->pending_sig_len, w->pending_sig_len);
            mem_buffer_custom_free(w->pending_sig);
            w->pending_sig = NULL;
        }
        w->pending_sig_len = 0;
        w->pending_link = false;
        w->pending_sig_omitted = false;
        w->pending_sig_alg = TLS_ALG_UNKNOWN;
    }

    /* Step 2: stash THIS cert's signature material so the next cert (its
     * issuer) can verify it. Pre-hash the tbs now so we don't have to retain
     * the cert buffer — only the 32-byte digest and the signature survive. */
    if (!tls_cert_extract_sig_material(w->cert_buf, w->cert_buf_len, &tbs,
                                       &tbs_len, &sig_alg, &sig, &sig_len))
    {
        ERROR_CODE(0x0b);
        return false;
    }
    {
        struct tls_hash_context hctx;
        if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
        {
            ERROR_CODE(0x0c);
            return false;
        }
        tls_hash_update(&hctx, tbs, tbs_len);
        tls_hash_digest(&hctx, w->pending_tbs_digest);
    }
    /* Copy the signature (it lives in cert_buf, which is freed after this
     * call returns). Oversized RSA signatures are retained by length only so
     * the next issuer can prove that the width matches an unsupported RSA
     * key; arbitrary oversized signatures remain malformed. */
    if (sig_len == 0)
    {
        ERROR_CODE(0x0d);
        return false;
    }
    else if (sig_alg == TLS_ALG_UNKNOWN)
    {
        /* Retain no attacker-controlled signature bytes for an operation this
         * build cannot dispatch. Structural and issuer-name checks still run. */
        w->pending_sig = NULL;
        w->pending_sig_len = sig_len;
        w->pending_sig_alg = sig_alg;
        w->pending_sig_omitted = true;
    }
    else if (sig_len > RSA_MODULUS_MAX_SUPPORTED)
    {
        if (sig_alg != TLS_ALG_RSA_PKCS1_SHA256 &&
            sig_alg != TLS_ALG_RSA_PSS_RSAE_SHA256)
        {
            ERROR_CODE(0x0d);
            return false;
        }
        w->pending_sig = NULL;
        w->pending_sig_len = sig_len;
        w->pending_sig_alg = sig_alg;
        w->pending_sig_omitted = true;
    }
    else
    {
        w->pending_sig = (uint8_t *)mem_buffer_custom_malloc(sig_len);
        if (!w->pending_sig)
        {
            ERROR_CODE(0x0e);
            return false;
        }
        mem_stats_tls_direct_add(sig_len, sig_len);
        memcpy(w->pending_sig, sig, sig_len);
        w->pending_sig_len = sig_len;
        w->pending_sig_alg = sig_alg;
        w->pending_sig_omitted = false;
    }
    w->pending_link = true;
    if (!cert->issuer_name || cert->issuer_name_len == 0)
        return false;
    {
        struct tls_hash_context name_hash;
        if (!tls_hash_context_init(&name_hash, TLS_HASH_SHA256)) return false;
        tls_hash_update(&name_hash, cert->issuer_name, cert->issuer_name_len);
        tls_hash_digest(&name_hash, w->pending_issuer_name_digest);
    }
    (void)is_leaf;
    return true;
}

/* Run per-cert handling on the just-completed cert_buf, walking the chain one
 * cert at a time (leaf first). Captures the leaf SPKI for the mandatory
 * CertificateVerify, then runs the adjacent-link chain check (verifies the
 * previously-stashed cert with this cert's key; see tls_cert_chain_verify_one).
 *
 * Sets w->chain_validated once the leaf SPKI is in hand and every link walked
 * has passed. Returns false only on a fatal parse error or a chain link the
 * verifier rejects (caller aborts the connection).
 */
static bool tls_cert_walker_validate_one(struct tls_cert_walker *w)
{
    struct tls_x509_object cert = {0};
    bool is_leaf = (w->cert_index == 0);

    INFO("cert: parse");
    if (!tls_x509_parse_certificate(w->cert_buf, w->cert_buf_len, &cert))
    {
        INFO("cert: parse fail");
        ERROR_CODE(0x01);
        return false;
    }
    if (cert.pubkey.type == TLS_KEY_TYPE_UNKNOWN ||
        ((cert.pubkey.type == TLS_KEY_TYPE_RSA)
             ? cert.pubkey.rsa.mod_len == 0 : cert.pubkey.ec.len == 0))
    {
        INFO("cert: spki fail");
        ERROR_CODE(0x02);
        return false;
    }

    /* Validity window check — requires SNTP sync (returns 0 if not set,
     * which fails closed since no real cert is valid at epoch 0). */
    if (!tls_x509_time_in_validity(&cert, lwip_sntp_get_unix_time()))
    {
        INFO("cert: date fail");
        ERROR_CODE(0x03);
        return false;
    }

    /* Enforce leaf TLS usage and every issuer's CA/key/path constraints.
     * cert_index excludes the leaf, so an issuer at index N has N-1
     * subordinate CA certificates beneath it. */
    if (!tls_x509_validate_path_extensions(&cert, !is_leaf,
                                            is_leaf ? 0 : w->cert_index - 1u))
    {
        INFO("cert: constraints fail");
        ERROR_CODE(0x12);
        return false;
    }

    /* Hostname/SAN check: leaf only. */
    if (is_leaf)
    {
        if (!w->ctx || !w->ctx->hostname ||
            !tls_x509_hostname_matches(cert.extensions, cert.extensions_len,
                                       cert.subject_cn, cert.subject_cn_len,
                                       w->ctx->hostname))
        {
            INFO("cert: host fail");
            ERROR_CODE(0x04);
            return false;
        }
    }

    /* Capture the leaf public key for CertificateVerify.  We need it to
     * survive past this function, so copy the key material into a heap block
     * and mark it allocated=true for tls_handshake_cleanup(). */
    if (is_leaf && w->ctx && w->ctx->leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN)
    {
        size_t mat_len = 0;
        if (cert.pubkey.type == TLS_KEY_TYPE_RSA)
            mat_len = cert.pubkey.rsa.mod_len + cert.pubkey.rsa.exp_len;
        else if (cert.pubkey.ec.len)
            mat_len = cert.pubkey.ec.len;

        if (mat_len == 0)
        {
            INFO("cert: key alloc fail");
            ERROR_CODE(0x0f);
            return false;
        }

        uint8_t *mat = (uint8_t *)mem_buffer_custom_malloc(mat_len);
        if (!mat)
        {
            INFO("cert: key alloc fail");
            ERROR_CODE(0x10);
            return false;
        }
        mem_stats_tls_direct_add(mat_len, mat_len);

        w->ctx->leaf_pubkey.type       = cert.pubkey.type;
        w->ctx->leaf_pubkey.allocated = true;

        if (cert.pubkey.type == TLS_KEY_TYPE_RSA)
        {
            memcpy(mat, cert.pubkey.rsa.modulus, cert.pubkey.rsa.mod_len);
            memcpy(mat + cert.pubkey.rsa.mod_len,
                   cert.pubkey.rsa.exponent, cert.pubkey.rsa.exp_len);
            w->ctx->leaf_pubkey.rsa.modulus  = mat;
            w->ctx->leaf_pubkey.rsa.mod_len  = cert.pubkey.rsa.mod_len;
            w->ctx->leaf_pubkey.rsa.exponent = mat + cert.pubkey.rsa.mod_len;
            w->ctx->leaf_pubkey.rsa.exp_len  = cert.pubkey.rsa.exp_len;
        }
        else
        {
            memcpy(mat, cert.pubkey.ec.data, cert.pubkey.ec.len);
            w->ctx->leaf_pubkey.ec.data = mat;
            w->ctx->leaf_pubkey.ec.len  = cert.pubkey.ec.len;
        }
    }

    /* Issuer CN — captured for truststore root lookup. */
    if (cert.issuer_cn && cert.issuer_cn_len > 0)
    {
        uint8_t copy_len = (cert.issuer_cn_len < TLS_TRUSTSTORE_SUBJECT_LEN)
                           ? (uint8_t)cert.issuer_cn_len
                           : TLS_TRUSTSTORE_SUBJECT_LEN;
        memcpy(w->topmost_issuer_cn, cert.issuer_cn, copy_len);
        memset(w->topmost_issuer_cn + copy_len, 0,
               TLS_TRUSTSTORE_SUBJECT_LEN - copy_len);
        w->topmost_issuer_cn_len = copy_len;
    }

    if (!tls_cert_chain_verify_one(w, &cert, is_leaf))
    {
        INFO("cert: chain fail");
        ERROR_CODE(0x11);
        return false;
    }

    if (w->ctx && w->ctx->leaf_pubkey.type != TLS_KEY_TYPE_UNKNOWN)
        w->chain_validated = true;

    INFO("cert: accepted");
    return true;
}

/* Feed body bytes into the walker. Consumes from `bytes` until either
 * (a) the message is complete (`*consumed == len`, walker state CW_DONE)
 * or (b) it needs more bytes (`*consumed == len`, walker state non-DONE)
 * or (c) it errors out (returns false). */
static bool tls_cert_walker_feed(struct tls_cert_walker *w,
                                 const uint8_t *bytes, size_t len)
{
    size_t off = 0;

    while (off < len && w->state != CW_DONE && w->state != CW_ERROR)
    {
        size_t prev_off = off;
        enum tls_cert_walk_state prev_state = w->state;
        size_t prev_field_remaining = w->field_remaining;
        size_t prev_chain_remaining = w->chain_remaining;
        uint8_t prev_len_have = w->len_have;

        switch (w->state)
        {
        case CW_REQ_CTX_LEN:
        case CW_CHAIN_LEN:
        case CW_CERT_LEN:
        case CW_EXT_LEN:
        {
            size_t want = w->len_need - w->len_have;
            size_t take = (len - off < want) ? (len - off) : want;
            memcpy(w->len_scratch + w->len_have, bytes + off, take);
            w->len_have += (uint8_t)take;
            off += take;
            if (w->len_have < w->len_need)
            {
                return true;
            }
            size_t value = 0;
            for (uint8_t i = 0; i < w->len_need; i++)
            {
                value = (value << 8) | w->len_scratch[i];
            }
            w->len_have = 0;

            switch (w->state)
            {
            case CW_REQ_CTX_LEN:
                w->field_remaining = value;
                w->state = (value == 0) ? CW_CHAIN_LEN : CW_REQ_CTX_BODY;
                if (w->state == CW_CHAIN_LEN)
                {
                    w->len_need = 3;
                }
                break;
            case CW_CHAIN_LEN:
                if (value == 0)
                {
                    w->state = CW_DONE;
                    break;
                }
                w->chain_remaining = value;
                w->state = CW_CERT_LEN;
                w->len_need = 3;
                break;
            case CW_CERT_LEN:
                /* Deduct the 3-byte length field itself from chain_remaining,
                 * then deduct the cert body length. Both are part of the
                 * CertificateList payload counted by chain_remaining.
                 * Check value bounds before computing 3+value to avoid
                 * size_t overflow on eZ80 (3-byte size_t, max 0xFFFFFF). */
                if (value == 0 || value > SIZE_MAX - 3u ||
                    w->chain_remaining < 3u + value)
                {
                    ERROR_CODE(0x10);
                    w->state = CW_ERROR;
                    return false;
                }
                w->chain_remaining -= 3 + value; /* length field + body */
                w->field_remaining = value;
                w->cert_buf = (uint8_t *)mem_buffer_custom_malloc(value);
                if (!w->cert_buf)
                {
                    ERROR_CODE(0x11);
                    w->state = CW_ERROR;
                    return false;
                }
                mem_stats_tls_direct_add(value, value);
                w->cert_buf_cap = value;
                w->cert_buf_len = 0;
                w->state = CW_CERT_BODY;
                break;
            case CW_EXT_LEN:
                /* Deduct the 2-byte ext_len field itself plus the ext body.
                 * ext_len is 2 bytes so value <= 0xFFFF; 2+value can't
                 * overflow a 3-byte size_t, but guard defensively anyway. */
                if (value > 0xFFFF || w->chain_remaining < 2 + value)
                {
                    ERROR_CODE(0x13);
                    w->state = CW_ERROR;
                    return false;
                }
                w->chain_remaining -= 2 + value; /* length field + body */
                w->field_remaining = value;
                /* Empty CertificateEntry extensions (value == 0) is the common
                 * TLS 1.3 case. Transition directly to the next cert (or DONE)
                 * instead of routing a zero-length body through CW_EXT_BODY. */
                if (value == 0)
                {
                    if (w->chain_remaining == 0)
                    {
                        w->state = CW_DONE;
                    }
                    else
                    {
                        w->state = CW_CERT_LEN;
                        w->len_need = 3;
                    }
                }
                else
                {
                    w->state = CW_EXT_BODY;
                }
                break;
            default:
                break;
            }
            break;
        }

        case CW_REQ_CTX_BODY:
        case CW_EXT_BODY:
        {
            size_t take = (len - off < w->field_remaining) ? (len - off) : w->field_remaining;
            off += take;
            w->field_remaining -= take;
            if (w->field_remaining == 0)
            {
                if (w->state == CW_REQ_CTX_BODY)
                {
                    w->state = CW_CHAIN_LEN;
                    w->len_need = 3;
                }
                else
                {
                    if (w->chain_remaining == 0)
                    {
                        w->state = CW_DONE;
                    }
                    else
                    {
                        w->state = CW_CERT_LEN;
                        w->len_need = 3;
                    }
                }
            }
            break;
        }

        case CW_CERT_BODY:
        {
            size_t take = (len - off < w->field_remaining) ? (len - off) : w->field_remaining;
            if (w->cert_buf_len + take > w->cert_buf_cap)
            {
                w->state = CW_ERROR;
                ERROR_CODE(0x12);
                return false;
            }
            memcpy(w->cert_buf + w->cert_buf_len, bytes + off, take);
            w->cert_buf_len += take;
            off += take;
            w->field_remaining -= take;
            if (w->field_remaining == 0)
            {
                /* Cert complete — validate it, then drop the buffer
                 * before moving on. Peak alloc never exceeds the largest
                 * single cert. cert_index is incremented after the
                 * validate call so the leaf (index 0) keeps that value
                 * while validate_one captures its SPKI. */
                bool ok = tls_cert_walker_validate_one(w);
                mem_stats_tls_direct_release(w->cert_buf_cap, w->cert_buf_cap);
                mem_buffer_custom_free(w->cert_buf);
                w->cert_buf = NULL;
                w->cert_buf_cap = 0;
                w->cert_buf_len = 0;
                if (!ok)
                {
                    w->state = CW_ERROR;
                    ERROR_CODE(0x13);
                    return false;
                }
                if (w->cert_index < UINT16_MAX) w->cert_index++;
                w->state = CW_EXT_LEN;
                w->len_need = 2;
            }
            break;
        }

        default:
            w->state = CW_ERROR;
            ERROR_CODE(0x14);
            return false;
        }

        /* No-progress guard: if a full switch pass consumed no input and left
         * every framing counter unchanged, the walker is wedged (malformed
         * framing or a state-machine bug). Bail out cleanly instead of
         * spinning forever. */
        if (off == prev_off && w->state == prev_state &&
            w->field_remaining == prev_field_remaining &&
            w->chain_remaining == prev_chain_remaining &&
            w->len_have == prev_len_have)
        {
            ERROR();
            w->state = CW_ERROR;
            return false;
        }
    }

    return w->state != CW_ERROR;
}

/* Forward decl: post-walk finalize for a streamed Certificate message.
 * Called once the walker reaches CW_DONE; performs state and PSK checks,
 * then advances the state machine (transcript already updated by walker). */
static bool tls_recv_certificate_streamed(struct tls_handshake_context *ctx,
                                          struct tls_cert_walker *w);

/* Feed `take` bytes of in-flight message body. Routes Certificate bytes
 * through the per-cert walker; everything else appends to hs_reasm_buf.
 * Returns false on fatal error. */
static bool tls_feed_inflight_body(struct tls_handshake_context *ctx,
                                   uint8_t msg_type,
                                   const uint8_t *bytes, size_t take)
{
    if (msg_type == TLS_HANDSHAKE_CERTIFICATE)
    {
        INFO("hs: certificate");
        if (!ctx->cert_walker)
        {
            ctx->cert_walker = tls_cert_walker_new(ctx);
            if (!ctx->cert_walker)
            {
                ERROR_CODE(0x12);
                return false;
            }
        }
        /* Update transcript hash incrementally as body bytes arrive, so
         * we never need a flat copy of the whole Certificate message. */
        if (ctx->transcript_hash)
        {
            transcript_hash_update(ctx->transcript_hash, bytes, take);
        }
        if (!tls_cert_walker_feed(ctx->cert_walker, bytes, take))
        {
            ERROR_CODE(0x15);
            return false;
        }
        ctx->hs_reasm_body_fed += take;
        return true;
    }
    /* Non-Certificate: legacy flat append into hs_reasm_buf. */
    if (!tls_hs_reasm_grow(ctx, ctx->hs_reasm_len + take))
    {
        ERROR_CODE(0x16);
        return false;
    }
    memcpy(ctx->hs_reasm_buf + ctx->hs_reasm_len, bytes, take);
    ctx->hs_reasm_len += take;
    return true;
}

/* Dispatch the completed in-flight message and reset reassembly state. */
static bool tls_dispatch_inflight(struct tls_handshake_context *ctx)
{
    bool ok;
    uint8_t msg_type = ctx->hs_reasm_buf[0];

    if (msg_type == TLS_HANDSHAKE_CERTIFICATE)
    {
        /* cert_walker must exist: it is created lazily in tls_feed_inflight_body
         * as soon as the first body byte arrives. A NULL walker here means the
         * Certificate body was zero bytes — an empty chain is a protocol error. */
        if (!ctx->cert_walker)
        {
            tls_hs_reasm_reset(ctx);
            ERROR_CODE(0x17);
            return false;
        }
        ok = tls_recv_certificate_streamed(ctx, ctx->cert_walker);
        tls_cert_walker_free(ctx->cert_walker);
        ctx->cert_walker = NULL;
    }
    else
    {
        ok = tls_dispatch_inner_handshake(ctx, msg_type,
                                          ctx->hs_reasm_buf,
                                          ctx->hs_reasm_expected);
    }
    tls_hs_reasm_reset(ctx);
    ctx->hs_reasm_body_fed = 0;
    return ok;
}

/* Body completion check: works for both the flat path (hs_reasm_len ==
 * hs_reasm_expected) and the walker path (4 + hs_reasm_body_fed ==
 * hs_reasm_expected). */
static bool tls_inflight_message_complete(const struct tls_handshake_context *ctx)
{
    uint8_t msg_type = ctx->hs_reasm_buf[0];
    if (msg_type == TLS_HANDSHAKE_CERTIFICATE)
    {
        return 4 + ctx->hs_reasm_body_fed >= ctx->hs_reasm_expected;
    }
    return ctx->hs_reasm_len >= ctx->hs_reasm_expected;
}

/**
 * @brief Process a buffer of decrypted handshake bytes, dispatching each
 *        complete message and spilling the tail into reassembly storage.
 *
 * On entry, if hs_reasm_expected != 0 we are continuing a previously-spilled
 * message: appended bytes are added to hs_reasm_buf and the whole message
 * dispatched once complete. Certificate messages bypass hs_reasm_buf and
 * stream through ctx->cert_walker instead, so only one cert at a time is
 * held flat regardless of chain depth.
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
        if (body_len > SIZE_MAX - 4u)
        {
            tls_hs_reasm_reset(ctx);
            ERROR_CODE(0x18);
            return false;
        }
        if (body_len == 0)
        {
            tls_hs_reasm_reset(ctx);
            ERROR_CODE(0x18);
            return false;
        }
        ctx->hs_reasm_expected = 4 + body_len;
        if (ctx->hs_reasm_buf[0] != TLS_HANDSHAKE_CERTIFICATE &&
            ctx->hs_reasm_expected > TLS_HS_REASSEMBLY_MAX)
        {
            tls_hs_reasm_reset(ctx);
            ERROR_CODE(0x18);
            return false;
        }
        /* If the just-revealed message is Certificate, feed the 4-byte
         * header through the transcript hash now — the walker won't see
         * it (the header was already in hs_reasm_buf before we knew the
         * type). */
        if (ctx->hs_reasm_buf[0] == TLS_HANDSHAKE_CERTIFICATE &&
            ctx->transcript_hash)
        {
            transcript_hash_update(ctx->transcript_hash, ctx->hs_reasm_buf, 4);
        }
    }

    /* If we were mid-reassembly, top up first. */
    if (ctx->hs_reasm_expected != 0)
    {
        uint8_t msg_type = ctx->hs_reasm_buf[0];
        size_t body_consumed = (msg_type == TLS_HANDSHAKE_CERTIFICATE)
                                   ? ctx->hs_reasm_body_fed
                                   : (ctx->hs_reasm_len - 4);
        size_t need = (ctx->hs_reasm_expected - 4) - body_consumed;
        size_t take = (buf_len - off < need) ? (buf_len - off) : need;

        if (take > 0)
        {
            if (!tls_feed_inflight_body(ctx, msg_type, buf + off, take))
            {
                tls_hs_reasm_reset(ctx);
                tls_cert_walker_free(ctx->cert_walker);
                ctx->cert_walker = NULL;
                ctx->hs_reasm_body_fed = 0;
                ERROR_CODE(0x19);
                return false;
            }
            off += take;
        }

        if (!tls_inflight_message_complete(ctx))
        {
            return true; /* Still incomplete; wait for more. */
        }

        if (!tls_dispatch_inflight(ctx))
        {
            ERROR_CODE(0x1a);
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
        if (body_len > SIZE_MAX - 4u)
        {
            ERROR_CODE(0x1b);
            return false;
        }
        size_t total = 4 + body_len;

        if (body_len == 0)
        {
            ERROR_CODE(0x1b);
            return false;
        }

        if (msg_type != TLS_HANDSHAKE_CERTIFICATE &&
            total > TLS_HS_REASSEMBLY_MAX)
        {
            /* Non-Certificate parsers hold their message flat, so enforce the
             * documented memory bound. Certificate chains stream below. */
            ERROR_CODE(0x1b);
            return false;
        }

        if (msg_type == TLS_HANDSHAKE_CERTIFICATE)
        {
            /* Certificate: install header, transcript-update the header,
             * route body through walker. The walker handles per-cert
             * alloc/free; hs_reasm_buf only ever holds the 4-byte header. */
            if (!tls_hs_reasm_grow(ctx, 4))
            {
                ERROR_CODE(0x1c);
                return false;
            }
            memcpy(ctx->hs_reasm_buf, buf + off, 4);
            ctx->hs_reasm_len = 4;
            ctx->hs_reasm_expected = total;
            ctx->hs_reasm_body_fed = 0;
            if (ctx->transcript_hash)
            {
                transcript_hash_update(ctx->transcript_hash, buf + off, 4);
            }
            off += 4;

            size_t body_avail = (buf_len - off < body_len) ? (buf_len - off) : body_len;
            if (body_avail > 0)
            {
                if (!tls_feed_inflight_body(ctx, msg_type, buf + off, body_avail))
                {
                    tls_hs_reasm_reset(ctx);
                    tls_cert_walker_free(ctx->cert_walker);
                    ctx->cert_walker = NULL;
                    ctx->hs_reasm_body_fed = 0;
                    ERROR_CODE(0x1d);
                    return false;
                }
                off += body_avail;
            }

            if (!tls_inflight_message_complete(ctx))
            {
                return true; /* Body spans into a future record. */
            }
            if (!tls_dispatch_inflight(ctx))
            {
                ERROR_CODE(0x1e);
                return false;
            }
            continue;
        }

        /* Non-Certificate: legacy path. */
        if (off + total > buf_len)
        {
            /* Partial message — spill the remainder into reassembly. */
            size_t have = buf_len - off;
            if (!tls_hs_reasm_grow(ctx, total))
            {
                ERROR_CODE(0x1f);
                return false;
            }
            memcpy(ctx->hs_reasm_buf, buf + off, have);
            ctx->hs_reasm_len = have;
            ctx->hs_reasm_expected = total;
            return true;
        }

        if (!tls_dispatch_inner_handshake(ctx, msg_type, buf + off, total))
        {
            ERROR_CODE(0x20);
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
            ERROR_CODE(0x21);
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
    bool ok;
    switch (msg_type)
    {
    case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
        INFO("hs: encrypted extensions");
        ok = tls_recv_encrypted_extensions(ctx, msg, msg_len);
        break;
    case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
        INFO("hs: certificate request");
        ok = tls_recv_certificate_request(ctx, msg, msg_len);
        break;
    /* TLS_HANDSHAKE_CERTIFICATE is handled by the streaming cert walker in
     * tls_consume_handshake_buffer; it never reaches this dispatcher. */
    case TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY:
        INFO("hs: cert verify");
        ok = tls_recv_certificate_verify(ctx, msg, msg_len);
        break;
    case TLS_HANDSHAKE_FINISHED:
        INFO("hs: server finished");
        /* tls_recv_finished holds finished_key/expected_verify_data/
         * hmac_ctx on its own stack frame; wrapping the call (rather than
         * scrubbing from inside it) lets tls_crypto_guard_disable() reach
         * that whole frame once it's returned and SP is back above it. */
        tls_crypto_guard_enable();
        ok = tls_recv_finished(ctx, true, msg, msg_len);
        tls_crypto_guard_disable();
        break;
    case TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET:
        INFO("hs: new ticket");
        ok = tls_recv_new_session_ticket(ctx, msg, msg_len);
        break;
    case TLS_HANDSHAKE_KEY_UPDATE:
        INFO("hs: key update");
        ok = tls_recv_key_update(ctx, msg, msg_len);
        break;
    default:
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        return false;
    }
    if (!ok)
    {
        ERROR_CODE(msg_type);
    }
    return ok;
}

/* Pbuf-walking inner-plaintext dispatcher. The decrypted
 * plaintext arrives as a pbuf chain so the caller doesn't have to flatten
 * a ~16 KiB Certificate message into a contiguous buffer just to hand it
 * in. We walk the chain segment-by-segment and feed each segment into
 * tls_consume_handshake_buffer, which is already slice-safe (it handles
 * partial headers and cross-record reassembly via hs_reasm_buf). At any
 * moment the only contiguous bytes in flight are one pbuf segment plus
 * hs_reasm_buf, which only fills if a single handshake message spans
 * records (the < 1% case). */
bool tls_process_inner_plaintext_pbuf(struct tls_handshake_context *ctx,
                                      uint8_t inner_content_type,
                                      const struct pbuf *plaintext,
                                      size_t plaintext_len)
{
    if (!ctx)
    {
        ERROR_CODE(0x22);
        return false;
    }
    if (plaintext_len != 0 && !plaintext)
    {
        ERROR_CODE(0x23);
        return false;
    }

    if (inner_content_type == TLS_CONTENT_TYPE_HANDSHAKE)
    {
        if (plaintext_len == 0)
        {
            tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            return false;
        }
        size_t consumed = 0;
        const struct pbuf *q = plaintext;

        while (consumed < plaintext_len)
        {
            /* Skip zero-length segments (legal in lwIP pool chains after
             * pbuf_realloc, and harmless to skip). */
            while (q && q->len == 0)
            {
                q = q->next;
            }
            if (!q)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                ERROR_CODE(0x24);
                return false;
            }
            size_t avail = (size_t)q->len;
            size_t remaining = plaintext_len - consumed;
            size_t chunk = (avail < remaining) ? avail : remaining;

            if (!tls_consume_handshake_buffer(ctx,
                                              (const uint8_t *)q->payload,
                                              chunk))
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
                ERROR_CODE(0x25);
                return false;
            }

            consumed += chunk;
            if (chunk == avail)
            {
                q = q->next;
            }
        }
        return true;
    }

    if (inner_content_type == TLS_CONTENT_TYPE_ALERT)
    {
        if (plaintext_len != 2)
        {
            tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            ctx->state = TLS_STATE_ERROR;
            ERROR_CODE(0x26);
            return false;
        }

        uint8_t alert_desc = pbuf_get_at((struct pbuf *)plaintext, 1);
        /* RFC 8446 section 6.1: recipients SHOULD ignore user_canceled so
         * that an otherwise valid connection is not failed closed. */
        if (alert_desc == TLS_ALERT_USER_CANCELED)
            return true;
        if (alert_desc == TLS_ALERT_CLOSE_NOTIFY)
            ctx->peer_close_notify_received = true;
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x26);
        return false;
    }

    /* Application data during handshake is unexpected. */
    tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
    ERROR_CODE(0x27);
    return false;
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
        ERROR_CODE(0x28);
        return false;
    }

    INFO("init: clear context");
    /* Clear context */
    tls_secure_memzero(ctx, sizeof(*ctx));
    ctx->leaf_pubkey.type = TLS_KEY_TYPE_UNKNOWN;

    /* Copy PSK and identity (NULL = pure ECDHE mode, PSK stays zeroed) */
    if (psk && psk_identity)
    {
        memcpy(ctx->psk, psk, 32);
        memcpy(&ctx->psk_identity, psk_identity, sizeof(*psk_identity));
        ctx->psk_mode = true;
        ctx->psk_type = TLS_PSK_TYPE_RESUMPTION;
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

    INFO("init: client random");
    /* Use the checked request path so entropy-source failure aborts before
     * any handshake secret or nonce is generated. */
    if (!tls_request_random_bytes(ctx->client_random,
                                  sizeof(ctx->client_random), NULL, NULL, true))
    {
        ERROR_CODE(0x2b);
        return false;
    }

    INFO("init: transcript hash");
    /* Initialize transcript hash (using embedded storage) */
    ctx->transcript_hash = &ctx->transcript_hash_storage;
    if (!transcript_hash_init(ctx->transcript_hash))
    {
        ctx->transcript_hash = NULL;
        ERROR_CODE(0x29);
        return false;
    }

    INFO("init: private random");
    /* Generate ephemeral X25519 keypair for ECDHE */
    if (!tls_request_random_bytes(ctx->ecdhe_private,
                                  sizeof(ctx->ecdhe_private), NULL, NULL, true))
    {
        ERROR_CODE(0x2c);
        return false;
    }

    INFO("init: X25519 public key");
    if (!tls_x25519_publickey(ctx->ecdhe_public, ctx->ecdhe_private,
                              NULL, NULL))
    {
        tls_secure_memzero(ctx->ecdhe_private, 32);
        ERROR_CODE(0x2a);
        return false;
    }

    INFO("init: X25519 done");
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
    enum {
        HELLO_RANDOM_OFFSET = 6,
        HELLO_EXT_LEN_OFFSET = 45,
        HELLO_EXT_START = 47,
        HELLO_KEY_SHARE_OFFSET = 72
    };
    /* Base ClientHello with zero placeholders for the 32-byte client random,
     * 32-byte key share, and dependent lengths. Optional extensions append. */
    static const uint8_t hello_template[] = {
        TLS_HANDSHAKE_CLIENT_HELLO, 0x00, 0x00, 0x00, /* body length patched */
        0x03, 0x03,                                   /* legacy_version */
        /* client_random patched at offset 6 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x00,                    /* legacy_session_id length */
        0x00, 0x02, 0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
        0x01, 0x00,              /* one null compression method */
        0x00, 0x00,              /* extensions length patched */
        /* supported_versions: TLS 1.3 */
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
        /* supported_groups: x25519 */
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
        /* key_share header: one 32-byte x25519 key follows */
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        /* x25519 key patched at offset 72 */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* signature_algorithms: rsa_pss_rsae_sha256 */
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04,
        /* signature_algorithms_cert: rsa_pkcs1_sha256, rsa_pss_rsae_sha256 */
        0x00, 0x32, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x08, 0x04
    };
    static const uint8_t sni_header[] = {
        0x00, 0x00,             /* server_name */
        0x00, 0x00,             /* extension length patched */
        0x00, 0x00,             /* name-list length patched */
        0x00,                   /* host_name */
        0x00, 0x00              /* hostname length patched */
    };
    static const uint8_t cookie_header[] = {
        0x00, 0x2c,             /* cookie */
        0x00, 0x00,             /* extension length patched */
        0x00, 0x00              /* cookie length patched */
    };
    static const uint8_t psk_modes[] = {
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 /* psk_dhe_ke */
    };
    static const uint8_t alpn_header[] = {
        0x00, 0x10,             /* application_layer_protocol_negotiation */
        0x00, 0x00,             /* extension length patched */
        0x00, 0x00              /* ProtocolNameList length patched */
    };
    static const uint8_t psk_header[] = {
        0x00, 0x29,             /* pre_shared_key */
        0x00, 0x00,             /* extension length patched */
        0x00, 0x00              /* identities length patched */
    };
    static const uint8_t binder_header[] = {
        0x00, 0x00,             /* binders length patched */
        0x20                    /* SHA-256 binder length */
    };

    if (!ctx || !written || (!out && out_len != 0))
    {
        ERROR();
        return false;
    }

    bool is_hrr_retry = (ctx->state == TLS_STATE_HRR_RECEIVED);
    if (!is_hrr_retry && ctx->state != TLS_STATE_INIT)
    {
        ERROR();
        return false;
    }

    /* This implementation reuses the original x25519 share in ClientHello2.
     * A conforming HRR cannot request x25519 because it was already offered
     * in ClientHello1; a cookie-only HRR leaves the key_share unchanged. */

    /* early_secret/binder_key/finished_key/binder/hmac_ctx are secret
     * material only ever populated inside the ctx->psk_mode block below,
     * held on this function's own stack frame. They're cleaned up by
     * the caller, which wraps this call with
     * tls_crypto_guard_enable()/disable(). */
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
    size_t hostname_len = 0;
    size_t sni_len = 0;
    size_t alpn_ext_len = 0;
    size_t required_len;
    size_t required_ext_len;

    if (ctx->hostname)
    {
        hostname_len = strlen(ctx->hostname);
        if (hostname_len > 0xFFFFu - 5u)
        {
            ERROR_CODE(0x2c);
            return false;
        }
        uint8_t ip[16];
        int ip_len = tls_identity_ip(ctx->hostname, ip);
        if (ip_len < 0)
        {
            ERROR_CODE(0x2d);
            return false;
        }
        /* SNI HostName is a DNS name, never an IP literal. */
        if (ip_len == 0) sni_len = 9 + hostname_len;
    }
    if (ctx->psk_mode &&
        (ctx->psk_identity.identity_len == 0 ||
         ctx->psk_identity.identity_len > TLS_PSK_IDENTITY_MAX_LEN))
    {
        ERROR_CODE(0x2e);
        return false;
    }

    if (ctx->alpn_protocols_len != 0)
    {
        size_t alpn_offset = 0;
        if (!ctx->alpn_protocols || ctx->alpn_protocols_len > 0xFFFFu)
        {
            ERROR_CODE(0x2f);
            return false;
        }
        while (alpn_offset < ctx->alpn_protocols_len)
        {
            size_t protocol_len = ctx->alpn_protocols[alpn_offset++];
            if (protocol_len == 0 ||
                protocol_len > ctx->alpn_protocols_len - alpn_offset)
            {
                ERROR_CODE(0x30);
                return false;
            }
            alpn_offset += protocol_len;
        }
        alpn_ext_len = sizeof(alpn_header) + ctx->alpn_protocols_len;
    }

    /* Cookie extension overhead: type(2)+len(2)+inner_len(2)+cookie_bytes. */
    size_t cookie_ext_len = 0;
    if (ctx->hrr_cookie_len > 0)
    {
        cookie_ext_len = 4 + 2 + ctx->hrr_cookie_len; /* ext header + inner length field */
    }

    /* The exact-size check makes all template copies below safe. */
    required_ext_len = sizeof(hello_template) - HELLO_EXT_START +
                       sni_len + cookie_ext_len + alpn_ext_len;
    if (ctx->psk_mode)
    {
        /* psk_key_exchange_modes (6: header 4 + modes-length 1 + psk_dhe_ke
         * 1) + pre_shared_key fixed overhead (47) + identity bytes. */
        required_ext_len += sizeof(psk_modes) + 47 + ctx->psk_identity.identity_len;
    }
    if (required_ext_len > 0xFFFFu)
    {
        ERROR_CODE(0x2f);
        return false;
    }
    required_len = HELLO_EXT_START + required_ext_len;
    if (required_len - 4 > 0xFFFFFFu)
    {
        ERROR_CODE(0x2f);
        return false;
    }
    if (!out)
    {
        *written = required_len;
        return true;
    }
    if (required_len > out_len)
    {
        ERROR_CODE(required_len > 0xFFFF ? 0xFFFF : required_len);
        return false;
    }

    memcpy(out, hello_template, sizeof(hello_template));
    memcpy(out + HELLO_RANDOM_OFFSET, ctx->client_random, 32);
    memcpy(out + HELLO_KEY_SHARE_OFFSET, ctx->ecdhe_public, 32);
    offset = sizeof(hello_template);
    size_t ext_len_offset = HELLO_EXT_LEN_OFFSET;
    size_t ext_start = HELLO_EXT_START;

    /* Extension 7: server_name (SNI) */
    if (sni_len)
    {
        size_t sni_offset = offset;
        memcpy(out + offset, sni_header, sizeof(sni_header));
        offset += sizeof(sni_header);
        /* Extension length = hostname_len + 5 */
        size_t sni_ext_len = hostname_len + 5;
        out[sni_offset + 2] = (uint8_t)(sni_ext_len >> 8);
        out[sni_offset + 3] = (uint8_t)(sni_ext_len & 0xFF);
        /* Server name list length = hostname_len + 3 */
        size_t sni_list_len = hostname_len + 3;
        out[sni_offset + 4] = (uint8_t)(sni_list_len >> 8);
        out[sni_offset + 5] = (uint8_t)(sni_list_len & 0xFF);
        out[sni_offset + 7] = (uint8_t)(hostname_len >> 8);
        out[sni_offset + 8] = (uint8_t)(hostname_len & 0xFF);
        memcpy(out + offset, ctx->hostname, hostname_len);
        offset += hostname_len;
    }

    /* Cookie extension (RFC 8446 §4.2.2): MUST be present in the second
     * ClientHello when the HRR included one. */
    if (ctx->hrr_cookie_len > 0)
    {
        size_t cookie_offset = offset;
        memcpy(out + offset, cookie_header, sizeof(cookie_header));
        offset += sizeof(cookie_header);
        size_t cookie_ext_body = 2 + ctx->hrr_cookie_len;
        out[cookie_offset + 2] = (uint8_t)(cookie_ext_body >> 8);
        out[cookie_offset + 3] = (uint8_t)(cookie_ext_body & 0xFF);
        out[cookie_offset + 4] = (uint8_t)(ctx->hrr_cookie_len >> 8);
        out[cookie_offset + 5] = (uint8_t)(ctx->hrr_cookie_len & 0xFF);
        memcpy(out + offset, ctx->hrr_cookie, ctx->hrr_cookie_len);
        offset += ctx->hrr_cookie_len;
    }

    /* ALPN is application policy, so it is sent only when configured. */
    if (alpn_ext_len != 0)
    {
        size_t alpn_offset = offset;
        size_t ext_body_len = 2 + ctx->alpn_protocols_len;
        memcpy(out + offset, alpn_header, sizeof(alpn_header));
        offset += sizeof(alpn_header);
        out[alpn_offset + 2] = (uint8_t)(ext_body_len >> 8);
        out[alpn_offset + 3] = (uint8_t)ext_body_len;
        out[alpn_offset + 4] = (uint8_t)(ctx->alpn_protocols_len >> 8);
        out[alpn_offset + 5] = (uint8_t)ctx->alpn_protocols_len;
        memcpy(out + offset, ctx->alpn_protocols, ctx->alpn_protocols_len);
        offset += ctx->alpn_protocols_len;
    }

    if (ctx->psk_mode)
    {
        /* Extension 4: psk_key_exchange_modes.
         * Advertise psk_dhe_ke only -- never psk_ke. Offering psk_ke lets
         * the server pick PSK-only resumption with no fresh ECDHE, so a
         * later-compromised PSK/ticket key would retroactively expose that
         * session's traffic. psk_dhe_ke-only means every resumed session
         * still gets forward secrecy via a fresh key_share. */
        memcpy(out + offset, psk_modes, sizeof(psk_modes));
        offset += sizeof(psk_modes);

        /* Extension 5: pre_shared_key (MUST be last extension). */
        size_t psk_header_offset = offset;
        memcpy(out + offset, psk_header, sizeof(psk_header));
        offset += sizeof(psk_header);
        size_t psk_ext_len_offset = psk_header_offset + 2;
        size_t psk_ext_start = psk_header_offset + 4;
        size_t identities_len_offset = psk_header_offset + 4;

        size_t identities_start = offset;

        /* PSK identity */
        out[offset++] = (uint8_t)(ctx->psk_identity.identity_len >> 8);
        out[offset++] = (uint8_t)(ctx->psk_identity.identity_len & 0xFF);
        if (offset + ctx->psk_identity.identity_len > out_len)
        {
            ERROR_CODE(0x35);
            return false;
        }
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

        /* PSK binders. The binder vector itself is a fixed-size template;
         * its value is the only dynamic portion. */
        binder_offset = offset;
        size_t binders_len_offset = offset;
        memcpy(out + offset, binder_header, sizeof(binder_header));
        offset += sizeof(binder_header);

        /* Calculate PSK binder */
        if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, early_secret))
        {
            ERROR_CODE(0x36);
            return false;
        }

        const char *binder_label = (ctx->psk_type == TLS_PSK_TYPE_EXTERNAL)
                                       ? "ext binder"
                                       : "res binder";
        /* RFC 8446 derives binder_key with Derive-Secret(..., ""),
         * so the HKDF context is Transcript-Hash(empty), not a zero-length
         * context field. */
        if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
        {
            ERROR_CODE(0x37);
            return false;
        }
        tls_hash_digest(&hash_ctx, partial_hash);

        if (!tls_hkdf_expand_label(TLS_HASH_SHA256, early_secret, 32,
                                   binder_label, 10,
                                   partial_hash, 32, binder_key, 32))
        {
            ERROR_CODE(0x38);
            return false;
        }

        if (!tls_hkdf_expand_label(TLS_HASH_SHA256, binder_key, 32,
                                   "finished", 8, NULL, 0, finished_key, 32))
        {
            ERROR_CODE(0x39);
            return false;
        }

        /* Fill in length fields for binder hash computation */
        size_t total_msg_len = offset + 32 - msg_start;
        out[0] = TLS_HANDSHAKE_CLIENT_HELLO;
        out[1] = (uint8_t)(total_msg_len >> 16);
        out[2] = (uint8_t)(total_msg_len >> 8);
        out[3] = (uint8_t)(total_msg_len & 0xFF);

        size_t ext_len = offset + 32 - ext_start;
        out[ext_len_offset] = (uint8_t)(ext_len >> 8);
        out[ext_len_offset + 1] = (uint8_t)(ext_len & 0xFF);

        size_t psk_ext_len = offset + 32 - psk_ext_start;
        out[psk_ext_len_offset] = (uint8_t)(psk_ext_len >> 8);
        out[psk_ext_len_offset + 1] = (uint8_t)(psk_ext_len & 0xFF);

        size_t binders_len = 1 + 32;
        out[binders_len_offset] = (uint8_t)(binders_len >> 8);
        out[binders_len_offset + 1] = (uint8_t)(binders_len & 0xFF);

        /* Compute transcript hash of ClientHello truncated before binders.
         * RFC 8446 4.2.11.2: Truncate removes the entire OfferedPsks.binders
         * field, i.e. the 2-byte binders-vector length AND the 1-byte
         * PskBinderEntry length, not just the 32-byte HMAC value — so the
         * cut point is binder_offset itself, not binder_offset + 3.
         *
         * On an HRR retry the binder is computed over the transcript so
         * far -- message_hash(CH1) || HRR -- followed by truncated CH2,
         * not just truncated CH2 alone (RFC 8446 §4.2.11.2). ctx->
         * transcript_hash already holds message_hash(CH1) || HRR at this
         * point (set by the HRR parser in tls_parse_server_hello), so
         * branch off a copy of it instead of starting from empty. */
        if (is_hrr_retry && ctx->transcript_hash)
        {
            tls_hash_context_copy(&hash_ctx, ctx->transcript_hash);
        }
        else if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
        {
            ERROR_CODE(0x3a);
            return false;
        }
        tls_hash_update(&hash_ctx, out, binder_offset);
        tls_hash_digest(&hash_ctx, partial_hash);

        /* Compute binder = HMAC(finished_key, partial_hash) */
        if (!tls_hmac_context_init(&hmac_ctx, TLS_HASH_SHA256, finished_key, 32))
        {
            ERROR_CODE(0x3b);
            return false;
        }
        tls_hmac_update(&hmac_ctx, partial_hash, 32);
        tls_hmac_digest(&hmac_ctx, binder);

        /* Write binder value */
        if (offset + 32 > out_len)
        {
            ERROR_CODE(0x3c);
            return false;
        }
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
    DEBUG();
    return true;
}

/**
 * @brief Parse a ServerHello and pull out everything we need to derive keys.
 *
 * ServerHello is the server's response to ClientHello. After parsing this
 * message we have enough material to derive handshake traffic secrets:
 *
 *   - server_random (32 bytes, but watch for HelloRetryRequest sentinel —
 *     RFC 8446 §4.1.3 reserves a specific value to signal HRR. We parse
 *     the HRR extensions: if the requested group is x25519 (or absent) we
 *     do the transcript replacement and return TLS_STATE_HRR_RECEIVED so
 *     the caller can send a second ClientHello. Any other group sends
 *     handshake_failure. A second HRR on the same connection is rejected
 *     with unexpected_message per RFC 8446 §4.1.4).
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
        ERROR_CODE(0x3d);
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
        ERROR_CODE(0x3e);
        return false;
    }

    size_t msg_end = offset + msg_len;

    /* Step 3: Verify legacy version (0x0303) */
    if (offset + 2 > msg_end || data[offset] != 0x03 || data[offset + 1] != 0x03)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x3f);
        return false;
    }
    offset += 2;

    /* Step 4: Extract server random */
    if (offset + 32 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x40);
        return false;
    }
    memcpy(ctx->server_random, data + offset, 32);
    offset += 32;

    /* Check for HelloRetryRequest (RFC 8446 §4.1.3).
     * HRR is signaled by server_random == SHA-256("HelloRetryRequest"). */
    {
        static const uint8_t hrr_random[32] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};
        if (memcmp(ctx->server_random, hrr_random, 32) == 0)
        {
            /* RFC 8446 §4.1.4 — parse HRR extensions to find the requested
             * key_share group and optional cookie, then do the transcript
             * replacement (§4.4.1) and return TLS_STATE_HRR_RECEIVED so the
             * caller can send a second ClientHello. */

            /* Reject a second HRR — RFC 8446 §4.1.4 forbids it. */
            if (ctx->hrr_done)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL,
                               TLS_ALERT_UNEXPECTED_MESSAGE);
                ERROR_CODE(0x41);
                return false; /* state already ERROR from tls_send_alert */
            }

            /* Skip session ID (same parse as the normal ServerHello path). */
            size_t hrr_offset = offset;
            if (hrr_offset >= msg_end)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x42);
                return false;
            }
            uint8_t sid_len = data[hrr_offset++];
            if (hrr_offset + sid_len > msg_end)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x43);
                return false;
            }
            if (sid_len != 0)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x43);
                return false;
            }
            hrr_offset += sid_len;

            /* Skip cipher suite (2) + compression method (1). */
            if (hrr_offset + 3 > msg_end)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x44);
                return false;
            }
            if ((((uint16_t)data[hrr_offset] << 8) | data[hrr_offset + 1]) !=
                    ctx->cipher_suite || data[hrr_offset + 2] != 0)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x44);
                return false;
            }
            hrr_offset += 3;

            /* Extensions block */
            if (hrr_offset + 2 > msg_end)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x45);
                return false;
            }
            uint16_t hrr_ext_len = ((uint16_t)data[hrr_offset] << 8) |
                                    data[hrr_offset + 1];
            hrr_offset += 2;
            size_t hrr_ext_end = hrr_offset + hrr_ext_len;
            if (hrr_ext_end != msg_end)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x46);
                return false;
            }

            const uint8_t *cookie_data = NULL;
            uint16_t cookie_len = 0;
            bool hrr_version = false, hrr_key_share = false, hrr_cookie_seen = false;

            while (hrr_offset + 4 <= hrr_ext_end)
            {
                uint16_t etype = ((uint16_t)data[hrr_offset] << 8) |
                                  data[hrr_offset + 1];
                uint16_t elen  = ((uint16_t)data[hrr_offset + 2] << 8) |
                                  data[hrr_offset + 3];
                hrr_offset += 4;
                if (hrr_offset + elen > hrr_ext_end)
                {
                    ctx->state = TLS_STATE_ERROR;
                    ERROR_CODE(0x47);
                    return false;
                }
                if (etype == TLS_EXT_KEY_SHARE)
                {
                    /* HRR key_share extension body = 2-byte NamedGroup. */
                    if (hrr_key_share || elen != 2)
                    {
                        ctx->state = TLS_STATE_ERROR;
                        ERROR_CODE(0x48);
                        return false;
                    }
                    hrr_key_share = true;
                }
                else if (etype == TLS_EXT_COOKIE)
                {
                    /* Cookie body = 2-byte length + cookie bytes. */
                    if (hrr_cookie_seen || elen < 3)
                    {
                        ctx->state = TLS_STATE_ERROR;
                        ERROR_CODE(0x49);
                        return false;
                    }
                    uint16_t clen = ((uint16_t)data[hrr_offset] << 8) |
                                     data[hrr_offset + 1];
                    if ((size_t)clen + 2u != elen)
                    {
                        ctx->state = TLS_STATE_ERROR;
                        ERROR_CODE(0x4a);
                        return false;
                    }
                    cookie_data = data + hrr_offset + 2;
                    cookie_len  = clen;
                    hrr_cookie_seen = true;
                }
                else if (etype == TLS_EXT_SUPPORTED_VERSIONS)
                {
                    if (hrr_version || elen != 2 || data[hrr_offset] != 0x03 ||
                        data[hrr_offset + 1] != 0x04)
                    {
                        ctx->state = TLS_STATE_ERROR;
                        ERROR_CODE(0x4a);
                        return false;
                    }
                    hrr_version = true;
                }
                else
                {
                    tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
                    return false;
                }
                hrr_offset += elen;
            }

            if (hrr_offset != hrr_ext_end || !hrr_version ||
                (!hrr_key_share && !hrr_cookie_seen))
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x4a);
                return false;
            }

            /* x25519 was already offered in ClientHello1 and therefore cannot
             * be selected by HRR; every other group is unsupported here. */
            if (hrr_key_share)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL,
                               TLS_ALERT_HANDSHAKE_FAILURE);
                ERROR_CODE(0x4b);
                return false;
            }

            /* RFC 8446 §4.4.1 transcript replacement: replace the transcript
             * with message_hash(H(ClientHello1)), represented as a synthetic
             * handshake message: type=0xfe, length=32, body=digest. */
            {
                uint8_t ch1_digest[32];
                tls_hash_digest(ctx->transcript_hash, ch1_digest);

                /* Re-initialise the transcript hash. */
                if (!transcript_hash_init(ctx->transcript_hash))
                {
                    ctx->state = TLS_STATE_ERROR;
                    ERROR_CODE(0x4c);
                    return false;
                }

                /* Feed the synthetic message_hash message (4 + 32 = 36 bytes). */
                uint8_t synth[36];
                synth[0] = 0xFE; /* message_hash */
                synth[1] = 0x00;
                synth[2] = 0x00;
                synth[3] = 0x20; /* length = 32 */
                memcpy(synth + 4, ch1_digest, 32);
                transcript_hash_update(ctx->transcript_hash, synth, sizeof(synth));
            }

            /* Feed the HRR itself into the new transcript. */
            transcript_hash_update(ctx->transcript_hash, data, msg_end);

            /* Save cookie for the second ClientHello (free any previous). */
            if (ctx->hrr_cookie)
            {
                mem_buffer_custom_free(ctx->hrr_cookie);
                ctx->hrr_cookie = NULL;
                ctx->hrr_cookie_len = 0;
            }
            if (cookie_data && cookie_len > 0)
            {
                ctx->hrr_cookie = (uint8_t *)mem_buffer_custom_malloc(cookie_len);
                if (!ctx->hrr_cookie)
                {
                    ctx->state = TLS_STATE_ERROR;
                    ERROR_CODE(0x4d);
                    return false;
                }
                memcpy(ctx->hrr_cookie, cookie_data, cookie_len);
                ctx->hrr_cookie_len = cookie_len;
            }

            ctx->hrr_done = true;
            ctx->state = TLS_STATE_HRR_RECEIVED;
            return true;
        }
    }

    /* Step 5: Skip session ID */
    if (offset >= msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x4e);
        return false;
    }
    uint8_t session_id_len = data[offset++];
    if (session_id_len != 0 || offset + session_id_len > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x4f);
        return false;
    }
    offset += session_id_len;

    /* Step 6: Parse cipher suite */
    if (offset + 2 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x50);
        return false;
    }
    uint16_t cipher_suite = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (cipher_suite != ctx->cipher_suite)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x51);
        return false;
    }

    /* Step 7: Verify compression method */
    if (offset >= msg_end || data[offset++] != 0x00)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x52);
        return false;
    }

    /* Step 8: Parse extensions */
    if (offset + 2 > msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x53);
        return false;
    }
    uint16_t ext_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    size_t ext_end = offset + ext_len;
    if (ext_end != msg_end)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x54);
        return false;
    }

    while (offset < ext_end)
    {
        if (offset + 4 > ext_end)
        {
            ctx->state = TLS_STATE_ERROR;
            ERROR_CODE(0x55);
            return false;
        }

        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_data_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_data_len > ext_end)
        {
            ctx->state = TLS_STATE_ERROR;
            ERROR_CODE(0x56);
            return false;
        }

        switch (ext_type)
        {
        case TLS_EXT_SUPPORTED_VERSIONS:
            /* Verify TLS 1.3 (0x0304) */
            if (found_supported_versions || ext_data_len != 2)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x57);
                return false;
            }
            if (data[offset] != 0x03 || data[offset + 1] != 0x04)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x58);
                return false;
            }
            found_supported_versions = true;
            break;

        case TLS_EXT_KEY_SHARE:
        {
            /* ServerHello key_share: named_group (2) + key_exchange_length (2) + key_exchange */
            if (ctx->ecdhe_negotiated || ext_data_len < 4)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x59);
                return false;
            }
            uint16_t group = (data[offset] << 8) | data[offset + 1];
            uint16_t ke_len = (data[offset + 2] << 8) | data[offset + 3];
            if (group != TLS_NAMED_GROUP_X25519 || ke_len != 32 ||
                ext_data_len != (size_t)(4 + ke_len))
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5a);
                return false;
            }
            /* Compute shared secret from server's public key */
            if (!tls_x25519_secret(ctx->ecdhe_shared, ctx->ecdhe_private,
                                   data + offset + 4,
                                   NULL, NULL))
            {
                ERROR();
                tls_secure_memzero(ctx->ecdhe_private, 32);
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5b);
                return false;
            }
            /* RFC 7748 §6 requires protocols using X25519 to reject an
             * all-zero shared secret (the result for low-order inputs). */
            if (!tls_x25519_shared_is_nonzero(ctx->ecdhe_shared))
            {
                tls_secure_memzero(ctx->ecdhe_private,
                                   sizeof(ctx->ecdhe_private));
                tls_secure_memzero(ctx->ecdhe_shared,
                                   sizeof(ctx->ecdhe_shared));
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL,
                               TLS_ALERT_ILLEGAL_PARAMETER);
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5c);
                return false;
            }
            /* Securely erase private key immediately */
            tls_secure_memzero(ctx->ecdhe_private, 32);
            ctx->ecdhe_negotiated = true;
            DEBUG();
            break;
        }

        case TLS_EXT_PRE_SHARED_KEY:
        {
            if (found_psk || !ctx->psk_mode)
            {
                /* Server selected a PSK identity we did not offer. */
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5c);
                return false;
            }
            /* Extract selected PSK identity (2 bytes, should be 0 for first PSK) */
            if (ext_data_len != 2)
            {
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5d);
                return false;
            }
            uint16_t selected_identity = (data[offset] << 8) | data[offset + 1];
            if (selected_identity != 0)
            {
                /* Server selected a PSK identity we didn't offer */
                ctx->state = TLS_STATE_ERROR;
                ERROR_CODE(0x5e);
                return false;
            }
            found_psk = true;
            break;
        }

        default:
            tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
            return false;
        }

        offset += ext_data_len;
    }

    /* Verify required extensions were present */
    if (!found_supported_versions || (!found_psk && !ctx->ecdhe_negotiated))
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x5f);
        return false;
    }
    ctx->psk_mode = found_psk;

    /* Step 9: Update transcript hash with ServerHello */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, msg_end);
    }

    ctx->state = TLS_STATE_SERVER_HELLO_RECEIVED;
    DEBUG();
    return true;
}

/**
 * @brief Finalize a streamed Certificate message.
 *
 * Called by tls_consume_handshake_buffer when the cert walker reaches
 * CW_DONE. Checks the state/PSK gates and requires w->chain_validated, which
 * now means "the leaf SPKI was captured and every chain link the walker checked
 * passed". It does NOT mean a truststore root matched. CertificateVerify later
 * proves possession of the leaf private key; server authentication additionally
 * depends on successful path anchoring and service-identity validation.
 * The walker has already updated the transcript hash incrementally as bytes
 * arrived, so we don't touch it here.
 */
static bool tls_recv_certificate_streamed(struct tls_handshake_context *ctx,
                                          struct tls_cert_walker *w)
{
    if (!ctx || !w)
    {
        ERROR_CODE(0x60);
        return false;
    }
    if (ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x61);
        return false;
    }
    /* PSK-authenticated handshakes, including PSK+DHE, MUST NOT send
     * Certificate. The PSK is the server authentication in that mode. */
    if (ctx->psk_mode)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x62);
        return false;
    }
    if (w->state != CW_DONE)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x63);
        return false;
    }
    if (!w->chain_validated)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x64);
        return false;
    }

    /* Root cert truststore validation: look up the topmost cert's issuer
     * (the root CA) in the truststore by subject name. */
    if (w->topmost_issuer_cn_len > 0)
    {
        struct tls_truststore_entry *root_entry = NULL;
        if (tls_truststore_lookup_by_subject(w->topmost_issuer_cn,
                                             w->topmost_issuer_cn_len,
                                             &root_entry) && root_entry)
        {
            tls_cert_sig_alg_t alg = (tls_cert_sig_alg_t)root_entry->alg_id;
            bool root_rsa = (alg == TLS_CERT_SIG_RSA_PSS_SHA256 ||
                             alg == TLS_CERT_SIG_RSA_PKCS1_SHA256);
            if (root_rsa)
            {
                /* Extract stored exp (uint24_t LE) and modulus from key[]. */
                if (root_entry->len < sizeof(struct tls_truststore_entry))
                {
                    ctx->state = TLS_STATE_ERROR;
                    ERROR_CODE(0x65);
                    return false;
                }
                size_t key_len = root_entry->len - sizeof(struct tls_truststore_entry);
                if (key_len >= 3 + RSA_MODULUS_MIN_SUPPORTED &&
                    w->pending_link)
                {
                    /* Truststore packs exponent as 3-byte LE; convert to BE for
                     * tls_rsa_key which expects big-endian exponent bytes. */
                    uint8_t exp_be[3] = {
                        root_entry->key[2],
                        root_entry->key[1],
                        root_entry->key[0],
                    };
                    const uint8_t *mod     = root_entry->key + 3;
                    size_t         mod_len = key_len - 3;
                    struct tls_rsa_key root_key = {
                        sizeof(exp_be), exp_be,
                        mod_len, mod,
                    };
                    struct tls_key root_tls_key = {
                        .type = TLS_KEY_TYPE_RSA,
                        .rsa = root_key,
                    };
                    tls_key_op_result_t verify_result =
                        tls_cert_verify_pending_link(w, &root_tls_key);
                    if (verify_result == TLS_KEY_OP_UNSUPPORTED)
                    {
                        WARN();
                    }
                    else if (verify_result != TLS_KEY_OP_OK)
                    {
                        ERROR();
                        ctx->state = TLS_STATE_ERROR;
                        return false;
                    }
                }
                else
                {
                    ctx->state = TLS_STATE_ERROR;
                    ERROR_CODE(0x66);
                    return false;
                }
            }
            else
            {
                /* Interim compatibility pinhole: the trust anchor exists but
                 * its key/signature operation is not implemented. */
                WARN();
            }
        }
        else
        {
            /* No truststore entry found: no root anchor available. Proceed
             * without root pinning (consistent with prior behaviour when
             * truststore absent), but tell the caller. */
            WARN();
        }
    }

    ctx->state = TLS_STATE_CERTIFICATE_RECEIVED;
    DEBUG();
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
 * The current implementation consumes ALPN and validates the informational
 * supported_groups list; otherwise it:
 *
 *   1. Validate the framing (length fields nest correctly).
 *   2. Validate every permitted extension and reject duplicates.
 *   3. Feed the message bytes into the running transcript hash, because
 *      the next message's transcript hash snapshot must include it.
 *   4. Advance state to ENCRYPTED_EXTENSIONS_RECEIVED.
 *
 * ALPN, when returned, must select exactly one protocol that appeared in the
 * client's configured ProtocolNameList.
 */
static bool tls_recv_encrypted_extensions(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 6)
    {
        ERROR_CODE(0x68);
        return false;
    }
    if (ctx->state != TLS_STATE_HANDSHAKE_KEYS_DERIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x69);
        return false;
    }

    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
                                               &msg_len);
    if (offset == 0)
    {
        ERROR_CODE(0x6a);
        return false;
    }

    /* Parse extensions length (2 bytes) */
    if (offset + 2 > data_len)
    {
        ERROR_CODE(0x6b);
        return false;
    }
    size_t ext_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;

    /* Verify extensions fit in message */
    if (offset + ext_len != data_len || ext_len != msg_len - 2u)
    {
        ERROR_CODE(0x6c);
        return false;
    }

    bool seen_server_name = false, seen_alpn = false, seen_groups = false;
    ctx->negotiated_alpn = NULL;
    ctx->negotiated_alpn_len = 0;
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
            ERROR_CODE(0x6d);
            return false;
        }

        const uint8_t *ext_data = data + offset + ext_offset;
        if (ext_type == TLS_EXT_SERVER_NAME)
        {
            if (seen_server_name || ext_data_len != 0)
            {
                ERROR_CODE(0x6f);
                return false;
            }
            seen_server_name = true;
        }
        else if (ext_type == TLS_EXT_ALPN)
        {
            size_t offered_offset = 0;
            const uint8_t *selected = NULL;
            uint16_t list_len;
            uint8_t selected_len;

            if (seen_alpn || !ctx->alpn_protocols ||
                ctx->alpn_protocols_len == 0 || ext_data_len < 4)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL,
                               TLS_ALERT_UNSUPPORTED_EXTENSION);
                return false;
            }
            list_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            selected_len = ext_data[2];
            /* A server ALPN response contains exactly one non-empty name. */
            if (selected_len == 0 || list_len != (uint16_t)(selected_len + 1u) ||
                ext_data_len != (uint16_t)(list_len + 2u))
            {
                ERROR_CODE(0x70);
                return false;
            }
            while (offered_offset < ctx->alpn_protocols_len)
            {
                uint8_t offered_len = ctx->alpn_protocols[offered_offset++];
                if (offered_len == 0 ||
                    offered_len > ctx->alpn_protocols_len - offered_offset)
                {
                    ERROR_CODE(0x71);
                    return false;
                }
                if (offered_len == selected_len &&
                    memcmp(ctx->alpn_protocols + offered_offset,
                           ext_data + 3, selected_len) == 0)
                {
                    selected = ctx->alpn_protocols + offered_offset;
                }
                offered_offset += offered_len;
            }
            if (!selected)
            {
                tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL,
                               TLS_ALERT_ILLEGAL_PARAMETER);
                return false;
            }
            ctx->negotiated_alpn = selected;
            ctx->negotiated_alpn_len = selected_len;
            seen_alpn = true;
        }
        else if (ext_type == TLS_EXT_SUPPORTED_GROUPS)
        {
            uint16_t groups_len;
            if (seen_groups || ext_data_len < 4)
            {
                ERROR_CODE(0x72);
                return false;
            }
            groups_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if (groups_len < 2 || (groups_len & 1u) != 0 ||
                groups_len != (uint16_t)(ext_data_len - 2u))
            {
                ERROR_CODE(0x73);
                return false;
            }
            /* This is the server's complete supported-group preference list,
             * not a second key-exchange selection. Unknown/private/grease
             * groups are valid here; ServerHello.key_share already selected
             * and validated X25519. Only malformed or duplicate entries are
             * rejected. */
            for (size_t group_offset = 2; group_offset < ext_data_len;
                 group_offset += 2)
            {
                uint16_t group = ((uint16_t)ext_data[group_offset] << 8) |
                                 ext_data[group_offset + 1];
                for (size_t previous = 2; previous < group_offset;
                     previous += 2)
                {
                    uint16_t previous_group =
                        ((uint16_t)ext_data[previous] << 8) |
                        ext_data[previous + 1];
                    if (previous_group == group)
                    {
                        ERROR_CODE(0x74);
                        return false;
                    }
                }
            }
            seen_groups = true;
        }
        else
        {
            tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNSUPPORTED_EXTENSION);
            return false;
        }
        ext_offset += ext_data_len;
    }
    if (ext_offset != ext_len)
    {
        ERROR_CODE(0x6e);
        return false;
    }

    /* Update transcript hash with the EncryptedExtensions message */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }

    /* Update state */
    ctx->state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    DEBUG();

    return true;
}

/**
 * @brief Parse a TLS 1.3 server CertificateRequest.
 *
 * This message is optional client-auth negotiation. Even when the client has
 * no certificate to present, the message still participates in the transcript
 * hash used by the server's CertificateVerify signature and Finished MAC. So
 * we validate the nested length fields, remember that the server asked, and
 * feed the exact handshake bytes into the transcript.
 */
static bool tls_recv_certificate_request(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    size_t msg_len = 0;
    size_t offset;
    size_t msg_end;
    uint8_t request_context_len;
    size_t ext_len;
    size_t ext_offset = 0;
    bool found_signature_algorithms = false;

    if (!ctx || !data || data_len < 7)
    {
        ERROR_CODE(0x6f);
        return false;
    }
    if (ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x70);
        return false;
    }
    /* A server authenticating this main handshake with a selected PSK is not
     * permitted to request a client certificate (RFC 8446 §4.3.2). */
    if (ctx->psk_mode)
    {
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        ERROR_CODE(0x71);
        return false;
    }

    offset = tls_parse_handshake_header(data, data_len,
                                        TLS_HANDSHAKE_CERTIFICATE_REQUEST,
                                        &msg_len);
    if (offset == 0)
    {
        ERROR_CODE(0x71);
        return false;
    }
    msg_end = offset + msg_len;
    if (msg_end != data_len)
    {
        ERROR_CODE(0x72);
        return false;
    }

    if (offset + 1 > msg_end)
    {
        ERROR_CODE(0x72);
        return false;
    }
    request_context_len = data[offset++];
    if (offset + request_context_len > msg_end)
    {
        ERROR_CODE(0x73);
        return false;
    }
    /* A CertificateRequest sent in the main handshake has an empty context.
     * Non-empty contexts are reserved for post-handshake authentication,
     * which this client does not negotiate. */
    if (request_context_len != 0)
    {
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
        ERROR_CODE(0x74);
        return false;
    }
    offset += request_context_len;

    if (offset + 2 > msg_end)
    {
        ERROR_CODE(0x74);
        return false;
    }
    ext_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;
    if (offset + ext_len != msg_end)
    {
        ERROR_CODE(0x75);
        return false;
    }

    while (ext_offset + 4 <= ext_len)
    {
        size_t this_ext_offset = ext_offset;
        size_t previous_offset = 0;
        uint16_t ext_type;
        uint16_t ext_data_len;

        ext_type = ((uint16_t)data[offset + ext_offset] << 8) |
                   (uint16_t)data[offset + ext_offset + 1];
        ext_offset += 2;
        ext_data_len = ((uint16_t)data[offset + ext_offset] << 8) |
                       (uint16_t)data[offset + ext_offset + 1];
        ext_offset += 2;

        if (ext_offset + ext_data_len > ext_len)
        {
            ERROR_CODE(0x76);
            return false;
        }

        /* RFC 8446 §4.2 forbids duplicate extensions in any extension block,
         * including types that this client otherwise ignores. */
        while (previous_offset < this_ext_offset)
        {
            uint16_t previous_type =
                ((uint16_t)data[offset + previous_offset] << 8) |
                (uint16_t)data[offset + previous_offset + 1];
            uint16_t previous_len =
                ((uint16_t)data[offset + previous_offset + 2] << 8) |
                (uint16_t)data[offset + previous_offset + 3];
            if (previous_type == ext_type)
            {
                ERROR_CODE(0x77);
                return false;
            }
            previous_offset += 4u + previous_len;
        }

        if (ext_type == TLS_EXT_SIGNATURE_ALGORITHMS ||
            ext_type == TLS_EXT_SIGNATURE_ALGORITHMS_CERT)
        {
            const uint8_t *ext_data = data + offset + ext_offset;
            uint16_t algorithms_len;
            if (ext_data_len < 4)
            {
                ERROR_CODE(0x78);
                return false;
            }
            algorithms_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if (algorithms_len < 2 || (algorithms_len & 1u) != 0 ||
                algorithms_len != (uint16_t)(ext_data_len - 2u))
            {
                ERROR_CODE(0x79);
                return false;
            }
            if (ext_type == TLS_EXT_SIGNATURE_ALGORITHMS)
            {
                found_signature_algorithms = true;
            }
        }
        else if (ext_type == TLS_EXT_CERTIFICATE_AUTHORITIES)
        {
            const uint8_t *ext_data = data + offset + ext_offset;
            size_t names_offset = 2;
            uint16_t names_len;
            if (ext_data_len < 5)
            {
                ERROR_CODE(0x7a);
                return false;
            }
            names_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if (names_len < 3 || names_len != (uint16_t)(ext_data_len - 2u))
            {
                ERROR_CODE(0x7b);
                return false;
            }
            while (names_offset < ext_data_len)
            {
                uint16_t name_len;
                if (ext_data_len - names_offset < 2)
                {
                    return false;
                }
                name_len = ((uint16_t)ext_data[names_offset] << 8) |
                           ext_data[names_offset + 1];
                names_offset += 2;
                if (name_len == 0 || name_len > ext_data_len - names_offset)
                {
                    return false;
                }
                names_offset += name_len;
            }
        }
        else if (ext_type == TLS_EXT_OID_FILTERS)
        {
            const uint8_t *ext_data = data + offset + ext_offset;
            size_t filter_offset = 2;
            uint16_t filters_len;
            if (ext_data_len < 2)
            {
                return false;
            }
            filters_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if (filters_len != (uint16_t)(ext_data_len - 2u))
            {
                return false;
            }
            while (filter_offset < ext_data_len)
            {
                size_t this_filter = filter_offset;
                size_t previous_filter = 2;
                uint8_t oid_len = ext_data[filter_offset++];
                uint16_t values_len;
                if (oid_len == 0 ||
                    oid_len > ext_data_len - filter_offset ||
                    ext_data_len - filter_offset - oid_len < 2)
                {
                    return false;
                }
                while (previous_filter < this_filter)
                {
                    uint8_t previous_oid_len = ext_data[previous_filter++];
                    uint16_t previous_values_len;
                    if (previous_oid_len == oid_len &&
                        memcmp(ext_data + previous_filter,
                               ext_data + filter_offset, oid_len) == 0)
                    {
                        return false;
                    }
                    previous_filter += previous_oid_len;
                    previous_values_len =
                        ((uint16_t)ext_data[previous_filter] << 8) |
                        ext_data[previous_filter + 1];
                    previous_filter += 2u + previous_values_len;
                }
                filter_offset += oid_len;
                values_len = ((uint16_t)ext_data[filter_offset] << 8) |
                             ext_data[filter_offset + 1];
                filter_offset += 2;
                if (values_len > ext_data_len - filter_offset)
                {
                    return false;
                }
                filter_offset += values_len;
            }
        }
        ext_offset += ext_data_len;
    }
    if (ext_offset != ext_len)
    {
        ERROR_CODE(0x77);
        return false;
    }
    /* signature_algorithms is mandatory in a TLS 1.3 CertificateRequest. */
    if (!found_signature_algorithms)
    {
        ERROR_CODE(0x7a);
        return false;
    }

    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }
    ctx->client_certificate_requested = true;
    DEBUG();
    return true;
}

/* TLS 1.3 signature_algorithms code points (RFC 8446 §4.2.3). */
#define TLS_SIG_RSA_PSS_RSAE_SHA256 0x0804


/* Verify a TLS 1.3 server CertificateVerify signature against the leaf
 * cert's SPKI. Implements the construction from RFC 8446 §4.4.3:
 *
 *     digest = SHA256(64 spaces || "TLS 1.3, server CertificateVerify" ||
 *                     0x00 || Transcript-Hash(ClientHello..Certificate))
 *
 * then RSA-decrypts the signature using the leaf modulus and runs the
 * PSS padding check against `digest`. Only rsa_pss_rsae_sha256 is wired
 * up — the rest of the PSS variants would need SHA-384/SHA-512, which
 * are not in the hash framework. Returns true iff the signature checks
 * out. */
static bool tls_certverify_rsa_pss_sha256(struct tls_handshake_context *ctx,
                                          const uint8_t *sig, size_t sig_len)
{
    static const char ctx_label[] = "TLS 1.3, server CertificateVerify";
    uint8_t spaces[64];
    uint8_t zero = 0;
    uint8_t transcript[32];
    uint8_t message_hash[32];
    struct tls_hash_context hash_ctx;
    uint8_t *em = NULL;
    bool ok = false;

    if (!ctx || ctx->leaf_pubkey.type != TLS_KEY_TYPE_RSA ||
        !sig || sig_len == 0)
    {
        ERROR_CODE(0x78);
        return false;
    }

    const struct tls_rsa_key *rsa = &ctx->leaf_pubkey.rsa;
    if (!rsa->modulus || rsa->mod_len == 0)
    {
        INFO("certverify: no rsa key");
        ERROR_CODE(0x79);
        return false;
    }

    /* TLS 1.3 PSS uses salt length == hash length, so the signature must
     * exactly match the modulus size in bytes. */
    if (sig_len != rsa->mod_len)
    {
        INFO("certverify: len mismatch");
        ERROR_CODE(0x7a);
        return false;
    }

    /* Build the signed-content digest. */
    if (!ctx->transcript_hash)
    {
        ERROR_CODE(0x7b);
        return false;
    }

    transcript_hash_digest(ctx->transcript_hash, transcript);

    memset(spaces, 0x20, sizeof(spaces));
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        ERROR_CODE(0x7c);
        return false;
    }

    tls_hash_update(&hash_ctx, spaces, sizeof(spaces));
    tls_hash_update(&hash_ctx, (const uint8_t *)ctx_label, sizeof(ctx_label) - 1);
    tls_hash_update(&hash_ctx, &zero, 1);
    tls_hash_update(&hash_ctx, transcript, sizeof(transcript));
    tls_hash_digest(&hash_ctx, message_hash);

    /* RSA decrypt the signature, then run the PSS padding check. */
    if (rsa->mod_len > RSA_TRANSIENT_SIZE)
    {
        ERROR_CODE(0x7d);
        return false;
    }

    em = __rsa_transient;
    if (!tls_rsa_decrypt_signature(sig, sig_len, em, rsa))
    {
        INFO("certverify: rsa decrypt fail");
        goto cleanup;
    }
    if (!tls_rsa_pss_verify(em, rsa->mod_len, message_hash, sizeof(message_hash),
                            TLS_HASH_SHA256))
    {
        INFO("certverify: pss verify fail");
        goto cleanup;
    }
    ok = true;

cleanup:
    if (em)
    {
        tls_secure_memzero(em, rsa->mod_len);
    }
    return ok;
}

/**
 * @brief Parse and verify the server's CertificateVerify.
 *
 * CertificateVerify is the server's signature over the handshake
 * transcript using the private key corresponding to the leaf cert it
 * just sent. It's the live proof-of-possession that binds "I trust this
 * cert chain" to "I'm actually talking to that cert's owner."
 *
 * Supports rsa_pss_rsae_sha256 only.
 */
static bool tls_recv_certificate_verify(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    INFO("certverify: begin");
    if (!ctx || !data || data_len < 8)
    {
        ERROR_CODE(0x7e);
        return false;
    }
    if (ctx->state != TLS_STATE_CERTIFICATE_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x7f);
        return false;
    }

    size_t msg_len = 0;
    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY,
                                               &msg_len);
    if (offset == 0)
    {
        ERROR_CODE(0x80);
        return false;
    }

    /* Signature algorithm (2 bytes). */
    if (offset + 2 > data_len)
    {
        ERROR_CODE(0x81);
        return false;
    }
    uint16_t sig_alg = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;

    /* Signature length (2 bytes) and bounds. */
    if (offset + 2 > data_len)
    {
        ERROR_CODE(0x82);
        return false;
    }
    size_t sig_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;
    if (offset + sig_len > data_len || offset + sig_len != 4 + msg_len)
    {
        ERROR_CODE(0x83);
        return false;
    }

    if (ctx->leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN)
    {
        /* No leaf cert in hand (e.g. pure-PSK handshake fluke).
         * CertificateVerify without a leaf is unverifiable; fail closed. */
        INFO("certverify: missing leaf key");
        ERROR();
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    bool sig_ok = false;
    switch (sig_alg)
    {
    case TLS_SIG_RSA_PSS_RSAE_SHA256:
        sig_ok = tls_certverify_rsa_pss_sha256(ctx, data + offset, sig_len);
        break;
    default:
        /* Unsupported algorithm — fail closed. */
        sig_ok = false;
        break;
    }

    if (!sig_ok)
    {
        INFO("certverify: signature fail");
        ERROR();
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECRYPT_ERROR);
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(0x84);
        return false;
    }

    /* Update transcript hash with the CertificateVerify message. Must
     * happen AFTER verify (the digest fed to PSS covers the transcript
     * through Certificate only). */
    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, data, 4 + msg_len);
    }

    ctx->state = TLS_STATE_CERTIFICATE_VERIFY_RECEIVED;
    INFO("certverify: accepted");
    DEBUG();

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
 * are ready for use by the altcp layer's streaming record encrypt/decrypt
 * in handshake-phase mode, and state advances to HANDSHAKE_KEYS_DERIVED.
 */
bool tls_derive_handshake_keys(struct tls_handshake_context *ctx)
{
    if (!ctx || ctx->state != TLS_STATE_SERVER_HELLO_RECEIVED)
    {
        ERROR();
        return false;
    }

    /* early_secret/handshake_secret/derived_secret are real TLS 1.3
     * secrets held on this function's own stack frame. They're cleaned
     * up by the caller, which wraps this call with
     * tls_crypto_guard_enable()/disable(). */
    uint8_t early_secret[32];
    uint8_t handshake_secret[32];
    uint8_t derived_secret[32];
    uint8_t empty_hash[32];
    uint8_t transcript_hash[32];
    struct tls_hash_context hash_ctx;

    /* Step 1: Compute early_secret from selected PSK, or zeros for a
     * full ECDHE handshake. A PSK offered but not selected has already
     * cleared ctx->psk_mode in tls_recv_server_hello().
     *
     * early_secret = HKDF-Extract(salt=0, IKM=PSK or 0)
     */
    {
        const uint8_t *psk_ikm = ctx->psk_mode ? ctx->psk : NULL;
        if (!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, psk_ikm, 32,
                              early_secret))
        {
            ERROR_CODE(0x85);
            return false;
        }
    }

    /* Step 2: Compute empty hash for "derived" secret
     * empty_hash = SHA-256("")
     */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        ERROR_CODE(0x86);
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 3: Derive "derived" secret from early_secret
     * derived = Derive-Secret(early_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, early_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret))
    {
        ERROR_CODE(0x87);
        return false;
    }

    /* Step 4: Compute handshake_secret
     * PSK+ECDHE: handshake_secret = HKDF-Extract(salt=derived, IKM=ecdhe_shared)
     * PSK-only:  handshake_secret = HKDF-Extract(salt=derived, IKM=0)
     */
    {
        /* PSK-only path passes ikm=NULL so hkdf_extract supplies 32 zero
         * bytes; saves a 32-byte stack buffer here. */
        const uint8_t *ecdhe_ikm = ctx->ecdhe_negotiated ? ctx->ecdhe_shared : NULL;
        if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                              ecdhe_ikm, 32, handshake_secret))
        {
            ERROR_CODE(0x88);
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
        ERROR_CODE(0x89);
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
        ERROR_CODE(0x8a);
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
        ERROR_CODE(0x8b);
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_handshake_iv, 12))
    {
        ERROR_CODE(0x8c);
        return false;
    }

    /* Step 9: Derive server handshake key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_handshake_key, 16))
    {
        ERROR_CODE(0x8d);
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_handshake_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_handshake_iv, 12))
    {
        ERROR_CODE(0x8e);
        return false;
    }

    /* Store handshake_secret for later use in application key derivation */
    memcpy(ctx->keys.handshake_secret, handshake_secret, 32);

    /* Advance state so this function is not called again */
    ctx->state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    DEBUG();

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
        ERROR();
        return false;
    }

    /* master_secret/derived_secret are real TLS 1.3 secrets held on this
     * function's own stack frame. They're cleaned up by the caller,
     * which wraps this call with tls_crypto_guard_enable()/disable(). */
    uint8_t master_secret[32];
    uint8_t derived_secret[32];
    uint8_t empty_hash[32];
    uint8_t transcript_hash[32];
    struct tls_hash_context hash_ctx;

    /* Step 1: Compute empty hash for "derived" secret
     * empty_hash = SHA-256("")
     */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        ERROR_CODE(0x8f);
        return false;
    }
    tls_hash_digest(&hash_ctx, empty_hash);

    /* Step 2: Derive "derived" secret from handshake_secret
     * derived = Derive-Secret(handshake_secret, "derived", empty_hash)
     */
    if (!tls_derive_secret(TLS_HASH_SHA256, ctx->keys.handshake_secret, 32,
                           "derived", 7, empty_hash, 32, derived_secret))
    {
        ERROR_CODE(0x90);
        return false;
    }

    /* Step 3: Compute master_secret
     * master_secret = HKDF-Extract(salt=derived, IKM=0)
     * ikm=NULL tells hkdf_extract to use 32 zero bytes.
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          NULL, 32, master_secret))
    {
        ERROR_CODE(0x91);
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
        ERROR_CODE(0x92);
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
        ERROR_CODE(0x93);
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
        ERROR_CODE(0x94);
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.client_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.client_application_iv, 12))
    {
        ERROR_CODE(0x95);
        return false;
    }

    /* Step 8: Derive server application key and IV */
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "key", 3, NULL, 0,
                               ctx->keys.server_application_key, 16))
    {
        ERROR_CODE(0x96);
        return false;
    }

    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "iv", 2, NULL, 0,
                               ctx->keys.server_application_iv, 12))
    {
        ERROR_CODE(0x97);
        return false;
    }

    DEBUG();
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
 * the altcp streaming encrypt with handshake keys, and pushes it down the TCP.
 */
bool tls_send_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    static const uint8_t finished_header[] = {
        TLS_HANDSHAKE_FINISHED, 0x00, 0x00, 0x20
    };

    if (!ctx || !out || !written)
    {
        ERROR_CODE(0x98);
        return false;
    }

    if (out_len < 36)
    { /* 4 byte header + 32 byte verify_data */
        ERROR_CODE(0x99);
        return false;
    }

    /* finished_key/verify_data/hmac_ctx are secret-derived material held
     * on this function's own stack frame. They're cleaned up by the
     * caller, which wraps this call with
     * tls_crypto_guard_enable()/disable(). */
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
        ERROR_CODE(0x9a);
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
        ERROR_CODE(0x9b);
        return false;
    }
    tls_hmac_update(&hmac_ctx, transcript_hash, 32);
    tls_hmac_digest(&hmac_ctx, verify_data);

    /* Step 5: Copy the fixed header, then append the dynamic verify_data. */
    memcpy(out, finished_header, sizeof(finished_header));
    memcpy(out + sizeof(finished_header), verify_data, 32);
    size_t offset = sizeof(finished_header) + 32;

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
            ERROR_CODE(0x9c);
            return false;
        }
    }

    return true;
}

/**
 * @brief Build an empty client Certificate message.
 *
 * TLS 1.3 says that when the server requests a client certificate and the
 * client has none, the client sends an empty Certificate message. The message
 * must be transcript-hashed before client Finished, because Finished covers
 * the complete client-auth response.
 *
 * Wire layout:
 *
 *     +----+--------+----+----------+
 *     | 0b | 00 00 04 | 00 | 00 00 00 |
 *     +----+--------+----+----------+
 *      type   length   request_context  certificate_list length
 */
bool tls_send_empty_certificate(
    struct tls_handshake_context *ctx,
    uint8_t *out,
    size_t out_len,
    size_t *written)
{
    static const uint8_t empty_certificate[] = {
        TLS_HANDSHAKE_CERTIFICATE, 0x00, 0x00, 0x04,
        0x00,                   /* certificate_request_context length */
        0x00, 0x00, 0x00       /* certificate_list length */
    };

    if (!ctx || !out || !written)
    {
        ERROR_CODE(0x9d);
        return false;
    }
    if (!ctx->client_certificate_requested ||
        ctx->state != TLS_STATE_SERVER_FINISHED_RECEIVED)
    {
        ERROR_CODE(0x9e);
        return false;
    }
    if (out_len < sizeof(empty_certificate))
    {
        ERROR_CODE(0x9f);
        return false;
    }

    memcpy(out, empty_certificate, sizeof(empty_certificate));
    *written = sizeof(empty_certificate);

    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, out, sizeof(empty_certificate));
    }

    DEBUG();
    return true;
}

/**
 * @brief Verify the server's Finished MAC.
 *
 * Finished proves that the peer derived the same handshake traffic secret and
 * that the transcript was not modified. Server identity authentication also
 * depends on the PSK or on certificate-path, identity, and CertificateVerify
 * validation performed earlier in the handshake.
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
static bool tls_recv_finished(
    struct tls_handshake_context *ctx,
    bool is_client,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 36)
    {
        ERROR_CODE(0xa0);
        return false;
    }
    if (is_client)
    {
        uint8_t required_state = ctx->psk_mode ? TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED
                                               : TLS_STATE_CERTIFICATE_VERIFY_RECEIVED;
        if (ctx->state != required_state)
        {
            ctx->state = TLS_STATE_ERROR;
            ERROR();
            return false;
        }
    }

    /* finished_key/expected_verify_data/hmac_ctx are secret-derived
     * material held on this function's own stack frame. They're cleaned
     * up by the caller, which wraps this call with
     * tls_crypto_guard_enable()/disable() -- once this function returns,
     * its whole frame sits below the caller's SP and gets scrubbed from
     * there, regardless of which exit path was taken. */
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
        ERROR_CODE(0xa1);
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
        ERROR_CODE(0xa2);
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
        ERROR_CODE(0xa3);
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
        ERROR();
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
        DEBUG();
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
 * The altcp layer copies accepted tickets into the in-memory PSK cache; the
 * cache is persisted by tls_cleanup().
 */
static bool tls_recv_new_session_ticket(
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
        ERROR_CODE(0xa4);
        return false;
    }
    if (ctx->state != TLS_STATE_HANDSHAKE_COMPLETE)
    {
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        return false;
    }

    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET,
                                               &msg_len);
    if (offset == 0)
    {
        ERROR_CODE(0xa5);
        return false;
    }
    msg_end = offset + msg_len;

    if (offset + 8 > msg_end)
    {
        ERROR_CODE(0xa6);
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

    if (ticket_lifetime == 0 || ticket_lifetime > 7u * 24u * 60u * 60u)
    {
        /* RFC 8446 uses a zero lifetime to invalidate/discard the ticket.
         * Resumption is optional; keep the established connection alive. */
        return true;
    }

    if (offset + 1 > msg_end)
    {
        ERROR_CODE(0xa7);
        return false;
    }
    nonce_len = data[offset++];
    if (offset + nonce_len > msg_end)
    {
        ERROR_CODE(0xa8);
        return false;
    }
    nonce = data + offset;
    offset += nonce_len;

    if (offset + 2 > msg_end)
    {
        ERROR_CODE(0xa9);
        return false;
    }
    ticket_len = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;
    if (offset + ticket_len > msg_end)
    {
        ERROR_CODE(0xaa);
        return false;
    }
    ticket = data + offset;
    offset += ticket_len;

    if (offset + 2 > msg_end)
    {
        ERROR_CODE(0xab);
        return false;
    }
    ext_len = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;
    if (offset + ext_len != msg_end)
    {
        ERROR_CODE(0xac);
        return false;
    }

    if (ticket_len == 0 || ticket_len > TLS_PSK_IDENTITY_MAX_LEN)
    {
        /* Some TLS 1.3 servers emit tickets larger than the calculator-side
         * PSK identity store. Ignore those tickets rather than aborting an
         * otherwise healthy application connection. */
        return true;
    }
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.resumption_master_secret, 32,
                               "resumption", 10,
                               nonce, nonce_len,
                               ctx->psk, 32))
    {
        return true;
    }

    memcpy(ctx->psk_identity.identity, ticket, ticket_len);
    ctx->psk_identity.identity_len = ticket_len;
    ctx->psk_identity.obfuscated_ticket_age = ticket_age_add;
    ctx->ticket_age_add = ticket_age_add;
    ctx->ticket_received_ms = sys_now();
    ctx->ticket_lifetime = ticket_lifetime;
    ctx->psk_mode = true;
    ctx->psk_type = TLS_PSK_TYPE_RESUMPTION;
    return true;
}

/**
 * @brief Process a post-handshake KeyUpdate from the server (RFC 8446 §4.6.3).
 *
 * Wire layout: a single request_update byte (0 = update_not_requested,
 * 1 = update_requested) inside the standard 4-byte handshake header.
 *
 * Ratchets the server's application traffic secret forward one step:
 *
 *   server_application_traffic_secret_N+1 =
 *       HKDF-Expand-Label(server_application_traffic_secret_N,
 *                          "traffic upd", "", 32)
 *
 * then re-derives the server application key/IV from the new secret and
 * resets server_seq_num to 0 (a fresh secret means a fresh nonce space,
 * per §7.2 / §5.3). For update_requested, a non-requesting reciprocal
 * KeyUpdate is sent under the old client key before that write key is ratcheted.
 */
static bool tls_recv_key_update(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    size_t msg_len = 0;

    if (!ctx || !data || data_len < 5)
    {
        ERROR_CODE(0xad);
        return false;
    }
    if (ctx->state != TLS_STATE_HANDSHAKE_COMPLETE ||
        ctx->server_key_updates >= TLS_MAX_KEY_UPDATES)
    {
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        return false;
    }

    size_t offset = tls_parse_handshake_header(data, data_len,
                                               TLS_HANDSHAKE_KEY_UPDATE,
                                               &msg_len);
    if (offset == 0 || msg_len != 1)
    {
        ERROR_CODE(0xae);
        return false;
    }

    uint8_t request_update = data[offset];
    if (request_update != 0 && request_update != 1)
    {
        ERROR_CODE(0xaf);
        return false;
    }

    uint8_t next_secret[32], next_key[16], next_iv[12];
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               ctx->keys.server_application_traffic_secret, 32,
                               "traffic upd", 11, NULL, 0,
                               next_secret, 32))
    {
        ERROR_CODE(0xb0);
        return false;
    }
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               next_secret, 32,
                               "key", 3, NULL, 0,
                               next_key, 16))
    {
        tls_secure_memzero(next_secret, sizeof(next_secret));
        ERROR_CODE(0xb1);
        return false;
    }
    if (!tls_hkdf_expand_label(TLS_HASH_SHA256,
                               next_secret, 32,
                               "iv", 2, NULL, 0,
                               next_iv, 12))
    {
        tls_secure_memzero(next_secret, sizeof(next_secret));
        tls_secure_memzero(next_key, sizeof(next_key));
        ERROR_CODE(0xb2);
        return false;
    }
    memcpy(ctx->keys.server_application_traffic_secret, next_secret, 32);
    memcpy(ctx->keys.server_application_key, next_key, 16);
    memcpy(ctx->keys.server_application_iv, next_iv, 12);
    tls_secure_memzero(next_secret, sizeof(next_secret));
    tls_secure_memzero(next_key, sizeof(next_key));
    tls_secure_memzero(next_iv, sizeof(next_iv));
    ctx->server_seq_num = 0;
    ctx->server_key_updates++;

    if (request_update == 1 && !tls_send_key_update_record(ctx))
    {
        ERROR_CODE(0xb3);
        return false;
    }

    INFO("hs: server key update applied");
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

static bool tls_ratchet_client_application_keys(struct tls_handshake_context *ctx)
{
    uint8_t next_secret[32], next_key[16], next_iv[12];
    bool ok = tls_hkdf_expand_label(TLS_HASH_SHA256,
                                    ctx->keys.client_application_traffic_secret, 32,
                                    "traffic upd", 11, NULL, 0, next_secret, 32) &&
              tls_hkdf_expand_label(TLS_HASH_SHA256, next_secret, 32,
                                    "key", 3, NULL, 0, next_key, 16) &&
              tls_hkdf_expand_label(TLS_HASH_SHA256, next_secret, 32,
                                    "iv", 2, NULL, 0, next_iv, 12);
    if (ok)
    {
        memcpy(ctx->keys.client_application_traffic_secret, next_secret, 32);
        memcpy(ctx->keys.client_application_key, next_key, 16);
        memcpy(ctx->keys.client_application_iv, next_iv, 12);
        ctx->client_seq_num = 0;
        ctx->client_key_updates++;
    }
    tls_secure_memzero(next_secret, sizeof(next_secret));
    tls_secure_memzero(next_key, sizeof(next_key));
    tls_secure_memzero(next_iv, sizeof(next_iv));
    return ok;
}

static bool tls_send_key_update_record(struct tls_handshake_context *ctx)
{
    uint8_t record[27]; /* 5 header + 5 handshake + 1 inner type + 16 tag */
    uint8_t nonce[12], tag[16];
    TLS_AUTOZERO_STRUCT(tls_aes_context, aes_ctx);
    static const uint8_t message[5] = {TLS_HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0};

    if (!ctx || ctx->state != TLS_STATE_HANDSHAKE_COMPLETE ||
        !ctx->transport_write || ctx->client_key_updates >= TLS_MAX_KEY_UPDATES ||
        ctx->client_seq_num >= TLS_AES_GCM_RECORD_LIMIT)
        return false;
    record[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
    record[1] = 0x03; record[2] = 0x03;
    record[3] = 0; record[4] = 22;
    tls_build_aead_nonce(ctx->keys.client_application_iv, ctx->client_seq_num, nonce);
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM,
                      ctx->keys.client_application_key, 16, nonce, sizeof(nonce)) ||
        !tls_aes_update_aad(&aes_ctx, record, 5) ||
        !tls_aes_encrypt(&aes_ctx, message, sizeof(message), record + 5))
        return false;
    uint8_t inner_type = TLS_CONTENT_TYPE_HANDSHAKE;
    if (!tls_aes_encrypt(&aes_ctx, &inner_type, 1, record + 10) ||
        !tls_aes_digest(&aes_ctx, tag))
        return false;
    memcpy(record + 11, tag, sizeof(tag));
    if (!ctx->transport_write(ctx->transport_arg, record, sizeof(record)))
        return false;
    ctx->client_seq_num++;
    return tls_ratchet_client_application_keys(ctx);
}

bool tls_update_write_keys_if_needed(struct tls_handshake_context *ctx)
{
    if (!ctx || ctx->state != TLS_STATE_HANDSHAKE_COMPLETE) return false;
    if (ctx->client_seq_num < TLS_AES_GCM_RECORD_LIMIT - 1u) return true;
    return tls_send_key_update_record(ctx);
}

/**
 * @brief Send alert message
 */
static bool tls_send_alert(
    struct tls_handshake_context *ctx,
    uint8_t level,
    uint8_t description)
{
    if (!ctx)
    {
        ERROR_CODE(0xb3);
        return false;
    }

    bool ok = false;
    uint8_t alert_body[2] = {level, description};

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
            /* Encrypt under the active client traffic keys. The inner record
             * is just 2 alert bytes + 1 inner content-type, so we inline the
             * AEAD path rather than depending on a general encrypt helper. */
            uint8_t record[24];          /* 5 hdr + 2 body + 1 type + 16 tag */
            const uint8_t *key, *iv;
            uint64_t *seq_num;
            uint8_t nonce[12];
            /* aes_ctx holds the expanded AES-GCM key schedule derived from
             * the live client traffic key; TLS_AUTOZERO_STRUCT zeroes it
             * automatically when this block ends. */
            TLS_AUTOZERO_STRUCT(tls_aes_context, aes_ctx);
            uint8_t auth_tag[16];

            if (phase == 1)
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

            if (*seq_num >= TLS_AES_GCM_RECORD_LIMIT)
                return false;

            record[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
            record[1] = 0x03;
            record[2] = 0x03;
            record[3] = 0x00;
            record[4] = 3 + 16; /* 2 body + 1 type + 16 tag */

            tls_build_aead_nonce(iv, *seq_num, nonce);
            if (tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, 12) &&
                tls_aes_update_aad(&aes_ctx, record, 5) &&
                tls_aes_encrypt(&aes_ctx, alert_body, 2, record + 5))
            {
                uint8_t type_byte = TLS_CONTENT_TYPE_ALERT;
                if (tls_aes_encrypt(&aes_ctx, &type_byte, 1, record + 7) &&
                    tls_aes_digest(&aes_ctx, auth_tag))
                {
                    memcpy(record + 8, auth_tag, 16);
                    ok = ctx->transport_write(ctx->transport_arg, record, sizeof(record));
                    if (ok) (*seq_num)++;
                }
            }
        }
    }

    if (level == TLS_ALERT_LEVEL_FATAL)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR_CODE(description);
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
        ERROR_CODE(0xb4);
        return false;
    }
    if (ctx->close_notify_sent)
    {
        return true;
    }
    bool ok = tls_send_alert(ctx, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    if (ok) ctx->close_notify_sent = true;
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

    /* Free any in-flight Certificate walker (cert_walker plus its
     * per-cert buffer). Safe on NULL. */
    tls_cert_walker_free(ctx->cert_walker);
    ctx->cert_walker = NULL;
    ctx->hs_reasm_body_fed = 0;

    /* Release captured leaf SPKI (allocated during cert walking,
     * consumed by tls_recv_certificate_verify). */
    if (ctx->leaf_pubkey.allocated)
    {
        /* Key material was heap-copied in tls_cert_walker_validate_one.
         * The allocation covers both modulus and exponent (or EC point)
         * contiguously; free via the modulus pointer (always the start). */
        bool is_rsa = ctx->leaf_pubkey.type == TLS_KEY_TYPE_RSA;
        size_t mat_len = is_rsa
            ? ctx->leaf_pubkey.rsa.mod_len + ctx->leaf_pubkey.rsa.exp_len
            : ctx->leaf_pubkey.ec.len;
        if (mat_len > 0)
        {
            const uint8_t *mat = is_rsa
                                 ? ctx->leaf_pubkey.rsa.modulus
                                 : ctx->leaf_pubkey.ec.data;
            mem_stats_tls_direct_release(mat_len, mat_len);
            mem_buffer_custom_free((void *)mat);
        }
        memset(&ctx->leaf_pubkey, 0, sizeof(ctx->leaf_pubkey));
    }

    /* Free HRR cookie if one was stashed. */
    if (ctx->hrr_cookie)
    {
        mem_buffer_custom_free(ctx->hrr_cookie);
        ctx->hrr_cookie = NULL;
        ctx->hrr_cookie_len = 0;
    }

    /* Securely zero sensitive data */
    tls_secure_memzero(ctx->psk, sizeof(ctx->psk));
    tls_secure_memzero(ctx->ecdhe_private, sizeof(ctx->ecdhe_private));
    tls_secure_memzero(ctx->ecdhe_shared, sizeof(ctx->ecdhe_shared));
    tls_secure_memzero(ctx->ecdhe_public, sizeof(ctx->ecdhe_public));
    tls_secure_memzero(&ctx->keys, sizeof(ctx->keys));
    tls_secure_memzero(ctx, sizeof(*ctx));
    ctx->leaf_pubkey.type = TLS_KEY_TYPE_UNKNOWN;
}

/*
 * ============================================================================
 * Outstanding work (post-refactor)
 * ============================================================================
 *
 * Status: PSK resumption, ECDHE-only, and PSK+ECDHE client handshakes are all
 * implemented and exercised. Record-layer encryption, transcript hashing,
 * key schedule, PSK binder, NewSessionTicket-driven resumption, alerts, and
 * close_notify are all done. CertificateVerify is mandatory and always
 * verified (RSA-PSS-SHA256 against the captured leaf SPKI). Adjacent chain
 * links are verified for RSA-2048+SHA256; the topmost cert's issuer is
 * additionally checked against the truststore by subject-name lookup when
 * present, but the chain is accepted without that final root anchor if the
 * issuer isn't found (see truststore.h).
 *
 * Remaining work, roughly ordered:
 *   - AES-GCM speedup. Pure-C in aes.c; this is the bulk-data hot path and
 *     dwarfs everything else on the wire. eZ80-asm GHASH/AES is the next
 *     big win.
 *   - Server-side handshake (currently the altcp layer returns "not
 *     implemented"). The same key schedule code applies in reverse.
 *   - Wider truststore coverage (RSA-4096, EC roots) + automated refresh
 *     tooling.
 *   - Interop testing against major TLS 1.3 stacks (Go, BoringSSL,
 *     mbedTLS, Rustls) — particularly the cross-record fragmentation path
 *     which is hard to trigger without help.
 */
