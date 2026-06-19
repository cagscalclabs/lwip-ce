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
 * separate for handshake and application phases — they do NOT reset.
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

#include "../includes/handshake.h"
#include "../includes/hash.h"
#include "../includes/hmac.h"
#include "../includes/aes.h"
#include "../includes/random.h"
#include "../includes/hkdf.h"
#include "../includes/asn1.h"
#include "../includes/rsa.h"
#include "../includes/keyobject.h"
#include "../includes/truststore.h"
#include "../includes/bytes.h"
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
static bool tls_send_alert(struct tls_handshake_context *ctx,
                           uint8_t level, uint8_t description);
static bool tls_spki_extract_rsa_public_key(const uint8_t *spki, size_t spki_len,
                                            const uint8_t **mod_out,
                                            size_t *mod_len_out,
                                            uint24_t *exp_out);

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
 * signature check is currently a stub that accepts (see
 * tls_cert_chain_verify_one) until P-256/RSA chain verification and an
 * issuer-key truststore exist. The walker captures ZERO bytes between certs —
 * once a cert is processed, its buffer is freed and we move on.
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
     * and every cert walked so far passed chain verification. The actual
     * cert-to-cert signature check is currently stubbed to accept — see
     * tls_cert_chain_verify_one(). Leaf authenticity is established separately
     * by the mandatory CertificateVerify record against the captured leaf
     * SPKI. */
    bool chain_validated;
    /* Index of the cert currently in cert_buf within the chain — 0 means
     * leaf. Used by tls_cert_walker_validate_one to know when to capture
     * the leaf SPKI into ctx->leaf_spki. */
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
     * RSA verify once the next cert's public key is in hand. The topmost
     * cert has no issuer in the chain and is left unverified (adjacent-links
     * only; see tls_cert_chain_verify_one). Only RSA-2048/sha256WithRSA links
     * are verified; other signature types are accepted with an ALERT. */
    bool pending_link;             /* a prior cert is awaiting its issuer key */
    bool pending_is_rsa_sha256;    /* prior cert used sha256WithRSAEncryption  */
    uint8_t pending_tbs_digest[32];/* SHA-256(tbsCertificate) of prior cert    */
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

/* DER prefix of a PKCS#1 v1.5 DigestInfo for id-sha256: the bytes that
 * precede the 32-byte digest in a correctly-padded SHA-256 signature.
 *   SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING }
 * (RFC 8017 §9.2 / B.1). Used to check the decrypted signature structure. */
static const uint8_t tls_pkcs1_sha256_digestinfo_prefix[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

/* Verify an RSASSA-PKCS1-v1.5 signature over a precomputed SHA-256 digest,
 * given the issuer's raw RSA public key. Decrypts the signature, then checks
 * the EMSA-PKCS1-v1.5 encoding:
 *   EM = 0x00 || 0x01 || 0xFF...0xFF || 0x00 || DigestInfo(SHA-256, digest)
 * Returns true iff the encoding is well-formed and the embedded digest equals
 * `digest`. CA signatures on RSA-2048 chain links are PKCS#1 v1.5, not PSS. */
static bool tls_rsa_pkcs1_v15_sha256_verify(const uint8_t *sig, size_t sig_len,
                                            const uint8_t digest[32],
                                            const uint8_t *modulus,
                                            size_t modulus_len,
                                            uint24_t exponent)
{
    uint8_t *em;
    size_t pos;
    bool ok = false;

    if (!sig || !digest || !modulus || sig_len != modulus_len ||
        modulus_len > RSA_TRANSIENT_SIZE)
    {
        return false;
    }
    /* DigestInfo + at least 8 bytes of 0xFF padding + leading 00 01 / 00. */
    if (modulus_len < sizeof(tls_pkcs1_sha256_digestinfo_prefix) + 32 + 11)
    {
        return false;
    }

    em = __rsa_transient;
    if (!tls_rsa_decrypt_signature_exp(sig, sig_len, em,
                                       exponent, modulus, modulus_len))
    {
        goto cleanup;
    }

    /* EM = 0x00 0x01 PS 0x00 T, where PS is >= 8 bytes of 0xFF and T is the
     * DigestInfo. */
    if (em[0] != 0x00 || em[1] != 0x01)
    {
        goto cleanup;
    }
    pos = 2;
    while (pos < modulus_len && em[pos] == 0xFF)
    {
        pos++;
    }
    /* Need >= 8 bytes of 0xFF, then a single 0x00 separator. */
    if (pos < 10 || pos >= modulus_len || em[pos] != 0x00)
    {
        goto cleanup;
    }
    pos++;
    /* The remaining bytes must be exactly DigestInfo-prefix || digest. */
    if (modulus_len - pos != sizeof(tls_pkcs1_sha256_digestinfo_prefix) + 32)
    {
        goto cleanup;
    }
    if (memcmp(em + pos, tls_pkcs1_sha256_digestinfo_prefix,
               sizeof(tls_pkcs1_sha256_digestinfo_prefix)) != 0)
    {
        goto cleanup;
    }
    if (memcmp(em + pos + sizeof(tls_pkcs1_sha256_digestinfo_prefix),
               digest, 32) != 0)
    {
        goto cleanup;
    }
    ok = true;

cleanup:
    tls_secure_memzero(em, modulus_len);
    return ok;
}

/* Pull the bits needed to verify a cert's issuer signature out of its DER:
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 * Captures the full tbsCertificate TLV bytes (what the signature covers),
 * whether signatureAlgorithm is sha256WithRSAEncryption, and the raw
 * signature bytes (BIT STRING content, unused-bits byte stripped).
 * Returns false only on malformed DER. */
static bool tls_cert_extract_sig_material(const uint8_t *der, size_t der_len,
                                          const uint8_t **tbs_out,
                                          size_t *tbs_len_out,
                                          bool *is_rsa_sha256_out,
                                          const uint8_t **sig_out,
                                          size_t *sig_len_out)
{
    struct tls_asn1_cursor top, items, alg_body;
    struct tls_asn1_tlv cert_seq, tbs, sig_alg, sig_val, alg_oid;

    *is_rsa_sha256_out = false;

    if (!tls_asn1_cursor_init(&top, der, der_len) ||
        !tls_asn1_next(&top, &cert_seq) ||
        tls_asn1_tag_number(cert_seq.tag) != ASN1_SEQUENCE ||
        !tls_asn1_tag_constructed(cert_seq.tag))
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&cert_seq, &items) ||
        !tls_asn1_next(&items, &tbs) ||
        !tls_asn1_next(&items, &sig_alg) ||
        !tls_asn1_next(&items, &sig_val))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(tbs.tag) ||
        tls_asn1_tag_number(tbs.tag) != ASN1_SEQUENCE ||
        tls_asn1_tag_number(sig_val.tag) != ASN1_BITSTRING)
    {
        return false;
    }

    /* The signature covers the whole tbsCertificate TLV (tag+len+value). */
    *tbs_out = tbs.tlv;
    *tbs_len_out = tbs.header_len + tbs.len;

    /* signatureAlgorithm: AlgorithmIdentifier { OID, params }. Flag the one
     * algorithm we verify (sha256WithRSAEncryption); leave the flag false for
     * anything else so the caller can ALERT-and-accept. */
    if (tls_asn1_tag_constructed(sig_alg.tag) &&
        tls_asn1_tag_number(sig_alg.tag) == ASN1_SEQUENCE &&
        tls_asn1_child_cursor(&sig_alg, &alg_body) &&
        tls_asn1_next(&alg_body, &alg_oid) &&
        tls_asn1_tag_number(alg_oid.tag) == ASN1_OBJECTID &&
        alg_oid.len == 9 &&
        memcmp(alg_oid.value,
               tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], 9) == 0)
    {
        *is_rsa_sha256_out = true;
    }

    /* signatureValue BIT STRING: first content byte is the unused-bits count
     * (0 for a byte-aligned signature); the rest is the signature. */
    if (sig_val.len < 2 || sig_val.value[0] != 0x00)
    {
        return false;
    }
    *sig_out = sig_val.value + 1;
    *sig_len_out = sig_val.len - 1;
    return true;
}

/*
 * Walk one link in the certificate chain (adjacent links only).
 *
 * A cert is signed by the NEXT cert in the wire chain (cert N signed-by cert
 * N+1's key), but N+1 has not arrived yet when N completes. So this defers:
 * it verifies the PREVIOUSLY stashed cert (if any) using THIS cert's public
 * key, then stashes this cert's own signature material for the next call.
 * The topmost cert is never stashed-then-verified — it has no issuer in the
 * chain — so the very top link is left unverified (we do not anchor to a
 * truststore root here; see the cert roadmap).
 *
 * Verification policy:
 *   - RSA-2048 + sha256WithRSAEncryption link: verified for real. A bad
 *     signature emits an ERROR and aborts the handshake (returns false).
 *   - any other signature type: NOT verified — emits an ALERT
 *     ("unsupported cert type, proceeding") and accepts the link.
 *
 * @param w           Walker (holds ctx, chain position, and the pending stash).
 * @param cert_parsed Parsed fields of the cert currently in cert_buf (for its
 *                    SPKI, used as the issuer key of the pending cert).
 * @param is_leaf     True for cert_index 0.
 * @return true if acceptable. Returning false aborts the chain.
 */
static bool tls_cert_chain_verify_one(struct tls_cert_walker *w,
                                      const struct tls_x509_parse_result *cert_parsed,
                                      bool is_leaf)
{
    const uint8_t *tbs, *sig;
    size_t tbs_len, sig_len;
    bool is_rsa_sha256;

    /* Step 1: if a prior cert is awaiting its issuer key, THIS cert is that
     * issuer — verify the pending link now. */
    if (w->pending_link)
    {
        bool verified_or_accepted = false;

        if (w->pending_is_rsa_sha256)
        {
            const uint8_t *modulus;
            size_t modulus_len;
            uint24_t exponent;

            /* Issuer key is this cert's SPKI. Only RSA issuers can have signed
             * an RSA-SHA256 link; a non-RSA issuer SPKI means we can't verify
             * it here — treat as unsupported (ALERT + accept). */
            if (cert_parsed->spki_raw && cert_parsed->spki_raw->data &&
                tls_spki_extract_rsa_public_key(cert_parsed->spki_raw->data,
                                                cert_parsed->spki_raw->len,
                                                &modulus, &modulus_len,
                                                &exponent))
            {
                if (tls_rsa_pkcs1_v15_sha256_verify(w->pending_sig,
                                                    w->pending_sig_len,
                                                    w->pending_tbs_digest,
                                                    modulus, modulus_len,
                                                    exponent))
                {
                    verified_or_accepted = true;
                }
                else
                {
                    /* RSA-2048 link that genuinely failed to verify: the chain
                     * is broken or tampered. ERROR + abort. */
                    ERROR();
                    return false;
                }
            }
            else
            {
                /* Issuer isn't an RSA-2048 key we can use: unsupported. */
                WARN();
                verified_or_accepted = true;
            }
        }
        else
        {
            /* Pending cert's signature wasn't RSA-SHA256 (e.g. ECDSA): we
             * don't verify it. Proceed, but tell the caller. */
            WARN();
            verified_or_accepted = true;
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
        w->pending_is_rsa_sha256 = false;

        if (!verified_or_accepted)
        {
            return false;
        }
    }

    /* Step 2: stash THIS cert's signature material so the next cert (its
     * issuer) can verify it. Pre-hash the tbs now so we don't have to retain
     * the cert buffer — only the 32-byte digest and the signature survive. */
    if (!tls_cert_extract_sig_material(w->cert_buf, w->cert_buf_len, &tbs,
                                       &tbs_len, &is_rsa_sha256, &sig, &sig_len))
    {
        return false;
    }
    {
        struct tls_hash_context hctx;
        if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
        {
            return false;
        }
        tls_hash_update(&hctx, tbs, tbs_len);
        tls_hash_digest(&hctx, w->pending_tbs_digest);
    }
    /* Copy the signature (it lives in cert_buf, which is freed after this
     * call returns). Cap at the max RSA modulus we support. */
    if (sig_len == 0 || sig_len > RSA_MODULUS_MAX_SUPPORTED)
    {
        /* Signature we could never verify with our RSA path: don't stash it
         * for verification, but the link itself is still "unsupported" rather
         * than malformed — record that only when it later goes unverified. */
        w->pending_is_rsa_sha256 = false;
        w->pending_sig = NULL;
        w->pending_sig_len = 0;
    }
    else
    {
        w->pending_sig = (uint8_t *)mem_buffer_custom_malloc(sig_len);
        if (!w->pending_sig)
        {
            return false;
        }
        mem_stats_tls_direct_add(sig_len, sig_len);
        memcpy(w->pending_sig, sig, sig_len);
        w->pending_sig_len = sig_len;
        w->pending_is_rsa_sha256 = is_rsa_sha256;
    }
    w->pending_link = true;
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
    struct tls_asn1_serialization cert_fields[13];
    struct tls_x509_parse_result cert_parsed = {0};
    bool is_leaf = (w->cert_index == 0);

    if (!tls_x509_parse_certificate(w->cert_buf, w->cert_buf_len,
                                    cert_fields, &cert_parsed))
    {
        return false;
    }
    if (!cert_parsed.spki_raw || !cert_parsed.spki_raw->data ||
        cert_parsed.spki_raw->len == 0)
    {
        return false;
    }

    /* Verify-leaf-first: capture the leaf SPKI so CertificateVerify can
     * authenticate the server. This is the actual trust anchor today. */
    if (is_leaf && w->ctx && !w->ctx->leaf_spki)
    {
        uint8_t *copy = (uint8_t *)mem_buffer_custom_malloc(cert_parsed.spki_raw->len);
        if (!copy)
        {
            /* Without the leaf SPKI, CertificateVerify can't run and the
             * server would be unauthenticated. Fail closed. */
            return false;
        }
        mem_stats_tls_direct_add(cert_parsed.spki_raw->len, cert_parsed.spki_raw->len);
        memcpy(copy, cert_parsed.spki_raw->data, cert_parsed.spki_raw->len);
        w->ctx->leaf_spki = copy;
        w->ctx->leaf_spki_len = cert_parsed.spki_raw->len;
    }

    /* Capture this cert's issuer CN on every cert — after the loop, the last
     * cert processed is the topmost, so w->topmost_issuer_cn will hold its
     * issuer (the root CA we look up in the truststore). */
    if (cert_parsed.issuer_cn && cert_parsed.issuer_cn->data &&
        cert_parsed.issuer_cn->len > 0)
    {
        uint8_t copy_len = (cert_parsed.issuer_cn->len < TLS_TRUSTSTORE_SUBJECT_LEN)
                           ? (uint8_t)cert_parsed.issuer_cn->len
                           : TLS_TRUSTSTORE_SUBJECT_LEN;
        memcpy(w->topmost_issuer_cn, cert_parsed.issuer_cn->data, copy_len);
        memset(w->topmost_issuer_cn + copy_len, 0,
               TLS_TRUSTSTORE_SUBJECT_LEN - copy_len);
        w->topmost_issuer_cn_len = copy_len;
    }

    /* Then walk the chain: verify the previously-stashed link against this
     * cert's key, and stash this cert for the next link. RSA-2048 links are
     * verified for real (a failure aborts here); unsupported sig types are
     * accepted with an ALERT. */
    if (!tls_cert_chain_verify_one(w, &cert_parsed, is_leaf))
    {
        return false;
    }

    /* Chain is acceptable once we have the leaf SPKI in hand and no verified
     * link has been rejected. (Unsupported links are accepted-with-alert and
     * still reach here; only a genuine RSA verify failure returns false.) */
    if (w->ctx && w->ctx->leaf_spki)
    {
        w->chain_validated = true;
    }
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
                if (value == 0 || value > TLS_HS_REASSEMBLY_MAX ||
                    w->chain_remaining < 3 + value)
                {
                    w->state = CW_ERROR;
                    return false;
                }
                w->chain_remaining -= 3 + value; /* length field + body */
                w->field_remaining = value;
                w->cert_buf = (uint8_t *)mem_buffer_custom_malloc(value);
                if (!w->cert_buf)
                {
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
            return false;
        }
        ctx->hs_reasm_body_fed += take;
        return true;
    }
    /* Non-Certificate: legacy flat append into hs_reasm_buf. */
    if (!tls_hs_reasm_grow(ctx, ctx->hs_reasm_len + take))
    {
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
        ctx->hs_reasm_expected = 4 + body_len;
        if (ctx->hs_reasm_expected > TLS_HS_REASSEMBLY_MAX)
        {
            tls_hs_reasm_reset(ctx);
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

        if (msg_type == TLS_HANDSHAKE_CERTIFICATE)
        {
            /* Certificate: install header, transcript-update the header,
             * route body through walker. The walker handles per-cert
             * alloc/free; hs_reasm_buf only ever holds the 4-byte header. */
            if (!tls_hs_reasm_grow(ctx, 4))
            {
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
        INFO("hs: encrypted extensions");
        return tls_recv_encrypted_extensions(ctx, msg, msg_len);
    case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
        INFO("hs: certificate request");
        return tls_recv_certificate_request(ctx, msg, msg_len);
    /* TLS_HANDSHAKE_CERTIFICATE is handled by the streaming cert walker in
     * tls_consume_handshake_buffer; it never reaches this dispatcher. */
    case TLS_SERVER_HANDSHAKE_CERTIFICATE_VERIFY:
        INFO("hs: cert verify");
        return tls_recv_certificate_verify(ctx, msg, msg_len);
    case TLS_HANDSHAKE_FINISHED:
        INFO("hs: server finished");
        return tls_recv_finished(ctx, true, msg, msg_len);
    case TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET:
        INFO("hs: new ticket");
        return tls_recv_new_session_ticket(ctx, msg, msg_len);
    default:
        /* Unknown inner type — ignore per RFC 8446 §4 forward-compat note. */
        return true;
    }
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
        return false;
    }
    if (plaintext_len != 0 && !plaintext)
    {
        return false;
    }

    if (inner_content_type == TLS_CONTENT_TYPE_HANDSHAKE)
    {
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
        if (plaintext_len >= 2)
        {
            uint8_t level = pbuf_get_at((struct pbuf *)plaintext, 0);
            if (level == TLS_ALERT_LEVEL_FATAL)
            {
                ctx->state = TLS_STATE_ERROR;
            }
        }
        return true;
    }

    /* Application data during handshake is unexpected. */
    tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
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
        ERROR();
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
    size_t hostname_len = 0;
    size_t sni_len = 0;
    size_t required_len;
    size_t required_ext_len;

    if (ctx->hostname)
    {
        hostname_len = strlen(ctx->hostname);
        if (hostname_len > 0xFFFFu - 5u)
        {
            return false;
        }
        sni_len = 9 + hostname_len;
    }
    if (ctx->psk_mode &&
        (ctx->psk_identity.identity_len == 0 ||
         ctx->psk_identity.identity_len > TLS_PSK_IDENTITY_MAX_LEN))
    {
        return false;
    }

    /* Fixed ClientHello body before extensions is 43 bytes. The constants
     * below include the 4-byte handshake header so the unchecked serializer
     * cannot overrun a too-small caller buffer. */
    required_ext_len = 7 + 8 + 42 + 8 + 18 + 15 + sni_len; /* +15 = ALPN http/1.1 */
    if (ctx->psk_mode)
    {
        required_ext_len += 7 + 47 + ctx->psk_identity.identity_len;
    }
    if (required_ext_len > 0xFFFFu)
    {
        return false;
    }
    required_len = 47 + required_ext_len;
    if (required_len > out_len || required_len - 4 > 0xFFFFFFu)
    {
        ERROR_CODE(required_len > 0xFFFF ? 0xFFFF : required_len);
        return false;
    }

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
    out[offset++] = 0x04; /* Extension length: 4 */
    out[offset++] = 0x00;
    out[offset++] = 0x02; /* Signature algorithms list length: 2 */
    out[offset++] = 0x08;
    out[offset++] = 0x04; /* rsa_pss_rsae_sha256 */

    /* Extension 5: signature_algorithms_cert.
     * Only advertise algorithms we actually verify: PKCS#1-v1.5-SHA256 for
     * chain links and PSS-SHA256 for CertificateVerify. */
    out[offset++] = 0x00;
    out[offset++] = 0x32; /* Extension type: signature_algorithms_cert */
    out[offset++] = 0x00;
    out[offset++] = 0x06; /* Extension length: 6 */
    out[offset++] = 0x00;
    out[offset++] = 0x04; /* Signature algorithms list length: 4 */
    out[offset++] = 0x04;
    out[offset++] = 0x01; /* rsa_pkcs1_sha256 */
    out[offset++] = 0x08;
    out[offset++] = 0x04; /* rsa_pss_rsae_sha256 */

    /* Extension 6: ALPN (application_layer_protocol_negotiation).
     * Advertise HTTP/1.1 explicitly. Some HTTP front doors (e.g. large CDNs /
     * Microsoft's) require ALPN to be negotiated; without it they may complete
     * the TLS handshake and then immediately close the connection once
     * application data starts — which looked like a post-Finished close.
     * 15 bytes total: type(2) + ext_len(2) + list_len(2) + name_len(1) + 8. */
    out[offset++] = 0x00;
    out[offset++] = 0x10; /* Extension type: ALPN */
    out[offset++] = 0x00;
    out[offset++] = 0x0b; /* Extension length: 11 */
    out[offset++] = 0x00;
    out[offset++] = 0x09; /* ProtocolNameList length: 9 */
    out[offset++] = 0x08; /* ProtocolName length: 8 */
    memcpy(out + offset, "http/1.1", 8);
    offset += 8;

    /* Extension 7: server_name (SNI) */
    if (ctx->hostname)
    {
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

        const char *binder_label = (ctx->psk_type == TLS_PSK_TYPE_EXTERNAL)
                                       ? "ext binder"
                                       : "res binder";
        /* RFC 8446 derives binder_key with Derive-Secret(..., ""),
         * so the HKDF context is Transcript-Hash(empty), not a zero-length
         * context field. */
        if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
            return false;
        tls_hash_digest(&hash_ctx, partial_hash);

        if (!tls_hkdf_expand_label(TLS_HASH_SHA256, early_secret, 32,
                                   binder_label, 10,
                                   partial_hash, 32, binder_key, 32))
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
         * cut point is binder_offset itself, not binder_offset + 3. */
        if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
            return false;
        tls_hash_update(&hash_ctx, out, binder_offset);
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
                ERROR();
                tls_secure_memzero(ctx->ecdhe_private, 32);
                ctx->state = TLS_STATE_ERROR;
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
            if (!ctx->psk_mode)
            {
                /* Server selected a PSK identity we did not offer. */
                ctx->state = TLS_STATE_ERROR;
                return false;
            }
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
    if (!found_supported_versions || (!found_psk && !ctx->ecdhe_negotiated))
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    ctx->psk_mode = found_psk;

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
    DEBUG();
    return true;
}

/**
 * @brief Finalize a streamed Certificate message.
 *
 * Called by tls_consume_handshake_buffer when the cert walker reaches
 * CW_DONE. Checks the state/PSK gates and requires w->chain_validated, which
 * now means "the leaf SPKI was captured and every chain link the walker checked
 * passed" (the per-link check is currently stubbed to accept). It does NOT mean
 * a truststore root-pin matched. Real server authentication still happens next,
 * in the mandatory CertificateVerify record against the captured leaf SPKI.
 * The walker has already updated the transcript hash incrementally as bytes
 * arrived, so we don't touch it here.
 */
static bool tls_recv_certificate_streamed(struct tls_handshake_context *ctx,
                                          struct tls_cert_walker *w)
{
    if (!ctx || !w)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    /* PSK-authenticated handshakes, including PSK+DHE, MUST NOT send
     * Certificate. The PSK is the server authentication in that mode. */
    if (ctx->psk_mode)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    if (w->state != CW_DONE)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }
    if (!w->chain_validated)
    {
        ctx->state = TLS_STATE_ERROR;
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
                size_t key_len = root_entry->len - sizeof(struct tls_truststore_entry);
                if (key_len >= 3 + RSA_MODULUS_MIN_SUPPORTED &&
                    w->pending_link && w->pending_sig)
                {
                    uint24_t exp = (uint24_t)root_entry->key[0]
                                 | ((uint24_t)root_entry->key[1] << 8)
                                 | ((uint24_t)root_entry->key[2] << 16);
                    const uint8_t *mod     = root_entry->key + 3;
                    size_t         mod_len = key_len - 3;
                    bool verified = false;

                    if (mod_len >= RSA_MODULUS_MIN_SUPPORTED &&
                        mod_len <= RSA_MODULUS_MAX_SUPPORTED)
                    {
                        if (alg == TLS_CERT_SIG_RSA_PSS_SHA256)
                        {
                            uint8_t *dsig = __rsa_transient;
                            if (tls_rsa_decrypt_signature_exp(w->pending_sig,
                                                              w->pending_sig_len,
                                                              dsig, exp, mod, mod_len))
                            {
                                verified = tls_rsa_pss_verify(dsig, mod_len,
                                               w->pending_tbs_digest,
                                               TLS_SHA256_DIGEST_LEN,
                                               TLS_HASH_SHA256);
                                tls_secure_memzero(dsig, mod_len);
                            }
                        }
                        else
                        {
                            verified = tls_rsa_pkcs1_v15_sha256_verify(
                                           w->pending_sig,
                                           w->pending_sig_len,
                                           w->pending_tbs_digest,
                                           mod, mod_len, exp);
                        }
                    }

                    if (!verified)
                    {
                        ERROR();
                        ctx->state = TLS_STATE_ERROR;
                        return false;
                    }
                }
            }
            else
            {
                /* Root alg not yet supported (e.g. ECDSA). Warn and accept. */
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
static bool tls_recv_encrypted_extensions(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 6)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_HANDSHAKE_KEYS_DERIVED)
    {
        ctx->state = TLS_STATE_ERROR;
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

    if (!ctx || !data || data_len < 7)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED)
    {
        ctx->state = TLS_STATE_ERROR;
        return false;
    }

    offset = tls_parse_handshake_header(data, data_len,
                                        TLS_HANDSHAKE_CERTIFICATE_REQUEST,
                                        &msg_len);
    if (offset == 0)
    {
        return false;
    }
    msg_end = offset + msg_len;

    if (offset + 1 > msg_end)
    {
        return false;
    }
    request_context_len = data[offset++];
    if (offset + request_context_len > msg_end)
    {
        return false;
    }
    offset += request_context_len;

    if (offset + 2 > msg_end)
    {
        return false;
    }
    ext_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;
    if (offset + ext_len != msg_end)
    {
        return false;
    }

    while (ext_offset + 4 <= ext_len)
    {
        uint16_t ext_data_len;

        ext_offset += 2; /* Extension type. */
        ext_data_len = ((uint16_t)data[offset + ext_offset] << 8) |
                       (uint16_t)data[offset + ext_offset + 1];
        ext_offset += 2;

        if (ext_offset + ext_data_len > ext_len)
        {
            return false;
        }
        ext_offset += ext_data_len;
    }
    if (ext_offset != ext_len)
    {
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

/* Extract the raw modulus bytes and public exponent from a DER-encoded
 * SubjectPublicKeyInfo for an rsaEncryption key. On success, *mod_out points into the SPKI
 * buffer at the first non-zero modulus byte and *mod_len_out is the
 * stripped length (matching the RSA modulus size in bytes; 256 for
 * RSA-2048). Returns false for non-RSA SPKIs, malformed input, or exponents
 * too large for powmod_exp_u24. */
static bool tls_spki_extract_rsa_public_key(const uint8_t *spki, size_t spki_len,
                                            const uint8_t **mod_out,
                                            size_t *mod_len_out,
                                            uint24_t *exp_out)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv spki_seq;
    struct tls_asn1_cursor spki_body;
    struct tls_asn1_tlv alg_seq;
    struct tls_asn1_tlv spk_bits;
    struct tls_asn1_cursor alg_body;
    struct tls_asn1_tlv alg_oid;
    struct tls_asn1_cursor rsa_body;
    struct tls_asn1_tlv rsa_seq;
    struct tls_asn1_cursor rsa_fields;
    struct tls_asn1_tlv modulus;
    struct tls_asn1_tlv exponent;

    if (!spki || spki_len == 0 || !mod_out || !mod_len_out || !exp_out)
    {
        return false;
    }

    /* SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING } */
    if (!tls_asn1_cursor_init(&c, spki, spki_len) ||
        !tls_asn1_next(&c, &spki_seq) ||
        tls_asn1_tag_number(spki_seq.tag) != ASN1_SEQUENCE ||
        !tls_asn1_tag_constructed(spki_seq.tag))
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&spki_seq, &spki_body) ||
        !tls_asn1_next(&spki_body, &alg_seq) ||
        !tls_asn1_next(&spki_body, &spk_bits))
    {
        return false;
    }
    if (tls_asn1_tag_number(spk_bits.tag) != ASN1_BITSTRING || spk_bits.len < 2)
    {
        return false;
    }

    /* AlgorithmIdentifier { OID rsaEncryption, NULL } */
    if (!tls_asn1_child_cursor(&alg_seq, &alg_body) ||
        !tls_asn1_next(&alg_body, &alg_oid) ||
        tls_asn1_tag_number(alg_oid.tag) != ASN1_OBJECTID)
    {
        return false;
    }
    if (alg_oid.len != 9 ||
        memcmp(alg_oid.value, tls_objectid_bytes[TLS_OID_RSA_ENCRYPTION], 9) != 0)
    {
        return false;
    }

    /* BIT STRING content: first byte is the unused-bits count (must be 0
     * for a DER-encoded RSAPublicKey), followed by RSAPublicKey DER. */
    if (spk_bits.value[0] != 0)
    {
        return false;
    }
    if (!tls_asn1_cursor_init(&rsa_body, spk_bits.value + 1, spk_bits.len - 1) ||
        !tls_asn1_next(&rsa_body, &rsa_seq) ||
        tls_asn1_tag_number(rsa_seq.tag) != ASN1_SEQUENCE ||
        !tls_asn1_tag_constructed(rsa_seq.tag))
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&rsa_seq, &rsa_fields) ||
        !tls_asn1_next(&rsa_fields, &modulus) ||
        tls_asn1_tag_number(modulus.tag) != ASN1_INTEGER ||
        modulus.len == 0 ||
        !tls_asn1_next(&rsa_fields, &exponent) ||
        tls_asn1_tag_number(exponent.tag) != ASN1_INTEGER ||
        exponent.len == 0)
    {
        return false;
    }

    /* ASN.1 INTEGER is signed big-endian — RSA moduli always have the high
     * bit set so DER prepends a 0x00 sign byte. Strip it (and any further
     * leading zeros, just in case) so we hand powmod the raw N. */
    const uint8_t *p = modulus.value;
    size_t n = modulus.len;
    while (n > 0 && *p == 0)
    {
        p++;
        n--;
    }
    if (n < RSA_MODULUS_MIN_SUPPORTED || n > RSA_MODULUS_MAX_SUPPORTED)
    {
        return false;
    }
    /* powmod requires odd modulus; RSA N is always odd. Belt-and-suspenders. */
    if ((p[n - 1] & 1) == 0)
    {
        return false;
    }

    const uint8_t *e = exponent.value;
    size_t e_len = exponent.len;
    while (e_len > 0 && *e == 0)
    {
        e++;
        e_len--;
    }
    if (e_len == 0 || e_len > 3)
    {
        /* powmod_exp_u24 is the current implementation boundary. */
        ERROR();
        return false;
    }
    uint24_t exp = 0;
    for (size_t i = 0; i < e_len; i++)
    {
        exp = (uint24_t)((exp << 8) | e[i]);
    }
    if (exp < 3 || (exp & 1) == 0)
    {
        ERROR();
        return false;
    }

    *mod_out = p;
    *mod_len_out = n;
    *exp_out = exp;
    return true;
}

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
    const uint8_t *modulus;
    size_t modulus_len;
    uint24_t exponent;
    uint8_t *em = NULL;
    bool ok = false;

    if (!ctx || !ctx->leaf_spki || ctx->leaf_spki_len == 0 ||
        !sig || sig_len == 0)
    {
        return false;
    }

    if (!tls_spki_extract_rsa_public_key(ctx->leaf_spki, ctx->leaf_spki_len,
                                         &modulus, &modulus_len, &exponent))
    {
        return false;
    }
    /* TLS 1.3 PSS uses salt length == hash length, so the signature must
     * exactly match the modulus size in bytes. */
    if (sig_len != modulus_len)
    {
        return false;
    }

    /* Build the signed-content digest. */
    if (!ctx->transcript_hash)
    {
        return false;
    }
    transcript_hash_digest(ctx->transcript_hash, transcript);

    memset(spaces, 0x20, sizeof(spaces));
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_update(&hash_ctx, spaces, sizeof(spaces));
    tls_hash_update(&hash_ctx, (const uint8_t *)ctx_label, sizeof(ctx_label) - 1);
    tls_hash_update(&hash_ctx, &zero, 1);
    tls_hash_update(&hash_ctx, transcript, sizeof(transcript));
    tls_hash_digest(&hash_ctx, message_hash);

    /* RSA decrypt the signature, then run the PSS padding check. Keep the
     * encoded-message buffer in the fixed RSA transient region instead of
     * allocating a mem_buffer block from inside the handshake callback path.
     * powmod has its own non-overlapping __tls_scratch arena. */
    if (modulus_len > RSA_TRANSIENT_SIZE)
    {
        return false;
    }
    em = __rsa_transient;
    if (!tls_rsa_decrypt_signature_exp(sig, sig_len, em,
                                       exponent, modulus, modulus_len))
    {
        goto cleanup;
    }
    if (!tls_rsa_pss_verify(em, modulus_len, message_hash, sizeof(message_hash),
                            TLS_HASH_SHA256))
    {
        goto cleanup;
    }
    ok = true;

cleanup:
    if (em)
    {
        tls_secure_memzero(em, modulus_len);
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
 * We RSA-decrypt the signature against the leaf SPKI captured during
 * cert walking and run PSS padding verification. Only rsa_pss_rsae_sha256
 * is wired up — the rest of the PSS variants would need SHA-384/SHA-512,
 * which are not in the hash framework. ECDSA / rsa_pkcs1_* are rejected
 * in CertificateVerify per RFC 8446 §4.4.3.
 */
static bool tls_recv_certificate_verify(
    struct tls_handshake_context *ctx,
    const uint8_t *data,
    size_t data_len)
{
    if (!ctx || !data || data_len < 8)
    {
        return false;
    }
    if (ctx->state != TLS_STATE_CERTIFICATE_RECEIVED)
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

    /* Signature algorithm (2 bytes). */
    if (offset + 2 > data_len)
    {
        return false;
    }
    uint16_t sig_alg = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
    offset += 2;

    /* Signature length (2 bytes) and bounds. */
    if (offset + 2 > data_len)
    {
        return false;
    }
    size_t sig_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
    offset += 2;
    if (offset + sig_len > data_len || offset + sig_len != 4 + msg_len)
    {
        return false;
    }

    if (!ctx->leaf_spki || ctx->leaf_spki_len == 0)
    {
        /* No leaf cert in hand (e.g. pure-PSK handshake fluke).
         * CertificateVerify without a leaf is unverifiable; fail closed. */
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
        /* Only rsa_pss_rsae_sha256 is advertised and supported; any other
         * algorithm selected by the server fails closed. */
        sig_ok = false;
        break;
    }

    if (!sig_ok)
    {
        ERROR();
        tls_send_alert(ctx, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECRYPT_ERROR);
        ctx->state = TLS_STATE_ERROR;
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
            return false;
        }
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
        /* PSK-only path passes ikm=NULL so hkdf_extract supplies 32 zero
         * bytes; saves a 32-byte stack buffer here. */
        const uint8_t *ecdhe_ikm = ctx->ecdhe_negotiated ? ctx->ecdhe_shared : NULL;
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
     * ikm=NULL tells hkdf_extract to use 32 zero bytes.
     */
    if (!tls_hkdf_extract(TLS_HASH_SHA256, derived_secret, 32,
                          NULL, 32, master_secret))
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
    size_t offset = 0;

    if (!ctx || !out || !written)
    {
        return false;
    }
    if (!ctx->client_certificate_requested ||
        ctx->state != TLS_STATE_SERVER_FINISHED_RECEIVED)
    {
        return false;
    }
    if (out_len < 8)
    {
        return false;
    }

    out[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x04;
    out[offset++] = 0x00; /* certificate_request_context length */
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00; /* certificate_list length */

    *written = offset;

    if (ctx->transcript_hash)
    {
        transcript_hash_update(ctx->transcript_hash, out, offset);
    }

    DEBUG();
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
static bool tls_recv_finished(
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
            ERROR();
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
 * The altcp layer is responsible for persisting (psk, identity) to flash
 * via the appvar mechanism — see altcp_tls_ce_save_pski.
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
        /* RFC 8446 uses a zero lifetime to invalidate/discard the ticket.
         * Resumption is optional; keep the established connection alive. */
        return true;
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
        /* Some TLS 1.3 servers emit tickets larger than the calculator-side
         * PSK identity store. Ignore those tickets rather than aborting an
         * otherwise healthy application connection. */
        return true;
    }
    if (nonce_len == 0)
    {
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
static bool tls_send_alert(
    struct tls_handshake_context *ctx,
    uint8_t level,
    uint8_t description)
{
    if (!ctx)
    {
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
            struct tls_aes_context aes_ctx;
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
                    (*seq_num)++;
                    ok = ctx->transport_write(ctx->transport_arg, record, sizeof(record));
                }
            }
        }
    }

    if (level == TLS_ALERT_LEVEL_FATAL)
    {
        ctx->state = TLS_STATE_ERROR;
        ERROR();
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

    /* Free any in-flight Certificate walker (cert_walker plus its
     * per-cert buffer). Safe on NULL. */
    tls_cert_walker_free(ctx->cert_walker);
    ctx->cert_walker = NULL;
    ctx->hs_reasm_body_fed = 0;

    /* Release captured leaf SPKI (allocated during cert walking,
     * consumed by tls_recv_certificate_verify). */
    if (ctx->leaf_spki)
    {
        mem_stats_tls_direct_release(ctx->leaf_spki_len, ctx->leaf_spki_len);
        mem_buffer_custom_free(ctx->leaf_spki);
        ctx->leaf_spki = NULL;
        ctx->leaf_spki_len = 0;
    }

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
