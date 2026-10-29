/**
 * @file altcp_tls_ce.c
 * @brief ALTCP TLS Layer for TI-84+ CE - Implementation
 *
 * This file provides TLS 1.3 integration with lwIP's altcp layer,
 * similar to the mbedtls port but using CE-optimized cryptography.
 */

#include "lwip/opt.h"

#if LWIP_ALTCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dispatch.h"
#include "lwip/priv/altcp_priv.h"
#include "lwip/mem.h"
#include "altcp_tls_ce.h"
#include "../../tls/includes/aes.h"

/* Internal record-layer hook implemented by handshake.c. */
extern bool tls_update_write_keys_if_needed(struct tls_handshake_context *ctx);
/* Internal streaming-authentication hooks for the TLS record layer. */
extern bool tls_aes_update_ciphertext(struct tls_aes_context *ctx, const uint8_t *ct, size_t ct_len);
extern bool tls_aes_verify_tag(struct tls_aes_context *ctx, const uint8_t *tag);
#include "../../tls/includes/bytes.h"
#include "../../tls/includes/crypto_guard.h"
#include "../../tls/includes/handshake.h"
#include "../../tls/includes/random.h"
#include "../../lwip-imports.h"
#include "../../tls/includes/tls.h"
#include "../../drivers/mem.h"
#include "../../wireless/crypto.h"
#include "../../wireless/wifi_proto.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_ALTCP_TLS_CE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"
#include "lwip/sntp_time.h"

#include <string.h>
#include <limits.h>

TLS_AUTOZERO_DECL_STRUCT(tls_aes_context)

/* Keep the stage labels beside the code as breadcrumbs, but do not emit them.
 * TLS record and handshake paths are too frequent for the bounded persistent
 * log; failures below already emit a location-bearing ERROR event. */
#define tls_dbg_status(msg) ((void)sizeof(msg))

/* Fatal TLS connection termination must always leave a traceback entry at the
 * actual decision site.  Do not call altcp_abort() directly for an error path;
 * reserve direct calls for explicitly documented teardown/ownership cleanup. */
#define ALTCP_TLS_CE_ERROR_ABORT(pcb) do { \
    ERROR(); \
    altcp_abort(pcb); \
} while (0)

#define ALTCP_TLS_CE_ERROR_ABORT_CODE(pcb, code) do { \
    ERROR_CODE(code); \
    altcp_abort(pcb); \
} while (0)

/* Debug flag for TLS CE layer */
#ifndef ALTCP_TLS_CE_DEBUG
#define ALTCP_TLS_CE_DEBUG LWIP_DBG_OFF
#endif

static enum mem_pressure_level g_tls_rx_throttle_level = MEM_PRESSURE_NONE;
static altcp_tls_ce_state_t *g_tls_state_head = NULL;

/* True while `state` is still linked, i.e. has not been freed by an app
 * callback that closed or aborted the connection. */
static bool altcp_tls_ce_state_alive(const altcp_tls_ce_state_t *state)
{
    for (const altcp_tls_ce_state_t *s = g_tls_state_head; s != NULL; s = s->next)
    {
        if (s == state)
        {
            return true;
        }
    }
    return false;
}
static bool g_tls_rx_release_attached = false;

static void altcp_tls_ce_lower_recved(struct altcp_pcb *inner_conn, int recvd_cnt);
static void altcp_tls_ce_consume_recved(altcp_tls_ce_state_t *state, size_t n);
static void altcp_tls_ce_ack_recved(altcp_tls_ce_state_t *state, size_t n);

#define ALTCP_TLS_CE_RX_RELEASE_MILD_MS 50u
#define ALTCP_TLS_CE_RX_RELEASE_HIGH_MS 100u
#define ALTCP_TLS_CE_RX_RELEASE_SEVERE_MS 250u
#define ALTCP_TLS_CE_RX_RELEASE_CRITICAL_MS 500u

#define ALTCP_TLS_CE_RX_RELEASE_MILD_BYTES 2048u
#define ALTCP_TLS_CE_RX_RELEASE_HIGH_BYTES 1024u
#define ALTCP_TLS_CE_RX_RELEASE_SEVERE_BYTES 512u
#define ALTCP_TLS_CE_RX_RELEASE_CRITICAL_BYTES 128u

static void tls_state_add(altcp_tls_ce_state_t *state)
{
    state->next = g_tls_state_head;
    g_tls_state_head = state;
}

static void tls_state_remove(altcp_tls_ce_state_t *state)
{
    altcp_tls_ce_state_t **pp = &g_tls_state_head;
    while (*pp)
    {
        if (*pp == state)
        {
            *pp = state->next;
            state->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

static uint32_t altcp_tls_ce_rx_release_interval_ms(enum mem_pressure_level level)
{
    switch (level)
    {
    case MEM_PRESSURE_MILD:
        return ALTCP_TLS_CE_RX_RELEASE_MILD_MS;
    case MEM_PRESSURE_HIGH:
        return ALTCP_TLS_CE_RX_RELEASE_HIGH_MS;
    case MEM_PRESSURE_SEVERE:
        return ALTCP_TLS_CE_RX_RELEASE_SEVERE_MS;
    case MEM_PRESSURE_CRITICAL:
        return ALTCP_TLS_CE_RX_RELEASE_CRITICAL_MS;
    case MEM_PRESSURE_NONE:
    default:
        return 0;
    }
}

static size_t altcp_tls_ce_rx_release_budget(enum mem_pressure_level level)
{
    switch (level)
    {
    case MEM_PRESSURE_MILD:
        return ALTCP_TLS_CE_RX_RELEASE_MILD_BYTES;
    case MEM_PRESSURE_HIGH:
        return ALTCP_TLS_CE_RX_RELEASE_HIGH_BYTES;
    case MEM_PRESSURE_SEVERE:
        return ALTCP_TLS_CE_RX_RELEASE_SEVERE_BYTES;
    case MEM_PRESSURE_CRITICAL:
        return ALTCP_TLS_CE_RX_RELEASE_CRITICAL_BYTES;
    case MEM_PRESSURE_NONE:
    default:
        return (size_t)-1;
    }
}

static bool altcp_tls_ce_has_pending_recved(void)
{
    altcp_tls_ce_state_t *state = g_tls_state_head;
    while (state)
    {
        if (state->rx_throttle_pending > 0 && state->conn && state->conn->inner_conn)
        {
            return true;
        }
        state = state->next;
    }
    return false;
}

static void altcp_tls_ce_release_pending(altcp_tls_ce_state_t *state, size_t budget)
{
    if (!state || !state->conn || !state->conn->inner_conn)
    {
        if (state && state->rx_throttle_pending > 0)
        {
            DEBUG(); /* throttled recved bytes stuck un-acked: conn/inner_conn gone before release */
        }
        return;
    }

    while (state->rx_throttle_pending > 0 && budget > 0)
    {
        size_t chunk = state->rx_throttle_pending;
        if (chunk > budget)
        {
            chunk = budget;
        }
        if (chunk > (size_t)INT_MAX)
        {
            chunk = (size_t)INT_MAX;
        }
        if (chunk == 0)
        {
            break;
        }
        altcp_tls_ce_lower_recved(state->conn->inner_conn, (int)chunk);
        state->rx_throttle_pending -= chunk;
        budget -= chunk;
    }
}

static void altcp_tls_ce_rx_release_dispatch(void)
{
    size_t budget = altcp_tls_ce_rx_release_budget(g_tls_rx_throttle_level);
    altcp_tls_ce_state_t *state = g_tls_state_head;
    while (state)
    {
        altcp_tls_ce_release_pending(state, budget);
        state = state->next;
    }

    if (!altcp_tls_ce_has_pending_recved())
    {
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RX_RECVD, 0);
    }
}

static void altcp_tls_ce_rx_release_arm(void)
{
    uint32_t interval_ms;

    if (!g_tls_rx_release_attached)
    {
        lwip_dispatch_attach(LWIP_DISPATCH_TLS_RX_RECVD, altcp_tls_ce_rx_release_dispatch);
        g_tls_rx_release_attached = true;
    }

    if (!altcp_tls_ce_has_pending_recved())
    {
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RX_RECVD, 0);
        return;
    }

    interval_ms = altcp_tls_ce_rx_release_interval_ms(g_tls_rx_throttle_level);
    if (interval_ms == 0)
    {
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RX_RECVD, 0);
        return;
    }

    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RX_RECVD,
                             lwip_dispatch_period_from_ms(interval_ms));
    lwip_dispatch_start();
}

/* Forward declarations */
static err_t altcp_tls_ce_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_tls_ce_lower_poll(void *arg, struct altcp_pcb *inner_conn);
static err_t altcp_tls_ce_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);
static err_t altcp_tls_ce_server_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);
static void altcp_tls_ce_cert_job_arm(void);
static void altcp_tls_ce_keyshare_arm(void);

/* True once the held-back server flight has been replayed and the server
 * Finished was processed, but the client Finished / key switch has not run yet
 * (it normally runs right after a record; after a deferred replay no record is
 * pending to drive it). */
static bool altcp_tls_ce_finish_ready(const altcp_tls_ce_state_t *state)
{
    return !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE) &&
           state->tls_ctx.state == TLS_STATE_SERVER_FINISHED_RECEIVED;
}
static err_t altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);

static void altcp_tls_ce_build_aead_nonce(const uint8_t iv[12], uint64_t seq_num,
                                          uint8_t out_nonce[12])
{
    memcpy(out_nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
    {
        out_nonce[4 + i] ^= (uint8_t)((seq_num >> (56 - i * 8)) & 0xFF);
    }
}

static bool altcp_tls_ce_record_aead_init(struct tls_aes_context *aes_ctx,
                                          const struct tls_handshake_context *ctx,
                                          const uint8_t key[16],
                                          const uint8_t nonce[12],
                                          size_t plaintext_len)
{
    if (ctx->cipher_suite == TLS_AES_128_CCM_SHA256)
    {
        return tls_aes_ccm_init(aes_ctx, key, 16, nonce, 12,
                                TLS_AES_AUTH_TAG_SIZE, plaintext_len, 5);
    }
    if (ctx->cipher_suite != TLS_AES_128_GCM_SHA256)
    {
        ERROR_CODE(ctx->cipher_suite);
        return false;
    }
    return tls_aes_init(aes_ctx, TLS_AES_GCM, key, 16, nonce, 12);
}

/* Chunk size for streaming AEAD passes. Sized to amortize per-call AES
 * overhead while keeping the working set well under one TLS record. */
#ifndef ALTCP_TLS_CE_STREAM_CHUNK
#define ALTCP_TLS_CE_STREAM_CHUNK 2048
#endif

/* Walk `len` ciphertext bytes from `src` starting at `src_offset`, feeding
 * them into the negotiated AEAD authentication path. GCM authenticates the
 * ciphertext directly; CCM runs its CTR/MAC pass without retaining plaintext.
 * Used as Pass 1 of record decryption before any plaintext is released.
 *
 * Walks pbuf segments directly to avoid materializing the ciphertext into
 * a contiguous buffer. */
static err_t altcp_tls_ce_pbuf_authenticate(struct tls_aes_context *aes_ctx,
                                            const struct pbuf *src,
                                            size_t src_offset,
                                            size_t len)
{
    u16_t inner = 0;
    const struct pbuf *q = pbuf_skip((struct pbuf *)src, (u16_t)src_offset, &inner);
    size_t done = 0;

    while (done < len)
    {
        size_t avail;
        size_t take;

        while (q && q->len == 0)
        {
            q = q->next;
            inner = 0;
        }
        if (!q || inner >= q->len)
        {
            return ERR_BUF;
        }

        avail = (size_t)q->len - inner;
        take = LWIP_MIN(avail, len - done);
        const uint8_t *ciphertext = (const uint8_t *)q->payload + inner;
        bool ok = aes_ctx->mode == TLS_AES_CCM
            ? tls_aes_decrypt(aes_ctx, ciphertext, take, NULL)
            : tls_aes_update_ciphertext(aes_ctx, ciphertext, take);
        if (!ok)
        {
            return ERR_VAL;
        }
        done += take;
        inner += (u16_t)take;
        if (inner == q->len)
        {
            q = q->next;
            inner = 0;
        }
    }
    return ERR_OK;
}

/* Streaming TLS 1.3 record decrypt with incremental input release.
 *
 *  Pass 1: authenticate the entire ciphertext without retaining plaintext,
 *          then verify the 16-byte tag. Tag mismatch is fatal and the
 *          input rx chain is left intact for the caller to free.
 *  Pass 2: re-init the selected AEAD and decrypt the ciphertext **in place,
 *          inside `state->rx` itself**, segment by segment. state->rx is always
 *          our own writable PBUF_RAM chain (altcp_tls_ce_copy_rx_to_ram), so
 *          no output pbuf is allocated and the record exists once rather than
 *          twice. The 5-byte header is released first; the 16-byte tag is
 *          trimmed with pbuf_realloc after the last segment.
 *
 * Peak working set for a record is therefore one record's worth of pbuf chain,
 * down from (ciphertext + plaintext). Nothing is allocated per record, so
 * there is no allocation-failure path to retry.
 *
 * On success, *plaintext is that chain (now plaintext, trailing zero padding
 * and the inner content-type byte stripped), *written is its length and
 * *inner_content_type is the discovered type. Ownership of the chain passes to
 * the caller: state->rx is cleared.
 *
 * Failure handling: once the header has been consumed the record cannot be
 * re-parsed, so every failure below is fatal and the caller aborts; the chain
 * stays in state->rx for the teardown path to free. */
static err_t altcp_tls_ce_decrypt_record_stream(altcp_tls_ce_state_t *state,
                                                struct altcp_pcb *conn,
                                                bool use_handshake_keys,
                                                size_t record_len,
                                                struct pbuf **plaintext,
                                                size_t *written,
                                                uint8_t *inner_content_type)
{
    uint8_t header[5];
    uint8_t nonce[12];
    uint8_t received_tag[16];
    TLS_AUTOZERO_STRUCT(tls_aes_context, aes_ctx);
    struct pbuf *out_head = NULL;
    struct tls_handshake_context *ctx = &state->tls_ctx;
    const uint8_t *key;
    const uint8_t *iv;
    uint64_t *seq_num;
    size_t ciphertext_len;
    size_t actual_plaintext_len;
    size_t processed;
    struct pbuf *rest = NULL;
    err_t status = ERR_OK;

    if (!state || !conn || !plaintext || !written || !inner_content_type)
    {
        return ERR_ARG;
    }
    *plaintext = NULL;
    *written = 0;
    *inner_content_type = 0;

    if (record_len < 5 + TLS_AES_AUTH_TAG_SIZE + 1 || record_len > 0xFFFF)
    {
        return ERR_VAL;
    }
    if (!state->rx || state->rx->tot_len < record_len)
    {
        return ERR_BUF;
    }

    if (pbuf_copy_partial(state->rx, header, sizeof(header), 0) != sizeof(header))
    {
        return ERR_BUF;
    }

    ciphertext_len = record_len - sizeof(header);
    actual_plaintext_len = ciphertext_len - TLS_AES_AUTH_TAG_SIZE;
    /* +1 for the mandatory inner content-type byte (RFC 8446 §5.2).
     * peer_record_size_limit is the RFC 8449 negotiated limit (default 16384);
     * a record whose plaintext exceeds it gets a fatal record_overflow alert. */
    if (actual_plaintext_len == 0 ||
        actual_plaintext_len > (size_t)ctx->peer_record_size_limit + 1u)
    {
        (void)tls_send_fatal_alert(ctx, TLS_ALERT_RECORD_OVERFLOW);
        return ERR_VAL;
    }

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

    altcp_tls_ce_build_aead_nonce(iv, *seq_num, nonce);

    /* Pass 2 decrypts in place inside the output pbuf, so no stream-sized
     * scratch is needed: one copy out of the RX pbuf instead of
     * copy-to-scratch + decrypt + copy-to-pbuf, and no 2 KiB allocation (and
     * free) per record for the allocator to fragment on. */

    /* Pass 1: verify the complete record before releasing plaintext. */
    if (!altcp_tls_ce_record_aead_init(&aes_ctx, ctx, key, nonce,
                                       actual_plaintext_len) ||
        !tls_aes_update_aad(&aes_ctx, header, sizeof(header)))
    {
        status = ERR_VAL;
        goto fail;
    }
    if (altcp_tls_ce_pbuf_authenticate(&aes_ctx, state->rx, sizeof(header),
                                       actual_plaintext_len) != ERR_OK)
    {
        status = ERR_VAL;
        goto fail;
    }
    if (pbuf_copy_partial(state->rx, received_tag, sizeof(received_tag),
                          (u16_t)(sizeof(header) + actual_plaintext_len)) != sizeof(received_tag))
    {
        status = ERR_BUF;
        goto fail;
    }
    if (!tls_aes_verify_tag(&aes_ctx, received_tag))
    {
        (void)tls_send_fatal_alert(ctx, TLS_ALERT_BAD_RECORD_MAC);
        status = ERR_VAL;
        goto fail;
    }

    /* Release the 5-byte header from the input pbuf. altcp_tls_ce_consume_recved
     * acks to the lower TCP only the bytes not already pre-acked at queue time,
     * so handshake bytes (pre-acked) aren't double-acked. Post-handshake
     * app-data bytes are not pre-acked here; they are acked exactly once when
     * the decrypter consumes the encrypted record from state->rx. */
    /* state->rx may hold further records behind this one: a server can stack
     * several records into one TCP segment and the caller loops over them.
     * lwIP pbufs cannot be split and pbuf_realloc below frees the tail, so
     * preserve the trailing bytes now, while the chain is still at the record
     * start and offsets are record-relative. This is one bounded copy of what
     * followed the record, replacing the much larger ciphertext-to-plaintext
     * copy this function used to make.
     *
     * Nothing has been consumed yet, so an allocation failure here is still
     * retryable: report ERR_MEM and let the caller try again on the next recv
     * rather than aborting a connection under transient memory pressure. */
    {
        u16_t buffered = state->rx->tot_len;

        if (buffered > (u16_t)record_len)
        {
            size_t rest_len = (size_t)buffered - record_len;
            rest = pbuf_alloc(PBUF_RAW, (u16_t)rest_len, PBUF_RAM);
            if (rest == NULL)
            {
                /* Nothing consumed yet: retryable, and the common exit still
                 * destroys the AEAD context (the ledger's AES-zeroization
                 * entry requires every exit to go through it). */
                status = ERR_MEM;
                goto fail;
            }
            if (pbuf_copy_partial(state->rx, rest->payload, (u16_t)rest_len,
                                  (u16_t)record_len) != rest_len)
            {
                status = ERR_BUF;
                goto fail;   /* fail frees `rest` and destroys the context */
            }
        }
    }

    altcp_tls_ce_consume_recved(state, sizeof(header));

    /* Pass 2: decrypt the ciphertext in place, in state->rx itself.
     *
     * state->rx is always built by altcp_tls_ce_copy_rx_to_ram, i.e. it is our
     * own writable PBUF_RAM chain, so the plaintext can replace the ciphertext
     * segment by segment. That removes the separate output pbuf entirely: the
     * record exists once, not twice, and the pbuf the application receives is
     * the one the record arrived in. The caller owns it after this returns.
     *
     * Safe because the tag has already verified (pass 1), so no unverified
     * plaintext can be observed; and because the record is consumed here, a
     * failure below is fatal rather than retryable — the caller aborts, which
     * matches the existing rule that consumption begins at the header. */
    processed = 0;
    {
        struct pbuf *q = state->rx;
        while (q != NULL && processed < actual_plaintext_len)
        {
            size_t take = actual_plaintext_len - processed;
            if (take > q->len)
            {
                take = q->len;
            }
            if (!tls_aes_decrypt(&aes_ctx, (u8_t *)q->payload, (size_t)take,
                                 (u8_t *)q->payload))
            {
                status = ERR_VAL;
                goto fail;
            }
            processed += take;
            q = q->next;
        }
        if (processed != actual_plaintext_len)
        {
            status = ERR_BUF;
            goto fail;
        }
    }

    /* Drop the trailing 16-byte tag: the chain now ends at the last plaintext
     * byte. The bytes themselves are acked (not freed) so the chain can be
     * handed to the application intact. */
    pbuf_realloc(state->rx, (u16_t)actual_plaintext_len);
    altcp_tls_ce_ack_recved(state, actual_plaintext_len + TLS_AES_AUTH_TAG_SIZE);
    out_head = state->rx;

    (*seq_num)++;

    /* Strip trailing zero padding and pull off the inner content-type byte. */
    {
        size_t pt_end = actual_plaintext_len;
        while (pt_end > 0 && pbuf_get_at(out_head, (u16_t)(pt_end - 1)) == 0)
        {
            pt_end--;
        }
        if (pt_end == 0)
        {
            /* out_head and state->rx still refer to the same (now useless)
             * record chain, so that chain belongs to the caller: it aborts and
             * its teardown frees state->rx. Only the local preserved tail is
             * ours to drop here. */
            if (rest)
            {
                pbuf_free(rest);
            }
            tls_aes_destroy_ctx(&aes_ctx);
            (void)tls_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
            return ERR_VAL;
        }
        *inner_content_type = pbuf_get_at(out_head, (u16_t)(pt_end - 1));
        *written = pt_end - 1;
        pbuf_realloc(out_head, (u16_t)*written);
    }

    /* Ownership handover, and only now: out_head (the record, now plaintext)
     * goes to the caller, and the preserved tail becomes the new state->rx so
     * the loop can parse the next record. Until this point `rest` is local, so
     * every failure path above can free it without leaving state->rx dangling;
     * after this point there is no failure path. */
    state->rx = rest;
    *plaintext = out_head;
    tls_aes_destroy_ctx(&aes_ctx);
    return ERR_OK;

fail:
    if (out_head)
    {
        pbuf_free(out_head);
    }
    if (rest)
    {
        /* Preserved tail of a coalesced segment: the caller is aborting, so
         * drop it rather than leaking it. */
        pbuf_free(rest);
    }
    tls_aes_destroy_ctx(&aes_ctx);
    return (status != ERR_OK) ? status : ERR_VAL;
}

/* Streaming TLS 1.3 record encrypt. Walks `plaintext` in chunked strides,
 * encrypting each stride directly into the right offset of the output
 * record buffer. Output must be contiguous because TCP expects a single
 * write. Header and tag are written at the ends; the inner content-type
 * byte is encrypted as a final tiny stride.
 *
 * The streaming pattern here is for code consistency with the decrypt
 * side and to keep AES per-call working set small; there is no memory
 * win because the output buffer must be allocated full-size up front. */
static bool altcp_tls_ce_encrypt_record_stream(struct tls_handshake_context *ctx,
                                               bool use_handshake_keys,
                                               uint8_t inner_content_type,
                                               const uint8_t *plaintext,
                                               size_t plaintext_len,
                                               uint8_t *record,
                                               size_t record_cap,
                                               size_t *written)
{
    uint8_t nonce[12];
    TLS_AUTOZERO_STRUCT(tls_aes_context, aes_ctx);
    const uint8_t *key;
    const uint8_t *iv;
    uint64_t *seq_num;
    size_t inner_len;
    size_t total_len;
    size_t processed;
    uint8_t auth_tag[16];

    if (!ctx || !record || !written || (!plaintext && plaintext_len != 0))
    {
        return false;
    }

    inner_len = plaintext_len + 1; /* + inner content-type byte */
    total_len = 5 + inner_len + TLS_AES_AUTH_TAG_SIZE;
    if (record_cap < total_len)
    {
        return false;
    }

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

    record[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (uint8_t)((inner_len + TLS_AES_AUTH_TAG_SIZE) >> 8);
    record[4] = (uint8_t)((inner_len + TLS_AES_AUTH_TAG_SIZE) & 0xFF);

    altcp_tls_ce_build_aead_nonce(iv, *seq_num, nonce);
    if (!altcp_tls_ce_record_aead_init(&aes_ctx, ctx, key, nonce, inner_len) ||
        !tls_aes_update_aad(&aes_ctx, record, 5))
    {
        return false;
    }

    processed = 0;
    while (processed < plaintext_len)
    {
        size_t take = LWIP_MIN(ALTCP_TLS_CE_STREAM_CHUNK, plaintext_len - processed);
        if (!tls_aes_encrypt(&aes_ctx, plaintext + processed, take,
                             record + 5 + processed))
        {
            return false;
        }
        processed += take;
    }

    /* Encrypt the inner content-type byte as a 1-byte final stride. */
    if (!tls_aes_encrypt(&aes_ctx, &inner_content_type, 1,
                         record + 5 + plaintext_len))
    {
        return false;
    }

    if (!tls_aes_digest(&aes_ctx, auth_tag))
    {
        return false;
    }
    memcpy(record + 5 + inner_len, auth_tag, sizeof(auth_tag));

    *written = total_len;
    return true;
}

static struct pbuf *altcp_tls_ce_copy_rx_to_ram(struct pbuf *p)
{
    struct pbuf *copy;
    u16_t len;

    if (!p)
    {
        return NULL;
    }

    len = p->tot_len;
    copy = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!copy)
    {
        return p;
    }
    if (pbuf_copy_partial(p, copy->payload, len, 0) != len)
    {
        pbuf_free(copy);
        return p;
    }

    pbuf_free(p);
    return copy;
}

static void altcp_tls_ce_open_window_for_record(altcp_tls_ce_state_t *state)
{
    uint8_t header[5];
    size_t want;

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE) || state->rx == NULL ||
        state->rx_app != NULL || state->conn == NULL || state->conn->inner_conn == NULL)
    {
        return;
    }
    want = state->rx->tot_len;
    if (want >= sizeof(header) &&
        pbuf_copy_partial(state->rx, header, sizeof(header), 0) == sizeof(header))
    {
        size_t record = sizeof(header) + (((size_t)header[3] << 8) | (size_t)header[4]);
        if (want > record)
        {
            want = record;
        }
    }
    if (want > state->rx_acked_len)
    {
        altcp_tls_ce_lower_recved(state->conn->inner_conn, (int)(want - state->rx_acked_len));
        state->rx_acked_len = want;
    }
}

static void altcp_tls_ce_queue_rx(altcp_tls_ce_state_t *state, struct pbuf *p)
{
    u16_t added = (p != NULL) ? p->tot_len : 0;
    struct pbuf *queued = altcp_tls_ce_copy_rx_to_ram(p);

    if (state->rx == NULL)
    {
        state->rx = queued;
    }
    else
    {
        LWIP_ASSERT("rx pbuf overflow", (int)state->rx->tot_len + (int)queued->tot_len <= 0xFFFF);
        pbuf_cat(state->rx, queued);
    }

    /* During the handshake there is no application backpressure: the bytes
     * are now safely held in our own state->rx buffer, so ack them to the
     * lower TCP immediately to keep the receive window open. Without this a
     * handshake record larger than the window (e.g. the server Certificate,
     * which spans several segments) can never fully arrive — the window fills
     * with un-acked partial-record bytes and the server stalls (observed as
     * tls:rec_partial looping forever).
     *
     * We track how many front-of-rx bytes have been acked here in
     * rx_acked_len; the consume path (altcp_tls_ce_consume_recved) then only
     * acks the bytes it releases that this counter did NOT already cover, so
     * no byte is ever acked twice — even for a pbuf that straddles the
     * handshake -> app-data transition. After the handshake only the bytes of
     * the record at the head of state->rx are pre-acked, so a record larger
     * than the TCP window can still complete. */
    if (added != 0 && !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE) &&
        state->conn != NULL && state->conn->inner_conn != NULL)
    {
        altcp_tls_ce_lower_recved(state->conn->inner_conn, (int)added);
        state->rx_acked_len += added;
    }
    else if (added != 0 && !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        /* Handshake still in progress but conn/inner_conn is gone: the
         * pre-ack that keeps the window open for a multi-segment handshake
         * record (see comment above) did NOT happen this time. */
        DEBUG();
    }
    altcp_tls_ce_open_window_for_record(state);
}

/* Release `n` bytes from the front of state->rx and ack to the lower TCP only
 * the portion not already pre-acked at queue time (tracked by rx_acked_len).
 * This keeps every received byte acked exactly once across the handshake ->
 * app-data boundary. */
/* Acknowledge n bytes already removed from state->rx with pbuf_free_header. */
static void altcp_tls_ce_ack_recved(altcp_tls_ce_state_t *state, size_t n)
{
    size_t to_ack;

    if (state->rx_acked_len >= n)
    {
        /* Entire span was already acked at queue time. */
        state->rx_acked_len -= n;
        return;
    }

    to_ack = n - state->rx_acked_len; /* bytes not yet acked */
    state->rx_acked_len = 0;
    if (to_ack != 0 && state->conn != NULL && state->conn->inner_conn != NULL)
    {
        altcp_tls_ce_lower_recved(state->conn->inner_conn, (int)to_ack);
    }
}

static void altcp_tls_ce_consume_recved(altcp_tls_ce_state_t *state, size_t n)
{
    state->rx = pbuf_free_header(state->rx, (u16_t)n);
    altcp_tls_ce_ack_recved(state, n);
}

/* Transport write hook used by handshake.c for alerts and close_notify.
 * The handshake context stores this as a function pointer set in
 * altcp_tls_ce_setup, so handshake code does not depend on lwIP/altcp. */
static bool altcp_tls_ce_transport_write(void *transport_arg,
                                         const uint8_t *data, size_t len)
{
    altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)transport_arg;
    if (!state || !state->conn || !state->conn->inner_conn || !data || len == 0)
    {
        ERROR_CODE(-ERR_ARG);
        return false;
    }
    err_t err = altcp_write(state->conn->inner_conn, data, (u16_t)len,
                            TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
    {
        ERROR_CODE(-err);
        return false;
    }
    (void)altcp_output(state->conn->inner_conn);
    return true;
}

/* Variable prototype for function table */
extern const struct altcp_functions altcp_tls_ce_functions;

/* ========== Configuration Management ========== */

struct altcp_tls_ce_config *altcp_tls_ce_create_config_psk_client(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity)
{
    struct altcp_tls_ce_config *conf;

    conf = (struct altcp_tls_ce_config *)mem_malloc(sizeof(struct altcp_tls_ce_config));
    if (conf == NULL)
    {
        ERROR_CODE(-ERR_MEM);
        return NULL;
    }
    mem_stats_tls_direct_add(sizeof(*conf), sizeof(*conf));

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 0;
    conf->psk_mode = 1;
    conf->psk_type = TLS_PSK_TYPE_EXTERNAL;
    memcpy(conf->psk, psk, 32);
    memcpy(&conf->psk_identity, psk_identity, sizeof(struct tls_psk_identity));
    /* RFC 8446 4.2.11: external PSKs use an obfuscated_ticket_age of zero. */
    conf->psk_identity.obfuscated_ticket_age = 0;

    return conf;
}

struct altcp_tls_ce_config *altcp_tls_ce_create_config_psk_server(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity)
{
    struct altcp_tls_ce_config *conf;

    conf = (struct altcp_tls_ce_config *)mem_malloc(sizeof(struct altcp_tls_ce_config));
    if (conf == NULL)
    {
        ERROR_CODE(-ERR_MEM);
        return NULL;
    }
    mem_stats_tls_direct_add(sizeof(*conf), sizeof(*conf));

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 1;
    conf->psk_mode = 1;
    conf->psk_type = TLS_PSK_TYPE_EXTERNAL;
    memcpy(conf->psk, psk, 32);
    memcpy(&conf->psk_identity, psk_identity, sizeof(struct tls_psk_identity));

    return conf;
}

struct altcp_tls_ce_config *altcp_tls_ce_create_config_client_ecdhe(
    const char *hostname)
{
    struct altcp_tls_ce_config *conf;
    uint8_t resumed_psk_type;
    uint8_t resumed_psk[32];
    struct tls_psk_identity resumed_identity;

    tls_dbg_status("config: ecdhe enter");
    size_t host_len = hostname ? strlen(hostname) + 1 : 0;
    conf = (struct altcp_tls_ce_config *)mem_malloc(sizeof(struct altcp_tls_ce_config) + host_len);
    if (conf == NULL)
    {
        ERROR_CODE(-ERR_MEM);
        return NULL;
    }
    mem_stats_tls_direct_add(sizeof(*conf) + host_len, sizeof(*conf) + host_len);

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 0;
    conf->psk_mode = 0;
    conf->hostname = hostname ? memcpy(conf + 1, hostname, host_len) : NULL;
    hostname = conf->hostname;

    /* Opportunistically resume from the in-memory PSK cache, but only if a
     * live (non-expired) entry exists for this exact hostname. Cross-host
     * PSK reuse is a protocol violation; a miss silently falls back to a
     * fresh ECDHE handshake. */
    tls_dbg_status("config: pski lookup");
    if (hostname && tls_psk_cache_get(hostname, &resumed_psk_type, resumed_psk, &resumed_identity))
    {
        conf->psk_mode = 1;
        conf->psk_type = resumed_psk_type;
        memcpy(conf->psk, resumed_psk, sizeof(conf->psk));
        memcpy(&conf->psk_identity, &resumed_identity, sizeof(conf->psk_identity));
        tls_dbg_status("config: resume found");
    }

    tls_secure_memzero(resumed_psk, sizeof resumed_psk);
    tls_secure_memzero(&resumed_identity, sizeof resumed_identity);

    tls_dbg_status("config: done");
    return conf;
}

/* Read an appvar into a heap buffer via the file_fn table.
 * Returns a mem_buffer_custom_malloc'd block; caller must free it.
 * *out_len receives the byte count. Returns NULL on any error. */
static char *read_appvar_pem(const char *appvar_name, size_t *out_len)
{
    if (!appvar_name || !out_len) return NULL;
    uint8_t h = file_fn.ti_open(appvar_name, "r");
    if (!h) return NULL;
    uint16_t size = file_fn.ti_getsize(h);
    if (size == 0) { file_fn.ti_close(h); return NULL; }
    char *buf = (char *)mem_buffer_custom_malloc(size);
    if (!buf) { file_fn.ti_close(h); return NULL; }
    size_t read = file_fn.ti_read(buf, 1, size, h);
    file_fn.ti_close(h);
    if (read != size)
    {
        mem_buffer_custom_free(buf);
        return NULL;
    }
    *out_len = size;
    return buf;
}

/* Parse a multi-cert PEM blob into a heap array of tls_x509_object pointers.
 * Returns the array (mem_malloc'd); *n receives the count. NULL on failure. */
static struct tls_x509_object **parse_cert_chain(const char *pem, size_t pem_len,
                                                  size_t *n)
{
    static const char banner[] = "-----BEGIN CERTIFICATE-----";
    const size_t blen = sizeof(banner) - 1;
    const char *p = pem, *end = pem + pem_len;
    size_t count = 0;

    /* Count banners. */
    for (const char *s = p; s + blen <= end; s++)
        if (memcmp(s, banner, blen) == 0) { count++; s += blen - 1; }
    if (count == 0) return NULL;

    struct tls_x509_object **arr =
        (struct tls_x509_object **)mem_malloc(count * sizeof(*arr));
    if (!arr) return NULL;
    memset(arr, 0, count * sizeof(*arr));

    size_t idx = 0;
    p = pem;
    while (p + blen <= end && idx < count)
    {
        /* Find next banner start. */
        const char *start = NULL;
        for (const char *s = p; s + blen <= end; s++)
            if (memcmp(s, banner, blen) == 0) { start = s; break; }
        if (!start) break;

        /* Find where this cert ends (next banner or end of blob). */
        const char *next = NULL;
        for (const char *s = start + blen; s + blen <= end; s++)
            if (memcmp(s, banner, blen) == 0) { next = s; break; }
        size_t cert_len = next ? (size_t)(next - start) : (size_t)(end - start);

        arr[idx] = tls_x509_import_certificate(start, cert_len);
        if (!arr[idx])
        {
            for (size_t j = 0; j < idx; j++) tls_x509_object_free(arr[j]);
            mem_free(arr);
            return NULL;
        }
        idx++;
        p = start + blen;
    }
    *n = idx;
    return arr;
}

static bool load_cert_identity(const char *privkey_appvar,
                               const char *chain_appvar,
                               struct tls_x509_object ***chain_out,
                               size_t *chain_len_out,
                               struct tls_key **key_out)
{
    size_t key_len = 0, chain_len = 0;
    if (!chain_out || !chain_len_out || !key_out)
        return false;
    *chain_out = NULL;
    *chain_len_out = 0;
    *key_out = NULL;
    INFO("tls-cert: loading identity");
    char *key_pem   = read_appvar_pem(privkey_appvar, &key_len);
    char *chain_pem = read_appvar_pem(chain_appvar,   &chain_len);

    if (!key_pem || !chain_pem)
    {
        if (key_pem)   mem_buffer_custom_free(key_pem);
        if (chain_pem) mem_buffer_custom_free(chain_pem);
        return false;
    }

    struct tls_key *key = NULL;
    tls_key_import_result_t rc = tls_key_import(&key, key_pem, key_len,
                                                TLS_KEY_FORMAT_PEM, NULL);
    mem_buffer_custom_free(key_pem);
    if (rc != TLS_KEY_IMPORT_OK || !key ||
        key->type != TLS_KEY_TYPE_EC_P256 || !key->ec.priv)
    {
        if (key) tls_key_free(key);
        mem_buffer_custom_free(chain_pem);
        return false;
    }

    size_t n_certs = 0;
    struct tls_x509_object **chain = parse_cert_chain(chain_pem, chain_len, &n_certs);
    mem_buffer_custom_free(chain_pem);
    if (!chain)
    {
        tls_key_free(key);
        return false;
    }
    /* Fail configuration immediately if CertificateVerify would use a key
     * other than the leaf certificate's P-256 public key. */
    if (n_certs == 0 || chain[0]->pubkey.type != TLS_KEY_TYPE_EC_P256 ||
        chain[0]->pubkey.ec.len != 65 || !chain[0]->pubkey.ec.pub ||
        key->ec.len != 65 || !key->ec.pub ||
        memcmp(chain[0]->pubkey.ec.pub, key->ec.pub, 65) != 0)
    {
        for (size_t i = 0; i < n_certs; i++) tls_x509_object_free(chain[i]);
        mem_free(chain);
        tls_key_free(key);
        return false;
    }

    INFO("tls-cert: identity loaded");
    *chain_out = chain;
    *chain_len_out = n_certs;
    *key_out = key;
    return true;
}

struct altcp_tls_ce_config *altcp_tls_ce_create_config_cert_server(
    const char *privkey_appvar,
    const char *chain_appvar)
{
    struct tls_x509_object **chain;
    size_t n_certs;
    struct tls_key *key;
    if (!load_cert_identity(privkey_appvar, chain_appvar,
                            &chain, &n_certs, &key))
        return NULL;

    struct altcp_tls_ce_config *conf =
        (struct altcp_tls_ce_config *)mem_malloc(sizeof(*conf));
    if (!conf)
    {
        for (size_t i = 0; i < n_certs; i++) tls_x509_object_free(chain[i]);
        mem_free(chain);
        tls_key_free(key);
        return NULL;
    }
    mem_stats_tls_direct_add(sizeof(*conf), sizeof(*conf));
    memset(conf, 0, sizeof(*conf));
    conf->is_server        = 1;
    conf->psk_mode         = 0;
    conf->server_chain     = chain;
    conf->server_chain_len = n_certs;
    conf->server_key       = key;
    return conf;
}

struct altcp_tls_ce_config *altcp_tls_ce_create_config_cert_client(
    const char *hostname,
    const char *privkey_appvar,
    const char *chain_appvar)
{
    struct altcp_tls_ce_config *conf =
        altcp_tls_ce_create_config_client_ecdhe(hostname);
    if (!conf)
        return NULL;

    /* An explicitly configured client identity requests a full handshake.
     * Do not let a cached ticket from an earlier non-mTLS connection bypass
     * CertificateRequest and identity selection. */
    conf->psk_mode = 0;
    tls_secure_memzero(conf->psk, sizeof(conf->psk));
    tls_secure_memzero(&conf->psk_identity, sizeof(conf->psk_identity));

    if (!load_cert_identity(privkey_appvar, chain_appvar,
                            &conf->client_chain, &conf->client_chain_len,
                            &conf->client_key))
    {
        altcp_tls_ce_free_config(conf);
        return NULL;
    }
    return conf;
}

void altcp_tls_ce_free_config(struct altcp_tls_ce_config *conf)
{
    if (conf)
    {
        if (conf->alpn_protocols)
        {
            mem_stats_tls_direct_release(conf->alpn_protocols_len,
                                         conf->alpn_protocols_len);
            mem_free(conf->alpn_protocols);
        }
        if (conf->server_chain)
        {
            for (size_t i = 0; i < conf->server_chain_len; i++)
                tls_x509_object_free(conf->server_chain[i]);
            mem_free(conf->server_chain);
        }
        if (conf->server_key)
            tls_key_free(conf->server_key);
        if (conf->client_chain)
        {
            for (size_t i = 0; i < conf->client_chain_len; i++)
                tls_x509_object_free(conf->client_chain[i]);
            mem_free(conf->client_chain);
        }
        if (conf->client_key)
            tls_key_free(conf->client_key);
        tls_secure_memzero(conf->psk, sizeof conf->psk);
        size_t size = sizeof(*conf);
        if (conf->hostname == (const char *)(conf + 1))
            size += strlen(conf->hostname) + 1;
        mem_stats_tls_direct_release(size, size);
        mem_free(conf);
    }
}

/* ========== Lower Connection Callbacks ========== */

/**
 * @brief Accept callback from lower connection (TCP)
 * Allocates TLS state and calls upper accept callback
 */
static err_t
altcp_tls_ce_lower_accept(void *arg, struct altcp_pcb *accepted_conn, err_t err)
{
    struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
    if (listen_conn && listen_conn->state && listen_conn->accept)
    {
        err_t setup_err;
        altcp_tls_ce_state_t *listen_state = (altcp_tls_ce_state_t *)listen_conn->state;

        /* Create new altcp_pcb for accepted connection */
        struct altcp_pcb *new_conn = altcp_alloc();
        if (new_conn == NULL)
        {
            ERROR_CODE(-ERR_MEM);
            return ERR_MEM;
        }

        setup_err = altcp_tls_ce_setup(listen_state->conf, new_conn, accepted_conn);
        if (setup_err != ERR_OK)
        {
            altcp_free(new_conn);
            return setup_err;
        }

        LWIP_TRACE_RETURN(listen_conn->accept(listen_conn->arg, new_conn, err));
    }
    ERROR_CODE(-ERR_ARG);
    return ERR_ARG;
}

/**
 * @brief Connected callback from lower connection (TCP)
 * Initiates TLS handshake for client connections
 */
static err_t
altcp_tls_ce_lower_connected(void *arg, struct altcp_pcb *inner_conn, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    LWIP_UNUSED_ARG(inner_conn);

    if (conn && conn->state)
    {
        altcp_tls_ce_state_t *state;
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        /* Upper connected callback called after handshake completes */
        if (err != ERR_OK)
        {
            ERROR_CODE(-err);
            if (conn->connected)
            {
                LWIP_TRACE_RETURN(conn->connected(conn->arg, conn, err));
            }
        }

        state = (altcp_tls_ce_state_t *)conn->state;
        state->overhead_bytes_adjust = 0;
        tls_dbg_status("lower: connected");

        /* Do NOT write the ClientHello directly from this connected callback.
         * The lower TCP pcb can be in a transient state here where altcp_write
         * returns ERR_MEM (send buffer not yet ready) — treating that as fatal
         * aborted the handshake intermittently right after connect. Instead
         * drive the handshake through lower_recv_process, which sends (and, on
         * ERR_MEM, retries) the ClientHello as a normal, non-fatal state step.
         * This keeps handshake sequencing entirely inside altcp_tls_ce. */
        LWIP_TRACE_RETURN(altcp_tls_ce_lower_recv_process(conn, state));
    }
    ERROR_CODE(-ERR_VAL);
    return ERR_VAL;
}

/* Call recved for possibly more than u16_t */
static void
altcp_tls_ce_lower_recved(struct altcp_pcb *inner_conn, int recvd_cnt)
{
    while (recvd_cnt > 0)
    {
        u16_t recvd_part = (u16_t)LWIP_MIN(recvd_cnt, 0xFFFF);
        altcp_recved(inner_conn, recvd_part);
        recvd_cnt -= recvd_part;
    }
}

/**
 * @brief Receive callback from lower connection (TCP)
 * Processes incoming TLS records (handshake or application data)
 */
static err_t
altcp_tls_ce_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err)
{
    altcp_tls_ce_state_t *state;
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;

    LWIP_ASSERT("no err expected", err == ERR_OK);
    LWIP_UNUSED_ARG(err);

    if (!conn)
    {
        ERROR_CODE(-ERR_CLSD);
        if (p != NULL)
        {
            pbuf_free(p);
        }
        /* Our wrapper is gone (or never wired); fall back to abort if
         * the orderly close can't go out. Returning ERR_CLSD without a
         * working close path would leave the pcb dangling. */
        if (altcp_close(inner_conn) != ERR_OK)
        {
            ALTCP_TLS_CE_ERROR_ABORT(inner_conn);
        }
        return ERR_CLSD;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

    if (!state)
    {
        ERROR_CODE(-ERR_CLSD);
        if (p != NULL)
        {
            pbuf_free(p);
        }
        if (altcp_close(inner_conn) != ERR_OK)
        {
            ALTCP_TLS_CE_ERROR_ABORT(inner_conn);
        }
        return ERR_CLSD;
    }

    /* Handle NULL pbuf (connection closed) */
    if (p == NULL)
    {
        if ((state->flags & (ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE | ALTCP_TLS_CE_FLAGS_UPPER_CALLED)) ==
            (ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE | ALTCP_TLS_CE_FLAGS_UPPER_CALLED))
        {

            if ((state->rx != NULL) || (state->rx_app != NULL))
            {
                state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED;
                altcp_tls_ce_handle_rx_appldata(conn, state);
                return ERR_OK;
            }

            state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSED;
            if (conn->recv)
            {
                return conn->recv(conn->arg, conn, NULL, ERR_OK);
            }
        }
        else
        {
            tls_dbg_status("lower: closed hs");
            ERROR_CODE(state->tls_ctx.state);
            /* Peer closed mid-handshake (or pre-upper-recv-attach).
             * The app saw ERR_ABRT; tear the wrapper down. Fall back to
             * abort if orderly close can't be enqueued, so we never
             * leak the wrapper pcb. */
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            if (altcp_close(conn) != ERR_OK)
            {
                ALTCP_TLS_CE_ERROR_ABORT(conn);
            }
        }
        return ERR_OK;
    }

    /* Single ingress path: copy encrypted TCP pbufs into non-pool RAM, then
     * release the ingress pbuf immediately. The record processor downstream
     * still walks state->rx as a pbuf chain, but the network pbuf pool is
     * available again for future RX bursts. */
    altcp_tls_ce_queue_rx(state, p);

    /* p is ours now (copied into state->rx and freed). Anything but ERR_ABRT
     * would tell TCP the segment was refused, so it would keep the freed pbuf
     * as refused_data and free it a second time. Data the application could
     * not take yet stays queued here and is retried on recved/poll. */
    if (altcp_tls_ce_lower_recv_process(conn, state) == ERR_ABRT)
    {
        /* ERROR_AUDIT: propagates an abort already logged by recv_process. */
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* Collects work handed to the Wi-Fi bridge. ERR_INPROGRESS while it is still
 * out: the state is flagged, and altcp_tls_ce_offload_ready() resumes it. */
static err_t
altcp_tls_ce_settle(altcp_tls_ce_state_t *state)
{
    int settled = tls_offload_settle(&state->tls_ctx);

    if (settled > 0)
    {
        return ERR_OK;
    }
    if (settled == 0)
    {
        state->flags |= ALTCP_TLS_CE_FLAGS_OFFLOAD_WAIT;
        return ERR_INPROGRESS;
    }
    return ERR_VAL;
}

void
altcp_tls_ce_offload_ready(void)
{
    altcp_tls_ce_state_t *state;

    for (state = g_tls_state_head; state != NULL; state = state->next)
    {
        if (state->flags & ALTCP_TLS_CE_FLAGS_OFFLOAD_WAIT)
        {
            state->flags = (u16_t)((state->flags & ~ALTCP_TLS_CE_FLAGS_OFFLOAD_WAIT) |
                                  ALTCP_TLS_CE_FLAGS_OFFLOAD_KICK);
        }
    }
    /* Resuming can abort a connection and unlink its state, so rescan from
     * the head after each one. A handshake still waiting sets WAIT again, not
     * KICK, so this ends. */
    state = g_tls_state_head;
    while (state != NULL)
    {
        if (!(state->flags & ALTCP_TLS_CE_FLAGS_OFFLOAD_KICK))
        {
            state = state->next;
            continue;
        }
        state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_OFFLOAD_KICK;
        if (state->conn != NULL && state->conn->state == state)
        {
            (void)altcp_tls_ce_lower_recv_process(state->conn, state);
        }
        state = g_tls_state_head;
    }
}

/* Generates our key shares and client random. Done before the TCP connect
 * when the RNG is ready: on the calculator alone this takes seconds, and some
 * servers reset a connection that stays silent that long. */
static void altcp_tls_ce_apply_handshake_config(altcp_tls_ce_state_t *state)
{
    struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;

    state->tls_ctx.hostname = config->hostname;
    state->tls_ctx.alpn_protocols = config->alpn_protocols;
    state->tls_ctx.alpn_protocols_len = config->alpn_protocols_len;
    state->tls_ctx.client_chain = config->client_chain;
    state->tls_ctx.client_chain_len = config->client_chain_len;
    state->tls_ctx.client_key = config->client_key;
    if (config->psk_mode)
    {
        state->tls_ctx.psk_type = config->psk_type;
    }
    tls_set_transport(&state->tls_ctx, altcp_tls_ce_transport_write, state);
}

static bool altcp_tls_ce_init_handshake(altcp_tls_ce_state_t *state)
{
    struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;
    bool init_ok;

    if (config->psk_mode)
    {
        init_ok = tls_handshake_init(&state->tls_ctx, config->psk, &config->psk_identity);
    }
    else
    {
        init_ok = tls_handshake_init(&state->tls_ctx, NULL, NULL);
    }
    if (!init_ok)
        return false;
    altcp_tls_ce_apply_handshake_config(state);
    state->flags |= ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED;
    return true;
}

static bool altcp_tls_ce_begin_keyshares(altcp_tls_ce_state_t *state)
{
    struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;
    bool init_ok;

    if (config->psk_mode)
    {
        init_ok = tls_handshake_keyshares_begin(&state->tls_ctx, config->psk,
                                                &config->psk_identity);
    }
    else
    {
        init_ok = tls_handshake_keyshares_begin(&state->tls_ctx, NULL, NULL);
    }
    if (!init_ok)
    {
        return false;
    }
    altcp_tls_ce_apply_handshake_config(state);
    return true;
}

/*
 * Send the ClientHello if the client handshake hasn't started yet. Driven from
 * lower_recv_process (which runs on the connected callback, every recv, and the
 * poll tick), so a transient ERR_MEM is simply retried on the next tick rather
 * than aborting the connection.
 *
 * Returns:
 *   ERR_OK   — ClientHello already sent, or just sent successfully.
 *   ERR_MEM  — lower send buffer not ready; caller should leave the handshake
 *              pending and retry on the next tick (NOT fatal).
 *   ERR_ABRT — fatal (generation failed, or a non-MEM write error); caller
 *              has already aborted the connection.
 */
static err_t
altcp_tls_ce_send_client_hello(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    err_t write_err;

    if (state->tls_ctx.state >= TLS_STATE_CLIENT_HELLO_SENT &&
        state->tls_ctx.state != TLS_STATE_HRR_RECEIVED)
    {
        return ERR_OK; /* already sent (and not retrying after HRR) */
    }

    /* ClientHello2 cannot be serialized until the HRR-selected P-256 share is
     * ready. Generation runs from the dispatcher so receive processing can
     * release the HRR record and retry the send afterward. */
    if (state->tls_ctx.state == TLS_STATE_HRR_RECEIVED &&
        state->tls_ctx.hrr_requested_group == TLS_NAMED_GROUP_SECP256R1 &&
        !(state->tls_ctx.keyshare_ready & TLS_KEYSHARE_P256_READY))
    {
        state->flags |= ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
        altcp_tls_ce_keyshare_arm();
        return ERR_MEM;
    }

    /* Deferred key generation: setup could not run tls_handshake_init because
     * the async DRBG was not seeded yet. Attempt it now; if the RNG is still
     * not ready (tls_random_bytes_ex returns NULL immediately rather than
     * spinning), return ERR_MEM so the caller retries next tick. */
    if (!(state->flags & ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED))
    {
        struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;

        /* Outbound clients cannot reach this point before staged generation
         * completes and opens TCP. Keep the server's deferred-RNG retry for an
         * already accepted socket. */
        if (!config->is_server)
        {
            altcp_tls_ce_keyshare_arm();
            return ERR_MEM;
        }
        tls_dbg_status("clienthello: deferred hs init");
        if (!altcp_tls_ce_init_handshake(state))
        {
            tls_dbg_status("clienthello: hs init not ready, retry");
            return ERR_MEM; /* retry next tick */
        }
    }

    /* Generate the ClientHello exactly once per attempt. tls_send_client_hello
     * folds it into the transcript hash as a side effect, so it must never be
     * called twice for the same attempt — we cache the built record and only
     * retry the write below on ERR_MEM. */
    if (state->pending_chello == NULL)
    {
        size_t client_hello_len = 0;
        size_t record_len;
        int prebuild_state = state->tls_ctx.state;
        err_t settle_err = altcp_tls_ce_settle(state);

        /* Our key share may still be on the bridge. */
        if (settle_err == ERR_INPROGRESS)
        {
            return ERR_MEM;
        }
        if (settle_err != ERR_OK)
        {
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }

        /* Query the exact serialized size first. Optional ALPN, SNI, PSK, and
         * HRR cookie data are variable-length; a fixed local buffer can reject
         * an otherwise valid ClientHello2 merely because the server supplied a
         * longer cookie. This sender emits one plaintext record, so retain the
         * TLS record-size bound explicitly. */
        if (!tls_send_client_hello(&state->tls_ctx, NULL, 0,
                                   &client_hello_len) ||
            client_hello_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT ||
            client_hello_len > UINT16_MAX - 5u)
        {
            tls_dbg_status("clienthello: size fail");
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }
        record_len = 5u + client_hello_len;
        state->pending_chello = (uint8_t *)mem_malloc(record_len);
        if (state->pending_chello == NULL)
        {
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }
        state->pending_chello_len = (uint16_t)record_len;
        mem_stats_tls_direct_add(record_len, record_len);

        tls_dbg_status("clienthello: gen");
        /* On the PSK path, tls_send_client_hello holds early_secret/
         * binder_key/finished_key/binder/hmac_ctx on its own stack
         * frame; wrapping the call lets tls_crypto_guard_disable()
         * scrub that whole frame once it's returned and SP is back
         * above it. Harmless no-op overhead on the non-PSK path. */
        tls_crypto_guard_enable();
        bool chello_ok = tls_send_client_hello(&state->tls_ctx,
                                               state->pending_chello + 5,
                                               record_len - 5,
                                               &client_hello_len);
        tls_crypto_guard_disable();
        if (!chello_ok)
        {
            tls_dbg_status("clienthello: gen fail");
            mem_stats_tls_direct_release(record_len, record_len);
            mem_free(state->pending_chello);
            state->pending_chello = NULL;
            state->pending_chello_len = 0;
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }
        /* Serialization updates the transcript and historically advanced the
         * protocol state. The flight is not sent until altcp_write succeeds,
         * so retain the pre-write state while the cached bytes are pending. */
        state->tls_ctx.state = prebuild_state;

        /* TLS record header. RFC 8446 section 5.1 permits 0x0301 only on an
         * initial ClientHello; ClientHello2 after HRR uses 0x0303. */
        state->pending_chello[0] = TLS_CONTENT_TYPE_HANDSHAKE;
        state->pending_chello[1] = 0x03;
        state->pending_chello[2] =
            (prebuild_state == TLS_STATE_HRR_RECEIVED) ? 0x03 : 0x01;
        state->pending_chello[3] = (uint8_t)(client_hello_len >> 8);
        state->pending_chello[4] = (uint8_t)(client_hello_len & 0xFF);
    }

    tls_dbg_status("clienthello: write");
    write_err = altcp_write(conn->inner_conn, state->pending_chello,
                            state->pending_chello_len, TCP_WRITE_FLAG_COPY);
    if (write_err == ERR_MEM)
    {
        /* Lower send buffer not ready yet (common right at connect). Keep the
         * cached record and retry on the next recv/poll tick — non-fatal. */
        return ERR_MEM;
    }
    if (write_err != ERR_OK)
    {
        tls_dbg_status("clienthello: write fail");
        if (conn->err)
        {
            conn->err(conn->arg, write_err);
        }
        ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -write_err);
        return ERR_ABRT;
    }

    altcp_output(conn->inner_conn);
    {
        struct altcp_tls_ce_config *sent_cfg = (struct altcp_tls_ce_config *)state->conf;
        if (sent_cfg && sent_cfg->psk_mode && sent_cfg->hostname)
        {
            /* The ticket is on the wire now; it is single use. */
            tls_psk_cache_discard(sent_cfg->hostname);
        }
    }
    mem_stats_tls_direct_release(state->pending_chello_len, state->pending_chello_len);
    mem_free(state->pending_chello);
    state->pending_chello = NULL;
    state->pending_chello_len = 0;
    state->tls_ctx.state = TLS_STATE_CLIENT_HELLO_SENT;
    tls_dbg_status("clienthello: sent");
    return ERR_OK;
}

#define ALTCP_TLS_CE_CERT_JOB_TICK_MS 20u

/* Runs one queued certificate verification for the first connection that has
 * any, then lets that connection continue (replayed handshake bytes, queued
 * records, completing the handshake). One job per tick keeps each blocking
 * stretch to a single signature check. */
static void altcp_tls_ce_cert_job_dispatch(void)
{
    for (altcp_tls_ce_state_t *state = g_tls_state_head; state != NULL; state = state->next)
    {
        struct altcp_pcb *conn = state->conn;

        if (!conn || !tls_cert_jobs_pending(&state->tls_ctx))
        {
            continue;
        }
        if (!tls_cert_jobs_step(&state->tls_ctx))
        {
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return; /* state may be freed */
        }
        (void)altcp_tls_ce_lower_recv_process(conn, state);
        return; /* state may be freed; resume from the list head next tick */
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_CERT_JOB, 0);
}

static void altcp_tls_ce_cert_job_arm(void)
{
    static bool attached;

    if (!attached)
    {
        lwip_dispatch_attach(LWIP_DISPATCH_TLS_CERT_JOB, altcp_tls_ce_cert_job_dispatch);
        attached = true;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_CERT_JOB,
                             lwip_dispatch_period_from_ms(ALTCP_TLS_CE_CERT_JOB_TICK_MS));
    lwip_dispatch_start();
}

#define ALTCP_TLS_CE_KEYSHARE_TICK_MS 10u

static err_t altcp_tls_ce_start_lower_connect(altcp_tls_ce_state_t *state)
{
    struct altcp_pcb *conn = state->conn;

    if (!conn || !conn->inner_conn)
    {
        return ERR_VAL;
    }
    state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_CONNECT_PENDING;

    /* Drive a temporarily blocked ClientHello write even if no receive event
     * arrives after TCP connection establishment. */
    altcp_poll(conn->inner_conn, altcp_tls_ce_lower_poll, 1);
    return altcp_connect(conn->inner_conn, &state->pending_connect_addr,
                         state->pending_connect_port,
                         altcp_tls_ce_lower_connected);
}

/* Gate TCP on X25519 only. Once it is ready, bridge-backed P-256 generation
 * may continue speculatively while TCP and ClientHello1 proceed. The blocking
 * software fallback is used only after an HRR actually requests P-256. */
static void altcp_tls_ce_keyshare_dispatch(void)
{
    altcp_tls_ce_state_t *state;

    for (state = g_tls_state_head; state != NULL; state = state->next)
    {
        int result;

        if (!(state->flags & ALTCP_TLS_CE_FLAGS_GENERATING_SHARES))
        {
            continue;
        }
        if (state->tls_ctx.keyshare_state == TLS_KEYSHARE_STATE_IDLE &&
            !altcp_tls_ce_begin_keyshares(state))
        {
            return; /* asynchronous RNG is not ready; try on the next tick */
        }

        if (!(state->flags & ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED))
        {
            result = tls_handshake_keyshares_step(&state->tls_ctx);
            if (result < 0)
            {
                bool connect_pending =
                    (state->flags & ALTCP_TLS_CE_FLAGS_CONNECT_PENDING) != 0;
                struct altcp_pcb *conn = state->conn;

                state->flags &= (u16_t)~(ALTCP_TLS_CE_FLAGS_GENERATING_SHARES |
                                        ALTCP_TLS_CE_FLAGS_CONNECT_PENDING);
                if (connect_pending && conn && conn->connected)
                {
                    (void)conn->connected(conn->arg, conn, ERR_ABRT);
                }
                return;
            }
            if (result == 0 ||
                !(state->tls_ctx.keyshare_ready & TLS_KEYSHARE_X25519_READY))
            {
                return;
            }

            state->flags |= ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED;
            if (state->flags & ALTCP_TLS_CE_FLAGS_CONNECT_PENDING)
            {
                struct altcp_pcb *conn = state->conn;
                err_t err = altcp_tls_ce_start_lower_connect(state);
                if (err != ERR_OK && conn && conn->connected)
                {
                    (void)conn->connected(conn->arg, conn, err);
                    return;
                }
            }
        }

        if (state->tls_ctx.state == TLS_STATE_HRR_RECEIVED &&
            state->tls_ctx.hrr_requested_group == TLS_NAMED_GROUP_SECP256R1)
        {
            result = tls_handshake_p256_step(&state->tls_ctx, true);
            if (result < 0)
            {
                struct altcp_pcb *conn = state->conn;
                state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
                if (conn && conn->err)
                {
                    conn->err(conn->arg, ERR_ABRT);
                }
                if (conn)
                {
                    ALTCP_TLS_CE_ERROR_ABORT(conn);
                }
                return;
            }
            if (result == 0)
            {
                return;
            }
            state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
            (void)altcp_tls_ce_send_client_hello(state->conn, state);
            return; /* callbacks may have freed state */
        }

        /* Once a real ServerHello arrives, its selected-group path either
         * consumed or canceled every public-share job. Never restart one. */
        if (state->tls_ctx.state >= TLS_STATE_SERVER_HELLO_RECEIVED)
        {
            state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
            return;
        }

        if (!(lwip_crypto_caps() & CTL_CAP_P256) ||
            (state->tls_ctx.keyshare_ready & TLS_KEYSHARE_P256_READY))
        {
            state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
            return;
        }

        /* Speculation is offload-only. Failure merely abandons the unused
         * optimization; an HRR can still trigger the software fallback. */
        result = tls_handshake_p256_step(&state->tls_ctx, false);
        if (result != 0)
        {
            state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
        }
        return;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_KEYSHARE, 0);
}

static void altcp_tls_ce_keyshare_arm(void)
{
    static bool attached;

    if (!attached)
    {
        lwip_dispatch_attach(LWIP_DISPATCH_TLS_KEYSHARE,
                             altcp_tls_ce_keyshare_dispatch);
        attached = true;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_KEYSHARE,
                             lwip_dispatch_period_from_ms(ALTCP_TLS_CE_KEYSHARE_TICK_MS));
    lwip_dispatch_start();
}

/* ========== Server role ========== */

/* The record layer encrypts with the client_* keys and decrypts with the
 * server_* keys. A server swaps the two sets after each derivation so the same
 * record code protects its traffic in the right direction. */
static void altcp_tls_ce_swap_keys(uint8_t *a_key, uint8_t *a_iv, uint8_t *b_key, uint8_t *b_iv)
{
    uint8_t tmp[16];
    memcpy(tmp, a_key, 16);
    memcpy(a_key, b_key, 16);
    memcpy(b_key, tmp, 16);
    memcpy(tmp, a_iv, 12);
    memcpy(a_iv, b_iv, 12);
    memcpy(b_iv, tmp, 12);
    tls_secure_memzero(tmp, sizeof(tmp));
}

/* ClientHello -> ServerHello, then the encrypted server flight: one record per
 * handshake message (EncryptedExtensions, Certificate, CertificateVerify,
 * Finished), each built into its own record buffer and encrypted in place. */
static bool altcp_tls_ce_server_hello(struct altcp_pcb *conn, altcp_tls_ce_state_t *state,
                                      const uint8_t *client_hello, size_t len)
{
    struct tls_handshake_context *ctx = &state->tls_ctx;
    struct altcp_tls_ce_config *conf = (struct altcp_tls_ce_config *)state->conf;
    struct tls_traffic_keys *k = &ctx->keys;
    uint8_t hello[5 + 128];
    size_t hello_len = 0, record_len = 0;
    bool ok;

    /* Wire cert chain into handshake context when configured. */
    if (conf && conf->server_chain && conf->server_chain_len > 0 && conf->server_key)
        tls_server_set_cert(ctx, conf->server_chain, conf->server_chain_len, conf->server_key);

    tls_crypto_guard_enable();
    ok = tls_server_recv_client_hello(ctx, client_hello, len, hello + 5, sizeof(hello) - 5, &hello_len);
    tls_crypto_guard_disable();
    if (!ok)
    {
        return false;
    }
    hello[0] = TLS_CONTENT_TYPE_HANDSHAKE;
    hello[1] = 0x03;
    hello[2] = 0x03;
    hello[3] = (uint8_t)(hello_len >> 8);
    hello[4] = (uint8_t)hello_len;
    if (altcp_write(conn->inner_conn, hello, (u16_t)(5 + hello_len), TCP_WRITE_FLAG_COPY) != ERR_OK)
    {
        return false;
    }

    /* HelloRetryRequest is a complete plaintext flight. Wait for the second
     * ClientHello before deriving handshake keys or sending encrypted data. */
    if (ctx->state == TLS_STATE_HRR_RECEIVED)
    {
        altcp_output(conn->inner_conn);
        return true;
    }

    tls_crypto_guard_enable();
    ok = tls_derive_handshake_keys(ctx);
    tls_crypto_guard_disable();
    if (!ok)
    {
        return false;
    }
    altcp_tls_ce_swap_keys(k->client_handshake_key, k->client_handshake_iv,
                           k->server_handshake_key, k->server_handshake_iv);

    /* Emit the flight one message per record: EncryptedExtensions, Certificate,
     * CertificateVerify, Finished. Each message is built straight into its
     * record's plaintext area (5-byte header reserved in front) and encrypted in
     * place, so only one record-sized buffer is ever live and the certificate
     * DER is copied exactly once. A message larger than one record is split
     * across records; the peer reassembles it from the handshake body length
     * (RFC 8446 section 5.1), and record framing never reaches the transcript. */
    {
        bool cert_mode = conf && conf->server_chain && conf->server_chain_len > 0;
        size_t cert_cap = 0;
        if (cert_mode)
        {
            cert_cap = 8u;
            for (size_t i = 0; i < conf->server_chain_len; i++)
            {
                size_t der_len = conf->server_chain[i]->der_len;
                if (cert_cap > UINT16_MAX || der_len > UINT16_MAX - cert_cap - 5u)
                    return false;
                cert_cap += der_len + 5u;
            }
        }
        INFO("tls-srv: flight begin");
        for (int step = TLS_SERVER_FLIGHT_ENCRYPTED_EXTENSIONS;
             ok && step <= TLS_SERVER_FLIGHT_FINISHED; step++)
        {
            switch (step)
            {
            case TLS_SERVER_FLIGHT_ENCRYPTED_EXTENSIONS: INFO("tls-srv: ee"); break;
            case TLS_SERVER_FLIGHT_CERTIFICATE: INFO("tls-srv: certificate"); break;
            case TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY: INFO("tls-srv: certverify"); break;
            default: INFO("tls-srv: finished"); break;
            }
            if ((step == TLS_SERVER_FLIGHT_CERTIFICATE ||
                 step == TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY) && !cert_mode)
                continue;

            size_t msg_cap;
            switch (step)
            {
            case TLS_SERVER_FLIGHT_ENCRYPTED_EXTENSIONS:
                msg_cap = 6u + (ctx->negotiated_alpn
                                ? 6u + ctx->negotiated_alpn_len : 0u);
                break;
            case TLS_SERVER_FLIGHT_CERTIFICATE:
                msg_cap = cert_cap;
                break;
            case TLS_SERVER_FLIGHT_CERTIFICATE_VERIFY:
                msg_cap = 4u + 2u + 2u + 72u;
                break;
            default:
                msg_cap = 4u + 32u;
                break;
            }
            /* The buffer holds this one message; a message bigger than a record
             * is fragmented from it in place rather than refused. */
            size_t record_cap = 5u + msg_cap + 1u + TLS_AES_AUTH_TAG_SIZE;
            uint8_t *record = (uint8_t *)mem_malloc(record_cap);
            if (!record)
            {
                ok = false;
                break;
            }

            size_t msg_len = 0;
            tls_crypto_guard_enable();
            ok = tls_server_send_flight(ctx, record + 5, msg_cap, &msg_len);
            tls_crypto_guard_disable();

            for (size_t sent = 0; ok && sent < msg_len;)
            {
                size_t chunk = msg_len - sent;
                if (chunk > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT - 1u)
                    chunk = ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT - 1u;

                /* Encrypting from record + 5 into record is an in-place
                 * transform of the first fragment; later fragments come from
                 * further into the same buffer. */
                size_t frag_cap = 5u + chunk + 1u + TLS_AES_AUTH_TAG_SIZE;
                if (!altcp_tls_ce_encrypt_record_stream(ctx, true,
                                                        TLS_CONTENT_TYPE_HANDSHAKE,
                                                        record + 5 + sent, chunk,
                                                        record, frag_cap,
                                                        &record_len) ||
                    altcp_write(conn->inner_conn, record, (u16_t)record_len,
                                TCP_WRITE_FLAG_COPY) != ERR_OK)
                {
                    ok = false;
                    break;
                }
                ctx->client_hs_seq_num++;
                sent += chunk;
            }
            mem_free(record);
        }
    }

    if (!ok)
    {
        INFO("tls-srv: flight failed");
        return false;
    }
    INFO("tls-srv: flight sent");
    altcp_output(conn->inner_conn);

    /* Application keys come from the transcript through the server Finished. */
    tls_crypto_guard_enable();
    ok = tls_derive_application_keys(ctx);
    tls_crypto_guard_disable();
    if (!ok)
    {
        return false;
    }
    altcp_tls_ce_swap_keys(k->client_application_key, k->client_application_iv,
                           k->server_application_key, k->server_application_iv);
    return true;
}

static err_t altcp_tls_ce_server_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    struct tls_handshake_context *ctx = &state->tls_ctx;

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED) && !altcp_tls_ce_init_handshake(state))
    {
        return ERR_OK; /* RNG not ready yet; retried on the next segment or poll */
    }

    while (state->rx != NULL && state->rx->tot_len >= 5 &&
           !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        uint8_t header[5];
        size_t rec_len, total_len;

        pbuf_copy_partial(state->rx, header, sizeof(header), 0);
        rec_len = ((size_t)header[3] << 8) | header[4];
        total_len = 5 + rec_len;
        if (rec_len == 0 || rec_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 256u)
        {
            (void)tls_send_fatal_alert(ctx, TLS_ALERT_RECORD_OVERFLOW);
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }
        if ((size_t)state->rx->tot_len < total_len)
        {
            break;
        }

        if (header[0] == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        {
            /* Middlebox-compatibility CCS (RFC 8446 D.4): ignored. */
            altcp_tls_ce_consume_recved(state, total_len);
            continue;
        }

        if ((ctx->state == TLS_STATE_INIT || ctx->state == TLS_STATE_HRR_RECEIVED) &&
            header[0] == TLS_CONTENT_TYPE_HANDSHAKE)
        {
            uint8_t *hello = (uint8_t *)mem_malloc(rec_len);
            bool ok;
            if (hello == NULL)
            {
                return ERR_OK; /* retry once memory frees up */
            }
            pbuf_copy_partial(state->rx, hello, (u16_t)rec_len, 5);
            altcp_tls_ce_consume_recved(state, total_len);
            ok = altcp_tls_ce_server_hello(conn, state, hello, rec_len);
            mem_free(hello);
            if (!ok)
            {
                ALTCP_TLS_CE_ERROR_ABORT(conn);
                return ERR_ABRT;
            }
            continue;
        }

        if (ctx->state == TLS_STATE_SERVER_FINISHED_RECEIVED &&
            header[0] == TLS_CONTENT_TYPE_APPLICATION_DATA)
        {
            struct pbuf *plain = NULL;
            size_t plain_len = 0;
            uint8_t inner_type = 0, finished[36];
            err_t err = altcp_tls_ce_decrypt_record_stream(state, conn, true, total_len,
                                                          &plain, &plain_len, &inner_type);
            bool ok;
            if (err == ERR_MEM)
            {
                return ERR_OK;
            }
            if (err != ERR_OK)
            {
                ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -err);
                return ERR_ABRT;
            }
            ok = inner_type == TLS_CONTENT_TYPE_HANDSHAKE && plain_len == sizeof(finished) &&
                 pbuf_copy_partial(plain, finished, sizeof(finished), 0) == sizeof(finished);
            pbuf_free(plain);
            if (ok)
            {
                tls_crypto_guard_enable();
                ok = tls_server_recv_finished(ctx, finished, sizeof(finished));
                tls_crypto_guard_disable();
            }
            if (!ok)
            {
                (void)tls_send_fatal_alert(ctx, TLS_ALERT_DECRYPT_ERROR);
                ALTCP_TLS_CE_ERROR_ABORT(conn);
                return ERR_ABRT;
            }
            state->flags |= ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE | ALTCP_TLS_CE_FLAGS_UPPER_CALLED;
            ctx->tx_epoch = 2;
            STATE_CHG(conn, LWIP_STATE_TLS_HANDSHAKE_DONE);
            break;
        }

        (void)tls_send_fatal_alert(ctx, TLS_ALERT_UNEXPECTED_MESSAGE);
        ALTCP_TLS_CE_ERROR_ABORT(conn);
        return ERR_ABRT;
    }

    if ((state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE) && state->rx != NULL)
    {
        return altcp_tls_ce_handle_rx_appldata(conn, state);
    }
    return ERR_OK;
}

/**
 * @brief Process received data (handshake or application data)
 */
static err_t
altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        tls_dbg_status("rx: handshake path");
        /* Handle handshake phase */
        struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;

        if (config->is_server)
        {
            return altcp_tls_ce_server_process(conn, state);
        }
        else
        {
            /* Kick off (or retry) the ClientHello. This runs from the connected
             * callback, every recv, and the poll tick; an ERR_MEM means the
             * lower send buffer isn't ready yet, so we leave the handshake
             * pending and try again next tick instead of aborting. */
            err_t ch_err = altcp_tls_ce_send_client_hello(conn, state);
            if (ch_err == ERR_ABRT)
            {
                return ERR_ABRT; /* helper already aborted */
            }
            if (ch_err == ERR_MEM)
            {
                return ERR_OK; /* not sent yet; wait for the next tick */
            }

            /* Client: process complete TLS records. Each iteration peeks the
             * 5-byte header, waits for the whole record to arrive, then hands
             * off to the streaming decrypter (encrypted records) or the
             * inline plaintext handler (ServerHello / CCS / early alert). */
            while ((state->rx != NULL && state->rx->tot_len >= 5) ||
                   altcp_tls_ce_finish_ready(state))
            {
                uint8_t header[5];
                if (altcp_tls_ce_finish_ready(state))
                {
                    goto record_processed; /* drive client Finished after a deferred replay */
                }
                if (tls_cert_jobs_pending(&state->tls_ctx))
                {
                    /* The server Finished is still held back, so later records
                     * may already be under application keys. Leave them queued;
                     * the job tick resumes this loop once the queue drains. */
                    break;
                }
                if (pbuf_copy_partial(state->rx, header, sizeof(header), 0) != sizeof(header))
                {
                    ALTCP_TLS_CE_ERROR_ABORT(conn);
                    return ERR_ABRT;
                }

                size_t rec_len = ((size_t)header[3] << 8) | (size_t)header[4];
                size_t total_len = 5 + rec_len;

                size_t record_limit = header[0] == TLS_CONTENT_TYPE_APPLICATION_DATA
                                          ? ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 256u
                                          : ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT;
                if (rec_len > record_limit || total_len > 0xFFFF)
                {
                    (void)tls_send_fatal_alert(&state->tls_ctx,
                                               TLS_ALERT_RECORD_OVERFLOW);
                    ALTCP_TLS_CE_ERROR_ABORT(conn);
                    return ERR_ABRT;
                }
                /* RFC 8446 5.1: legacy_record_version is ignored. */
                if (rec_len == 0)
                {
                    (void)tls_send_fatal_alert(&state->tls_ctx,
                                               TLS_ALERT_UNEXPECTED_MESSAGE);
                    ALTCP_TLS_CE_ERROR_ABORT(conn);
                    return ERR_ABRT;
                }
                if ((size_t)state->rx->tot_len < total_len)
                {
                    /* Record split across TCP segments — wait for the rest.
                     * Large messages (Certificate) commonly land here. */
                    break;
                }

                /* Derive handshake keys exactly once, right after ServerHello,
                 * so we can decrypt the subsequent encrypted handshake records */
                if (state->tls_ctx.state == TLS_STATE_SERVER_HELLO_RECEIVED)
                {
                    /* The shared secret may still be on the bridge; the
                     * record stays queued until it is in. */
                    err_t settle_err = altcp_tls_ce_settle(state);
                    if (settle_err == ERR_INPROGRESS)
                    {
                        return ERR_OK;
                    }
                    if (settle_err != ERR_OK)
                    {
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }
                    /* tls_derive_handshake_keys holds early_secret/
                     * handshake_secret/derived_secret on its own stack
                     * frame; wrapping the call lets tls_crypto_guard_disable()
                     * scrub that whole frame once it's returned and SP is
                     * back above it. */
                    tls_crypto_guard_enable();
                    bool derive_ok = tls_derive_handshake_keys(&state->tls_ctx);
                    tls_crypto_guard_disable();
                    if (!derive_ok)
                    {
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: handshake key derivation failed\n"));
                        (void)tls_send_fatal_alert(&state->tls_ctx, TLS_ALERT_INTERNAL_ERROR);
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }
                }

                if (header[0] == TLS_CONTENT_TYPE_APPLICATION_DATA)
                {
                    bool use_hs_keys = (state->tls_ctx.state >= TLS_STATE_HANDSHAKE_KEYS_DERIVED &&
                                        state->tls_ctx.state < TLS_STATE_HANDSHAKE_COMPLETE);
                    struct pbuf *dec_pbuf = NULL;
                    size_t dec_len = 0;
                    uint8_t inner_type = 0;
                    err_t dec_err;

                    if (!use_hs_keys)
                    {
                        (void)tls_send_fatal_alert(&state->tls_ctx,
                                                   TLS_ALERT_UNEXPECTED_MESSAGE);
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }

                    /* Streaming decrypt: verifies the tag against the full
                     * ciphertext first, then decrypts in 2KB strides while
                     * releasing the corresponding bytes from state->rx. */
                    dec_err = altcp_tls_ce_decrypt_record_stream(state, conn,
                                                                 true, total_len,
                                                                 &dec_pbuf, &dec_len,
                                                                 &inner_type);
                    if (dec_err == ERR_MEM)
                    {
                        /* Scratch alloc deferred — the record stays in
                         * state->rx and we retry on the next recv. A
                         * persistent ERR_MEM here stalls the handshake, so
                         * surface it as a WARN carrying the pending length. */
                        WARN_CODE(total_len > 0xFFFF ? 0xFFFF : total_len);
                        return ERR_OK;
                    }
                    if (dec_err != ERR_OK)
                    {
                        ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -dec_err);
                        return ERR_ABRT;
                    }
                    if (!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type,
                                                          dec_pbuf, dec_len))
                    {
                        pbuf_free(dec_pbuf);
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record processing failed\n"));
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }
                    tls_dbg_status("rx: inner ok");

                    pbuf_free(dec_pbuf);
                    if (tls_cert_jobs_pending(&state->tls_ctx))
                    {
                        altcp_tls_ce_cert_job_arm();
                    }
                    goto record_processed;
                }

                /* Plaintext record path: only ServerHello / CCS / early alert
                 * are legal here in TLS 1.3. Records at this stage are small
                 * (well under 1 KiB), so a single flat copy is fine. */
                {
                    uint8_t *tmp = (uint8_t *)mem_malloc(total_len);
                    if (!tmp)
                    {
                        /* Allocation failed: leave the record queued and
                         * retry on the next tick/recv rather than aborting
                         * on transient memory pressure. */
                        DEBUG();
                        return ERR_OK;
                    }
                    mem_stats_tls_direct_add(total_len, total_len);
                    tls_dbg_status("rx: plaintext rec");
                    if (pbuf_copy_partial(state->rx, tmp, (u16_t)total_len, 0) != total_len)
                    {
                        mem_stats_tls_direct_release(total_len, total_len);
                        mem_free(tmp);
                        tls_dbg_status("rx: copy fail");
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }

                    bool plaintext_ok = true;
                    if (header[0] == TLS_CONTENT_TYPE_HANDSHAKE)
                    {
                        const uint8_t *payload = tmp + 5;
                        size_t off = 0;
                        while (off + 4 <= rec_len)
                        {
                            uint8_t msg_type = payload[off];
                            size_t msg_len = ((size_t)payload[off + 1] << 16) |
                                             ((size_t)payload[off + 2] << 8) |
                                             (size_t)payload[off + 3];
                            size_t msg_end = off + 4 + msg_len;
                            if (msg_end > rec_len)
                            {
                                /* ServerHello split across TLS records: not done
                                 * in practice (fits in ~150 bytes), and TLS
                                 * record reassembly already waits for a full
                                 * record before this path runs.  Reject. */
                                (void)tls_send_fatal_alert(&state->tls_ctx,
                                                           TLS_ALERT_DECODE_ERROR);
                                plaintext_ok = false;
                                break;
                            }
                            if (msg_type == TLS_HANDSHAKE_SERVER_HELLO)
                            {
                                tls_dbg_status("serverhello: parse");
                                bool sh_state_ok =
                                    (state->tls_ctx.state == TLS_STATE_CLIENT_HELLO_SENT);
                                if (!sh_state_ok ||
                                    !tls_recv_server_hello(&state->tls_ctx,
                                                           payload + off,
                                                           msg_end - off))
                                {
                                    tls_dbg_status("serverhello: fail");
                                    if (!state->tls_ctx.fatal_alert_sent)
                                    {
                                        (void)tls_send_fatal_alert(&state->tls_ctx,
                                                                   sh_state_ok
                                                                   ? TLS_ALERT_ILLEGAL_PARAMETER
                                                                   : TLS_ALERT_UNEXPECTED_MESSAGE);
                                    }
                                    plaintext_ok = false;
                                    break;
                                }
                                if (state->tls_ctx.state == TLS_STATE_HRR_RECEIVED)
                                {
                                    /* Server sent HelloRetryRequest — send second CH. */
                                    tls_dbg_status("serverhello: hrr, retry ch");
                                    err_t hrr_err = altcp_tls_ce_send_client_hello(conn, state);
                                    if (hrr_err == ERR_ABRT)
                                    {
                                        /* ERROR_AUDIT: send helper emitted before abort. */
                                        return ERR_ABRT;
                                    }
                                    if (hrr_err == ERR_MEM)
                                    {
                                        /* Lower buffer not ready; retry on next tick. */
                                        plaintext_ok = true;
                                    }
                                }
                                else
                                {
                                    tls_dbg_status("serverhello: ok");
                                }
                            }
                            else
                            {
                                /* Any other handshake message must arrive encrypted
                                 * post-ServerHello (RFC 8446 §2). Reject. */
                                (void)tls_send_fatal_alert(&state->tls_ctx,
                                                           TLS_ALERT_UNEXPECTED_MESSAGE);
                                plaintext_ok = false;
                                break;
                            }
                            off = msg_end;
                        }
                        if (plaintext_ok && off != rec_len)
                        {
                            (void)tls_send_fatal_alert(&state->tls_ctx,
                                                       TLS_ALERT_DECODE_ERROR);
                            plaintext_ok = false;
                        }
                    }
                    else if (header[0] == TLS_CONTENT_TYPE_ALERT)
                    {
                        uint8_t alert_desc = (rec_len == 2) ? tmp[6] : 0xFFu;
                        if (alert_desc == TLS_ALERT_USER_CANCELED)
                        {
                            /* This warning is explicitly ignorable, including
                             * before handshake traffic keys are available. */
                            plaintext_ok = true;
                        }
                        else
                        {
                            ERROR_CODE(alert_desc);
                            ERROR_INFO(tls_alert_name(alert_desc));
                            state->tls_ctx.state = TLS_STATE_ERROR;
                            plaintext_ok = false;
                        }
                    }
                    else if (header[0] == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
                    {
                        plaintext_ok = rec_len == 1 && tmp[5] == 0x01 &&
                            state->tls_ctx.state >= TLS_STATE_CLIENT_HELLO_SENT &&
                            state->tls_ctx.state < TLS_STATE_SERVER_FINISHED_RECEIVED;
                        if (!plaintext_ok)
                        {
                            (void)tls_send_fatal_alert(&state->tls_ctx,
                                                       TLS_ALERT_UNEXPECTED_MESSAGE);
                        }
                    }
                    else
                    {
                        (void)tls_send_fatal_alert(&state->tls_ctx,
                                                   TLS_ALERT_UNEXPECTED_MESSAGE);
                        plaintext_ok = false;
                    }

                    mem_stats_tls_direct_release(total_len, total_len);
                    mem_free(tmp);
                    if (!plaintext_ok)
                    {
                        tls_dbg_status("rx: plaintext fail");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record processing failed\n"));
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }
                }

                /* Release the consumed record; consume_recved acks only the
                 * bytes not already pre-acked at queue time. */
                altcp_tls_ce_consume_recved(state, total_len);

            record_processed:
                /* Check if server Finished received — time to send client Finished */
                if (state->tls_ctx.state == TLS_STATE_SERVER_FINISHED_RECEIVED)
                {
                    /* Signature checks handed to the bridge must all pass
                     * before anything is sent or delivered under the new
                     * keys. */
                    err_t settle_err = altcp_tls_ce_settle(state);
                    if (settle_err == ERR_INPROGRESS)
                    {
                        return ERR_OK;
                    }
                    if (settle_err != ERR_OK)
                    {
                        tls_dbg_status("offload: verify fail");
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }

                    /* Derive application keys BEFORE client Finished, because
                     * RFC 8446 Section 7.1 uses transcript through server Finished only.
                     * tls_send_finished() will update the transcript with client Finished. */
                    tls_dbg_status("keys: derive app");
                    /* tls_derive_application_keys holds master_secret/
                     * derived_secret on its own stack frame; wrapping the
                     * call lets tls_crypto_guard_disable() scrub that
                     * whole frame once it's returned and SP is back
                     * above it. */
                    tls_crypto_guard_enable();
                    bool derive_app_ok = tls_derive_application_keys(&state->tls_ctx);
                    tls_crypto_guard_disable();
                    if (!derive_app_ok)
                    {
                        tls_dbg_status("keys: derive app fail");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: application key derivation failed\n"));
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }
                    tls_dbg_status("keys: derive app ok");

                    if (state->tls_ctx.client_certificate_requested)
                    {
                        /* Certificate, then CertificateVerify, one record each,
                         * built straight into the record and encrypted in place.
                         * An unsatisfiable request yields an empty Certificate
                         * and no CertificateVerify, ending the flight after one
                         * message. */
                        bool compatible = state->tls_ctx.client_certificate_compatible &&
                                          state->tls_ctx.client_key &&
                                          state->tls_ctx.client_chain &&
                                          state->tls_ctx.client_chain_len > 0;
                        size_t cert_cap = 8u;
                        if (compatible)
                        {
                            for (size_t i = 0; i < state->tls_ctx.client_chain_len; i++)
                            {
                                size_t der_len = state->tls_ctx.client_chain[i]->der_len;
                                if (cert_cap > UINT16_MAX ||
                                    der_len > UINT16_MAX - cert_cap - 5u)
                                {
                                    tls_dbg_status("clientcert: too large");
                                    ALTCP_TLS_CE_ERROR_ABORT(conn);
                                    return ERR_ABRT;
                                }
                                cert_cap += der_len + 5u;
                            }
                        }

                        bool cert_ok = true;
                        for (int step = TLS_CLIENT_FLIGHT_CERTIFICATE;
                             cert_ok && step <= TLS_CLIENT_FLIGHT_CERTIFICATE_VERIFY; step++)
                        {
                            if (step == TLS_CLIENT_FLIGHT_CERTIFICATE_VERIFY && !compatible)
                                break;

                            size_t msg_cap = (step == TLS_CLIENT_FLIGHT_CERTIFICATE)
                                             ? cert_cap : (4u + 2u + 2u + 72u);
                            size_t record_cap = 5u + msg_cap + 1u + TLS_AES_AUTH_TAG_SIZE;
                            uint8_t *record = (uint8_t *)mem_malloc(record_cap);
                            if (!record)
                            {
                                cert_ok = false;
                                break;
                            }

                            size_t msg_len = 0;
                            tls_crypto_guard_enable();
                            cert_ok = tls_send_client_certificate(&state->tls_ctx,
                                                                  record + 5, msg_cap,
                                                                  &msg_len);
                            tls_crypto_guard_disable();

                            if (cert_ok && msg_len == 0)
                            {
                                /* Flight already complete (cursor past the end). */
                                mem_free(record);
                                break;
                            }

                            err_t write_err = ERR_OK;
                            size_t enc_cert_len = 0;
                            for (size_t sent = 0; cert_ok && write_err == ERR_OK &&
                                                  sent < msg_len;)
                            {
                                size_t chunk = msg_len - sent;
                                if (chunk > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT - 1u)
                                    chunk = ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT - 1u;
                                size_t frag_cap = 5u + chunk + 1u + TLS_AES_AUTH_TAG_SIZE;
                                if (!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, true,
                                                                        TLS_CONTENT_TYPE_HANDSHAKE,
                                                                        record + 5 + sent, chunk,
                                                                        record, frag_cap,
                                                                        &enc_cert_len))
                                {
                                    cert_ok = false;
                                    break;
                                }
                                write_err = altcp_write(conn->inner_conn, record,
                                                        (u16_t)enc_cert_len,
                                                        TCP_WRITE_FLAG_COPY);
                                if (write_err == ERR_OK)
                                {
                                    state->tls_ctx.client_hs_seq_num++;
                                    sent += chunk;
                                }
                            }
                            mem_free(record);
                            if (!cert_ok)
                            {
                                tls_dbg_status("clientcert: gen/enc fail");
                                ALTCP_TLS_CE_ERROR_ABORT(conn);
                                return ERR_ABRT;
                            }
                            if (write_err != ERR_OK)
                            {
                                tls_dbg_status("clientcert: write fail");
                                ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -write_err);
                                return ERR_ABRT;
                            }
                        }
                        altcp_output(conn->inner_conn);
                        if (!cert_ok)
                        {
                            ALTCP_TLS_CE_ERROR_ABORT(conn);
                            return ERR_ABRT;
                        }
                        tls_dbg_status("clientcert: sent");
                    }

                    /* Generate client Finished message (plaintext handshake) */
                    uint8_t finished_hs[36];
                    size_t finished_hs_len = 0;
                    tls_dbg_status("clientfin: gen");
                    /* tls_send_finished holds finished_key/verify_data/
                     * hmac_ctx on its own stack frame; wrapping the call
                     * lets tls_crypto_guard_disable() scrub that whole
                     * frame once it's returned and SP is back above it. */
                    tls_crypto_guard_enable();
                    bool send_finished_ok = tls_send_finished(&state->tls_ctx, true, finished_hs,
                                                              sizeof(finished_hs), &finished_hs_len);
                    tls_crypto_guard_disable();
                    if (!send_finished_ok)
                    {
                        tls_dbg_status("clientfin: gen fail");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: Finished generation failed\n"));
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }

                    /* Encrypt the Finished as a TLS 1.3 record */
                    uint8_t enc_finished[128];
                    size_t enc_finished_len = 0;
                    tls_dbg_status("clientfin: encrypt");
                    if (!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, true,
                                                            TLS_CONTENT_TYPE_HANDSHAKE,
                                                            finished_hs, finished_hs_len,
                                                            enc_finished, sizeof(enc_finished),
                                                            &enc_finished_len))
                    {
                        tls_dbg_status("clientfin: enc fail");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: Finished encryption failed\n"));
                        ALTCP_TLS_CE_ERROR_ABORT(conn);
                        return ERR_ABRT;
                    }

                    err_t write_err = altcp_write(conn->inner_conn, enc_finished,
                                                  (u16_t)enc_finished_len, TCP_WRITE_FLAG_COPY);
                    altcp_output(conn->inner_conn);

                    if (write_err != ERR_OK)
                    {
                        tls_dbg_status("clientfin: write fail");
                        ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -write_err);
                        return ERR_ABRT;
                    }
                    state->tls_ctx.client_hs_seq_num++;
                    tls_dbg_status("clientfin: sent");

                    /* Handshake complete */
                    state->flags |= ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE;
                    state->tls_ctx.state = TLS_STATE_HANDSHAKE_COMPLETE;
                    state->tls_ctx.tx_epoch = 2;
                    STATE_CHG(conn, LWIP_STATE_TLS_HANDSHAKE_DONE);

                    /* Notify upper layer */
                    if (conn->connected)
                    {
                        tls_dbg_status("upper: connected cb");
                        err_t err = conn->connected(conn->arg, conn, ERR_OK);
                        if (err != ERR_OK)
                        {
                            tls_dbg_status("upper: connected fail");
                            return err;
                        }
                        tls_dbg_status("upper: connected ok");
                        state->flags |= ALTCP_TLS_CE_FLAGS_UPPER_CALLED;
                    }

                    if (state->rx == NULL)
                    {
                        return ERR_OK;
                    }
                    break; /* Exit record processing loop */
                }
            }
        }
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        return ERR_OK;
    }

    /* Handle application data */
    return altcp_tls_ce_handle_rx_appldata(conn, state);
}

/**
 * @brief Pass queued decrypted rx data to application
 */
static err_t
altcp_tls_ce_pass_rx_data(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    err_t err;
    struct pbuf *buf;

    LWIP_ASSERT("conn != NULL", conn != NULL);
    LWIP_ASSERT("state != NULL", state != NULL);

    buf = state->rx_app;
    if (buf)
    {
        state->rx_app = NULL;
        if (conn->recv)
        {
            u16_t tot_len = buf->tot_len;
            state->rx_passed_unrecved += tot_len;
            state->flags |= ALTCP_TLS_CE_FLAGS_UPPER_CALLED;

            err = conn->recv(conn->arg, conn, buf, ERR_OK);
            if (err != ERR_OK)
            {
                if (err == ERR_ABRT)
                {
                    ERROR_CODE(-ERR_ABRT);
                    return ERR_ABRT;
                }
                /* Not received, re-queue */
                LWIP_ASSERT("state == conn->state", state == conn->state);
                state->rx_app = buf;
                state->rx_passed_unrecved -= tot_len;
                LWIP_ASSERT("state->rx_passed_unrecved >= 0", state->rx_passed_unrecved >= 0);
                if (state->rx_passed_unrecved < 0)
                {
                    state->rx_passed_unrecved = 0;
                }
                return err;
            }
        }
        else
        {
            pbuf_free(buf);
        }
    }
    else if ((state->flags & (ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED | ALTCP_TLS_CE_FLAGS_RX_CLOSED)) ==
             ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED)
    {
        state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSED;
        if (conn->recv)
        {
            return conn->recv(conn->arg, conn, NULL, ERR_OK);
        }
    }

    if (conn->state != state)
    {
        return ERR_ARG;
    }
    return ERR_OK;
}

/**
 * @brief Handle decrypting and processing application data
 *
 * After handshake, incoming TCP data is TLS records (type 0x17).
 * Each record has a 5-byte header followed by encrypted payload.
 */
static err_t altcp_tls_ce_handle_rx_appldata_impl(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);

/* Entry point for plaintext delivery. Not re-entrant: a nested call (from an
 * app recv callback) records RX_REPEAT and returns, and this outer call loops
 * again. The loop is bounded, nothing here waits, and after any callback the
 * state is re-validated before it is touched, so the guard can neither spin
 * nor dangle. Data left queued by the bound is picked up by the next recv,
 * recved() or poll tick. */
static err_t
altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    enum { ALTCP_TLS_CE_RX_PASSES = 4 };
    err_t err = ERR_OK;

    LWIP_ASSERT("state != NULL", state != NULL);
    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        return ERR_VAL;
    }
    if (state->flags & ALTCP_TLS_CE_FLAGS_RX_BUSY)
    {
        state->flags |= ALTCP_TLS_CE_FLAGS_RX_REPEAT;
        return ERR_OK;
    }

    state->flags |= ALTCP_TLS_CE_FLAGS_RX_BUSY;
    for (unsigned pass = 0; pass < ALTCP_TLS_CE_RX_PASSES; pass++)
    {
        state->flags &= (u16_t)~ALTCP_TLS_CE_FLAGS_RX_REPEAT;

        if (state->rx_app != NULL)
        {
            err = altcp_tls_ce_pass_rx_data(conn, state);
            if (err == ERR_ABRT || !altcp_tls_ce_state_alive(state))
            {
                return err; /* state may be gone: do not touch it */
            }
            if (err != ERR_OK)
            {
                break; /* app declined the data; retried on the next event */
            }
        }
        if (state->rx_app == NULL)
        {
            err = altcp_tls_ce_handle_rx_appldata_impl(conn, state);
            if (err == ERR_ABRT || !altcp_tls_ce_state_alive(state))
            {
                return err;
            }
        }
        if (!(state->flags & ALTCP_TLS_CE_FLAGS_RX_REPEAT))
        {
            break;
        }
    }
    state->flags &= (u16_t)~(ALTCP_TLS_CE_FLAGS_RX_BUSY | ALTCP_TLS_CE_FLAGS_RX_REPEAT);
    return err;
}

static err_t
altcp_tls_ce_handle_rx_appldata_impl(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    tls_dbg_status("rx: appdata path");

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        return ERR_VAL;
    }

    /* Process available TLS records. Each record is consumed bytes-as-decrypted
     * by altcp_tls_ce_decrypt_record_stream, which calls lower_recved itself
     * as it releases header / payload chunks / tag from state->rx. The caller
     * here only routes the decrypted plaintext by inner content-type. */
    while (state->rx != NULL && state->rx->tot_len >= 5)
    {
        if (state->tls_ctx.peer_close_notify_received)
        {
            altcp_tls_ce_consume_recved(state, state->rx->tot_len);
            break;
        }
        if (state->rx_app != NULL)
        {
            err_t pass_err = altcp_tls_ce_pass_rx_data(conn, state);
            if (pass_err == ERR_ABRT)
            {
                /* ERROR_AUDIT: pass_rx_data emitted before abort. */
                return ERR_ABRT;
            }
            if (state->rx_app != NULL)
            {
                return ERR_OK;
            }
        }
        uint8_t header[5];
        pbuf_copy_partial(state->rx, header, 5, 0);

        size_t rec_payload_len = ((size_t)header[3] << 8) | (size_t)header[4];
        size_t total_rec_len = 5 + rec_payload_len;

        if ((size_t)state->rx->tot_len < total_rec_len)
        {
            break;
        }

        if (rec_payload_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 256u)
        {
            (void)tls_send_fatal_alert(&state->tls_ctx,
                                       TLS_ALERT_RECORD_OVERFLOW);
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }
        if (header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA ||
            rec_payload_len == 0)
        {
            /* All post-handshake records must arrive AEAD-wrapped inside an
             * application_data outer record (RFC 8446 §5). Any plaintext
             * here is a protocol violation. */
            (void)tls_send_fatal_alert(&state->tls_ctx,
                                       TLS_ALERT_UNEXPECTED_MESSAGE);
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }

        size_t dec_len = 0;
        uint8_t inner_type = 0;
        struct pbuf *dec_pbuf = NULL;
        tls_dbg_status("rx: app decrypt");
        err_t dec_err = altcp_tls_ce_decrypt_record_stream(state, conn,
                                                           false, total_rec_len,
                                                           &dec_pbuf, &dec_len,
                                                           &inner_type);
        if (dec_err == ERR_MEM)
        {
            /* Decrypt buffer allocation failed: leave the record queued and
             * retry on the next tick/recv. */
            DEBUG();
            return ERR_OK;
        }
        if (dec_err != ERR_OK)
        {
            ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, -dec_err);
            return ERR_ABRT;
        }
        tls_dbg_status("rx: app decrypted");

        if (inner_type == TLS_CONTENT_TYPE_APPLICATION_DATA)
        {
            if (dec_len > 0)
            {
                if (state->rx_app == NULL)
                {
                    state->rx_app = dec_pbuf;
                }
                else
                {
                    pbuf_cat(state->rx_app, dec_pbuf);
                }
                dec_pbuf = NULL;
            }
            if (dec_pbuf)
            {
                pbuf_free(dec_pbuf);
            }
        }
        else if (inner_type == TLS_CONTENT_TYPE_HANDSHAKE)
        {
            /* Post-handshake handshake messages (NewSessionTicket, KeyUpdate,
             * etc.) flow through the same reassembly dispatcher we use during
             * the handshake. The dispatcher already routes NewSessionTicket
             * into the PSK store. */
            if (!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type,
                                                  dec_pbuf, dec_len))
            {
                pbuf_free(dec_pbuf);
                ALTCP_TLS_CE_ERROR_ABORT(conn);
                return ERR_ABRT;
            }
            if (dec_len > 0)
            {
                /* Side-effect: NewSessionTicket may have updated ctx's PSK fields;
                 * cache the fresh resumption identity in memory. No disk I/O here —
                 * the in-memory cache is flushed to flash once at tls_cleanup(). */
                if (state->tls_ctx.ticket_fresh &&
                    state->tls_ctx.psk_mode &&
                    state->tls_ctx.psk_type == TLS_PSK_TYPE_RESUMPTION &&
                    state->tls_ctx.psk_identity.identity_len > 0 &&
                    state->tls_ctx.psk_identity.identity_len <= sizeof(state->tls_ctx.psk_identity.identity) &&
                    state->tls_ctx.ticket_lifetime > 0)
                {
                    struct altcp_tls_ce_config *cfg = (struct altcp_tls_ce_config *)state->conf;
                    if (cfg && cfg->hostname)
                    {
                        tls_psk_cache_put(cfg->hostname, TLS_PSK_TYPE_RESUMPTION,
                                          state->tls_ctx.psk, &state->tls_ctx.psk_identity,
                                          state->tls_ctx.ticket_lifetime);
                    }
                }
                state->tls_ctx.ticket_fresh = false;
            }
            pbuf_free(dec_pbuf);
        }
        else if (inner_type == TLS_CONTENT_TYPE_ALERT)
        {
            if (dec_len != 2)
            {
                pbuf_free(dec_pbuf);
                ALTCP_TLS_CE_ERROR_ABORT(conn);
                return ERR_ABRT;
            }
            uint8_t alert_desc = pbuf_get_at(dec_pbuf, 1);
            if (alert_desc == TLS_ALERT_CLOSE_NOTIFY)
            {
                /* RFC 8446 §6.1: a close_notify is the peer's orderly
                 * shutdown signal and must be surfaced as EOF to the
                 * application, the same way a TCP FIN is. Without this,
                 * the alert was previously just discarded and the
                 * application's recv callback would never fire — it would
                 * sit waiting on a FIN that may arrive late or not at all.
                 * Queueing through RX_CLOSE_QUEUED (rather than delivering
                 * EOF immediately) ensures any application data already
                 * pending in state->rx_app is drained first, same as the
                 * TCP-FIN path below. */
                state->tls_ctx.peer_close_notify_received = true;
                state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED;
            }
            else if (alert_desc == TLS_ALERT_USER_CANCELED)
            {
                /* RFC 8446 section 6.1 recommends ignoring this alert. The
                 * peer normally follows it with close_notify. */
            }
            else
            {
                pbuf_free(dec_pbuf);
                ALTCP_TLS_CE_ERROR_ABORT_CODE(conn, alert_desc);
                ERROR_INFO(tls_alert_name(alert_desc));
                return ERR_ABRT;
            }
            pbuf_free(dec_pbuf);
        }
        else
        {
            pbuf_free(dec_pbuf);
            ALTCP_TLS_CE_ERROR_ABORT(conn);
            return ERR_ABRT;
        }

        err_t err = altcp_tls_ce_pass_rx_data(conn, state);
        if (err != ERR_OK)
        {
            if (err == ERR_ABRT)
            {
                ERROR_CODE(-ERR_ABRT);
                return ERR_ABRT;
            }
            /* Non-fatal, non-abort error delivering decrypted app data to
             * the application layer -- bytes stay queued, retried later. */
            DEBUG();
            return ERR_OK;
        }
        tls_dbg_status("rx: app delivered");
    }

    altcp_tls_ce_open_window_for_record(state);
    return ERR_OK;
}

/**
 * @brief Sent callback from lower connection (TCP)
 */
static err_t
altcp_tls_ce_lower_sent(void *arg, struct altcp_pcb *inner_conn, u16_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    LWIP_UNUSED_ARG(inner_conn);

    if (conn)
    {
        int overhead;
        u16_t app_len;
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;

        LWIP_ASSERT("state", state != NULL);
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        /* Calculate TLS overhead (16-byte authentication tag per record) */
        overhead = state->overhead_bytes_adjust;
        if ((unsigned)overhead > len)
        {
            overhead = len;
        }

        state->overhead_bytes_adjust -= len;
        app_len = len - (u16_t)overhead;

        if (app_len)
        {
            state->overhead_bytes_adjust += app_len;
            if (conn->sent)
            {
                return conn->sent(conn->arg, conn, app_len);
            }
        }
    }
    return ERR_OK;
}

/**
 * @brief Poll callback from lower connection (TCP)
 */
static err_t
altcp_tls_ce_lower_poll(void *arg, struct altcp_pcb *inner_conn)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    LWIP_UNUSED_ARG(inner_conn);

    if (conn)
    {
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        if (conn->state)
        {
            altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
            err_t err = altcp_tls_ce_lower_recv_process(conn, state);
            if (err == ERR_ABRT)
            {
                /* ERROR_AUDIT: receive processor emitted before abort. */
                return ERR_ABRT;
            }
        }

        if (conn->poll)
        {
            return conn->poll(conn->arg, conn);
        }
    }
    return ERR_OK;
}

/**
 * @brief Error callback from lower connection (TCP)
 *
 * Snapshot the app's err callback + arg locally, detach the TLS state
 * BEFORE invoking the app cb, then altcp_free the wrapper. This way the
 * app's err cb can't reach into TLS state that altcp_free's dealloc is
 * about to release — a guard that matters most when the app logs or
 * inspects the conn during teardown.
 */
static void
altcp_tls_ce_lower_err(void *arg, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    ERROR_CODE(-err);
    if (!conn)
    {
        return;
    }
    /* Snapshot before any state mutation so the app callback gets the
     * same arg/fn it registered, regardless of what we do next. */
    altcp_err_fn app_err = conn->err;
    void *app_arg = conn->arg;

    conn->inner_conn = NULL; /* lower freed us before raising err */
    conn->err = NULL;
    conn->recv = NULL;
    conn->sent = NULL;
    conn->poll = NULL;
    conn->connected = NULL;

    if (app_err)
    {
        app_err(app_arg, err);
    }
    altcp_free(conn);
}

/* ========== Setup Functions ========== */

static void
altcp_tls_ce_remove_callbacks(struct altcp_pcb *inner_conn)
{
    altcp_arg(inner_conn, NULL);
    altcp_recv(inner_conn, NULL);
    altcp_sent(inner_conn, NULL);
    altcp_err(inner_conn, NULL);
    /* A listening pcb never gets a poll callback, and tcp_poll() asserts on
     * one, so only clear a poll that was set. */
    if (inner_conn->poll != NULL)
    {
        altcp_poll(inner_conn, NULL, inner_conn->pollinterval);
    }
}

static void
altcp_tls_ce_setup_callbacks(struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
    altcp_arg(inner_conn, conn);
    altcp_recv(inner_conn, altcp_tls_ce_lower_recv);
    altcp_sent(inner_conn, altcp_tls_ce_lower_sent);
    altcp_err(inner_conn, altcp_tls_ce_lower_err);
}

static err_t
altcp_tls_ce_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn)
{
    altcp_tls_ce_state_t *state;

    if (!conf || !tls_ctx.initialized)
    {
        /* lwip_start() deliberately survives a TLS-only initialization
         * failure. Do not let direct ALTCP callers bypass that TLS gate. */
        ERROR_CODE(-ERR_ARG);
        return ERR_ARG;
    }
    LWIP_ASSERT("invalid inner_conn", conn != inner_conn);

    /* Allocate state */
    tls_dbg_status("setup: alloc state");
    state = (altcp_tls_ce_state_t *)mem_malloc(sizeof(altcp_tls_ce_state_t));
    if (state == NULL)
    {
        tls_dbg_status("setup: alloc fail");
        ERROR_CODE(-ERR_MEM);
        return ERR_MEM;
    }
    mem_stats_tls_direct_add(sizeof(*state), sizeof(*state));

    memset(state, 0, sizeof(altcp_tls_ce_state_t));
    state->conf = conf;
    state->conn = conn;

    /* Accepted server sockets retain their existing synchronous setup. Client
     * sockets enter the pre-connect pseudo state: one share is generated per
     * dispatcher turn, and TCP is not opened until both readiness bits exist. */
    tls_dbg_status("setup: hs init");
    if (((struct altcp_tls_ce_config *)conf)->is_server)
    {
        (void)altcp_tls_ce_init_handshake(state);
    }
    else
    {
        state->flags |= ALTCP_TLS_CE_FLAGS_GENERATING_SHARES;
        (void)altcp_tls_ce_begin_keyshares(state);
    }

    /* Wire the transport write hook so handshake.c can emit alerts and
     * close_notify without depending on lwIP/altcp directly. */
    tls_dbg_status("setup: transport");
    tls_set_transport(&state->tls_ctx, altcp_tls_ce_transport_write, state);

    altcp_tls_ce_setup_callbacks(conn, inner_conn);
    conn->inner_conn = inner_conn;
    conn->fns = &altcp_tls_ce_functions;
    conn->state = state;
    state->rx_throttle_pending = 0;
    tls_state_add(state);
    mem_set_global_pressure_cb(altcp_tls_ce_set_rx_throttle);
    if (state->flags & ALTCP_TLS_CE_FLAGS_GENERATING_SHARES)
    {
        altcp_tls_ce_keyshare_arm();
    }

    tls_dbg_status("setup: done");

    return ERR_OK;
}

/* ========== Public API ========== */

struct altcp_pcb *
altcp_tls_ce_wrap(struct altcp_tls_ce_config *config, struct altcp_pcb *inner_pcb)
{
    struct altcp_pcb *ret;

    if (inner_pcb == NULL)
    {
        ERROR_CODE(-ERR_ARG);
        return NULL;
    }

    ret = altcp_alloc();
    if (ret == NULL)
    {
        ERROR_CODE(-ERR_MEM);
        return NULL;
    }
    if (altcp_tls_ce_setup(config, ret, inner_pcb) != ERR_OK)
    {
        altcp_free(ret);
        return NULL;
    }
    return ret;
}

struct altcp_pcb *
altcp_tls_ce_new(struct altcp_tls_ce_config *config, u8_t ip_type)
{
    struct altcp_pcb *inner_pcb, *ret;

    inner_pcb = altcp_tcp_new_ip_type(ip_type);
    if (inner_pcb == NULL)
    {
        ERROR_CODE(-ERR_MEM);
        return NULL;
    }

    ret = altcp_tls_ce_wrap(config, inner_pcb);
    if (ret == NULL)
    {
        /* ERROR_AUDIT: altcp_tls_ce_wrap emitted; release the owned pcb. */
        altcp_abort(inner_pcb);
    }
    return ret;
}

struct altcp_pcb *
altcp_tls_ce_alloc(void *arg, u8_t ip_type)
{
    return altcp_tls_ce_new((struct altcp_tls_ce_config *)arg, ip_type);
}

/* ========== Virtual Functions ========== */

void altcp_tls_ce_set_rx_throttle(enum mem_pressure_level level)
{
    g_tls_rx_throttle_level = level;
    if (level == MEM_PRESSURE_NONE)
    {
        altcp_tls_ce_state_t *state = g_tls_state_head;
        while (state)
        {
            altcp_tls_ce_release_pending(state, (size_t)-1);
            state = state->next;
        }
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RX_RECVD, 0);
    }
    else
    {
        altcp_tls_ce_rx_release_arm();
    }
}

static void
altcp_tls_ce_set_poll(struct altcp_pcb *conn, u8_t interval)
{
    if (conn != NULL)
    {
        altcp_poll(conn->inner_conn, altcp_tls_ce_lower_poll, interval);
    }
}

static void
altcp_tls_ce_recved(struct altcp_pcb *conn, u16_t len)
{
    altcp_tls_ce_state_t *state;

    if (conn == NULL)
    {
        return;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL)
    {
        return;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        return;
    }

    if (len > state->rx_passed_unrecved)
    {
        len = (u16_t)state->rx_passed_unrecved;
    }

    if (len == 0)
    {
        return;
    }

    /* TLS record bytes are released to the lower TCP layer as the decrypter
     * removes them from state->rx. Upper-layer recved() is therefore only an
     * accounting signal for plaintext already handed upward; forwarding this
     * plaintext length to TCP would double-credit the receive window and can
     * destabilize long-lived TLS streams. */
    state->rx_passed_unrecved -= len;
    (void)altcp_tls_ce_handle_rx_appldata(conn, state);
}

static err_t
altcp_tls_ce_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
    altcp_tls_ce_state_t *state;

    if (conn == NULL || ipaddr == NULL)
    {
        ERROR_CODE(-ERR_VAL);
        return ERR_VAL;
    }
    conn->connected = connected;
    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL)
    {
        ERROR_CODE(-ERR_VAL);
        return ERR_VAL;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_CTX_INITIALIZED))
    {
        if (state->tls_ctx.keyshare_state == TLS_KEYSHARE_STATE_ERROR)
        {
            ERROR_CODE(-ERR_ABRT);
            return ERR_ABRT;
        }
        ip_addr_copy(state->pending_connect_addr, *ipaddr);
        state->pending_connect_port = port;
        state->flags |= (ALTCP_TLS_CE_FLAGS_GENERATING_SHARES |
                         ALTCP_TLS_CE_FLAGS_CONNECT_PENDING);
        altcp_tls_ce_keyshare_arm();
        return ERR_OK;
    }

    ip_addr_copy(state->pending_connect_addr, *ipaddr);
    state->pending_connect_port = port;
    LWIP_TRACE_RETURN(altcp_tls_ce_start_lower_connect(state));
}

static struct altcp_pcb *
altcp_tls_ce_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
    struct altcp_pcb *lpcb;

    if (conn == NULL)
    {
        ERROR_CODE(-ERR_VAL);
        return NULL;
    }

    lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
    if (lpcb != NULL)
    {
        conn->inner_conn = lpcb;
        altcp_accept(lpcb, altcp_tls_ce_lower_accept);
        return conn;
    }
    ERROR_CODE(err ? (uint16_t)(-*err) : 0u);
    return NULL;
}

static void
altcp_tls_ce_abort(struct altcp_pcb *conn)
{
    if (conn != NULL)
    {
        /* ERROR_AUDIT: caller-requested abort, not a newly detected error. */
        altcp_abort(conn->inner_conn);
    }
}

static err_t
altcp_tls_ce_close(struct altcp_pcb *conn)
{
    struct altcp_pcb *inner_conn;

    if (conn == NULL)
    {
        ERROR_CODE(-ERR_VAL);
        return ERR_VAL;
    }

    /* Best-effort: send TLS close_notify before tearing down the TCP
     * side. Tracked via CLOSE_NOTIFY_SENT so a retried close (when the
     * TCP-level close hits ERR_MEM and the caller retries) doesn't
     * re-emit the alert — the peer has already seen one. */
    altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
    if (state && !state->tls_ctx.fatal_alert_sent &&
        !(state->flags & ALTCP_TLS_CE_FLAGS_CLOSE_NOTIFY_SENT))
    {
        if (tls_send_close_notify(&state->tls_ctx))
        {
            state->flags |= ALTCP_TLS_CE_FLAGS_CLOSE_NOTIFY_SENT;
        }
    }

    inner_conn = conn->inner_conn;
    if (inner_conn)
    {
        err_t err;
        altcp_poll_fn oldpoll = inner_conn->poll;

        altcp_tls_ce_remove_callbacks(conn->inner_conn);
        err = altcp_close(conn->inner_conn);

        if (err != ERR_OK)
        {
            /* Not closed; restore callbacks so the lower layer can
             * keep delivering events. The CLOSE_NOTIFY_SENT flag stays
             * set — the alert is on the wire even though the TCP-side
             * close didn't go through. */
            altcp_tls_ce_setup_callbacks(conn, inner_conn);
            if (oldpoll != NULL)
            {
                altcp_poll(inner_conn, oldpoll, inner_conn->pollinterval);
            }
            ERROR_CODE(-err);
            return err;
        }
        conn->inner_conn = NULL;
    }
    altcp_free(conn);
    return ERR_OK;
}

static u16_t
altcp_tls_ce_sndbuf(struct altcp_pcb *conn)
{
    if (conn)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;

        if (!state || !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
        {
            /* Reports 0 until the handshake completes -- an app write stall
             * here is expected/by-design, not a bug, but worth being able
             * to see when diagnosing "writes never happen". */
            return 0;
        }

        if (conn->inner_conn)
        {
            u16_t sndbuf = altcp_sndbuf(conn->inner_conn);
            /* Account for TLS record overhead: 5 header + 1 content_type + 16 tag = 22 */
            if (sndbuf > 22)
            {
                return sndbuf - 22;
            }
            return 0;
        }
    }
    return altcp_default_sndbuf(conn);
}

static err_t
altcp_tls_ce_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
    altcp_tls_ce_state_t *state;
    size_t ciphertext_len = 0;

    LWIP_UNUSED_ARG(apiflags);

    if (conn == NULL)
    {
        ERROR_CODE(-ERR_VAL);
        return ERR_VAL;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL)
    {
        ERROR_CODE(-ERR_ARG);
        return ERR_ARG;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        ERROR_CODE(-ERR_VAL);
        return ERR_VAL;
    }
    if (!tls_update_write_keys_if_needed(&state->tls_ctx))
    {
        ERROR_CODE(-ERR_MEM);
        return ERR_MEM;
    }
    if ((size_t)len + 22u > TCP_SND_BUF)
    {
        return ERR_VAL; /* can never fit; ERR_MEM would be retried forever */
    }
    if ((size_t)altcp_sndbuf(conn->inner_conn) < (size_t)len + 22u)
    {
        return ERR_MEM;
    }

    tls_dbg_status("tx: app encrypt");
    /* Allocate ciphertext buffer: 5 header + len + 1 content_type + 16 tag */
    size_t ct_buf_size = (size_t)len + 22;
    uint8_t *ciphertext = (uint8_t *)mem_malloc(ct_buf_size);
    if (!ciphertext)
    {
        ERROR_CODE(-ERR_MEM);
        return ERR_MEM;
    }
    mem_stats_tls_direct_add(ct_buf_size, ct_buf_size);

    /* Encrypt data as a TLS record (includes 5-byte header + ciphertext + tag) */
    if (!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, false,
                                            TLS_CONTENT_TYPE_APPLICATION_DATA,
                                            (const uint8_t *)dataptr, len,
                                            ciphertext, ct_buf_size, &ciphertext_len))
    {
        mem_stats_tls_direct_release(ct_buf_size, ct_buf_size);
        mem_free(ciphertext);
        ERROR_CODE(-ERR_MEM);
        return ERR_MEM;
    }

    tls_dbg_status("tx: app write");
    /* Send encrypted record over TCP */
    err_t err = altcp_write(conn->inner_conn, ciphertext, (u16_t)ciphertext_len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK)
    {
        state->tls_ctx.client_seq_num++;
        altcp_output(conn->inner_conn);
        state->overhead_bytes_adjust -= len;
        state->overhead_bytes_adjust += ciphertext_len;
        tls_dbg_status("tx: app sent");
    }

    mem_stats_tls_direct_release(ct_buf_size, ct_buf_size);
    mem_free(ciphertext);
    if (err != ERR_OK && err != ERR_MEM)
        ERROR_CODE(-err);
    return err;
}

static u16_t
altcp_tls_ce_mss(struct altcp_pcb *conn)
{
    if (conn == NULL)
    {
        return 0;
    }
    /* Subtract TLS record overhead: 5 header + 1 content_type + 16 tag = 22 */
    u16_t inner_mss = altcp_mss(conn->inner_conn);
    if (inner_mss > 22)
    {
        return inner_mss - 22;
    }
    return 0;
}

static void
altcp_tls_ce_dealloc(struct altcp_pcb *conn)
{
    if (conn)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        if (state)
        {
            tls_handshake_cleanup(&state->tls_ctx);
            state->flags = 0;

            if (state->rx)
            {
                pbuf_free(state->rx);
                state->rx = NULL;
            }
            state->rx_acked_len = 0;
            if (state->rx_app)
            {
                pbuf_free(state->rx_app);
                state->rx_app = NULL;
            }
            if (state->pending_chello)
            {
                tls_secure_memzero(state->pending_chello, state->pending_chello_len);
                mem_stats_tls_direct_release(state->pending_chello_len, state->pending_chello_len);
                mem_free(state->pending_chello);
                state->pending_chello = NULL;
                state->pending_chello_len = 0;
            }
            tls_state_remove(state);
            state->conn = NULL;
            mem_stats_tls_direct_release(sizeof(*state), sizeof(*state));
            mem_free(state);
            conn->state = NULL;
        }
    }
}

/* Function table for TLS CE */
const struct altcp_functions altcp_tls_ce_functions = {
    altcp_tls_ce_set_poll,
    altcp_tls_ce_recved,
    altcp_default_bind,
    altcp_tls_ce_connect,
    altcp_tls_ce_listen,
    altcp_tls_ce_abort,
    altcp_tls_ce_close,
    altcp_default_shutdown,
    altcp_tls_ce_write,
    altcp_default_output,
    altcp_tls_ce_mss,
    altcp_tls_ce_sndbuf,
    altcp_default_sndqueuelen,
    altcp_default_nagle_disable,
    altcp_default_nagle_enable,
    altcp_default_nagle_disabled,
    altcp_default_setprio,
    altcp_tls_ce_dealloc,
    altcp_default_get_tcp_addrinfo,
    altcp_default_get_ip,
    altcp_default_get_port
#if LWIP_TCP_KEEPALIVE
    ,
    altcp_default_keepalive_disable,
    altcp_default_keepalive_enable
#endif
#ifdef LWIP_DEBUG
    ,
    altcp_default_dbg_get_tcp_state
#endif
};

/* ========== Generic altcp_tls API (for lwIP apps: MQTT, SMTP, HTTP) ========== */

#if LWIP_ALTCP_TLS

/**
 * @brief Map generic altcp_tls_config to our CE config
 *
 * The generic lwIP TLS API uses opaque struct altcp_tls_config*.
 * We cast directly to our altcp_tls_ce_config since we own the only backend.
 */

struct altcp_tls_config *altcp_tls_create_config_server(u8_t cert_count)
{
    LWIP_UNUSED_ARG(cert_count);
    /* Server config requires PSK, use altcp_tls_ce_create_config_psk_server directly */
    ERROR_CODE(-ERR_ARG);
    return NULL;
}

err_t altcp_tls_config_server_add_privkey_cert(struct altcp_tls_config *config,
                                               const u8_t *privkey, size_t privkey_len,
                                               const u8_t *privkey_pass, size_t privkey_pass_len,
                                               const u8_t *cert, size_t cert_len)
{
    LWIP_UNUSED_ARG(config);
    LWIP_UNUSED_ARG(privkey);
    LWIP_UNUSED_ARG(privkey_len);
    LWIP_UNUSED_ARG(privkey_pass);
    LWIP_UNUSED_ARG(privkey_pass_len);
    LWIP_UNUSED_ARG(cert);
    LWIP_UNUSED_ARG(cert_len);
    /* Certificate-based auth not yet supported on CE */
    ERROR_CODE(-ERR_ARG);
    return ERR_ARG;
}

struct altcp_tls_config *altcp_tls_create_config_server_privkey_cert(
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
    LWIP_UNUSED_ARG(privkey);
    LWIP_UNUSED_ARG(privkey_len);
    LWIP_UNUSED_ARG(privkey_pass);
    LWIP_UNUSED_ARG(privkey_pass_len);
    LWIP_UNUSED_ARG(cert);
    LWIP_UNUSED_ARG(cert_len);
    /* Certificate-based auth not yet supported on CE */
    ERROR_CODE(-ERR_ARG);
    return NULL;
}

struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *cert, size_t cert_len)
{
    LWIP_UNUSED_ARG(cert);
    LWIP_UNUSED_ARG(cert_len);
    /* This API has no hostname parameter, so it cannot create a configuration
     * that performs RFC 9525 service-identity verification. Fail here instead
     * of constructing a client that is guaranteed to fail (or be tempted to
     * skip hostname validation). Host-aware CE callers use the ECDHE factory. */
    ERROR_CODE(-ERR_ARG);
    return NULL;
}

struct altcp_tls_config *altcp_tls_create_config_psk_client(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity)
{
    return (struct altcp_tls_config *)altcp_tls_ce_create_config_psk_client(psk, psk_identity);
}

struct altcp_tls_config *altcp_tls_create_config_psk_server(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity)
{
    return (struct altcp_tls_config *)altcp_tls_ce_create_config_psk_server(psk, psk_identity);
}

struct altcp_tls_config *altcp_tls_create_config_cert_server(
    const char *privkey_appvar,
    const char *chain_appvar)
{
    return (struct altcp_tls_config *)altcp_tls_ce_create_config_cert_server(
                privkey_appvar, chain_appvar);
}

struct altcp_tls_config *altcp_tls_create_config_cert_client(
    const char *hostname,
    const char *privkey_appvar,
    const char *chain_appvar)
{
    return (struct altcp_tls_config *)altcp_tls_ce_create_config_cert_client(
        hostname, privkey_appvar, chain_appvar);
}

struct altcp_tls_config *altcp_tls_create_config_client_2wayauth(
    const u8_t *ca, size_t ca_len,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
    LWIP_UNUSED_ARG(ca);
    LWIP_UNUSED_ARG(ca_len);
    LWIP_UNUSED_ARG(privkey);
    LWIP_UNUSED_ARG(privkey_len);
    LWIP_UNUSED_ARG(privkey_pass);
    LWIP_UNUSED_ARG(privkey_pass_len);
    LWIP_UNUSED_ARG(cert);
    LWIP_UNUSED_ARG(cert_len);
    ERROR_CODE(-ERR_ARG);
    return NULL;
}

int altcp_tls_configure_alpn_protocols(struct altcp_tls_config *conf, const char **protos)
{
    struct altcp_tls_ce_config *ce_conf = (struct altcp_tls_ce_config *)conf;
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    size_t offset = 0;

    if (!ce_conf)
    {
        ERROR_CODE(-ERR_ARG);
        return -1;
    }

    if (protos)
    {
        for (size_t i = 0; protos[i] != NULL; i++)
        {
            size_t protocol_len = strlen(protos[i]);
            if (protocol_len == 0 || protocol_len > TLS_ALPN_PROTOCOL_NAME_MAX ||
                encoded_len > 0xFFFFu - protocol_len - 1u)
            {
                ERROR_CODE(-ERR_VAL);
                return -1;
            }
            encoded_len += protocol_len + 1u;
        }
    }

    if (encoded_len != 0)
    {
        encoded = (uint8_t *)mem_malloc(encoded_len);
        if (!encoded)
        {
            ERROR_CODE(-ERR_MEM);
            return -1;
        }
        mem_stats_tls_direct_add(encoded_len, encoded_len);
        for (size_t i = 0; protos[i] != NULL; i++)
        {
            size_t protocol_len = strlen(protos[i]);
            encoded[offset++] = (uint8_t)protocol_len;
            memcpy(encoded + offset, protos[i], protocol_len);
            offset += protocol_len;
        }
    }

    if (ce_conf->alpn_protocols)
    {
        mem_stats_tls_direct_release(ce_conf->alpn_protocols_len,
                                     ce_conf->alpn_protocols_len);
        mem_free(ce_conf->alpn_protocols);
    }
    ce_conf->alpn_protocols = encoded;
    ce_conf->alpn_protocols_len = encoded_len;
    return 0;
}

void altcp_tls_free_config(struct altcp_tls_config *conf)
{
    altcp_tls_ce_free_config((struct altcp_tls_ce_config *)conf);
}

void altcp_tls_free_entropy(void)
{
    /* Compatibility no-op: CE entropy state follows tls_init/tls_cleanup. */
}

struct altcp_pcb *altcp_tls_wrap(struct altcp_tls_config *config, struct altcp_pcb *inner_pcb)
{
    return altcp_tls_ce_wrap((struct altcp_tls_ce_config *)config, inner_pcb);
}

void *altcp_tls_context(struct altcp_pcb *conn)
{
    if (conn && conn->state)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        return &state->tls_ctx;
    }
    return NULL;
}

void altcp_tls_init_session(struct altcp_tls_session *dest)
{
    if (dest)
    {
        memset(dest, 0, sizeof(*dest));
    }
}

err_t altcp_tls_get_session(struct altcp_pcb *conn, struct altcp_tls_session *dest)
{
    if (!dest)
    {
        ERROR_CODE(-ERR_ARG);
        return ERR_ARG;
    }

    memset(dest, 0, sizeof(*dest));

    if (conn && conn->state)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        if (state->tls_ctx.psk_mode &&
            state->tls_ctx.psk_identity.identity_len > 0 &&
            state->tls_ctx.psk_identity.identity_len <= sizeof(state->tls_ctx.psk_identity.identity))
        {
            dest->valid = 1;
            dest->psk_type = state->tls_ctx.psk_type;
            memcpy(dest->psk, state->tls_ctx.psk, sizeof(dest->psk));
            memcpy(&dest->identity, &state->tls_ctx.psk_identity, sizeof(dest->identity));
            /* Not re-cached here: the ticket was cached when it arrived, and
             * caching again would restart its lifetime and could resurrect a
             * ticket another connection already used. */
            return ERR_OK;
        }
    }

    /* No live conn / no in-flight session: can't safely load without
     * knowing the target hostname. The conn-attached create path
     * (altcp_tls_ce_create_config_client_ecdhe) is the host-aware way
     * to do an opportunistic resume. */
    ERROR_CODE(-ERR_VAL);
    return ERR_VAL;
}

err_t altcp_tls_set_session(struct altcp_pcb *conn, struct altcp_tls_session *from)
{
    uint8_t psk_type;

    if (!from || !from->valid ||
        from->identity.identity_len == 0 ||
        from->identity.identity_len > sizeof(from->identity.identity))
    {
        ERROR_CODE(-ERR_ARG);
        return ERR_ARG;
    }

    psk_type = from->psk_type;
    if (psk_type != TLS_PSK_TYPE_EXTERNAL)
    {
        psk_type = TLS_PSK_TYPE_RESUMPTION;
    }

    if (conn && conn->state)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        struct altcp_tls_ce_config *conf = (struct altcp_tls_ce_config *)state->conf;
        if (conf)
        {
            conf->psk_mode = 1;
            conf->psk_type = psk_type;
            memcpy(conf->psk, from->psk, sizeof(conf->psk));
            memcpy(&conf->psk_identity, &from->identity, sizeof(conf->psk_identity));
        }
        memcpy(state->tls_ctx.psk, from->psk, sizeof(state->tls_ctx.psk));
        memcpy(&state->tls_ctx.psk_identity, &from->identity, sizeof(state->tls_ctx.psk_identity));
        state->tls_ctx.psk_mode = true;
        state->tls_ctx.psk_type = psk_type;
    }

    from->psk_type = psk_type;
    /* Not cached: a caller-supplied session has no receive time we can trust,
     * and caching would stamp it as fresh (RFC 8446 4.6.1). */
    return ERR_OK;
}

void altcp_tls_free_session(struct altcp_tls_session *dest)
{
    LWIP_UNUSED_ARG(dest);
    /* Nothing to free */
}

#endif /* LWIP_ALTCP_TLS */

#endif /* LWIP_ALTCP */
