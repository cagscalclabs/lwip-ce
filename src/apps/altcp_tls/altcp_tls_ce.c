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
#include "lwip/priv/altcp_priv.h"
#include "lwip/mem.h"
#include <ti/vars.h>
#include "altcp_tls_ce.h"
#include "../../tls/includes/aes.h"
#include "../../tls/includes/bytes.h"
#include "../../tls/includes/handshake.h"
#include "../../drivers/mem.h"

#include <string.h>
#include <limits.h>
#include <fileioc.h>

/* Temporary debug display for on-calc TLS handshake tracing.
 * Remove once handshake is working. */
#include <ti/screen.h>
#define TLS_DBG_Y 90
#define TLS_DBG_VRAM ((uint16_t *)0xD40000)
static void tls_dbg_status(const char *msg)
{
    /* Clear line at y=90, 320 wide, 12 tall */
    for (int row = TLS_DBG_Y; row < TLS_DBG_Y + 12; row++)
    {
        uint16_t *ptr = TLS_DBG_VRAM + row * 320;
        for (int col = 0; col < 320; col++)
            *ptr++ = 0xFFFF;
    }
    os_FontDrawText(msg, 10, TLS_DBG_Y);
}

/* Debug flag for TLS CE layer */
#ifndef ALTCP_TLS_CE_DEBUG
#define ALTCP_TLS_CE_DEBUG LWIP_DBG_OFF
#endif

static enum mem_pressure_level g_tls_rx_throttle_level = MEM_PRESSURE_NONE;
static altcp_tls_ce_state_t *g_tls_state_head = NULL;

#define ALTCP_TLS_CE_PSKI_APPVAR "lwIPPSKI"
#define ALTCP_TLS_CE_PSKI_MAGIC 0x49534B50u /* "PSKI" */
#define ALTCP_TLS_CE_PSKI_VERSION 2u
#define ALTCP_TLS_CE_PSKI_HOSTNAME_MAX 64

/* Persisted TLS PSK identity record. Bound to a hostname so a saved
 * session is only ever offered back to the server it came from. Older
 * v1 blobs lack the hostname field; load_pski treats them as a no-match
 * (an opportunistic resumption that fails just falls back to ECDHE). */
struct altcp_tls_ce_pski_blob
{
    uint32_t magic;
    uint16_t version;
    uint16_t psk_type;
    uint8_t psk[32];
    char hostname[ALTCP_TLS_CE_PSKI_HOSTNAME_MAX];  /* NUL-terminated */
    struct tls_psk_identity identity;
};

static bool altcp_tls_ce_save_pski(const struct altcp_tls_session *session,
                                   const char *hostname)
{
    uint8_t handle;
    struct altcp_tls_ce_pski_blob blob;

    if (!session || !session->valid || !hostname ||
        session->identity.identity_len > sizeof(session->identity.identity))
    {
        return false;
    }
    size_t host_len = strlen(hostname);
    if (host_len == 0 || host_len >= sizeof(blob.hostname))
    {
        /* Hostnames that don't fit can't be safely resumed; skip persistence
         * rather than truncating (truncation could match the wrong host). */
        return false;
    }

    memset(&blob, 0, sizeof(blob));
    blob.magic = ALTCP_TLS_CE_PSKI_MAGIC;
    blob.version = ALTCP_TLS_CE_PSKI_VERSION;
    blob.psk_type = session->psk_type;
    memcpy(blob.psk, session->psk, sizeof(blob.psk));
    memcpy(blob.hostname, hostname, host_len + 1);  /* +1 for NUL */
    memcpy(&blob.identity, &session->identity, sizeof(blob.identity));

    handle = ti_Open(ALTCP_TLS_CE_PSKI_APPVAR, "w");
    if (!handle)
    {
        return false;
    }
    if (ti_Write(&blob, sizeof(blob), 1, handle) != 1)
    {
        ti_Close(handle);
        return false;
    }
    ti_Close(handle);
    return true;
}

/* Load a saved PSK identity only if it was issued for `hostname`. Older
 * v1 blobs (no hostname field) fail this check by version mismatch and
 * are silently ignored; the caller falls back to a fresh ECDHE handshake
 * and may write a fresh v2 blob via NewSessionTicket. */
static bool altcp_tls_ce_load_pski(struct altcp_tls_session *session,
                                   const char *hostname)
{
    uint8_t handle;
    struct altcp_tls_ce_pski_blob blob;

    if (!session || !hostname)
    {
        return false;
    }

    handle = ti_Open(ALTCP_TLS_CE_PSKI_APPVAR, "r");
    if (!handle)
    {
        return false;
    }
    if (ti_Read(&blob, sizeof(blob), 1, handle) != 1)
    {
        ti_Close(handle);
        return false;
    }
    ti_Close(handle);

    if (blob.magic != ALTCP_TLS_CE_PSKI_MAGIC ||
        blob.version != ALTCP_TLS_CE_PSKI_VERSION ||
        blob.identity.identity_len > sizeof(blob.identity.identity))
    {
        return false;
    }
    /* Hostname match is mandatory. Force NUL-termination in case the
     * stored field was tampered with. */
    blob.hostname[sizeof(blob.hostname) - 1] = '\0';
    if (strcmp(blob.hostname, hostname) != 0)
    {
        return false;
    }

    memset(session, 0, sizeof(*session));
    session->valid = 1;
    session->psk_type = (uint8_t)blob.psk_type;
    if (session->psk_type != TLS_PSK_TYPE_EXTERNAL)
    {
        session->psk_type = TLS_PSK_TYPE_RESUMPTION;
    }
    memcpy(session->psk, blob.psk, sizeof(session->psk));
    memcpy(&session->identity, &blob.identity, sizeof(session->identity));
    return true;
}

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

/* Forward declarations */
static err_t altcp_tls_ce_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_tls_ce_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);
static err_t altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);
static void altcp_tls_ce_lower_recved(struct altcp_pcb *inner_conn, int recvd_cnt);

static void altcp_tls_ce_build_aead_nonce(const uint8_t iv[12], uint64_t seq_num,
                                          uint8_t out_nonce[12])
{
    memcpy(out_nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
    {
        out_nonce[4 + i] ^= (uint8_t)((seq_num >> (56 - i * 8)) & 0xFF);
    }
}

/* Chunk size for streaming AEAD passes. Sized to amortize per-call AES
 * overhead while keeping the working set well under one TLS record. */
#ifndef ALTCP_TLS_CE_STREAM_CHUNK
#define ALTCP_TLS_CE_STREAM_CHUNK 2048
#endif

/* Walk `len` ciphertext bytes from `src` starting at `src_offset`, feeding
 * each byte into the GHASH-only update path. No plaintext is produced and
 * no CTR keystream is touched. Used as Pass 1 of the streaming decrypt
 * before we trust any of the record contents.
 *
 * Walks pbuf segments directly to avoid materializing the ciphertext into
 * a contiguous buffer. */
static err_t altcp_tls_ce_pbuf_ghash(struct tls_aes_context *aes_ctx,
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
        if (!tls_aes_update_ciphertext(aes_ctx,
                                       (const uint8_t *)q->payload + inner,
                                       take))
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
 *  Pass 1: GHASH the entire ciphertext (no decryption), then verify the
 *          16-byte tag against the trailer. Tag mismatch is fatal and the
 *          input rx chain is left intact for the caller to free.
 *  Pass 2: Re-init AES-GCM and walk the ciphertext in ALTCP_TLS_CE_STREAM_CHUNK
 *          strides. Each stride is copied from the head of `state->rx` into
 *          a scratch buffer, decrypted in place, and appended to a fresh
 *          output pbuf chain. After each stride we release the consumed
 *          bytes from `state->rx` via pbuf_free_header and ack them with
 *          altcp_tls_ce_lower_recved. The 5-byte header is released first
 *          (before pass 2 starts), and the 16-byte tag is released after
 *          the last stride.
 *
 * Peak working set during pass 2 is (record_size - consumed) + chunk_scratch
 * + (output pbuf chain so far). Input and output sum stays bounded near
 * record_size — at no point are both copies live at full size.
 *
 * On success, *plaintext is a pbuf chain containing the decrypted record
 * with trailing zero padding and the inner content-type byte stripped.
 * *written is its length and *inner_content_type is the discovered type. */
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
    uint8_t computed_tag[16];
    uint8_t received_tag[16];
    struct tls_aes_context aes_ctx;
    struct pbuf *out_head = NULL;
    struct pbuf *out_tail = NULL;
    struct tls_handshake_context *ctx = &state->tls_ctx;
    const uint8_t *key;
    const uint8_t *iv;
    uint64_t *seq_num;
    size_t ciphertext_len;
    size_t actual_plaintext_len;
    size_t processed;
    uint8_t *scratch = NULL;
    uint8_t diff = 0;

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
    if (actual_plaintext_len == 0 ||
        actual_plaintext_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 1)
    {
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

    /* Pass 1: GHASH-only verification over the ciphertext. */
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, sizeof(nonce)) ||
        !tls_aes_update_aad(&aes_ctx, header, sizeof(header)))
    {
        return ERR_VAL;
    }
    if (altcp_tls_ce_pbuf_ghash(&aes_ctx, state->rx, sizeof(header),
                                actual_plaintext_len) != ERR_OK)
    {
        return ERR_VAL;
    }
    if (!tls_aes_digest(&aes_ctx, computed_tag))
    {
        return ERR_VAL;
    }
    if (pbuf_copy_partial(state->rx, received_tag, sizeof(received_tag),
                          (u16_t)(sizeof(header) + actual_plaintext_len)) != sizeof(received_tag))
    {
        return ERR_BUF;
    }
    for (size_t i = 0; i < sizeof(computed_tag); i++)
    {
        diff |= computed_tag[i] ^ received_tag[i];
    }
    if (diff != 0)
    {
        return ERR_VAL;
    }

    /* Tag verified. Re-init AES for the decrypt pass. */
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, sizeof(nonce)) ||
        !tls_aes_update_aad(&aes_ctx, header, sizeof(header)))
    {
        return ERR_VAL;
    }

    scratch = (uint8_t *)mem_buffer_custom_malloc(ALTCP_TLS_CE_STREAM_CHUNK);
    if (!scratch)
    {
        return ERR_MEM;
    }

    /* Release the 5-byte header from the input pbuf and ack it. */
    state->rx = pbuf_free_header(state->rx, (u16_t)sizeof(header));
    altcp_tls_ce_lower_recved(conn->inner_conn, (int)sizeof(header));

    /* Pass 2: chunked decrypt-and-accumulate, releasing input as we go. */
    processed = 0;
    while (processed < actual_plaintext_len)
    {
        size_t take = LWIP_MIN(ALTCP_TLS_CE_STREAM_CHUNK,
                               actual_plaintext_len - processed);
        struct pbuf *out_seg;

        if (pbuf_copy_partial(state->rx, scratch, (u16_t)take, 0) != take)
        {
            goto fail;
        }
        if (!tls_aes_decrypt(&aes_ctx, scratch, take, scratch))
        {
            goto fail;
        }

        out_seg = pbuf_alloc(PBUF_RAW, (u16_t)take, PBUF_POOL);
        if (!out_seg)
        {
            goto fail;
        }
        if (pbuf_take(out_seg, scratch, (u16_t)take) != ERR_OK)
        {
            pbuf_free(out_seg);
            goto fail;
        }
        if (!out_head)
        {
            out_head = out_seg;
            out_tail = out_seg;
        }
        else
        {
            pbuf_cat(out_tail, out_seg);
            out_tail = out_seg;
        }

        state->rx = pbuf_free_header(state->rx, (u16_t)take);
        altcp_tls_ce_lower_recved(conn->inner_conn, (int)take);
        processed += take;
    }

    /* Release the trailing 16-byte tag from the input. */
    state->rx = pbuf_free_header(state->rx, TLS_AES_AUTH_TAG_SIZE);
    altcp_tls_ce_lower_recved(conn->inner_conn, (int)TLS_AES_AUTH_TAG_SIZE);

    tls_secure_memzero(scratch, ALTCP_TLS_CE_STREAM_CHUNK);
    mem_buffer_custom_free(scratch);
    scratch = NULL;

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
            pbuf_free(out_head);
            return ERR_VAL;
        }
        *inner_content_type = pbuf_get_at(out_head, (u16_t)(pt_end - 1));
        *written = pt_end - 1;
        pbuf_realloc(out_head, (u16_t)*written);
    }

    *plaintext = out_head;
    return ERR_OK;

fail:
    if (scratch)
    {
        tls_secure_memzero(scratch, ALTCP_TLS_CE_STREAM_CHUNK);
        mem_buffer_custom_free(scratch);
    }
    if (out_head)
    {
        pbuf_free(out_head);
    }
    return ERR_VAL;
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
    struct tls_aes_context aes_ctx;
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
    if (!tls_aes_init(&aes_ctx, TLS_AES_GCM, key, 16, nonce, sizeof(nonce)) ||
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

    (*seq_num)++;
    *written = total_len;
    return true;
}

static void altcp_tls_ce_queue_rx(altcp_tls_ce_state_t *state, struct pbuf *p)
{
    if (state->rx == NULL)
    {
        state->rx = p;
    }
    else
    {
        LWIP_ASSERT("rx pbuf overflow", (int)state->rx->tot_len + (int)p->tot_len <= 0xFFFF);
        pbuf_cat(state->rx, p);
    }
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
        return false;
    }
    err_t err = altcp_write(state->conn->inner_conn, data, (u16_t)len,
                            TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
    {
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
        return NULL;
    }

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 0;
    conf->psk_mode = 1;
    conf->psk_type = TLS_PSK_TYPE_EXTERNAL;
    memcpy(conf->psk, psk, 32);
    memcpy(&conf->psk_identity, psk_identity, sizeof(struct tls_psk_identity));

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
        return NULL;
    }

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
    struct altcp_tls_session resumed;

    conf = (struct altcp_tls_ce_config *)mem_malloc(sizeof(struct altcp_tls_ce_config));
    if (conf == NULL)
    {
        return NULL;
    }

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 0;
    conf->psk_mode = 0;
    conf->hostname = hostname;

    /* Opportunistically resume from persisted PSK identity state, but
     * only if the saved blob's hostname matches the one we're about to
     * connect to. Cross-host PSK reuse is a protocol violation; a
     * mismatch silently falls back to a fresh ECDHE handshake. */
    memset(&resumed, 0, sizeof(resumed));
    if (hostname && altcp_tls_ce_load_pski(&resumed, hostname) && resumed.valid)
    {
        conf->psk_mode = 1;
        conf->psk_type = resumed.psk_type;
        memcpy(conf->psk, resumed.psk, sizeof(conf->psk));
        memcpy(&conf->psk_identity, &resumed.identity, sizeof(conf->psk_identity));
    }

    return conf;
}

void altcp_tls_ce_free_config(struct altcp_tls_ce_config *conf)
{
    if (conf)
    {
        /* Zero sensitive data */
        memset(conf->psk, 0, 32);
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
            return ERR_MEM;
        }

        setup_err = altcp_tls_ce_setup(listen_state->conf, new_conn, accepted_conn);
        if (setup_err != ERR_OK)
        {
            altcp_free(new_conn);
            return setup_err;
        }

        return listen_conn->accept(listen_conn->arg, new_conn, err);
    }
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
            if (conn->connected)
            {
                return conn->connected(conn->arg, conn, err);
            }
        }

        state = (altcp_tls_ce_state_t *)conn->state;
        state->overhead_bytes_adjust = 0;

        /* For client: send ClientHello to initiate handshake */
        if (!((struct altcp_tls_ce_config *)state->conf)->is_server)
        {
            uint8_t record[512];
            uint8_t *client_hello = record + 5; /* Leave room for record header */
            size_t client_hello_len = 0;

            if (!tls_send_client_hello(&state->tls_ctx, client_hello,
                                       sizeof(record) - 5, &client_hello_len))
            {
                if (conn->err)
                {
                    conn->err(conn->arg, ERR_ABRT);
                }
                altcp_abort(conn);
                return ERR_ABRT;
            }

            /* Wrap in TLS record header */
            record[0] = TLS_CONTENT_TYPE_HANDSHAKE; /* 0x16 */
            record[1] = 0x03;
            record[2] = 0x01; /* TLS 1.0 for ClientHello record */
            record[3] = (uint8_t)(client_hello_len >> 8);
            record[4] = (uint8_t)(client_hello_len & 0xFF);

            size_t record_len = 5 + client_hello_len;

            /* Send ClientHello record over TCP */
            err_t write_err = altcp_write(inner_conn, record, (u16_t)record_len, TCP_WRITE_FLAG_COPY);
            altcp_output(inner_conn);

            if (write_err != ERR_OK)
            {
                if (conn->err)
                {
                    conn->err(conn->arg, write_err);
                }
                altcp_abort(conn);
                return ERR_ABRT;
            }

            state->tls_ctx.state = TLS_STATE_CLIENT_HELLO_SENT;
            tls_dbg_status("ClientHello sent");
        }

        return altcp_tls_ce_lower_recv_process(conn, state);
    }
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
        if (p != NULL)
        {
            pbuf_free(p);
        }
        altcp_close(inner_conn);
        return ERR_CLSD;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

    if (!state)
    {
        if (p != NULL)
        {
            pbuf_free(p);
        }
        altcp_close(inner_conn);
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
            if (conn->err)
            {
                conn->err(conn->arg, ERR_ABRT);
            }
            altcp_close(conn);
        }
        return ERR_OK;
    }

    /* Single ingress path: the pbuf goes onto state->rx regardless of
     * handshake/app-data phase. The record processor downstream walks
     * the chain in place; nothing copies the encrypted bytes into a
     * separate ring. */
    altcp_tls_ce_queue_rx(state, p);

    return altcp_tls_ce_lower_recv_process(conn, state);
}

/**
 * @brief Process received data (handshake or application data)
 */
static err_t
altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        /* Handle handshake phase */
        struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;

        if (config->is_server)
        {
            /* Server: expect ClientHello, send ServerHello */
            /* @todo: implement server handshake processing */
            LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: server handshake not yet implemented\n"));
            altcp_abort(conn);
            return ERR_ABRT;
        }
        else
        {
            /* Client: process complete TLS records. Each iteration peeks the
             * 5-byte header, waits for the whole record to arrive, then hands
             * off to the streaming decrypter (encrypted records) or the
             * inline plaintext handler (ServerHello / CCS / early alert). */
            while (state->rx != NULL && state->rx->tot_len >= 5)
            {
                uint8_t header[5];
                if (pbuf_copy_partial(state->rx, header, sizeof(header), 0) != sizeof(header))
                {
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                size_t rec_len = ((size_t)header[3] << 8) | (size_t)header[4];
                size_t total_len = 5 + rec_len;

                if (total_len > 0xFFFF)
                {
                    altcp_abort(conn);
                    return ERR_ABRT;
                }
                if ((size_t)state->rx->tot_len < total_len)
                {
                    break;
                }

                /* Derive handshake keys exactly once, right after ServerHello,
                 * so we can decrypt the subsequent encrypted handshake records */
                if (state->tls_ctx.state == TLS_STATE_SERVER_HELLO_RECEIVED)
                {
                    tls_dbg_status("Deriving HS keys...");
                    if (!tls_derive_handshake_keys(&state->tls_ctx))
                    {
                        tls_dbg_status("ERR: HS key derivation");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: handshake key derivation failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }
                    tls_dbg_status("HS keys derived OK");
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
                        altcp_abort(conn);
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
                        return ERR_OK;
                    }
                    if (dec_err != ERR_OK)
                    {
                        tls_dbg_status("ERR: record decrypt");
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    if (!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type,
                                                          dec_pbuf, dec_len))
                    {
                        pbuf_free(dec_pbuf);
                        tls_dbg_status("ERR: record processing");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record processing failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    pbuf_free(dec_pbuf);
                    goto record_processed;
                }

                /* Plaintext record path: only ServerHello / CCS / early alert
                 * are legal here in TLS 1.3. Records at this stage are small
                 * (well under 1 KiB), so a single flat copy is fine. */
                {
                    uint8_t *tmp = (uint8_t *)mem_malloc(total_len);
                    if (!tmp)
                    {
                        return ERR_OK;
                    }
                    if (pbuf_copy_partial(state->rx, tmp, (u16_t)total_len, 0) != total_len)
                    {
                        mem_free(tmp);
                        altcp_abort(conn);
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
                                plaintext_ok = false;
                                break;
                            }
                            if (msg_type == TLS_HANDSHAKE_SERVER_HELLO)
                            {
                                if (state->tls_ctx.state != TLS_STATE_CLIENT_HELLO_SENT ||
                                    !tls_recv_server_hello(&state->tls_ctx,
                                                           payload + off,
                                                           msg_end - off))
                                {
                                    plaintext_ok = false;
                                    break;
                                }
                            }
                            else
                            {
                                /* Any other handshake message must arrive encrypted
                                 * post-ServerHello (RFC 8446 §2). Reject. */
                                plaintext_ok = false;
                                break;
                            }
                            off = msg_end;
                        }
                        if (plaintext_ok && off != rec_len)
                        {
                            plaintext_ok = false;
                        }
                    }
                    else if (header[0] == TLS_CONTENT_TYPE_ALERT)
                    {
                        if (rec_len >= 2 && tmp[5] == TLS_ALERT_LEVEL_FATAL)
                        {
                            state->tls_ctx.state = TLS_STATE_ERROR;
                        }
                    }
                    /* CCS (0x14) is silently ignored for middlebox compatibility. */

                    mem_free(tmp);
                    if (!plaintext_ok)
                    {
                        tls_dbg_status("ERR: record processing");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record processing failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }
                }

                state->rx = pbuf_free_header(state->rx, (u16_t)total_len);
                altcp_tls_ce_lower_recved(conn->inner_conn, (int)total_len);

record_processed:
                /* Show which state we reached after processing */
                switch (state->tls_ctx.state)
                {
                case TLS_STATE_SERVER_HELLO_RECEIVED:
                    tls_dbg_status("ServerHello received");
                    break;
                case TLS_STATE_HANDSHAKE_KEYS_DERIVED:
                    tls_dbg_status("HS keys derived");
                    break;
                case TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED:
                    tls_dbg_status("EncryptedExts received");
                    break;
                case TLS_STATE_CERTIFICATE_RECEIVED:
                    tls_dbg_status("Certificate received");
                    break;
                case TLS_STATE_CERTIFICATE_VERIFY_RECEIVED:
                    tls_dbg_status("CertVerify received");
                    break;
                case TLS_STATE_SERVER_FINISHED_RECEIVED:
                    tls_dbg_status("Server Finished received");
                    break;
                case TLS_STATE_ERROR:
                    tls_dbg_status("ERR: TLS state error");
                    break;
                default:
                    break;
                }
                /* Check if server Finished received — time to send client Finished */
                if (state->tls_ctx.state == TLS_STATE_SERVER_FINISHED_RECEIVED)
                {
                    /* Derive application keys BEFORE client Finished, because
                     * RFC 8446 Section 7.1 uses transcript through server Finished only.
                     * tls_send_finished() will update the transcript with client Finished. */
                    tls_dbg_status("Deriving app keys...");
                    if (!tls_derive_application_keys(&state->tls_ctx))
                    {
                        tls_dbg_status("ERR: app key derivation");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: application key derivation failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }
                    tls_dbg_status("App keys OK, sending Fin");

                    /* Generate client Finished message (plaintext handshake) */
                    uint8_t finished_hs[36];
                    size_t finished_hs_len = 0;
                    if (!tls_send_finished(&state->tls_ctx, true, finished_hs,
                                           sizeof(finished_hs), &finished_hs_len))
                    {
                        tls_dbg_status("ERR: Finished gen");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: Finished generation failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    /* Encrypt the Finished as a TLS 1.3 record */
                    uint8_t enc_finished[128];
                    size_t enc_finished_len = 0;
                    if (!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, true,
                                                            TLS_CONTENT_TYPE_HANDSHAKE,
                                                            finished_hs, finished_hs_len,
                                                            enc_finished, sizeof(enc_finished),
                                                            &enc_finished_len))
                    {
                        tls_dbg_status("ERR: Finished encrypt");
                        LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: Finished encryption failed\n"));
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    err_t write_err = altcp_write(conn->inner_conn, enc_finished,
                                                  (u16_t)enc_finished_len, TCP_WRITE_FLAG_COPY);
                    altcp_output(conn->inner_conn);

                    if (write_err != ERR_OK)
                    {
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    tls_dbg_status("Finished sent, HS done!");

                    /* Handshake complete */
                    state->flags |= ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE;
                    state->tls_ctx.state = TLS_STATE_HANDSHAKE_COMPLETE;

                    /* Persist existing resumption PSK identity payload for future connects.
                     * Fresh tickets are handled below by NewSessionTicket. */
                    if (state->tls_ctx.psk_mode &&
                        state->tls_ctx.psk_type == TLS_PSK_TYPE_RESUMPTION &&
                        state->tls_ctx.psk_identity.identity_len > 0 &&
                        state->tls_ctx.psk_identity.identity_len <= sizeof(state->tls_ctx.psk_identity.identity))
                    {
                        struct altcp_tls_session session_blob;
                        struct altcp_tls_ce_config *cfg = (struct altcp_tls_ce_config *)state->conf;
                        memset(&session_blob, 0, sizeof(session_blob));
                        session_blob.valid = 1;
                        session_blob.psk_type = state->tls_ctx.psk_type;
                        memcpy(session_blob.psk, state->tls_ctx.psk, sizeof(session_blob.psk));
                        memcpy(&session_blob.identity, &state->tls_ctx.psk_identity, sizeof(session_blob.identity));
                        (void)altcp_tls_ce_save_pski(&session_blob,
                                                     cfg ? cfg->hostname : NULL);
                    }

                    /* Notify upper layer */
                    if (conn->connected)
                    {
                        err_t err = conn->connected(conn->arg, conn, ERR_OK);
                        if (err != ERR_OK)
                        {
                            return err;
                        }
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
static err_t
altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    LWIP_ASSERT("state != NULL", state != NULL);

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
        uint8_t header[5];
        pbuf_copy_partial(state->rx, header, 5, 0);

        size_t rec_payload_len = ((size_t)header[3] << 8) | (size_t)header[4];
        size_t total_rec_len = 5 + rec_payload_len;

        if ((size_t)state->rx->tot_len < total_rec_len)
        {
            break;
        }

        if (header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA)
        {
            /* All post-handshake records must arrive AEAD-wrapped inside an
             * application_data outer record (RFC 8446 §5). Any plaintext
             * here is a protocol violation. */
            altcp_abort(conn);
            return ERR_ABRT;
        }

        size_t dec_len = 0;
        uint8_t inner_type = 0;
        struct pbuf *dec_pbuf = NULL;
        err_t dec_err = altcp_tls_ce_decrypt_record_stream(state, conn,
                                                           false, total_rec_len,
                                                           &dec_pbuf, &dec_len,
                                                           &inner_type);
        if (dec_err == ERR_MEM)
        {
            return ERR_OK;
        }
        if (dec_err != ERR_OK)
        {
            altcp_abort(conn);
            return ERR_ABRT;
        }

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
            if (dec_len > 0)
            {
                if (!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type,
                                                      dec_pbuf, dec_len))
                {
                    pbuf_free(dec_pbuf);
                    altcp_abort(conn);
                    return ERR_ABRT;
                }
                /* Side-effect: NewSessionTicket may have updated the PSK store;
                 * persist any fresh resumption identity that landed in ctx. */
                if (state->tls_ctx.psk_mode &&
                    state->tls_ctx.psk_type == TLS_PSK_TYPE_RESUMPTION &&
                    state->tls_ctx.psk_identity.identity_len > 0 &&
                    state->tls_ctx.psk_identity.identity_len <= sizeof(state->tls_ctx.psk_identity.identity))
                {
                    struct altcp_tls_session session_blob;
                    struct altcp_tls_ce_config *cfg = (struct altcp_tls_ce_config *)state->conf;
                    memset(&session_blob, 0, sizeof(session_blob));
                    session_blob.valid = 1;
                    session_blob.psk_type = TLS_PSK_TYPE_RESUMPTION;
                    memcpy(session_blob.psk, state->tls_ctx.psk, sizeof(session_blob.psk));
                    memcpy(&session_blob.identity, &state->tls_ctx.psk_identity, sizeof(session_blob.identity));
                    (void)altcp_tls_ce_save_pski(&session_blob,
                                                 cfg ? cfg->hostname : NULL);
                }
            }
            pbuf_free(dec_pbuf);
        }
        else if (inner_type == TLS_CONTENT_TYPE_ALERT)
        {
            if (dec_len >= 2 && pbuf_get_at(dec_pbuf, 0) == TLS_ALERT_LEVEL_FATAL)
            {
                pbuf_free(dec_pbuf);
                altcp_abort(conn);
                return ERR_ABRT;
            }
            pbuf_free(dec_pbuf);
        }
        else
        {
            /* Unknown inner content type — ignore per RFC 8446 §5.1 forward-compat. */
            pbuf_free(dec_pbuf);
        }

        err_t err = altcp_tls_ce_pass_rx_data(conn, state);
        if (err != ERR_OK)
        {
            if (err == ERR_ABRT)
            {
                return ERR_ABRT;
            }
            return ERR_OK;
        }
    }

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
 */
static void
altcp_tls_ce_lower_err(void *arg, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    if (conn)
    {
        conn->inner_conn = NULL; /* already freed */
        if (conn->err)
        {
            conn->err(conn->arg, err);
        }
        altcp_free(conn);
    }
}

/* ========== Setup Functions ========== */

static void
altcp_tls_ce_remove_callbacks(struct altcp_pcb *inner_conn)
{
    altcp_arg(inner_conn, NULL);
    altcp_recv(inner_conn, NULL);
    altcp_sent(inner_conn, NULL);
    altcp_err(inner_conn, NULL);
    altcp_poll(inner_conn, NULL, inner_conn->pollinterval);
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
    struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)conf;
    altcp_tls_ce_state_t *state;

    if (!conf)
    {
        return ERR_ARG;
    }
    LWIP_ASSERT("invalid inner_conn", conn != inner_conn);

    /* Allocate state */
    state = (altcp_tls_ce_state_t *)mem_malloc(sizeof(altcp_tls_ce_state_t));
    if (state == NULL)
    {
        return ERR_MEM;
    }

    memset(state, 0, sizeof(altcp_tls_ce_state_t));
    state->conf = conf;
    state->conn = conn;

    /* Initialize TLS handshake context */
    if (config->psk_mode)
    {
        if (!tls_handshake_init(&state->tls_ctx, config->psk, &config->psk_identity))
        {
            mem_free(state);
            return ERR_MEM;
        }
        state->tls_ctx.psk_type = config->psk_type;
    }
    else
    {
        if (!tls_handshake_init(&state->tls_ctx, NULL, NULL))
        {
            mem_free(state);
            return ERR_MEM;
        }
    }

    /* Set SNI hostname if configured */
    state->tls_ctx.hostname = config->hostname;

    /* Wire the transport write hook so handshake.c can emit alerts and
     * close_notify without depending on lwIP/altcp directly. */
    tls_set_transport(&state->tls_ctx, altcp_tls_ce_transport_write, state);

    altcp_tls_ce_setup_callbacks(conn, inner_conn);
    conn->inner_conn = inner_conn;
    conn->fns = &altcp_tls_ce_functions;
    conn->state = state;
    state->rx_throttle_pending = 0;
    state->rx_mild_toggle = 0;
    tls_state_add(state);

    return ERR_OK;
}

/* ========== Public API ========== */

struct altcp_pcb *
altcp_tls_ce_wrap(struct altcp_tls_ce_config *config, struct altcp_pcb *inner_pcb)
{
    struct altcp_pcb *ret;

    if (inner_pcb == NULL)
    {
        return NULL;
    }

    ret = altcp_alloc();
    if (ret != NULL)
    {
        if (altcp_tls_ce_setup(config, ret, inner_pcb) != ERR_OK)
        {
            altcp_free(ret);
            return NULL;
        }
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
        return NULL;
    }

    ret = altcp_tls_ce_wrap(config, inner_pcb);
    if (ret == NULL)
    {
        altcp_close(inner_pcb);
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
            size_t pending = state->rx_throttle_pending;
            while (pending > 0 && state->conn && state->conn->inner_conn)
            {
                int chunk = (pending > (size_t)INT_MAX) ? INT_MAX : (int)pending;
                altcp_tls_ce_lower_recved(state->conn->inner_conn, chunk);
                pending -= (size_t)chunk;
            }
            state->rx_throttle_pending = 0;
            state->rx_mild_toggle = 0;
            state = state->next;
        }
    }
    else
    {
        altcp_tls_ce_state_t *state = g_tls_state_head;
        while (state)
        {
            state->rx_mild_toggle = 0;
            state = state->next;
        }
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
    u16_t lower_recved;
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

    lower_recved = len;
    if (lower_recved > state->rx_passed_unrecved)
    {
        lower_recved = (u16_t)state->rx_passed_unrecved;
    }
    state->rx_passed_unrecved -= lower_recved;

    uint8_t throttle_div = 1u;
    switch (g_tls_rx_throttle_level)
    {
    case MEM_PRESSURE_NONE:
        throttle_div = 1u;
        break;
    case MEM_PRESSURE_MILD:
        throttle_div = 2u;
        break;
    case MEM_PRESSURE_HIGH:
        throttle_div = 4u;
        break;
    case MEM_PRESSURE_SEVERE:
        throttle_div = 8u;
        break;
    case MEM_PRESSURE_CRITICAL:
        throttle_div = 0u;
        break;
    default:
        throttle_div = 2u;
        break;
    }

    if (throttle_div == 0u)
    {
        state->rx_throttle_pending += lower_recved;
        return;
    }
    if (throttle_div > 1u)
    {
        state->rx_throttle_pending += lower_recved;
        state->rx_mild_toggle = (uint8_t)((state->rx_mild_toggle + 1u) % throttle_div);
        if (state->rx_mild_toggle != 0u)
        {
            return;
        }
        if (state->rx_throttle_pending > 0 && conn->inner_conn)
        {
            size_t pending = state->rx_throttle_pending;
            int chunk = (pending > (size_t)INT_MAX) ? INT_MAX : (int)pending;
            altcp_tls_ce_lower_recved(conn->inner_conn, chunk);
            state->rx_throttle_pending -= (size_t)chunk;
        }
        return;
    }

    altcp_recved(conn->inner_conn, lower_recved);
}

static err_t
altcp_tls_ce_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
    if (conn == NULL)
    {
        return ERR_VAL;
    }
    conn->connected = connected;
    return altcp_connect(conn->inner_conn, ipaddr, port, altcp_tls_ce_lower_connected);
}

static struct altcp_pcb *
altcp_tls_ce_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
    struct altcp_pcb *lpcb;

    if (conn == NULL)
    {
        return NULL;
    }

    lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
    if (lpcb != NULL)
    {
        conn->inner_conn = lpcb;
        altcp_accept(lpcb, altcp_tls_ce_lower_accept);
        return conn;
    }
    return NULL;
}

static void
altcp_tls_ce_abort(struct altcp_pcb *conn)
{
    if (conn != NULL)
    {
        altcp_abort(conn->inner_conn);
    }
}

static err_t
altcp_tls_ce_close(struct altcp_pcb *conn)
{
    struct altcp_pcb *inner_conn;

    if (conn == NULL)
    {
        return ERR_VAL;
    }

    /* Best-effort: send TLS close_notify before tearing down the TCP side.
     * If the handshake never completed, tls_send_close_notify will simply
     * emit a plaintext alert (or skip if no transport is wired). */
    if (conn->state)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        if (state && (state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
        {
            (void)tls_send_close_notify(&state->tls_ctx);
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
            /* Not closed, restore callbacks */
            altcp_tls_ce_setup_callbacks(conn, inner_conn);
            altcp_poll(inner_conn, oldpoll, inner_conn->pollinterval);
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
        return ERR_VAL;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL)
    {
        return ERR_ARG;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        return ERR_VAL;
    }

    /* Allocate ciphertext buffer: 5 header + len + 1 content_type + 16 tag */
    size_t ct_buf_size = (size_t)len + 22;
    uint8_t *ciphertext = (uint8_t *)mem_malloc(ct_buf_size);
    if (!ciphertext)
    {
        return ERR_MEM;
    }

    /* Encrypt data as a TLS record (includes 5-byte header + ciphertext + tag) */
    if (!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, false,
                                            TLS_CONTENT_TYPE_APPLICATION_DATA,
                                            (const uint8_t *)dataptr, len,
                                            ciphertext, ct_buf_size, &ciphertext_len))
    {
        mem_free(ciphertext);
        return ERR_MEM;
    }

    /* Send encrypted record over TCP */
    err_t err = altcp_write(conn->inner_conn, ciphertext, (u16_t)ciphertext_len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK)
    {
        altcp_output(conn->inner_conn);
        state->overhead_bytes_adjust -= len;
        state->overhead_bytes_adjust += ciphertext_len;
    }

    mem_free(ciphertext);
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
            if (state->rx_app)
            {
                pbuf_free(state->rx_app);
                state->rx_app = NULL;
            }

            tls_state_remove(state);
            state->conn = NULL;
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
    return NULL;
}

struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *cert, size_t cert_len)
{
    LWIP_UNUSED_ARG(cert);
    LWIP_UNUSED_ARG(cert_len);
    /* Certificate-based client config not supported; use PSK via altcp_tls_ce API */
    return NULL;
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
    return NULL;
}

int altcp_tls_configure_alpn_protocols(struct altcp_tls_config *conf, const char **protos)
{
    LWIP_UNUSED_ARG(conf);
    LWIP_UNUSED_ARG(protos);
    /* ALPN not yet supported on CE */
    return -1;
}

void altcp_tls_free_config(struct altcp_tls_config *conf)
{
    altcp_tls_ce_free_config((struct altcp_tls_ce_config *)conf);
}

void altcp_tls_free_entropy(void)
{
    /* No global entropy state on CE */
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
            struct altcp_tls_ce_config *cfg = (struct altcp_tls_ce_config *)state->conf;
            dest->valid = 1;
            dest->psk_type = state->tls_ctx.psk_type;
            memcpy(dest->psk, state->tls_ctx.psk, sizeof(dest->psk));
            memcpy(&dest->identity, &state->tls_ctx.psk_identity, sizeof(dest->identity));
            (void)altcp_tls_ce_save_pski(dest, cfg ? cfg->hostname : NULL);
            return ERR_OK;
        }
    }

    /* No live conn / no in-flight session: can't safely load without
     * knowing the target hostname. The conn-attached create path
     * (altcp_tls_ce_create_config_client_ecdhe) is the host-aware way
     * to do an opportunistic resume. */
    return ERR_VAL;
}

err_t altcp_tls_set_session(struct altcp_pcb *conn, struct altcp_tls_session *from)
{
    uint8_t psk_type;

    if (!from || !from->valid ||
        from->identity.identity_len == 0 ||
        from->identity.identity_len > sizeof(from->identity.identity))
    {
        return ERR_ARG;
    }

    psk_type = from->psk_type;
    if (psk_type != TLS_PSK_TYPE_EXTERNAL)
    {
        psk_type = TLS_PSK_TYPE_RESUMPTION;
    }

    const char *hostname = NULL;
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
            hostname = conf->hostname;
        }
        memcpy(state->tls_ctx.psk, from->psk, sizeof(state->tls_ctx.psk));
        memcpy(&state->tls_ctx.psk_identity, &from->identity, sizeof(state->tls_ctx.psk_identity));
        state->tls_ctx.psk_mode = true;
        state->tls_ctx.psk_type = psk_type;
    }

    from->psk_type = psk_type;
    /* Persist only if we have a hostname to bind the session to; without
     * one we can't safely cache (cross-host PSK reuse is a protocol bug). */
    if (hostname)
    {
        (void)altcp_tls_ce_save_pski(from, hostname);
    }
    return ERR_OK;
}

void altcp_tls_free_session(struct altcp_tls_session *dest)
{
    LWIP_UNUSED_ARG(dest);
    /* Nothing to free */
}

#endif /* LWIP_ALTCP_TLS */

#endif /* LWIP_ALTCP */
