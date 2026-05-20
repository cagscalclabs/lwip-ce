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
#define ALTCP_TLS_CE_PSKI_VERSION 1u

struct altcp_tls_ce_pski_blob
{
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint8_t psk[32];
    struct tls_psk_identity identity;
};

static bool altcp_tls_ce_save_pski(const struct altcp_tls_session *session)
{
    uint8_t handle;
    struct altcp_tls_ce_pski_blob blob;

    if (!session || !session->valid || session->identity.identity_len > sizeof(session->identity.identity))
    {
        return false;
    }

    memset(&blob, 0, sizeof(blob));
    blob.magic = ALTCP_TLS_CE_PSKI_MAGIC;
    blob.version = ALTCP_TLS_CE_PSKI_VERSION;
    memcpy(blob.psk, session->psk, sizeof(blob.psk));
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

static bool altcp_tls_ce_load_pski(struct altcp_tls_session *session)
{
    uint8_t handle;
    struct altcp_tls_ce_pski_blob blob;

    if (!session)
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

    memset(session, 0, sizeof(*session));
    session->valid = 1;
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

static bool tls_ring_write_pbuf(altcp_tls_ce_state_t *state, const struct pbuf *p)
{
    for (const struct pbuf *q = p; q != NULL; q = q->next)
    {
        if (!mem_buffer_push(state->rx_ring, (const uint8_t *)q->payload, q->len))
        {
            return false;
        }
    }
    return true;
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
    conf->rx_ring_size = ALTCP_TLS_CE_DEFAULT_RX_RING_SIZE;
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
    conf->rx_ring_size = ALTCP_TLS_CE_DEFAULT_RX_RING_SIZE;
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
    conf->rx_ring_size = ALTCP_TLS_CE_DEFAULT_RX_RING_SIZE;

    /* Opportunistically resume from persisted PSK identity state. */
    memset(&resumed, 0, sizeof(resumed));
    if (altcp_tls_ce_load_pski(&resumed) && resumed.valid)
    {
        conf->psk_mode = 1;
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

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE))
    {
        if (!tls_ring_write_pbuf(state, p))
        {
            pbuf_free(p);
            altcp_abort(conn);
            return ERR_ABRT;
        }
        pbuf_free(p);
    }
    else
    {
        /* Queue pbuf for application data processing */
        if (state->rx == NULL)
        {
            state->rx = p;
        }
        else
        {
            LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
            pbuf_cat(state->rx, p);
        }
    }

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
            /* Client: process complete TLS records */
            while (mem_buffer_len(state->rx_ring) >= 5)
            {
                uint8_t header[5];
                if (!mem_buffer_peek(state->rx_ring, 0, header, sizeof(header)))
                {
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                size_t rec_len = ((size_t)header[3] << 8) | (size_t)header[4];
                size_t total_len = 5 + rec_len;

                if (total_len > mem_buffer_capacity(state->rx_ring))
                {
                    size_t buffered = mem_buffer_len(state->rx_ring);
                    if (total_len > buffered)
                    {
                        if (!mem_buffer_reserve(state->rx_ring, total_len - buffered))
                        {
                            tls_dbg_status("ERR: ring full");
                            LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record exceeds ring max\n"));
                            altcp_abort(conn);
                            return ERR_ABRT;
                        }
                    }
                }
                if (mem_buffer_len(state->rx_ring) < total_len)
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

                /* Allocate temp buffer and peek complete record */
                uint8_t *tmp = (uint8_t *)mem_malloc(total_len);
                if (!tmp)
                {
                    altcp_abort(conn);
                    return ERR_ABRT;
                }
                if (!mem_buffer_peek(state->rx_ring, 0, tmp, total_len))
                {
                    mem_free(tmp);
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                if (!tls_process_record(&state->tls_ctx, tmp, total_len))
                {
                    mem_free(tmp);
                    tls_dbg_status("ERR: record processing");
                    LWIP_DEBUGF(ALTCP_TLS_CE_DEBUG, ("TLS CE: TLS record processing failed\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                mem_free(tmp);

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
                /* Discard processed data by popping into a dummy buffer */
                uint8_t discard_buf[64];
                size_t remaining = total_len;
                while (remaining > 0)
                {
                    size_t chunk = (remaining > sizeof(discard_buf)) ? sizeof(discard_buf) : remaining;
                    mem_buffer_pop(state->rx_ring, discard_buf, chunk);
                    remaining -= chunk;
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
                    if (!tls_encrypt_record(&state->tls_ctx, true,
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

                    /* Persist resumable PSK identity payload for future connects. */
                    if (state->tls_ctx.psk_mode &&
                        state->tls_ctx.psk_identity.identity_len > 0 &&
                        state->tls_ctx.psk_identity.identity_len <= sizeof(state->tls_ctx.psk_identity.identity))
                    {
                        struct altcp_tls_session session_blob;
                        memset(&session_blob, 0, sizeof(session_blob));
                        session_blob.valid = 1;
                        memcpy(session_blob.psk, state->tls_ctx.psk, sizeof(session_blob.psk));
                        memcpy(&session_blob.identity, &state->tls_ctx.psk_identity, sizeof(session_blob.identity));
                        (void)altcp_tls_ce_save_pski(&session_blob);
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

    /* Process available TLS records */
    while (state->rx != NULL && state->rx->tot_len >= 5)
    {
        /* Read the 5-byte TLS record header */
        uint8_t header[5];
        pbuf_copy_partial(state->rx, header, 5, 0);

        size_t rec_payload_len = ((size_t)header[3] << 8) | (size_t)header[4];
        size_t total_rec_len = 5 + rec_payload_len;

        /* Wait for complete record */
        if ((size_t)state->rx->tot_len < total_rec_len)
        {
            break;
        }

        /* Copy full record into temp buffer */
        uint8_t *rec_buf = (uint8_t *)mem_malloc(total_rec_len);
        if (!rec_buf)
        {
            return ERR_OK; /* Try again later */
        }
        pbuf_copy_partial(state->rx, rec_buf, (u16_t)total_rec_len, 0);

        /* Decrypt the record — allocate buffer on heap for large records */
        size_t dec_buf_size = rec_payload_len; /* plaintext <= ciphertext */
        uint8_t *dec_buf = (uint8_t *)mem_malloc(dec_buf_size);
        if (!dec_buf)
        {
            mem_free(rec_buf);
            return ERR_OK; /* Try again later */
        }
        size_t dec_len = 0;
        uint8_t inner_type = 0;

        if (!tls_decrypt_record(&state->tls_ctx, false,
                                rec_buf, total_rec_len,
                                dec_buf, dec_buf_size,
                                &dec_len, &inner_type))
        {
            mem_free(dec_buf);
            mem_free(rec_buf);
            altcp_abort(conn);
            return ERR_ABRT;
        }
        mem_free(rec_buf);

        /* Consume the record from the rx chain */
        state->rx = pbuf_free_header(state->rx, (u16_t)total_rec_len);

        state->bio_bytes_read += total_rec_len;

        if (inner_type == TLS_CONTENT_TYPE_APPLICATION_DATA)
        {
            /* Actual application data */
            if (dec_len > 0)
            {
                struct pbuf *buf = pbuf_alloc(PBUF_RAW, (u16_t)dec_len, PBUF_POOL);
                if (buf == NULL)
                {
                    mem_free(dec_buf);
                    return ERR_OK;
                }
                pbuf_take(buf, dec_buf, (u16_t)dec_len);

                state->bio_bytes_appl += dec_len;

                /* Track overhead */
                int overhead_bytes = state->bio_bytes_read - state->bio_bytes_appl;
                altcp_tls_ce_lower_recved(conn->inner_conn, overhead_bytes);
                state->bio_bytes_read = 0;
                state->bio_bytes_appl = 0;

                /* Queue decrypted data */
                if (state->rx_app == NULL)
                {
                    state->rx_app = buf;
                }
                else
                {
                    pbuf_cat(state->rx_app, buf);
                }
            }
        }
        else if (inner_type == TLS_CONTENT_TYPE_HANDSHAKE)
        {
            size_t hs_off = 0;
            while (hs_off + 4 <= dec_len)
            {
                uint8_t msg_type = dec_buf[hs_off];
                size_t msg_len = ((size_t)dec_buf[hs_off + 1] << 16) |
                                 ((size_t)dec_buf[hs_off + 2] << 8) |
                                 (size_t)dec_buf[hs_off + 3];
                size_t msg_end = hs_off + 4 + msg_len;
                if (msg_end > dec_len)
                {
                    mem_free(dec_buf);
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                if (msg_type == TLS_SERVER_HANDSHAKE_NEW_SESSION_TICKET)
                {
                    if (!tls_recv_new_session_ticket(&state->tls_ctx, dec_buf + hs_off, msg_end - hs_off))
                    {
                        mem_free(dec_buf);
                        altcp_abort(conn);
                        return ERR_ABRT;
                    }

                    struct altcp_tls_session session_blob;
                    memset(&session_blob, 0, sizeof(session_blob));
                    session_blob.valid = 1;
                    memcpy(session_blob.psk, state->tls_ctx.psk, sizeof(session_blob.psk));
                    memcpy(&session_blob.identity, &state->tls_ctx.psk_identity, sizeof(session_blob.identity));
                    (void)altcp_tls_ce_save_pski(&session_blob);
                }

                hs_off = msg_end;
            }
        }
        else if (inner_type == TLS_CONTENT_TYPE_ALERT)
        {
            /* Handle alert */
            if (dec_len >= 2 && dec_buf[0] == 2)
            {
                mem_free(dec_buf);
                altcp_abort(conn);
                return ERR_ABRT;
            }
            mem_free(dec_buf);
            continue;
        }
        mem_free(dec_buf);
        /* Ignore other inner types */

        /* Pass data to application */
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
            if (altcp_tls_ce_handle_rx_appldata(conn, state) == ERR_ABRT)
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
    size_t ring_size = config->rx_ring_size ? config->rx_ring_size : ALTCP_TLS_CE_DEFAULT_RX_RING_SIZE;
    size_t ring_max_size = ALTCP_TLS_CE_MAX_RX_RING_SIZE;
    if (ring_max_size < ring_size)
    {
        ring_max_size = ring_size;
    }
    state->rx_ring = mem_buffer_create(MEM_BUFFER_RING, ring_size, ring_max_size, 1024, 0);
    if (state->rx_ring == NULL)
    {
        mem_free(state);
        return ERR_MEM;
    }
    mem_buffer_set_grow(state->rx_ring, 85, 1024);
    mem_buffer_set_shrink(state->rx_ring, 40, 1024);

    /* Initialize TLS handshake context */
    if (config->psk_mode)
    {
        if (!tls_handshake_init(&state->tls_ctx, config->psk, &config->psk_identity))
        {
            mem_buffer_destroy(state->rx_ring);
            mem_free(state);
            return ERR_MEM;
        }
    }
    else
    {
        if (!tls_handshake_init(&state->tls_ctx, NULL, NULL))
        {
            mem_buffer_destroy(state->rx_ring);
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
    if (!tls_encrypt_record(&state->tls_ctx, false,
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

            if (state->rx_ring)
            {
                mem_buffer_destroy(state->rx_ring);
                state->rx_ring = NULL;
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
            dest->valid = 1;
            memcpy(dest->psk, state->tls_ctx.psk, sizeof(dest->psk));
            memcpy(&dest->identity, &state->tls_ctx.psk_identity, sizeof(dest->identity));
            (void)altcp_tls_ce_save_pski(dest);
            return ERR_OK;
        }
    }

    if (altcp_tls_ce_load_pski(dest) && dest->valid)
    {
        return ERR_OK;
    }

    return ERR_VAL;
}

err_t altcp_tls_set_session(struct altcp_pcb *conn, struct altcp_tls_session *from)
{
    if (!from || !from->valid ||
        from->identity.identity_len == 0 ||
        from->identity.identity_len > sizeof(from->identity.identity))
    {
        return ERR_ARG;
    }

    if (conn && conn->state)
    {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        struct altcp_tls_ce_config *conf = (struct altcp_tls_ce_config *)state->conf;
        if (conf)
        {
            conf->psk_mode = 1;
            memcpy(conf->psk, from->psk, sizeof(conf->psk));
            memcpy(&conf->psk_identity, &from->identity, sizeof(conf->psk_identity));
        }
        memcpy(state->tls_ctx.psk, from->psk, sizeof(state->tls_ctx.psk));
        memcpy(&state->tls_ctx.psk_identity, &from->identity, sizeof(state->tls_ctx.psk_identity));
        state->tls_ctx.psk_mode = true;
    }

    (void)altcp_tls_ce_save_pski(from);
    return ERR_OK;
}

void altcp_tls_free_session(struct altcp_tls_session *dest)
{
    LWIP_UNUSED_ARG(dest);
    /* Nothing to free */
}

#endif /* LWIP_ALTCP_TLS */

#endif /* LWIP_ALTCP */
