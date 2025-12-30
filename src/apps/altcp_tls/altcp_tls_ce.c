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
#include "lwip/priv/altcp_priv.h"
#include "altcp_tls_ce.h"
#include "../../tls/includes/handshake.h"

#include <string.h>

/* Forward declarations */
static err_t altcp_tls_ce_lower_recv(void *arg, struct altcp_pcb *inner_conn, struct pbuf *p, err_t err);
static err_t altcp_tls_ce_setup(void *conf, struct altcp_pcb *conn, struct altcp_pcb *inner_conn);
static err_t altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);
static err_t altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state);

/* Variable prototype for function table */
extern const struct altcp_functions altcp_tls_ce_functions;

/* ========== Configuration Management ========== */

struct altcp_tls_ce_config *altcp_tls_ce_create_config_psk_client(
    const u8_t psk[32],
    const struct tls_psk_identity *psk_identity)
{
    struct altcp_tls_ce_config *conf;

    conf = (struct altcp_tls_ce_config *)mem_malloc(sizeof(struct altcp_tls_ce_config));
    if (conf == NULL) {
        return NULL;
    }

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 0;
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
    if (conf == NULL) {
        return NULL;
    }

    memset(conf, 0, sizeof(struct altcp_tls_ce_config));
    conf->is_server = 1;
    memcpy(conf->psk, psk, 32);
    memcpy(&conf->psk_identity, psk_identity, sizeof(struct tls_psk_identity));

    return conf;
}

void altcp_tls_ce_free_config(struct altcp_tls_ce_config *conf)
{
    if (conf) {
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
    if (listen_conn && listen_conn->state && listen_conn->accept) {
        err_t setup_err;
        altcp_tls_ce_state_t *listen_state = (altcp_tls_ce_state_t *)listen_conn->state;

        /* Create new altcp_pcb for accepted connection */
        struct altcp_pcb *new_conn = altcp_alloc();
        if (new_conn == NULL) {
            return ERR_MEM;
        }

        setup_err = altcp_tls_ce_setup(listen_state->conf, new_conn, accepted_conn);
        if (setup_err != ERR_OK) {
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

    if (conn && conn->state) {
        altcp_tls_ce_state_t *state;
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        /* Upper connected callback called after handshake completes */
        if (err != ERR_OK) {
            if (conn->connected) {
                return conn->connected(conn->arg, conn, err);
            }
        }

        state = (altcp_tls_ce_state_t *)conn->state;
        state->overhead_bytes_adjust = 0;

        /* For client: send ClientHello to initiate handshake */
        if (!((struct altcp_tls_ce_config *)state->conf)->is_server) {
            uint8_t client_hello[512];
            size_t client_hello_len = 0;

            if (!tls_generate_client_hello(&state->tls_ctx, client_hello,
                                          sizeof(client_hello), &client_hello_len)) {
                if (conn->err) {
                    conn->err(conn->arg, ERR_ABRT);
                }
                altcp_abort(conn);
                return ERR_ABRT;
            }

            /* Send ClientHello over TCP */
            err_t write_err = altcp_write(inner_conn, client_hello, (u16_t)client_hello_len, TCP_WRITE_FLAG_COPY);
            altcp_output(inner_conn);

            if (write_err != ERR_OK) {
                if (conn->err) {
                    conn->err(conn->arg, write_err);
                }
                altcp_abort(conn);
                return ERR_ABRT;
            }

            state->tls_ctx.state = TLS_STATE_CLIENT_HELLO_SENT;
        }

        return altcp_tls_ce_lower_recv_process(conn, state);
    }
    return ERR_VAL;
}

/* Call recved for possibly more than u16_t */
static void
altcp_tls_ce_lower_recved(struct altcp_pcb *inner_conn, int recvd_cnt)
{
    while (recvd_cnt > 0) {
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

    if (!conn) {
        if (p != NULL) {
            pbuf_free(p);
        }
        altcp_close(inner_conn);
        return ERR_CLSD;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

    if (!state) {
        if (p != NULL) {
            pbuf_free(p);
        }
        altcp_close(inner_conn);
        return ERR_CLSD;
    }

    /* Handle NULL pbuf (connection closed) */
    if (p == NULL) {
        if ((state->flags & (ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE | ALTCP_TLS_CE_FLAGS_UPPER_CALLED)) ==
            (ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE | ALTCP_TLS_CE_FLAGS_UPPER_CALLED)) {

            if ((state->rx != NULL) || (state->rx_app != NULL)) {
                state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED;
                altcp_tls_ce_handle_rx_appldata(conn, state);
                return ERR_OK;
            }

            state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSED;
            if (conn->recv) {
                return conn->recv(conn->arg, conn, NULL, ERR_OK);
            }
        } else {
            if (conn->err) {
                conn->err(conn->arg, ERR_ABRT);
            }
            altcp_close(conn);
        }
        return ERR_OK;
    }

    /* Queue pbuf for processing */
    if (state->rx == NULL) {
        state->rx = p;
    } else {
        LWIP_ASSERT("rx pbuf overflow", (int)p->tot_len + (int)p->len <= 0xFFFF);
        pbuf_cat(state->rx, p);
    }

    return altcp_tls_ce_lower_recv_process(conn, state);
}

/**
 * @brief Process received data (handshake or application data)
 */
static err_t
altcp_tls_ce_lower_recv_process(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)) {
        /* Handle handshake phase */
        struct altcp_tls_ce_config *config = (struct altcp_tls_ce_config *)state->conf;

        if (config->is_server) {
            /* Server: expect ClientHello, send ServerHello */
            /* @todo: implement server handshake processing */
            LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: server handshake not yet implemented\n"));
            altcp_abort(conn);
            return ERR_ABRT;
        } else {
            /* Client: expect ServerHello */
            if (state->tls_ctx.state == TLS_STATE_CLIENT_HELLO_SENT && state->rx != NULL) {
                /* Copy ServerHello from pbuf chain */
                u16_t server_hello_len = state->rx->tot_len;
                uint8_t server_hello[512];

                if (server_hello_len > sizeof(server_hello)) {
                    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: ServerHello too large\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                pbuf_copy_partial(state->rx, server_hello, server_hello_len, 0);

                /* Process ServerHello */
                if (!tls_process_server_hello(&state->tls_ctx, server_hello, server_hello_len)) {
                    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: ServerHello processing failed\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                /* Free processed data */
                pbuf_free(state->rx);
                state->rx = NULL;

                /* Derive handshake keys */
                if (!tls_derive_handshake_keys(&state->tls_ctx)) {
                    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: handshake key derivation failed\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                /* Generate and send Finished message */
                uint8_t finished[36];
                size_t finished_len = 0;
                if (!tls_generate_finished(&state->tls_ctx, true, finished, sizeof(finished), &finished_len)) {
                    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: Finished generation failed\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                err_t write_err = altcp_write(conn->inner_conn, finished, (u16_t)finished_len, TCP_WRITE_FLAG_COPY);
                altcp_output(conn->inner_conn);

                if (write_err != ERR_OK) {
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                /* Derive application keys */
                if (!tls_derive_application_keys(&state->tls_ctx)) {
                    LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("TLS CE: application key derivation failed\n"));
                    altcp_abort(conn);
                    return ERR_ABRT;
                }

                /* Handshake complete */
                state->flags |= ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE;
                state->tls_ctx.state = TLS_STATE_HANDSHAKE_COMPLETE;

                /* Notify upper layer */
                if (conn->connected) {
                    err_t err = conn->connected(conn->arg, conn, ERR_OK);
                    if (err != ERR_OK) {
                        return err;
                    }
                }

                if (state->rx == NULL) {
                    return ERR_OK;
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
    if (buf) {
        state->rx_app = NULL;
        if (conn->recv) {
            u16_t tot_len = buf->tot_len;
            state->rx_passed_unrecved += tot_len;
            state->flags |= ALTCP_TLS_CE_FLAGS_UPPER_CALLED;

            err = conn->recv(conn->arg, conn, buf, ERR_OK);
            if (err != ERR_OK) {
                if (err == ERR_ABRT) {
                    return ERR_ABRT;
                }
                /* Not received, re-queue */
                LWIP_ASSERT("state == conn->state", state == conn->state);
                state->rx_app = buf;
                state->rx_passed_unrecved -= tot_len;
                LWIP_ASSERT("state->rx_passed_unrecved >= 0", state->rx_passed_unrecved >= 0);
                if (state->rx_passed_unrecved < 0) {
                    state->rx_passed_unrecved = 0;
                }
                return err;
            }
        } else {
            pbuf_free(buf);
        }
    } else if ((state->flags & (ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED | ALTCP_TLS_CE_FLAGS_RX_CLOSED)) ==
               ALTCP_TLS_CE_FLAGS_RX_CLOSE_QUEUED) {
        state->flags |= ALTCP_TLS_CE_FLAGS_RX_CLOSED;
        if (conn->recv) {
            return conn->recv(conn->arg, conn, NULL, ERR_OK);
        }
    }

    if (conn->state != state) {
        return ERR_ARG;
    }
    return ERR_OK;
}

/**
 * @brief Handle decrypting and processing application data
 */
static err_t
altcp_tls_ce_handle_rx_appldata(struct altcp_pcb *conn, altcp_tls_ce_state_t *state)
{
    LWIP_ASSERT("state != NULL", state != NULL);

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)) {
        return ERR_VAL;
    }

    /* Process available encrypted data */
    while (state->rx != NULL) {
        /* Allocate buffer for decrypted data */
        struct pbuf *buf = pbuf_alloc(PBUF_RAW, PBUF_POOL_BUFSIZE, PBUF_POOL);
        if (buf == NULL) {
            return ERR_OK;
        }

        /* Copy ciphertext from pbuf chain */
        u16_t ct_len = LWIP_MIN(state->rx->tot_len, PBUF_POOL_BUFSIZE + 16); /* +16 for tag */
        uint8_t ciphertext[PBUF_POOL_BUFSIZE + 16];
        pbuf_copy_partial(state->rx, ciphertext, ct_len, 0);

        /* Decrypt */
        size_t plaintext_len = 0;
        bool decrypt_ok = tls_decrypt_data(&state->tls_ctx, ciphertext, ct_len,
                                          (uint8_t *)buf->payload, PBUF_POOL_BUFSIZE,
                                          &plaintext_len);

        if (!decrypt_ok) {
            pbuf_free(buf);
            /* Decryption failed - possibly authentication error */
            altcp_abort(conn);
            return ERR_ABRT;
        }

        /* Remove processed ciphertext from rx chain */
        pbuf_header(state->rx, -(s16_t)ct_len);
        if (state->rx->len == 0) {
            struct pbuf *q = state->rx;
            state->rx = pbuf_dechain(state->rx);
            pbuf_free(q);
        }

        state->bio_bytes_read += ct_len;
        state->bio_bytes_appl += plaintext_len;

        if (plaintext_len > 0) {
            pbuf_realloc(buf, (u16_t)plaintext_len);

            /* Track overhead */
            int overhead_bytes = state->bio_bytes_read - state->bio_bytes_appl;
            altcp_tls_ce_lower_recved(conn->inner_conn, overhead_bytes);
            state->bio_bytes_read = 0;
            state->bio_bytes_appl = 0;

            /* Queue decrypted data */
            if (state->rx_app == NULL) {
                state->rx_app = buf;
            } else {
                pbuf_cat(state->rx_app, buf);
            }
        } else {
            pbuf_free(buf);
        }

        /* Pass data to application */
        err_t err = altcp_tls_ce_pass_rx_data(conn, state);
        if (err != ERR_OK) {
            if (err == ERR_ABRT) {
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

    if (conn) {
        int overhead;
        u16_t app_len;
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;

        LWIP_ASSERT("state", state != NULL);
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        /* Calculate TLS overhead (16-byte authentication tag per record) */
        overhead = state->overhead_bytes_adjust;
        if ((unsigned)overhead > len) {
            overhead = len;
        }

        state->overhead_bytes_adjust -= len;
        app_len = len - (u16_t)overhead;

        if (app_len) {
            state->overhead_bytes_adjust += app_len;
            if (conn->sent) {
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

    if (conn) {
        LWIP_ASSERT("pcb mismatch", conn->inner_conn == inner_conn);

        if (conn->state) {
            altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
            if (altcp_tls_ce_handle_rx_appldata(conn, state) == ERR_ABRT) {
                return ERR_ABRT;
            }
        }

        if (conn->poll) {
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
    if (conn) {
        conn->inner_conn = NULL; /* already freed */
        if (conn->err) {
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

    if (!conf) {
        return ERR_ARG;
    }
    LWIP_ASSERT("invalid inner_conn", conn != inner_conn);

    /* Allocate state */
    state = (altcp_tls_ce_state_t *)mem_malloc(sizeof(altcp_tls_ce_state_t));
    if (state == NULL) {
        return ERR_MEM;
    }

    memset(state, 0, sizeof(altcp_tls_ce_state_t));
    state->conf = conf;

    /* Initialize TLS handshake context */
    if (!tls_handshake_init(&state->tls_ctx, config->psk, &config->psk_identity)) {
        mem_free(state);
        return ERR_MEM;
    }

    altcp_tls_ce_setup_callbacks(conn, inner_conn);
    conn->inner_conn = inner_conn;
    conn->fns = &altcp_tls_ce_functions;
    conn->state = state;

    return ERR_OK;
}

/* ========== Public API ========== */

struct altcp_pcb *
altcp_tls_ce_wrap(struct altcp_tls_ce_config *config, struct altcp_pcb *inner_pcb)
{
    struct altcp_pcb *ret;

    if (inner_pcb == NULL) {
        return NULL;
    }

    ret = altcp_alloc();
    if (ret != NULL) {
        if (altcp_tls_ce_setup(config, ret, inner_pcb) != ERR_OK) {
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
    if (inner_pcb == NULL) {
        return NULL;
    }

    ret = altcp_tls_ce_wrap(config, inner_pcb);
    if (ret == NULL) {
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

static void
altcp_tls_ce_set_poll(struct altcp_pcb *conn, u8_t interval)
{
    if (conn != NULL) {
        altcp_poll(conn->inner_conn, altcp_tls_ce_lower_poll, interval);
    }
}

static void
altcp_tls_ce_recved(struct altcp_pcb *conn, u16_t len)
{
    u16_t lower_recved;
    altcp_tls_ce_state_t *state;

    if (conn == NULL) {
        return;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL) {
        return;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)) {
        return;
    }

    lower_recved = len;
    if (lower_recved > state->rx_passed_unrecved) {
        lower_recved = (u16_t)state->rx_passed_unrecved;
    }
    state->rx_passed_unrecved -= lower_recved;

    altcp_recved(conn->inner_conn, lower_recved);
}

static err_t
altcp_tls_ce_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected)
{
    if (conn == NULL) {
        return ERR_VAL;
    }
    conn->connected = connected;
    return altcp_connect(conn->inner_conn, ipaddr, port, altcp_tls_ce_lower_connected);
}

static struct altcp_pcb *
altcp_tls_ce_listen(struct altcp_pcb *conn, u8_t backlog, err_t *err)
{
    struct altcp_pcb *lpcb;

    if (conn == NULL) {
        return NULL;
    }

    lpcb = altcp_listen_with_backlog_and_err(conn->inner_conn, backlog, err);
    if (lpcb != NULL) {
        conn->inner_conn = lpcb;
        altcp_accept(lpcb, altcp_tls_ce_lower_accept);
        return conn;
    }
    return NULL;
}

static void
altcp_tls_ce_abort(struct altcp_pcb *conn)
{
    if (conn != NULL) {
        altcp_abort(conn->inner_conn);
    }
}

static err_t
altcp_tls_ce_close(struct altcp_pcb *conn)
{
    struct altcp_pcb *inner_conn;

    if (conn == NULL) {
        return ERR_VAL;
    }

    inner_conn = conn->inner_conn;
    if (inner_conn) {
        err_t err;
        altcp_poll_fn oldpoll = inner_conn->poll;

        altcp_tls_ce_remove_callbacks(conn->inner_conn);
        err = altcp_close(conn->inner_conn);

        if (err != ERR_OK) {
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
    if (conn) {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;

        if (!state || !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)) {
            return 0;
        }

        if (conn->inner_conn) {
            u16_t sndbuf = altcp_sndbuf(conn->inner_conn);
            /* Account for 16-byte authentication tag per record */
            if (sndbuf > 16) {
                return sndbuf - 16;
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
    uint8_t ciphertext[2048];
    size_t ciphertext_len = 0;

    LWIP_UNUSED_ARG(apiflags);

    if (conn == NULL) {
        return ERR_VAL;
    }

    state = (altcp_tls_ce_state_t *)conn->state;
    if (state == NULL) {
        return ERR_ARG;
    }

    if (!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)) {
        return ERR_VAL;
    }

    /* Encrypt data */
    if (!tls_encrypt_data(&state->tls_ctx, (const uint8_t *)dataptr, len,
                         ciphertext, sizeof(ciphertext), &ciphertext_len)) {
        return ERR_MEM;
    }

    /* Send encrypted data over TCP */
    err_t err = altcp_write(conn->inner_conn, ciphertext, (u16_t)ciphertext_len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK) {
        altcp_output(conn->inner_conn);
        state->overhead_bytes_adjust -= len;
        state->overhead_bytes_adjust += ciphertext_len;
    }

    return err;
}

static u16_t
altcp_tls_ce_mss(struct altcp_pcb *conn)
{
    if (conn == NULL) {
        return 0;
    }
    /* Subtract TLS overhead (16-byte tag) from MSS */
    u16_t inner_mss = altcp_mss(conn->inner_conn);
    if (inner_mss > 16) {
        return inner_mss - 16;
    }
    return 0;
}

static void
altcp_tls_ce_dealloc(struct altcp_pcb *conn)
{
    if (conn) {
        altcp_tls_ce_state_t *state = (altcp_tls_ce_state_t *)conn->state;
        if (state) {
            tls_handshake_cleanup(&state->tls_ctx);
            state->flags = 0;

            if (state->rx) {
                pbuf_free(state->rx);
                state->rx = NULL;
            }
            if (state->rx_app) {
                pbuf_free(state->rx_app);
                state->rx_app = NULL;
            }

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

#endif /* LWIP_ALTCP */
