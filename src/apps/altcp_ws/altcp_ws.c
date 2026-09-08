#include "lwip/opt.h"
#if LWIP_ALTCP

#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/priv/altcp_priv.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"
#include "altcp_ws.h"
#include "../altcp_tls/altcp_tls_ce.h"
#include "../../tls/includes/random.h"
#include "../../tls/includes/base64.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_ALTCP_WS
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_WS
#include "lwip/logging.h"

#include <string.h>
#include <stdio.h>

/* WebSocket frame flags */
#define WS_FIN          0x80u
#define WS_OP_CONT      0x00u
#define WS_OP_TEXT      0x01u
#define WS_OP_BINARY    0x02u
#define WS_OP_CLOSE     0x08u
#define WS_OP_PING      0x09u
#define WS_OP_PONG      0x0Au
#define WS_MASK_BIT     0x80u

/* Max frame header overhead: 2 base + 8 ext len + 4 mask = 14 bytes */
#define WS_MAX_FRAME_OVERHEAD 14u

/* altcp_ws_state_t flags */
#define ALTCP_WS_FLAGS_UPGRADE_DONE     0x01u
#define ALTCP_WS_FLAGS_UPPER_CALLED     0x02u
#define ALTCP_WS_FLAGS_CLOSE_SENT       0x04u
#define ALTCP_WS_FLAGS_RX_CLOSE_QUEUED  0x08u
#define ALTCP_WS_FLAGS_RECV_FRAGMENT    0x10u
#define ALTCP_WS_FLAGS_RX_CLOSED        0x20u

/* Whole frames must fit the receive window until the streaming parser exists. */
#define WS_RX_LIMIT ((TCP_WND < 65535u) ? TCP_WND : 65535u)

typedef struct altcp_ws_state
{
    altcp_ws_config_t  *conf;
    struct altcp_pcb   *conn;

    struct pbuf        *rx;                  /* raw bytes from inner layer      */
    struct pbuf        *rx_app;              /* decoded payload ready for app   */
    int                 rx_passed_unrecved;  /* payload bytes passed but not recved'd */

    int                 overhead_bytes_adjust; /* TX frame-overhead accounting  */

    uint8_t             flags;
    uint8_t             rx_opcode;           /* opcode of first fragment        */
} altcp_ws_state_t;

/* Forward declarations */
static err_t altcp_ws_lower_recv_process(struct altcp_pcb *conn,
                                         altcp_ws_state_t *state);
static err_t altcp_ws_pass_rx_data(struct altcp_pcb *conn,
                                   altcp_ws_state_t *state);
static void  altcp_ws_send_close_frame(struct altcp_pcb *conn,
                                       altcp_ws_state_t *state);
static void  altcp_ws_setup_callbacks(struct altcp_pcb *conn,
                                      struct altcp_pcb *inner);
static void  altcp_ws_remove_callbacks(struct altcp_pcb *inner);
static void  altcp_ws_dealloc(struct altcp_pcb *conn);

/* Lower-layer callback prototypes (referenced in setup_callbacks) */
static err_t altcp_ws_lower_recv(void *arg, struct altcp_pcb *inner_conn,
                                 struct pbuf *p, err_t err);
static err_t altcp_ws_lower_sent(void *arg, struct altcp_pcb *inner_conn,
                                 u16_t len);
static void  altcp_ws_lower_err(void *arg, err_t err);
static err_t altcp_ws_lower_connected(void *arg, struct altcp_pcb *inner_conn,
                                      err_t err);
static err_t altcp_ws_lower_poll(void *arg, struct altcp_pcb *inner_conn);

/* -------------------------------------------------------------------------
 * Config helpers
 * ---------------------------------------------------------------------- */

altcp_ws_config_t *altcp_ws_create_config(const char *host,
                                           const char *path,
                                           const char *subprotocol)
{
    altcp_ws_config_t *conf = (altcp_ws_config_t *)mem_malloc(sizeof(*conf));
    if (!conf)
        return NULL;
    conf->host        = host;
    conf->path        = path ? path : "/";
    conf->subprotocol = subprotocol;
    return conf;
}

void altcp_ws_free_config(altcp_ws_config_t *conf)
{
    if (conf)
        mem_free(conf);
}

/* -------------------------------------------------------------------------
 * Minimal base64 encoder for 16-byte WS key → 24-char output.
 * Used because tls_base64_encode signature may not null-terminate.
 * ---------------------------------------------------------------------- */
static void ws_base64_encode16(const uint8_t *in, char out[25])
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i < 15; i += 3)
    {
        uint32_t v = ((uint32_t)in[i] << 16) |
                     ((uint32_t)in[i+1] << 8) |
                     (uint32_t)in[i+2];
        out[o++] = tbl[(v >> 18) & 0x3F];
        out[o++] = tbl[(v >> 12) & 0x3F];
        out[o++] = tbl[(v >>  6) & 0x3F];
        out[o++] = tbl[(v >>  0) & 0x3F];
    }
    /* Last byte (index 15): pad to 3-byte group with two '=' */
    {
        uint32_t v = (uint32_t)in[15] << 16;
        out[o++] = tbl[(v >> 18) & 0x3F];
        out[o++] = tbl[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* -------------------------------------------------------------------------
 * Lower-layer callback helpers
 * ---------------------------------------------------------------------- */

static void altcp_ws_setup_callbacks(struct altcp_pcb *conn,
                                     struct altcp_pcb *inner)
{
    altcp_arg(inner, conn);
    altcp_recv(inner, altcp_ws_lower_recv);
    altcp_sent(inner, altcp_ws_lower_sent);
    altcp_err(inner, altcp_ws_lower_err);
    altcp_poll(inner, altcp_ws_lower_poll, conn->pollinterval ? conn->pollinterval : 1u);
    /* connected callback is wired at connect() time */
    (void)altcp_ws_lower_connected; /* suppress unused-function warning */
    (void)altcp_ws_lower_poll;
}

static void altcp_ws_remove_callbacks(struct altcp_pcb *inner)
{
    altcp_arg(inner, NULL);
    altcp_recv(inner, NULL);
    altcp_sent(inner, NULL);
    altcp_err(inner, NULL);
    altcp_poll(inner, NULL, 0);
}

/* -------------------------------------------------------------------------
 * HTTP Upgrade request
 * ---------------------------------------------------------------------- */

static err_t altcp_ws_send_upgrade_request(struct altcp_pcb *conn,
                                           altcp_ws_state_t *state)
{
    char buf[512];
    char key_b64[25];
    uint8_t key_raw[16];
    int n;

    tls_random_bytes(key_raw, sizeof(key_raw));
    ws_base64_encode16(key_raw, key_b64);

    if (state->conf->subprotocol)
    {
        n = snprintf(buf, sizeof(buf),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: %s\r\n"
                     "\r\n",
                     state->conf->path,
                     state->conf->host,
                     key_b64,
                     state->conf->subprotocol);
    }
    else
    {
        n = snprintf(buf, sizeof(buf),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "\r\n",
                     state->conf->path,
                     state->conf->host,
                     key_b64);
    }

    if (n <= 0 || (size_t)n >= sizeof(buf))
    {
        ERROR();
        return ERR_VAL;
    }

    err_t e = altcp_write(conn->inner_conn, buf, (u16_t)n, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK)
    {
        ERROR_CODE((int)e);
        return e;
    }
    altcp_output(conn->inner_conn);
    return ERR_OK;
}

/* -------------------------------------------------------------------------
 * Close / Ping-Pong helpers
 * ---------------------------------------------------------------------- */

static void altcp_ws_send_close_frame(struct altcp_pcb *conn,
                                      altcp_ws_state_t *state)
{
    uint8_t frame[6];
    (void)state;
    frame[0] = WS_FIN | WS_OP_CLOSE;
    frame[1] = WS_MASK_BIT | 0u; /* masked, payload len = 0 */
    tls_random_bytes(&frame[2], 4);
    altcp_write(conn->inner_conn, frame, 6, TCP_WRITE_FLAG_COPY);
    altcp_output(conn->inner_conn);
}

static void altcp_ws_send_pong(struct altcp_pcb *conn,
                               altcp_ws_state_t *state,
                               u16_t hdr_size,
                               u16_t payload_len)
{
    /* Cap at 125 bytes per RFC 6455 §5.5 */
    if (payload_len > 125u)
        payload_len = 0u;

    uint8_t frame[6u + 125u];
    frame[0] = WS_FIN | WS_OP_PONG;
    frame[1] = (uint8_t)(WS_MASK_BIT | payload_len);
    tls_random_bytes(&frame[2], 4);

    if (payload_len > 0u && state->rx)
    {
        uint8_t ping_pay[125];
        pbuf_copy_partial(state->rx, ping_pay, payload_len, hdr_size);
        const uint8_t *mask = &frame[2];
        for (u16_t i = 0; i < payload_len; i++)
            frame[6u + i] = ping_pay[i] ^ mask[i & 3u];
    }

    altcp_write(conn->inner_conn, frame, (u16_t)(6u + payload_len),
                TCP_WRITE_FLAG_COPY);
    altcp_output(conn->inner_conn);
}

/* -------------------------------------------------------------------------
 * RX: deliver payload to upper layer
 * ---------------------------------------------------------------------- */

static err_t altcp_ws_pass_rx_data(struct altcp_pcb *conn,
                                   altcp_ws_state_t *state)
{
    struct pbuf *buf = state->rx_app;
    if (!buf)
    {
        if ((state->flags & ALTCP_WS_FLAGS_RX_CLOSE_QUEUED) &&
            !(state->flags & ALTCP_WS_FLAGS_RX_CLOSED) && conn->recv)
        {
            state->flags |= ALTCP_WS_FLAGS_RX_CLOSED;
            return conn->recv(conn->arg, conn, NULL, ERR_OK);
        }
        return ERR_OK;
    }
    if (!conn->recv)
        return ERR_MEM;

    state->rx_app = NULL;
    state->rx_passed_unrecved += (int)buf->tot_len;

    err_t e = ERR_OK;
    if (conn->recv)
        e = conn->recv(conn->arg, conn, buf, ERR_OK);

    if (e == ERR_ABRT)
        return e; /* callback has freed conn and state */
    if (e != ERR_OK)
    {
        /* Upper layer rejected the data — put it back */
        state->rx_passed_unrecved -= (int)buf->tot_len;
        state->rx_app = buf;
    }
    return e;
}

/* -------------------------------------------------------------------------
 * RX: frame parser and HTTP header scanner
 * ---------------------------------------------------------------------- */

static err_t altcp_ws_lower_recv_process(struct altcp_pcb *conn,
                                         altcp_ws_state_t *state)
{
    /* Retry refused payload before consuming any more wire data. */
    if (state->rx_app)
    {
        err_t e = altcp_ws_pass_rx_data(conn, state);
        if (e == ERR_ABRT) return e;
        if (e != ERR_OK) return ERR_OK;
    }
    if (state->flags & ALTCP_WS_FLAGS_RX_CLOSE_QUEUED)
        return altcp_ws_pass_rx_data(conn, state);

    /* ---- Phase 1: HTTP upgrade handshake ---- */
    if (!(state->flags & ALTCP_WS_FLAGS_UPGRADE_DONE))
    {
        /* Scan for \r\n\r\n in rx chain */
        struct pbuf *p = state->rx;
        if (!p)
            return ERR_OK;

        /* We need at least 12 bytes to verify "HTTP/1.1 101" */
        u16_t tot = p->tot_len;
        if (tot < 12u)
            return ERR_OK;

        /* Scan for header terminator — look for \r\n\r\n */
        u16_t header_end = 0;
        uint8_t tmp[4];
        for (u16_t i = 0; i + 4u <= tot; i++)
        {
            pbuf_copy_partial(p, tmp, 4, i);
            if (tmp[0] == '\r' && tmp[1] == '\n' &&
                tmp[2] == '\r' && tmp[3] == '\n')
            {
                header_end = (u16_t)(i + 4u);
                break;
            }
        }

        if (header_end == 0u)
        {
            if (tot >= WS_RX_LIMIT)
            {
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
            return ERR_OK; /* wait for more data */
        }

        /* Verify HTTP 101 */
        uint8_t status[13];
        pbuf_copy_partial(p, status, sizeof(status), 0);
        if (memcmp(status, "HTTP/1.1 101", 12) != 0 || status[12] != ' ')
        {
            unsigned http_status = 0;
            if (status[9] >= '0' && status[9] <= '9' &&
                status[10] >= '0' && status[10] <= '9' &&
                status[11] >= '0' && status[11] <= '9')
                http_status = (status[9] - '0') * 100u +
                              (status[10] - '0') * 10u + status[11] - '0';
            ERROR_CODE(http_status);
            altcp_abort(conn->inner_conn);
            return ERR_ABRT;
        }

        /* Verify required response headers: Upgrade: websocket and
         * Connection: Upgrade (case-insensitive substring scan).
         * We do not validate Sec-WebSocket-Accept (requires SHA-1). */
        {
            uint8_t hdr_buf[header_end < 512u ? header_end : 512u];
            u16_t   scan_len = (u16_t)(header_end < 512u ? header_end : 512u);
            pbuf_copy_partial(p, hdr_buf, scan_len, 0);

            /* Lowercase scan: look for "upgrade: websocket" and
             * "connection: upgrade" anywhere in the header block. */
            bool found_upgrade    = false;
            bool found_connection = false;
            for (u16_t i = 0; i + 10u < scan_len; i++)
            {
                /* "upgrade: w" (case-insensitive on first char of value) */
                if (!found_upgrade &&
                    (hdr_buf[i]   | 0x20u) == 'u' &&
                    (hdr_buf[i+1] | 0x20u) == 'p' &&
                    (hdr_buf[i+2] | 0x20u) == 'g' &&
                    (hdr_buf[i+3] | 0x20u) == 'r' &&
                    (hdr_buf[i+4] | 0x20u) == 'a' &&
                    (hdr_buf[i+5] | 0x20u) == 'd' &&
                    (hdr_buf[i+6] | 0x20u) == 'e' &&
                     hdr_buf[i+7]           == ':')
                {
                    /* skip whitespace, then check "websocket" */
                    u16_t j = (u16_t)(i + 8u);
                    while (j < scan_len && hdr_buf[j] == ' ') j++;
                    if (j + 9u <= scan_len &&
                        (hdr_buf[j+0] | 0x20u) == 'w' &&
                        (hdr_buf[j+1] | 0x20u) == 'e' &&
                        (hdr_buf[j+2] | 0x20u) == 'b' &&
                        (hdr_buf[j+3] | 0x20u) == 's' &&
                        (hdr_buf[j+4] | 0x20u) == 'o' &&
                        (hdr_buf[j+5] | 0x20u) == 'c' &&
                        (hdr_buf[j+6] | 0x20u) == 'k' &&
                        (hdr_buf[j+7] | 0x20u) == 'e' &&
                        (hdr_buf[j+8] | 0x20u) == 't')
                    {
                        found_upgrade = true;
                    }
                }
                /* "connection: " — just need it present, value may be
                 * "upgrade" or "keep-alive, upgrade" etc. */
                if (!found_connection && i + 12u < scan_len &&
                    (hdr_buf[i]    | 0x20u) == 'c' &&
                    (hdr_buf[i+1]  | 0x20u) == 'o' &&
                    (hdr_buf[i+2]  | 0x20u) == 'n' &&
                    (hdr_buf[i+3]  | 0x20u) == 'n' &&
                    (hdr_buf[i+4]  | 0x20u) == 'e' &&
                    (hdr_buf[i+5]  | 0x20u) == 'c' &&
                    (hdr_buf[i+6]  | 0x20u) == 't' &&
                    (hdr_buf[i+7]  | 0x20u) == 'i' &&
                    (hdr_buf[i+8]  | 0x20u) == 'o' &&
                    (hdr_buf[i+9]  | 0x20u) == 'n' &&
                     hdr_buf[i+10]           == ':')
                {
                    /* value must contain "upgrade" somewhere */
                    for (u16_t j = (u16_t)(i + 11u);
                         j + 7u <= scan_len && hdr_buf[j] != '\r';
                         j++)
                    {
                        if ((hdr_buf[j+0] | 0x20u) == 'u' &&
                            (hdr_buf[j+1] | 0x20u) == 'p' &&
                            (hdr_buf[j+2] | 0x20u) == 'g' &&
                            (hdr_buf[j+3] | 0x20u) == 'r' &&
                            (hdr_buf[j+4] | 0x20u) == 'a' &&
                            (hdr_buf[j+5] | 0x20u) == 'd' &&
                            (hdr_buf[j+6] | 0x20u) == 'e')
                        {
                            found_connection = true;
                            break;
                        }
                    }
                }
            }

            if (!found_upgrade || !found_connection)
            {
                WARN();
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
        }

        /* Consume header bytes — ack to inner layer */
        altcp_recved(conn->inner_conn, header_end);
        state->rx = pbuf_free_header(state->rx, header_end);
        if (!state->rx)
            state->rx = NULL;

        state->flags |= ALTCP_WS_FLAGS_UPGRADE_DONE;

        if (!(state->flags & ALTCP_WS_FLAGS_UPPER_CALLED))
        {
            state->flags |= ALTCP_WS_FLAGS_UPPER_CALLED;
            if (conn->connected)
            {
                err_t e = conn->connected(conn->arg, conn, ERR_OK);
                if (e != ERR_OK)
                    return e;
            }
        }

        if (!state->rx)
            return ERR_OK;
        /* Fall through to frame parsing if there's leftover data */
    }

    /* ---- Phase 2: WebSocket frame parsing ---- */
    while (state->rx)
    {
        struct pbuf *p = state->rx;
        u16_t tot = p->tot_len;

        if (tot < 2u)
            break; /* wait */

        uint8_t hdr[2];
        pbuf_copy_partial(p, hdr, 2, 0);

        uint8_t  opcode      = hdr[0] & 0x0Fu;
        bool     fin         = (hdr[0] & WS_FIN) != 0u;
        bool     masked      = (hdr[1] & WS_MASK_BIT) != 0u;
        uint32_t payload_len = hdr[1] & 0x7Fu;
        u16_t    hdr_size    = 2u;

        if (payload_len == 126u)
        {
            if (tot < 4u) break;
            uint8_t ext[2];
            pbuf_copy_partial(p, ext, 2, 2);
            payload_len = ((uint32_t)ext[0] << 8u) | ext[1];
            hdr_size    = 4u;
        }
        else if (payload_len == 127u)
        {
            /* 8-byte extended length — cap at u16_t max */
            if (tot < 10u) break;
            uint8_t ext[8];
            pbuf_copy_partial(p, ext, 8, 2);
            /* Only handle payloads that fit u16_t */
            if (ext[0] || ext[1] || ext[2] || ext[3] ||
                ext[4] || ext[5] || (((uint32_t)ext[6] << 8u) | ext[7]) > 0xFFFFu)
            {
                ERROR();
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
            payload_len = ((uint32_t)ext[6] << 8u) | ext[7];
            hdr_size    = 10u;
        }

        if (masked)
            hdr_size = (u16_t)(hdr_size + 4u);

        if (masked || (hdr[0] & 0x70u) ||
            payload_len + hdr_size > WS_RX_LIMIT ||
            (opcode >= WS_OP_CLOSE && (!fin || payload_len > 125u)) ||
            (opcode == WS_OP_CLOSE && payload_len == 1u) ||
            (opcode == WS_OP_CONT && !(state->flags & ALTCP_WS_FLAGS_RECV_FRAGMENT)) ||
            ((opcode == WS_OP_TEXT || opcode == WS_OP_BINARY) &&
             (state->flags & ALTCP_WS_FLAGS_RECV_FRAGMENT)))
        {
            WARN_CODE(opcode);
            altcp_abort(conn->inner_conn);
            return ERR_ABRT;
        }
        u16_t total_frame = (u16_t)(hdr_size + payload_len);
        if (tot < total_frame)
            break; /* wait for rest of frame */

        switch (opcode)
        {
        case WS_OP_CONT:
        case WS_OP_TEXT:
        case WS_OP_BINARY:
        {
            if (payload_len > 0u)
            {
                struct pbuf *pay = pbuf_alloc(PBUF_RAW, (u16_t)payload_len, PBUF_RAM);
                if (!pay)
                    return ERR_OK; /* retry on next recv */

                pbuf_copy_partial(p, pay->payload, (u16_t)payload_len, hdr_size);

                if (masked)
                {
                    uint8_t mask[4];
                    pbuf_copy_partial(p, mask, 4, (u16_t)(hdr_size - 4u));
                    uint8_t *d = (uint8_t *)pay->payload;
                    for (u16_t i = 0u; i < (u16_t)payload_len; i++)
                        d[i] ^= mask[i & 3u];
                }

                if (!state->rx_app)
                    state->rx_app = pay;
                else
                    pbuf_cat(state->rx_app, pay);
            }
            if (fin)
                state->flags &= (uint8_t)~ALTCP_WS_FLAGS_RECV_FRAGMENT;
            else
                state->flags |= ALTCP_WS_FLAGS_RECV_FRAGMENT;
            break;
        }

        case WS_OP_CLOSE:
            /* RFC 6455 §5.5: control frames must not be fragmented and
             * must have payload ≤ 125 bytes. */
            if (!fin || payload_len > 125u)
            {
                WARN();
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
            if (!(state->flags & ALTCP_WS_FLAGS_CLOSE_SENT))
            {
                altcp_ws_send_close_frame(conn, state);
                state->flags |= ALTCP_WS_FLAGS_CLOSE_SENT;
            }
            state->flags |= ALTCP_WS_FLAGS_RX_CLOSE_QUEUED;
            break;

        case WS_OP_PING:
            /* RFC 6455 §5.5: control frames must not be fragmented and
             * must have payload ≤ 125 bytes. */
            if (!fin || payload_len > 125u)
            {
                WARN();
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
            altcp_ws_send_pong(conn, state, hdr_size, (u16_t)payload_len);
            break;

        case WS_OP_PONG:
            if (!fin || payload_len > 125u)
            {
                WARN();
                altcp_abort(conn->inner_conn);
                return ERR_ABRT;
            }
            break; /* ignore */

        default:
            /* RFC 6455 §5.2: unknown opcodes must close with Protocol Error */
            WARN_CODE(opcode);
            if (!(state->flags & ALTCP_WS_FLAGS_CLOSE_SENT))
            {
                altcp_ws_send_close_frame(conn, state);
                state->flags |= ALTCP_WS_FLAGS_CLOSE_SENT;
            }
            altcp_abort(conn->inner_conn);
            return ERR_ABRT;
        }

        /* Consume frame bytes — ack to inner layer */
        altcp_recved(conn->inner_conn, total_frame);
        state->rx = pbuf_free_header(state->rx, total_frame);

        /* Deliver complete message to upper layer */
        if (opcode == WS_OP_TEXT || opcode == WS_OP_BINARY ||
            opcode == WS_OP_CONT)
        {
            err_t e = altcp_ws_pass_rx_data(conn, state);
            if (e == ERR_ABRT)
                return ERR_ABRT;
            if (e != ERR_OK)
                return ERR_OK; /* input is owned here; retry payload on poll */
        }

        if (state->flags & ALTCP_WS_FLAGS_RX_CLOSE_QUEUED)
            return altcp_ws_pass_rx_data(conn, state);
    }

    return ERR_OK;
}

/* -------------------------------------------------------------------------
 * Lower-layer callbacks
 * ---------------------------------------------------------------------- */

static err_t altcp_ws_lower_recv(void *arg, struct altcp_pcb *inner_conn,
                                 struct pbuf *p, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_ws_state_t *state;

    (void)inner_conn;
    (void)err;

    if (!conn || !conn->state)
    {
        if (p) pbuf_free(p);
        return ERR_VAL;
    }
    state = (altcp_ws_state_t *)conn->state;

    /* Peer closed */
    if (!p)
    {
        state->flags |= ALTCP_WS_FLAGS_RX_CLOSE_QUEUED;
        return altcp_ws_pass_rx_data(conn, state);
    }

    if ((state->rx ? (uint32_t)state->rx->tot_len : 0u) + p->tot_len > 65535u)
        return ERR_MEM; /* caller retains p on refusal */

    /* Copy incoming data to RAM pbuf and append to rx chain */
    struct pbuf *copy = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
    if (!copy)
        return ERR_MEM; /* caller retains p for retry */
    pbuf_copy(copy, p);
    pbuf_free(p);

    if (!state->rx)
        state->rx = copy;
    else
        pbuf_cat(state->rx, copy);

    return altcp_ws_lower_recv_process(conn, state);
}

static err_t altcp_ws_lower_sent(void *arg, struct altcp_pcb *inner_conn,
                                 u16_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_ws_state_t *state;

    (void)inner_conn;

    if (!conn || !conn->state)
        return ERR_VAL;
    state = (altcp_ws_state_t *)conn->state;

    /* Strip frame overhead from the ACKed byte count.
     * overhead_bytes_adjust accumulates (frame_size - payload) per write.
     * Each ACK consumes from that pool first; remainder is app payload. */
    int overhead = state->overhead_bytes_adjust;
    if (overhead < 0) overhead = 0;
    if ((int)len <= overhead)
    {
        /* Entire ACK is overhead bytes */
        state->overhead_bytes_adjust -= (int)len;
        return ERR_OK;
    }
    /* Part overhead, part payload */
    state->overhead_bytes_adjust = 0;
    u16_t app_len = (u16_t)((int)len - overhead);
    if (conn->sent)
        return conn->sent(conn->arg, conn, app_len);
    return ERR_OK;
}

static void altcp_ws_lower_err(void *arg, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    if (!conn) return;

    altcp_ws_state_t *state = (altcp_ws_state_t *)conn->state;

    /* Snapshot upper callbacks before tearing down */
    altcp_err_fn  app_err = conn->err;
    void         *app_arg = conn->arg;

    /* Detach inner so dealloc doesn't double-abort */
    conn->inner_conn = NULL;

    if (state)
    {
        if (state->rx)     { pbuf_free(state->rx);     state->rx = NULL; }
        if (state->rx_app) { pbuf_free(state->rx_app); state->rx_app = NULL; }
        mem_free(state);
        conn->state = NULL;
    }

    altcp_free(conn);

    if (app_err)
        app_err(app_arg, err);
}

static err_t altcp_ws_lower_connected(void *arg, struct altcp_pcb *inner_conn,
                                      err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_ws_state_t *state;

    (void)inner_conn;

    if (!conn || !conn->state)
        return ERR_VAL;
    state = (altcp_ws_state_t *)conn->state;

    if (err != ERR_OK)
    {
        if (conn->connected)
            conn->connected(conn->arg, conn, err);
        return ERR_OK;
    }

    err_t e = altcp_ws_send_upgrade_request(conn, state);
    if (e != ERR_OK)
    {
        altcp_abort(conn->inner_conn);
        return ERR_ABRT;
    }
    return ERR_OK;
}

static err_t altcp_ws_lower_poll(void *arg, struct altcp_pcb *inner_conn)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    (void)inner_conn;

    if (conn && conn->state)
    {
        err_t e = altcp_ws_lower_recv_process(conn, (altcp_ws_state_t *)conn->state);
        if (e == ERR_ABRT)
            return e;
    }

    if (conn && conn->poll)
        return conn->poll(conn->arg, conn);

    return ERR_OK;
}

/* -------------------------------------------------------------------------
 * altcp vtable functions
 * ---------------------------------------------------------------------- */

static void altcp_ws_set_poll(struct altcp_pcb *conn, u8_t interval)
{
    if (conn && conn->inner_conn)
        altcp_poll(conn->inner_conn, altcp_ws_lower_poll, interval);
}

static void altcp_ws_recved(struct altcp_pcb *conn, u16_t len)
{
    altcp_ws_state_t *state = conn ? (altcp_ws_state_t *)conn->state : NULL;
    if (!state || !(state->flags & ALTCP_WS_FLAGS_UPGRADE_DONE))
        return;
    if ((int)len > state->rx_passed_unrecved)
        len = (u16_t)state->rx_passed_unrecved;
    if (len == 0u)
        return;
    state->rx_passed_unrecved -= (int)len;
}

static err_t altcp_ws_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr,
                              u16_t port, altcp_connected_fn connected)
{
    if (!conn || !conn->inner_conn)
        return ERR_VAL;

    conn->connected = connected;
    altcp_poll(conn->inner_conn, altcp_ws_lower_poll, 1u);
    return altcp_connect(conn->inner_conn, ipaddr, port,
                         altcp_ws_lower_connected);
}

static err_t altcp_ws_write(struct altcp_pcb *conn, const void *dataptr,
                            u16_t len, u8_t apiflags)
{
    altcp_ws_state_t *state;
    uint8_t          *frame;
    u16_t             hdr_end;
    u16_t             frame_size;
    err_t             e;

    (void)apiflags;

    if (!conn || !conn->state || !conn->inner_conn)
        return ERR_VAL;
    state = (altcp_ws_state_t *)conn->state;
    if (!(state->flags & ALTCP_WS_FLAGS_UPGRADE_DONE) ||
        (state->flags & (ALTCP_WS_FLAGS_CLOSE_SENT | ALTCP_WS_FLAGS_RX_CLOSE_QUEUED)))
        return ERR_CONN;
    if ((len && !dataptr) || len > 65535u - 8u)
        return ERR_VAL;

    if (len <= 125u)
    {
        frame_size = (u16_t)(2u + 4u + len);
        hdr_end    = 2u;
    }
    else
    {
        frame_size = (u16_t)(4u + 4u + len);
        hdr_end    = 4u;
    }

    frame = (uint8_t *)mem_malloc(frame_size);
    if (!frame)
        return ERR_MEM;

    /* Frame header */
    frame[0] = WS_FIN | WS_OP_BINARY;
    if (len <= 125u)
    {
        frame[1] = (uint8_t)(WS_MASK_BIT | len);
    }
    else
    {
        frame[1] = (uint8_t)(WS_MASK_BIT | 126u);
        frame[2] = (uint8_t)(len >> 8u);
        frame[3] = (uint8_t)(len & 0xFFu);
    }

    /* Masking key */
    tls_random_bytes(&frame[hdr_end], 4);

    /* Masked payload */
    const uint8_t *mask = &frame[hdr_end];
    const uint8_t *src  = (const uint8_t *)dataptr;
    uint8_t       *dst  = &frame[hdr_end + 4u];
    for (u16_t i = 0u; i < len; i++)
        dst[i] = src[i] ^ mask[i & 3u];

    e = altcp_write(conn->inner_conn, frame, frame_size, TCP_WRITE_FLAG_COPY);
    if (e == ERR_OK)
    {
        altcp_output(conn->inner_conn);
        /* Track overhead: we sent frame_size bytes, app sent len bytes */
        state->overhead_bytes_adjust += (int)frame_size - (int)len;
    }

    mem_free(frame);
    return e;
}

static err_t altcp_ws_close(struct altcp_pcb *conn)
{
    altcp_ws_state_t *state = conn ? (altcp_ws_state_t *)conn->state : NULL;

    if (state && (state->flags & ALTCP_WS_FLAGS_UPGRADE_DONE) &&
        !(state->flags & ALTCP_WS_FLAGS_CLOSE_SENT))
    {
        altcp_ws_send_close_frame(conn, state);
        state->flags |= ALTCP_WS_FLAGS_CLOSE_SENT;
    }

    if (conn->inner_conn)
    {
        altcp_ws_remove_callbacks(conn->inner_conn);
        err_t e = altcp_close(conn->inner_conn);
        if (e != ERR_OK)
        {
            /* Restore callbacks so we still hear about the close */
            altcp_ws_setup_callbacks(conn, conn->inner_conn);
            return e;
        }
        conn->inner_conn = NULL;
    }

    altcp_ws_dealloc(conn);
    altcp_free(conn);
    return ERR_OK;
}

static void altcp_ws_abort(struct altcp_pcb *conn)
{
    if (conn && conn->inner_conn)
        altcp_abort(conn->inner_conn);
}

static void altcp_ws_dealloc(struct altcp_pcb *conn)
{
    altcp_ws_state_t *state = conn ? (altcp_ws_state_t *)conn->state : NULL;
    if (state)
    {
        if (state->rx)     { pbuf_free(state->rx);     state->rx = NULL; }
        if (state->rx_app) { pbuf_free(state->rx_app); state->rx_app = NULL; }
        mem_free(state);
        conn->state = NULL;
    }
}

static u16_t altcp_ws_sndbuf(struct altcp_pcb *conn)
{
    if (!conn || !conn->state)
        return altcp_default_sndbuf(conn);
    altcp_ws_state_t *state = (altcp_ws_state_t *)conn->state;
    if (!(state->flags & ALTCP_WS_FLAGS_UPGRADE_DONE))
        return 0u;
    if (conn->inner_conn)
    {
        u16_t s = altcp_sndbuf(conn->inner_conn);
        return s > WS_MAX_FRAME_OVERHEAD ? (u16_t)(s - WS_MAX_FRAME_OVERHEAD) : 0u;
    }
    return altcp_default_sndbuf(conn);
}

static u16_t altcp_ws_mss(struct altcp_pcb *conn)
{
    u16_t inner = (conn && conn->inner_conn) ? altcp_mss(conn->inner_conn) : 0u;
    return inner > WS_MAX_FRAME_OVERHEAD ? (u16_t)(inner - WS_MAX_FRAME_OVERHEAD) : 0u;
}

/* -------------------------------------------------------------------------
 * vtable
 * ---------------------------------------------------------------------- */

const struct altcp_functions altcp_ws_functions = {
    altcp_ws_set_poll,
    altcp_ws_recved,
    altcp_default_bind,
    altcp_ws_connect,
    NULL,               /* listen: WS is client-only */
    altcp_ws_abort,
    altcp_ws_close,
    altcp_default_shutdown,
    altcp_ws_write,
    altcp_default_output,
    altcp_ws_mss,
    altcp_ws_sndbuf,
    altcp_default_sndqueuelen,
    altcp_default_nagle_disable,
    altcp_default_nagle_enable,
    altcp_default_nagle_disabled,
    altcp_default_setprio,
    altcp_ws_dealloc,
    altcp_default_get_tcp_addrinfo,
    altcp_default_get_ip,
    altcp_default_get_port,
#if LWIP_TCP_KEEPALIVE
    altcp_default_keepalive_disable,
    altcp_default_keepalive_enable,
#endif
#ifdef LWIP_DEBUG
    altcp_default_dbg_get_tcp_state,
#endif
};

/* -------------------------------------------------------------------------
 * Internal setup
 * ---------------------------------------------------------------------- */

static err_t altcp_ws_setup(altcp_ws_config_t *conf,
                            struct altcp_pcb  *conn,
                            struct altcp_pcb  *inner_conn)
{
    LWIP_ASSERT("conf != NULL", conf != NULL);
    LWIP_ASSERT("conn != inner_conn", conn != inner_conn);

    altcp_ws_state_t *state =
        (altcp_ws_state_t *)mem_malloc(sizeof(altcp_ws_state_t));
    if (!state)
        return ERR_MEM;

    memset(state, 0, sizeof(*state));
    state->conf = conf;
    state->conn = conn;

    altcp_ws_setup_callbacks(conn, inner_conn);

    conn->inner_conn = inner_conn;
    conn->fns        = &altcp_ws_functions;
    conn->state      = state;

    return ERR_OK;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

struct altcp_pcb *altcp_ws_wrap(altcp_ws_config_t *conf,
                                struct altcp_pcb  *inner_pcb)
{
    struct altcp_pcb *conn = altcp_alloc();
    if (!conn)
        return NULL;

    if (altcp_ws_setup(conf, conn, inner_pcb) != ERR_OK)
    {
        altcp_free(conn);
        return NULL;
    }
    return conn;
}

struct altcp_pcb *altcp_ws_new(altcp_ws_config_t *conf, u8_t ip_type)
{
    struct altcp_pcb *inner = altcp_tcp_new_ip_type(ip_type);
    if (!inner)
        return NULL;

    struct altcp_pcb *ret = altcp_ws_wrap(conf, inner);
    if (!ret)
    {
        altcp_abort(inner);
        return NULL;
    }
    return ret;
}

struct altcp_pcb *altcp_ws_new_tls(altcp_ws_config_t          *conf,
                                   struct altcp_tls_ce_config  *tls_conf,
                                   u8_t                         ip_type)
{
    struct altcp_pcb *tls_pcb = altcp_tls_ce_new(tls_conf, ip_type);
    if (!tls_pcb)
        return NULL;

    struct altcp_pcb *ret = altcp_ws_wrap(conf, tls_pcb);
    if (!ret)
    {
        altcp_abort(tls_pcb);
        return NULL;
    }
    return ret;
}

struct altcp_pcb *altcp_ws_alloc(void *arg, u8_t ip_type)
{
    return altcp_ws_new((altcp_ws_config_t *)arg, ip_type);
}

#endif /* LWIP_ALTCP */
