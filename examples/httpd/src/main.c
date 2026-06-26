/**
 * lwIP-CE HTTP/1.1 server example.
 *
 * Serves static files from a TI AppVar packed by lwip-webpacker.py.
 * Uses the lwip_socket_* API exported by the lwip-ce dylib.
 *
 * AppVar layout (produced by lwip-webpacker.py):
 *
 *   Offset   Size   Description
 *   0        4      Magic 'LWFS'
 *   4        2      Entry count N  (uint16 LE)
 *   6        N*var  Index table entries, each:
 *              0    2   path length L  (uint16 LE)
 *              2    L   URL path string (not NUL-terminated)
 *            L+2    4   data offset from AppVar start  (uint32 LE)
 *            L+6    4   data length in bytes            (uint32 LE)
 *            L+10   1   MIME type index                 (uint8)
 *   after index     file data blobs (concatenated)
 *
 * Build steps (from the examples/httpd/ directory):
 *   python3 lwip-webpacker.py --www www/ --outname LWHTTPD
 *   make
 * Send both LWHTTPD.8xv and the compiled app to the calculator.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ti/screen.h>
#include <ti/getkey.h>
#include <fileioc.h>

#include <lwip.h>

#include "../../common/lwip_example.h"

/* -------------------------------------------------------------------------
 * AppVar filesystem
 * ------------------------------------------------------------------------- */

#define MAGIC_STR   "LWFS"
#define MAGIC       0x5346574CUL

static const char *const mime_table[] = {
    "text/html; charset=utf-8",  /* 0 */
    "text/plain; charset=utf-8", /* 1 */
    "text/css",                  /* 2 */
    "application/javascript",    /* 3 */
    "application/json",          /* 4 */
    "image/png",                 /* 5 */
    "image/jpeg",                /* 6 */
    "image/gif",                 /* 7 */
    "image/svg+xml",             /* 8 */
    "application/octet-stream",  /* 9 — fallback */
};
#define MIME_COUNT    ((uint8_t)(sizeof(mime_table) / sizeof(mime_table[0])))
#define MIME_FALLBACK 9

static const uint8_t *g_appvar    = NULL;
static size_t         g_appvar_sz = 0;

/* ---- AppVar scanner ---- */

#define AV_MAX 16

typedef struct {
    char     name[9];   /* AppVar name, NUL-terminated (max 8 chars) */
    uint16_t entries;   /* file count stored in this AppVar */
} av_info_t;

static av_info_t g_av_list[AV_MAX];
static uint8_t   g_av_count = 0;

static void appvar_scan(void)
{
    void   *vat_ptr = NULL;
    char   *name;
    g_av_count = 0;

    while (g_av_count < AV_MAX &&
           (name = ti_Detect(&vat_ptr, MAGIC_STR)) != NULL) {
        uint8_t h = ti_Open(name, "r");
        if (!h) continue;

        size_t         sz  = ti_GetSize(h);
        const uint8_t *ptr = (const uint8_t *)ti_GetDataPtr(h);
        ti_Close(h);

        if (!ptr || sz < 6) continue;
        if (*(const uint32_t *)ptr != MAGIC) continue;

        uint16_t n = (uint16_t)(ptr[4] | ((uint16_t)ptr[5] << 8));
        strncpy(g_av_list[g_av_count].name, name, 8);
        g_av_list[g_av_count].name[8] = '\0';
        g_av_list[g_av_count].entries = n;
        g_av_count++;
    }
}

/* ---- AppVar picker menu ---- */

/* Returns index into g_av_list, or -1 if user pressed Clear. */
static int appvar_menu(void)
{
    if (g_av_count == 0)
        return -1;

    const uint8_t line_h  = 10;
    const uint8_t visible = (240 - 20) / line_h;  /* rows that fit on screen */
    uint8_t       cursor  = 0;
    uint8_t       scroll  = 0;   /* index of top visible item */

    /* Use 0x01 as the transparent color for the duration of this menu so
     * both 0x00 (black) and 0xFF (white) are available as opaque fg/bg. */
    gfx_SetTextTransparentColor(0x01);

    for (;;) {
        /* --- draw --- */
        gfx_FillScreen(LWIP_EXAMPLE_COLOR_BG);
        gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
        gfx_SetTextBGColor(LWIP_EXAMPLE_COLOR_BG);
        gfx_PrintStringXY("Select site AppVar", LWIP_EXAMPLE_LEFT, 2);
        gfx_PrintStringXY("[up/dn] [enter] [clear]", LWIP_EXAMPLE_LEFT, 12);

        for (uint8_t i = 0; i < visible && (scroll + i) < g_av_count; i++) {
            uint8_t idx = scroll + i;
            uint8_t y   = 24 + i * line_h;

            char row[32];
            snprintf(row, sizeof(row), "%-8s  %u files",
                     g_av_list[idx].name, g_av_list[idx].entries);

            if (idx == cursor) {
                gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_BG);  /* white text */
                gfx_SetTextBGColor(LWIP_EXAMPLE_COLOR_FG);  /* black bar  */
            } else {
                gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);  /* black text */
                gfx_SetTextBGColor(LWIP_EXAMPLE_COLOR_BG);  /* white bg   */
            }
            gfx_PrintStringXY(row, LWIP_EXAMPLE_LEFT, y);
        }

        /* scroll indicators */
        if (scroll > 0)
            gfx_PrintStringXY("^", 310, 24);
        if (scroll + visible < g_av_count)
            gfx_PrintStringXY("v", 310, 24 + (visible - 1) * line_h);

        gfx_BlitBuffer();

        /* --- input --- */
        uint8_t key = os_GetCSC();
        while (!key) key = os_GetCSC();

        if (key == sk_Clear || key == sk_Enter || key == sk_2nd) {
            gfx_SetTextTransparentColor(LWIP_EXAMPLE_COLOR_BG);
            gfx_SetTextBGColor(LWIP_EXAMPLE_COLOR_BG);
            gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
            return (key == sk_Clear) ? -1 : (int)cursor;
        }
        if (key == sk_Up && cursor > 0) {
            cursor--;
            if (cursor < scroll) scroll = cursor;
        }
        if (key == sk_Down && cursor + 1 < g_av_count) {
            cursor++;
            if (cursor >= scroll + visible)
                scroll = cursor - visible + 1;
        }
    }
}

/* ---- AppVar loader (by name) ---- */

static bool appvar_load_named(const char *name)
{
    uint8_t handle = ti_Open(name, "r");
    if (!handle)
        return false;

    g_appvar_sz = ti_GetSize(handle);
    g_appvar    = (const uint8_t *)ti_GetDataPtr(handle);
    ti_Close(handle);

    if (!g_appvar || g_appvar_sz < 6)
        return false;
    if (*(const uint32_t *)g_appvar != MAGIC)
        return false;
    return true;
}

static uint16_t av_u16(size_t off)
{
    return (uint16_t)(g_appvar[off] | ((uint16_t)g_appvar[off + 1] << 8));
}

static uint32_t av_u32(size_t off)
{
    return (uint32_t)g_appvar[off]
         | ((uint32_t)g_appvar[off + 1] <<  8)
         | ((uint32_t)g_appvar[off + 2] << 16)
         | ((uint32_t)g_appvar[off + 3] << 24);
}

static bool appvar_find(const char *path, size_t path_len,
                        const uint8_t **data_out, size_t *len_out,
                        const char **mime_out)
{
    uint16_t n    = av_u16(4);
    size_t   ioff = 6;

    for (uint16_t i = 0; i < n; i++) {
        uint16_t plen = av_u16(ioff);
        const char *entry_path = (const char *)(g_appvar + ioff + 2);
        uint32_t doff = av_u32(ioff + 2 + plen);
        uint32_t dlen = av_u32(ioff + 2 + plen + 4);
        uint8_t  mime = g_appvar[ioff + 2 + plen + 8];
        ioff += 2 + plen + 9;

        if (plen == path_len && memcmp(entry_path, path, plen) == 0) {
            *data_out = g_appvar + doff;
            *len_out  = dlen;
            *mime_out = mime_table[mime < MIME_COUNT ? mime : MIME_FALLBACK];
            return true;
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * HTTP/1.1 server — keep-alive, concurrent connections, idle timeout
 * ------------------------------------------------------------------------- */

#define HTTP_PORT        80
#define MAX_PEERS        2        /* 2 × peer_t in BSS; each has a 2 KB buffer */
#define KEEPALIVE_MS     15000u   /* idle timeout per connection */
#define REQ_BUF_MAX      2048     /* covers modern browser header sets */
#define MAX_REQUESTS     100      /* per-connection request limit (rate cap) */

/* Per-connection state. */
typedef struct {
    struct lwip_socket sock;
    char               buf[REQ_BUF_MAX];
    size_t             buf_len;
    uint32_t           idle_since;  /* lwip_now_ms() when last activity ended */
    uint16_t           req_count;   /* requests served on this connection */
    bool               in_use;
    bool               keep_alive;  /* client wants keep-alive */
} peer_t;

static peer_t g_peers[MAX_PEERS];

/* ---- header parsing ---- */

/* Case-insensitive ASCII comparison of exactly len bytes. */
static bool ci_eq(const char *a, const char *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca |= 0x20;
        if (cb >= 'A' && cb <= 'Z') cb |= 0x20;
        if (ca != cb) return false;
    }
    return true;
}

/* Find a header value (case-insensitive name match).
 * headers points to the byte after the request line's \n.
 * Returns pointer to value (after ": "), or NULL if not found. */
static const char *find_header(const char *headers, size_t hlen,
                               const char *name, size_t nlen)
{
    const char *p = headers;
    const char *end = headers + hlen;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        /* blank line = end of headers */
        if (eol == p || (eol == p + 1 && *p == '\r')) break;

        size_t llen = (size_t)(eol - p);
        if (llen > nlen + 1 && ci_eq(p, name, nlen) && p[nlen] == ':') {
            const char *val = p + nlen + 1;
            while (val < eol && (*val == ' ' || *val == '\t')) val++;
            return val;
        }
        p = eol + 1;
    }
    return NULL;
}

/* Returns true if the request has a complete header block (\r\n\r\n or \n\n). */
static bool headers_complete(const char *buf, size_t len)
{
    /* Fast search for the blank-line terminator. */
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n')
            return true;
        if (i + 3 < len &&
            buf[i]   == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return true;
    }
    return false;
}

/* ---- response builder ---- */

static void send_response(peer_t *p,
                          int code, const char *reason,
                          const char *content_type,
                          const uint8_t *body, size_t body_len,
                          bool keep_alive)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Connection: %s\r\n"
        "\r\n",
        code, reason,
        content_type,
        (unsigned)body_len,
        keep_alive ? "keep-alive" : "close");
    if (n > 0)
        lwip_socket_write(&p->sock, (const uint8_t *)hdr, (size_t)n);
    if (body && body_len)
        lwip_socket_write(&p->sock, body, body_len);
}

/* ---- request dispatch ---- */

/* Parse and serve one HTTP request from p->buf[0..len).
 * Returns true if the connection should be kept alive. */
static bool dispatch(peer_t *p, size_t len)
{
    char *buf = p->buf;

    /* --- request line --- */
    char *eol = memchr(buf, '\n', len);
    if (!eol) goto bad;

    char *rl_end = eol;
    if (rl_end > buf && rl_end[-1] == '\r') rl_end--;
    *rl_end = '\0';

    char *method = buf;
    char *sp1 = strchr(method, ' ');
    if (!sp1) goto bad;
    *sp1 = '\0';
    char *path = sp1 + 1;
    char *sp2 = strchr(path, ' ');
    bool http11 = false;
    if (sp2) {
        *sp2 = '\0';
        http11 = ci_eq(sp2 + 1, "HTTP/1.1", 8);
    }

    /* --- connection header --- */
    const char *hdrs_start = eol + 1;
    size_t      hdrs_len   = len - (size_t)(hdrs_start - buf);
    const char *conn_hdr   = find_header(hdrs_start, hdrs_len,
                                         "Connection", 10);
    bool want_close = false;
    if (conn_hdr) {
        size_t vlen = strcspn(conn_hdr, "\r\n");
        want_close = ci_eq(conn_hdr, "close", vlen < 5 ? vlen : 5);
    }
    /* HTTP/1.1 default is keep-alive unless client says close.
     * HTTP/1.0 default is close unless client says keep-alive. */
    bool ka = http11 ? !want_close
                     : (conn_hdr && ci_eq(conn_hdr, "keep-alive", 10));

    /* Rate limit: force close after MAX_REQUESTS on this connection. */
    if (p->req_count + 1 >= MAX_REQUESTS)
        ka = false;

    bool is_get  = (strcmp(method, "GET")  == 0);
    bool is_head = (strcmp(method, "HEAD") == 0);

    if (!is_get && !is_head) {
        static const char b[] = "Method Not Allowed";
        send_response(p, 405, "Method Not Allowed", "text/plain",
                      (const uint8_t *)b, sizeof(b) - 1, ka);
        return ka;
    }

    size_t path_len = strlen(path);

    /* Remap / → /index.html */
    char mapped[128];
    if (path_len == 1 && path[0] == '/') {
        memcpy(mapped, "/index.html", 11);
        path     = mapped;
        path_len = 11;
    }

    /* Strip query string. */
    char *qs = memchr(path, '?', path_len);
    if (qs) { path_len = (size_t)(qs - path); }

    const uint8_t *data;
    size_t         data_len;
    const char    *mime;

    if (!appvar_find(path, path_len, &data, &data_len, &mime)) {
        static const char b[] = "Not Found";
        send_response(p, 404, "Not Found", "text/plain",
                      (const uint8_t *)b, sizeof(b) - 1, ka);
        return ka;
    }

    send_response(p, 200, "OK", mime,
                  is_head ? NULL : data, data_len, ka);
    return ka;

bad:
    send_response(p, 400, "Bad Request", "text/plain",
                  (const uint8_t *)"Bad Request", 11, false);
    return false;
}

/* ---- per-peer tick ---- */

/* Drive one peer slot each event loop tick.
 * Returns true if the slot is still in use after this call. */
static bool peer_tick(peer_t *p)
{
    if (!p->in_use)
        return false;

    lwip_status_t st = lwip_socket_status(&p->sock);

    /* Socket gone (reset, error, closed by remote). */
    if (!lwip_socket_is_active(&p->sock)) {
        lwip_socket_destroy(&p->sock);
        p->in_use = false;
        return false;
    }

    /* Idle timeout. */
    if ((uint32_t)(lwip_now_ms() - p->idle_since) >= KEEPALIVE_MS) {
        lwip_socket_close(&p->sock);
        /* Let it drain to CLOSED/RESET before destroying. */
        if (!lwip_socket_is_active(&p->sock)) {
            lwip_socket_destroy(&p->sock);
            p->in_use = false;
        }
        return p->in_use;
    }

    if (st != LWIP_STATUS_CONNECTED)
        return true;

    /* Drain ring into request buffer. */
    size_t avail = lwip_socket_available(&p->sock);
    if (avail) {
        size_t space  = REQ_BUF_MAX - 1 - p->buf_len;
        size_t to_read = avail < space ? avail : space;
        p->buf_len += lwip_socket_read(&p->sock,
                                       (uint8_t *)(p->buf + p->buf_len),
                                       to_read);
        p->buf[p->buf_len] = '\0';
        p->idle_since = lwip_now_ms();
    }

    /* Process complete requests (one per tick to stay non-blocking). */
    if (headers_complete(p->buf, p->buf_len)) {
        size_t req_len = p->buf_len;
        p->keep_alive  = dispatch(p, req_len);
        p->req_count++;

        if (!p->keep_alive) {
            lwip_socket_close(&p->sock);
        } else {
            /* Consume the processed request from the buffer.
             * Simple: find end of headers (\r\n\r\n or \n\n) and discard. */
            const char *b = p->buf;
            size_t consumed = 0;
            for (size_t i = 0; i + 1 < req_len; i++) {
                if (b[i] == '\n' && b[i+1] == '\n') {
                    consumed = i + 2; break;
                }
                if (i + 3 < req_len &&
                    b[i] == '\r' && b[i+1] == '\n' &&
                    b[i+2] == '\r' && b[i+3] == '\n') {
                    consumed = i + 4; break;
                }
            }
            if (consumed && consumed <= p->buf_len) {
                p->buf_len -= consumed;
                memmove(p->buf, p->buf + consumed, p->buf_len);
            }
            p->idle_since = lwip_now_ms();
        }
    } else if (p->buf_len >= REQ_BUF_MAX - 1) {
        /* Buffer full without a complete header block.  We only need the
         * request line and Connection: header, both of which arrive early —
         * if the terminator is anywhere in what we have, dispatch on the
         * partial capture.  Otherwise the headers genuinely are too large. */
        if (headers_complete(p->buf, p->buf_len)) {
            p->keep_alive = dispatch(p, p->buf_len);
            p->req_count++;
            if (!p->keep_alive)
                lwip_socket_close(&p->sock);
            else
                p->buf_len = 0;   /* discard; next request starts fresh */
        } else {
            send_response(p, 431, "Request Header Fields Too Large", "text/plain",
                          (const uint8_t *)"Request too large", 17, false);
            lwip_socket_close(&p->sock);
        }
    }

    return true;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void)
{
    if (!lwip_example_stack_start())
        return 1;

    /* --- AppVar selection --- */
    appvar_scan();

    if (g_av_count == 0) {
        lwip_example_dbg_console_begin("HTTP Server");
        lwip_example_line("no LWFS appvar found");
        lwip_example_line("run: python3 lwip-webpacker.py");
        lwip_example_line("     --www www/ --outname LWHTTPD");
        lwip_example_present();
        lwip_example_wait_key();
        return lwip_example_finish(1);
    }

    int sel;
    if (g_av_count == 1) {
        /* Only one option — skip the menu. */
        sel = 0;
    } else {
        sel = appvar_menu();
        if (sel < 0)
            return lwip_example_finish(0);
    }

    if (!appvar_load_named(g_av_list[sel].name)) {
        lwip_example_dbg_console_begin("HTTP Server");
        lwip_example_line("failed to load AppVar");
        lwip_example_present();
        lwip_example_wait_key();
        return lwip_example_finish(1);
    }

    lwip_example_dbg_console_begin("HTTP Server");
    lwip_example_line("waiting for network...");
    lwip_example_line("press [clear] to quit");
    lwip_example_present();
    lwip_set_event_cb(lwip_example_dbg_console_cb);

    lwip_request_services(LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS);

    struct lwip_socket listen_sock = {0};
    if (lwip_socket_create(&listen_sock, LWIP_SOCKET_TCP,
                           LWIP_NETIF_EXT, NULL, 0) != LWIP_OK) {
        lwip_example_line("socket create failed");
        lwip_example_wait_key();
        return lwip_example_finish(1);
    }

    memset(g_peers, 0, sizeof(g_peers));
    bool listening = false;

    for (;;) {
        uint8_t key;
        lwip_service_events();
        key = os_GetCSC();
        if (key == sk_Clear)
            break;
        lwip_example_mem_stats_tick(key);

        /* ---- Phase 1: wait for DHCP ---- */
        if (!listening) {
            lwip_netif_info_t info = {0};
            lwip_default_netif_info(&info);
            if (info.has_ipv4) {
                if (lwip_socket_listen(&listen_sock, HTTP_PORT) != LWIP_OK) {
                    lwip_example_line("listen failed");
                    lwip_example_present();
                    break;
                }
                listening = true;
                lwip_example_clear();
                lwip_example_draw_mem_stats();
                lwip_example_linef("http://%u.%u.%u.%u/",
                    info.ipv4_addr[0], info.ipv4_addr[1],
                    info.ipv4_addr[2], info.ipv4_addr[3]);
                lwip_example_line("serving - [clear] to quit");
                lwip_example_present();
            }
        }

        /* ---- Phase 2: accept new connections ---- */
        for (int i = 0; i < MAX_PEERS; i++) {
            if (g_peers[i].in_use)
                continue;
            peer_t *p = &g_peers[i];
            if (lwip_socket_accept(&listen_sock, &p->sock) != LWIP_OK)
                break;   /* queue empty */
            p->buf_len   = 0;
            p->req_count = 0;
            p->keep_alive = true;
            p->idle_since = lwip_now_ms();
            p->in_use    = true;
            lwip_example_linef("conn %d", i);
            lwip_example_present();
        }

        /* ---- Phase 3: drive active peers ---- */
        for (int i = 0; i < MAX_PEERS; i++)
            peer_tick(&g_peers[i]);
    }

    /* Teardown. */
    for (int i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].in_use)
            lwip_socket_destroy(&g_peers[i].sock);
    }
    lwip_socket_destroy(&listen_sock);
    lwip_example_draw_mem_stats();
    lwip_example_wait_key();
    return lwip_example_finish(0);
}
