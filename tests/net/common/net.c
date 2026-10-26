#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fileioc.h>
#include <graphx.h>
#include <ti/getcsc.h>

#include "net.h"

#define LOG_NAME "NETLOG"
#define LINE_H   10
#define LINES    24

enum { C_BLACK, C_WHITE, C_GREEN, C_RED, C_CYAN };

uint8_t buf[2048];
char line[96];

static uint8_t log_handle;
static unsigned passed, failed;
static bool started;

static void out(const char *s, uint8_t color)
{
    gfx_ShiftUp(LINE_H);
    gfx_SetColor(C_BLACK);
    gfx_FillRectangle_NoClip(0, (LINES - 1) * LINE_H, GFX_LCD_WIDTH, LINE_H);
    gfx_SetTextFGColor(color);
    gfx_PrintStringXY(s, 0, (LINES - 1) * LINE_H + 1);
    if (log_handle)
    {
        ti_Write(s, strlen(s), 1, log_handle);
        ti_Write("\n", 1, 1, log_handle);
    }
}

void note(const char *fmt, ...)
{
    char msg[96];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    out(msg, C_WHITE);
}

bool check(const char *name, bool ok)
{
    char msg[96];
    snprintf(msg, sizeof(msg), "%s %s", ok ? "PASS" : "FAIL", name);
    out(msg, ok ? C_GREEN : C_RED);
    if (ok) passed++;
    else failed++;
    return ok;
}

void metric(const char *name, unsigned long value, const char *unit)
{
    char msg[96];
    snprintf(msg, sizeof(msg), "METRIC %s %lu %s", name, value, unit);
    out(msg, C_CYAN);
}

void note_traceback(uint8_t max)
{
    uint8_t count = 0;
    const struct lwip_traceback_entry *tb = lwip_get_traceback(&count);
    for (uint8_t i = 0; tb && i < count && i < max; i++)
        note("  tb %s %s:%lu x%u r%d", lwip_debug_module_name(tb[i].module), lwip_debug_file_name(tb[i].file),
             (unsigned long)tb[i].line, tb[i].extra, tb[i].raw_error);
}

uint8_t pattern(uint32_t i) { return (uint8_t)(i * 31u + (i >> 8)); }

bool pump(bool (*done)(void *), void *arg, uint32_t timeout_ms)
{
    uint32_t start = lwip_now_ms();
    while (!done(arg))
    {
        lwip_service_events();
        if (lwip_now_ms() - start > timeout_ms) return false;
    }
    return true;
}

void settle(uint32_t ms)
{
    uint32_t start = lwip_now_ms();
    while (lwip_now_ms() - start < ms) lwip_service_events();
}

size_t heap_used(void)
{
    struct mem_accounting_stats st;
    return mem_get_stats(&st) ? st.heap_used : 0;
}

/* ---- host control channel (raw UDP API) ------------------------------- */

static struct udp_pcb *control;
static char control_reply[96];
static bool control_have;

static void control_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (!p) return;
    control_reply[pbuf_copy_partial(p, control_reply, sizeof(control_reply) - 1, 0)] = '\0';
    control_have = true;
    pbuf_free(p);
}

static bool control_done(void *arg)
{
    (void)arg;
    return control_have;
}

bool host_call(const char *cmd, char *reply, size_t reply_len, uint32_t timeout_ms)
{
    ip_addr_t host;
    if (!control)
    {
        control = udp_new();
        if (!control || udp_bind(control, IP4_ADDR_ANY, PORT_CONTROL) != ERR_OK) return false;
        udp_recv(control, control_recv, NULL);
    }
    static unsigned seq;
    char request[96];
    snprintf(request, sizeof(request), "%u %s", ++seq, cmd);
    cmd = request;
    ipaddr_aton(HOST, &host);
    /* Emulated time runs ahead of the host's wall clock; give slow host
     * actions (ping, openssl peers) room before retrying. */
    if (timeout_ms < 30000) timeout_ms = 30000;
    for (int attempt = 0; attempt < 3; attempt++)
    {
        size_t len = strlen(cmd);
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
        if (!p) return false;
        pbuf_take(p, cmd, (u16_t)len);
        control_have = false;
        udp_sendto(control, p, &host, PORT_CONTROL);
        pbuf_free(p);
        if (pump(control_done, NULL, timeout_ms / 3 + 1)) break;
    }
    if (!control_have || strncmp(control_reply, "OK", 2)) return false;
    if (reply && reply_len)
    {
        const char *payload = control_reply[2] == ' ' ? control_reply + 3 : control_reply + 2;
        strncpy(reply, payload, reply_len - 1);
        reply[reply_len - 1] = '\0';
    }
    return true;
}

/* ---- sockets ----------------------------------------------------------- */

bool not_connecting(void *arg)
{
    lwip_status_t st = lwip_socket_status(arg);
    return st != LWIP_STATUS_INIT && st != LWIP_STATUS_WAITING_SERVICES &&
           st != LWIP_STATUS_RESOLVING && st != LWIP_STATUS_CONNECTING;
}

bool not_active(void *arg) { return !lwip_socket_is_active(arg); }

struct lwip_socket *open_socket(lwip_socket_type_t type, const char *host, uint16_t port,
                                const char *ws_path, uint32_t timeout_ms)
{
    struct lwip_socket *sock = lwip_socket_create(type, LWIP_NETIF_EXT, NULL, timeout_ms);
    if (!sock) return NULL;
    if (ws_path) lwip_socket_set_ws_config(sock, ws_path, NULL);
    if (lwip_socket_connect(sock, host, port) != LWIP_OK)
    {
        lwip_socket_destroy(sock);
        return NULL;
    }
    pump(not_connecting, sock, timeout_ms + 5000);
    if (lwip_socket_status(sock) != LWIP_STATUS_CONNECTED)
    {
        note("  status %u err %u", lwip_socket_status(sock), lwip_socket_last_error(sock));
        lwip_socket_destroy(sock);
        return NULL;
    }
    return sock;
}

bool write_all(struct lwip_socket *sock, const uint8_t *data, size_t len)
{
    uint32_t start = lwip_now_ms();
    while (len)
    {
        size_t n = len > 512 ? 512 : len;
        lwip_error_t err = lwip_socket_write(sock, data, n);
        if (err == LWIP_OK)
        {
            data += n;
            len -= n;
            start = lwip_now_ms();
        }
        else if (err != LWIP_ERR_MEM || lwip_now_ms() - start > 30000)
        {
            note("  write err %u", err);
            return false;
        }
        lwip_service_events();
    }
    return true;
}

size_t read_exact(struct lwip_socket *sock, uint8_t *dst, size_t len, uint32_t timeout_ms)
{
    size_t got = 0;
    uint32_t start = lwip_now_ms();
    while (got < len && lwip_now_ms() - start < timeout_ms)
    {
        lwip_service_events();
        got += lwip_socket_read(sock, dst + got, len - got);
        if (!lwip_socket_available(sock) && !lwip_socket_is_active(sock)) break;
    }
    return got;
}

void close_socket(struct lwip_socket *sock)
{
    if (!sock) return;
    lwip_socket_close(sock);
    pump(not_active, sock, 10000);
    lwip_socket_destroy(sock);
}

/* ---- lifecycle --------------------------------------------------------- */

static bool has_ipv4(void *arg)
{
    lwip_netif_info_t *info = arg;
    return lwip_default_netif_info(info) && info->has_ipv4;
}

struct services { uint8_t ready, failed; };

static void on_service(struct netif *netif, const lwip_netif_service_event_t *ev, void *arg)
{
    struct services *s = arg;
    (void)netif;
    if (ev->status == LWIP_NETIF_SERVICE_UP) s->ready |= ev->service_id;
    else s->failed |= ev->service_id;
}

static bool services_done(void *arg)
{
    struct services *s = arg;
    return ((s->ready | s->failed) & (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS)) ==
           (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS);
}

bool net_begin(const char *suite)
{
    static const uint8_t want_ip[4] = CALC_IP_BYTES, want_gw[4] = HOST_IP_BYTES;
    lwip_netif_info_t info = {0};
    struct services s = {0};
    uint32_t t0;

    gfx_Begin();
    gfx_palette[C_BLACK] = gfx_RGBTo1555(0, 0, 0);
    gfx_palette[C_WHITE] = gfx_RGBTo1555(255, 255, 255);
    gfx_palette[C_GREEN] = gfx_RGBTo1555(64, 220, 96);
    gfx_palette[C_RED] = gfx_RGBTo1555(255, 72, 72);
    gfx_palette[C_CYAN] = gfx_RGBTo1555(96, 200, 255);
    gfx_FillScreen(C_BLACK);
    gfx_SetMonospaceFont(8);
    gfx_SetTextBGColor(C_BLACK);
    gfx_SetTextTransparentColor(255);

    ti_Delete(LOG_NAME);
    log_handle = ti_Open(LOG_NAME, "w");
    note("SUITE %s", suite);

    started = check("lwip_start", lwip_start());
    if (!started) return false;
    note("lwIP-CE %s", lwip_version_string());
    if (!check("lwip_network_up", lwip_network_up())) return false;
    t0 = lwip_now_ms();
    if (!check("dhcp lease", pump(has_ipv4, &info, 60000))) return false;
    metric("dhcp_lease_ms", lwip_now_ms() - t0, "ms");
    check("dhcp address", !memcmp(info.ipv4_addr, want_ip, 4));
    check("dhcp gateway", info.has_ipv4_gateway && !memcmp(info.ipv4_gateway, want_gw, 4));
    check("services request",
          lwip_netif_request_services(NULL, LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS, 30000, on_service, &s) ==
              LWIP_OK);
    pump(services_done, &s, 35000);
    check("services ready", s.ready == (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS));
    snprintf(line, sizeof(line), "begin %s", suite);
    return check("host control channel", host_call(line, NULL, 0, 15000));
}

int net_end(void)
{
    char msg[48];
    snprintf(msg, sizeof(msg), "DONE pass %u fail %u", passed, failed);
    out(msg, failed ? C_RED : C_GREEN);
    if (control)
    {
        host_call("end", NULL, 0, 3000);
        udp_remove(control);
        control = NULL;
    }
    if (log_handle) ti_Close(log_handle);
    log_handle = ti_Open(LOG_NAME, "r");
    if (log_handle)
    {
        ti_SetArchiveStatus(true, log_handle);
        ti_Close(log_handle);
    }
    if (started) lwip_stop();
    gfx_FillScreen(failed || !passed ? C_RED : C_GREEN);
    while (!os_GetCSC())
        ;
    gfx_End();
    return 0;
}
