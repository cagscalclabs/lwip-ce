/* Networked integration suite for lwIP-CE.
 *
 * Runs against the host side in tests/net/run.py, which serves the
 * endpoints below on the TAP gateway while CEmu emulates the calc's USB
 * Ethernet adapter. Every check is logged to the NETLOG appvar; the screen
 * ends solid green (all passed) or solid red so the autotester can detect
 * completion with a fixed CRC. */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fileioc.h>
#include <graphx.h>
#include <ti/getcsc.h>

#include <lwip.h>

#define HOST         "192.168.84.1"
#define CALC_IP      {192, 168, 84, 2}
#define GATEWAY_IP   {192, 168, 84, 1}
#define PORT_ECHO    7001
#define PORT_UDP     7002
#define PORT_SERVER  7003
#define PORT_WS      7004
#define PORT_TLS_BAD 7005
#define PORT_BULK    7006
#define PORT_CLOSED  7999
#define BULK_BYTES   262144ul
#define LOG_NAME     "NETLOG"
#define LINE_H       10
#define LINES        24

enum { C_BLACK, C_WHITE, C_GREEN, C_RED };

static uint8_t log_handle;
static unsigned passed, failed;
static char line[96];
static uint8_t buf[2048];

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

static void note(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    out(line, C_WHITE);
}

static bool check(const char *name, bool ok)
{
    char msg[96];
    snprintf(msg, sizeof(msg), "%s %s", ok ? "PASS" : "FAIL", name);
    out(msg, ok ? C_GREEN : C_RED);
    if (ok) passed++;
    else failed++;
    return ok;
}

static uint8_t pattern(uint32_t i) { return (uint8_t)(i * 31u + (i >> 8)); }

static bool pump(bool (*done)(void *), void *arg, uint32_t timeout_ms)
{
    uint32_t start = lwip_now_ms();
    while (!done(arg))
    {
        lwip_service_events();
        if (lwip_now_ms() - start > timeout_ms) return false;
    }
    return true;
}

static void settle(uint32_t ms)
{
    uint32_t start = lwip_now_ms();
    while (lwip_now_ms() - start < ms) lwip_service_events();
}

/* ---- network services ------------------------------------------------ */

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

static bool test_dhcp(void)
{
    static const uint8_t want_ip[4] = CALC_IP, want_gw[4] = GATEWAY_IP;
    lwip_netif_info_t info = {0};
    struct services s = {0};
    bool ok = check("dhcp lease", pump(has_ipv4, &info, 60000));
    if (!ok) return false;
    note("  ip %u.%u.%u.%u", info.ipv4_addr[0], info.ipv4_addr[1], info.ipv4_addr[2], info.ipv4_addr[3]);
    check("dhcp address", !memcmp(info.ipv4_addr, want_ip, 4));
    check("dhcp gateway", info.has_ipv4_gateway && !memcmp(info.ipv4_gateway, want_gw, 4));
    check("services request",
          lwip_netif_request_services(NULL, LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS, 30000,
                                      on_service, &s) == LWIP_OK);
    pump(services_done, &s, 35000);
    check("services ready", s.ready == (LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS));
    return true;
}

/* ---- socket helpers -------------------------------------------------- */

static bool not_connecting(void *arg)
{
    lwip_status_t st = lwip_socket_status(arg);
    return st != LWIP_STATUS_INIT && st != LWIP_STATUS_WAITING_SERVICES &&
           st != LWIP_STATUS_RESOLVING && st != LWIP_STATUS_CONNECTING;
}

static bool not_active(void *arg) { return !lwip_socket_is_active(arg); }

static struct lwip_socket *open_socket(lwip_socket_type_t type, const char *host, uint16_t port,
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

static bool write_all(struct lwip_socket *sock, const uint8_t *data, size_t len)
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

static size_t read_exact(struct lwip_socket *sock, uint8_t *dst, size_t len, uint32_t timeout_ms)
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

/* ---- tests ----------------------------------------------------------- */

static void test_echo(const char *name, lwip_socket_type_t type, uint16_t port, const char *ws_path,
                      size_t total)
{
    struct lwip_socket *sock = open_socket(type, HOST, port, ws_path, 20000);
    size_t sent = 0, matched = 0;
    snprintf(line, sizeof(line), "%s connect", name);
    if (!check(line, sock != NULL)) return;
    while (sent < total)
    {
        size_t n = total - sent > 700 ? 700 : total - sent;
        for (size_t i = 0; i < n; i++) buf[i] = pattern(sent + i);
        if (!write_all(sock, buf, n)) break;
        if (read_exact(sock, buf + 1024, n, 20000) != n) break;
        for (size_t i = 0; i < n; i++)
            if (buf[1024 + i] != pattern(sent + i)) goto done;
        sent += n;
        matched = sent;
    }
done:
    snprintf(line, sizeof(line), "%s %u bytes", name, (unsigned)total);
    check(line, matched == total);
    lwip_socket_close(sock);
    pump(not_active, sock, 10000);
    lwip_socket_destroy(sock);
}

static void test_udp(void)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_UDP, HOST, PORT_UDP, NULL, 10000);
    unsigned echoed = 0;
    if (!check("udp connect", sock != NULL)) return;
    for (unsigned i = 0; i < 8; i++)
    {
        size_t n = 32 + i * 64;
        memset(buf, 'a' + i, n);
        if (lwip_socket_write(sock, buf, n) != LWIP_OK) break;
        if (read_exact(sock, buf + 1024, n, 5000) == n && buf[1024] == 'a' + i && buf[1024 + n - 1] == 'a' + i)
            echoed++;
    }
    note("  udp echoed %u/8", echoed);
    check("udp datagrams", echoed >= 7);
    lwip_socket_destroy(sock);
}

static void test_bulk(void)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_BULK, NULL, 20000);
    uint32_t got = 0, start, bad = 0;
    if (!check("bulk connect", sock != NULL)) return;
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 300000)
    {
        size_t n;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf));
        for (size_t i = 0; i < n; i++)
            if (buf[i] != pattern(got + i)) bad++;
        got += n;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  bulk %lu bytes in %lu ms", (unsigned long)got, (unsigned long)(lwip_now_ms() - start));
    check("bulk download", got == BULK_BYTES && !bad);
    lwip_socket_destroy(sock);
}

static void test_server(void)
{
    struct lwip_socket *listener = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 0);
    struct lwip_socket *peer = NULL;
    unsigned served = 0;
    uint32_t start;
    if (!check("server listen", listener && lwip_socket_listen(listener, PORT_SERVER) == LWIP_OK)) return;
    start = lwip_now_ms();
    while (served < 3 && lwip_now_ms() - start < 60000)
    {
        lwip_service_events();
        peer = lwip_socket_accept(listener);
        if (!peer) continue;
        if (read_exact(peer, buf, 16, 10000) == 16 && !memcmp(buf, "lwip-ce-server-", 15) &&
            write_all(peer, buf, 16))
            served++;
        lwip_socket_close(peer);
        pump(not_active, peer, 10000);
        lwip_socket_destroy(peer);
    }
    check("server accepted 3 clients", served == 3);
    lwip_socket_destroy(listener);
}

static void on_error(struct lwip_socket *sock, lwip_socket_event_type_t type, const void *ev_data, void *arg)
{
    (void)sock;
    if (type == LWIP_SOCKET_EV_ERROR && ev_data) *(lwip_socket_error_data_t *)arg = *(const lwip_socket_error_data_t *)ev_data;
}

static void expect_failure(const char *name, lwip_socket_type_t type, const char *host, uint16_t port,
                           lwip_error_t want, int component)
{
    struct lwip_socket *sock = lwip_socket_create(type, LWIP_NETIF_EXT, NULL, 20000);
    lwip_socket_error_data_t error = {0};
    lwip_error_t err;
    if (sock) lwip_socket_on_event(sock, LWIP_SOCKET_EVENTF_ERROR, on_error, &error);
    if (!check(name, sock && lwip_socket_connect(sock, host, port) == LWIP_OK)) return;
    pump(not_connecting, sock, 60000);
    settle(200);
    err = lwip_socket_last_error(sock);
    note("  status %u err %u comp %u raw %d", lwip_socket_status(sock), err, error.component, error.raw_error);
    snprintf(line, sizeof(line), "%s rejected", name);
    check(line, lwip_socket_status(sock) != LWIP_STATUS_CONNECTED && (want == LWIP_OK || err == want) &&
                    (component < 0 || error.component == component));
    lwip_socket_destroy(sock);
}

static void test_https(const char *name, const char *host, const char *path, bool need_body)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_ALTCP_TLS, host, 443, NULL, 60000);
    uint32_t got = 0, start, content_length = 0, header_end = 0;
    char *body;
    snprintf(line, sizeof(line), "%s handshake", name);
    if (!check(line, sock != NULL)) return;
    snprintf((char *)buf, sizeof(buf),
             "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: lwip-ce-nettest\r\nConnection: close\r\n\r\n",
             need_body ? "GET" : "HEAD", path, host);
    write_all(sock, buf, strlen((char *)buf));
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 180000)
    {
        size_t room = got < 1024 ? 1024 - got : 0, n;
        lwip_service_events();
        if (room)
        {
            n = lwip_socket_read(sock, buf + got, room);
            buf[got + n] = '\0';
        }
        else
        {
            n = lwip_socket_read(sock, buf + 1100, sizeof(buf) - 1100);
        }
        got += n;
        if (!header_end && (body = strstr((char *)buf, "\r\n\r\n")))
        {
            char *cl = strstr((char *)buf, "ontent-Length:");
            header_end = (uint32_t)(body + 4 - (char *)buf);
            if (cl) content_length = strtoul(cl + 14, NULL, 10);
        }
        if (!n && !lwip_socket_is_active(sock)) break;
        if (!need_body && header_end) break;
    }
    snprintf(line, sizeof(line), "%s status 200", name);
    check(line, !strncmp((char *)buf, "HTTP/1.1 200", 12));
    if (need_body)
    {
        note("  body %lu of %lu", (unsigned long)(got - header_end), (unsigned long)content_length);
        snprintf(line, sizeof(line), "%s full body", name);
        check(line, content_length && got - header_end == content_length);
    }
    lwip_socket_destroy(sock);
}

static void test_churn(void)
{
    unsigned ok = 0;
    for (unsigned i = 0; i < 16; i++)
    {
        struct lwip_socket *sock = open_socket(i & 1 ? LWIP_SOCKET_ALTCP : LWIP_SOCKET_TCP, HOST,
                                               PORT_ECHO, NULL, 10000);
        if (!sock) continue;
        if (write_all(sock, (const uint8_t *)"churn", 5) && read_exact(sock, buf, 5, 5000) == 5) ok++;
        if (i & 2) lwip_socket_abort(sock);
        else lwip_socket_close(sock);
        pump(not_active, sock, 10000);
        lwip_socket_destroy(sock);
    }
    note("  churn %u/16", ok);
    check("connection churn", ok == 16);
}

int main(void)
{
    bool started;

    gfx_Begin();
    gfx_palette[C_BLACK] = gfx_RGBTo1555(0, 0, 0);
    gfx_palette[C_WHITE] = gfx_RGBTo1555(255, 255, 255);
    gfx_palette[C_GREEN] = gfx_RGBTo1555(64, 220, 96);
    gfx_palette[C_RED] = gfx_RGBTo1555(255, 72, 72);
    gfx_FillScreen(C_BLACK);
    gfx_SetMonospaceFont(8);
    gfx_SetTextBGColor(C_BLACK);
    gfx_SetTextTransparentColor(255);

    ti_Delete(LOG_NAME);
    log_handle = ti_Open(LOG_NAME, "w");
    started = check("lwip_start", lwip_start());
    note("lwIP-CE %s", lwip_version_string());
    if (started && check("lwip_network_up", lwip_network_up()) && test_dhcp())
    {
        test_echo("tcp echo", LWIP_SOCKET_TCP, PORT_ECHO, NULL, 8192);
        test_echo("altcp echo", LWIP_SOCKET_ALTCP, PORT_ECHO, NULL, 4096);
        test_echo("ws echo", LWIP_SOCKET_ALTCP_WS, PORT_WS, "/echo", 2048);
        test_udp();
        test_bulk();
        test_server();
        test_churn();
        expect_failure("tcp refused", LWIP_SOCKET_TCP, HOST, PORT_CLOSED, LWIP_OK, -1);
        expect_failure("dns nxdomain", LWIP_SOCKET_TCP, "lwip-ce-nettest.invalid", 80, LWIP_ERR_DNS, -1);
        expect_failure("tls self-signed", LWIP_SOCKET_ALTCP_TLS, HOST, PORT_TLS_BAD, LWIP_ERR_CONNECT, -1);
        test_https("https head", "tls13.akamai.io", "/", false);
        test_https("https get", "raw.githubusercontent.com",
                   "/lwip-tcpip/lwip/STABLE-2_2_1_RELEASE/src/core/udp.c", true);
    }

    snprintf(line, sizeof(line), "DONE pass %u fail %u", passed, failed);
    out(line, failed ? C_RED : C_GREEN);
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
