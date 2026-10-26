/* NETPERF: throughput, latency and memory profile of lwIP-CE.
 *
 * All timings come from lwip_now_ms(), i.e. the calc's own clock, so they
 * measure what the eZ80 + stack can do rather than the emulator host. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"

#define PORT_SIZED_BULK 7016
#define PORT_BLAST      7050
#define PORT_LOOP       7301
#define PSK_IDENTITY    "lwip-ce-nettest"

static uint8_t psk[32];
static size_t heap_peak;

static void sample_heap(void)
{
    size_t h = heap_used();
    if (h > heap_peak) heap_peak = h;
}

static unsigned long kbps(uint32_t bytes, uint32_t ms) { return ms ? (unsigned long)((uint64_t)bytes * 1000 / 1024 / ms) : 0; }

/* ---- TCP throughput, socket API --------------------------------------- */

static void tcp_down_socket(uint32_t total)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_SIZED_BULK, NULL, 20000);
    uint8_t req[4] = {(uint8_t)(total >> 24), (uint8_t)(total >> 16), (uint8_t)(total >> 8), (uint8_t)total};
    uint32_t got = 0, bad = 0, t0;
    if (!check("tcp download connect", sock != NULL)) return;
    write_all(sock, req, 4);
    t0 = lwip_now_ms();
    while (got < total && lwip_now_ms() - t0 < 600000)
    {
        size_t n;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf));
        for (size_t i = 0; i < n; i += 61)
            if (buf[i] != pattern(got + i)) bad++;
        got += n;
        sample_heap();
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    check("tcp download 1 MiB intact", got == total && !bad);
    metric("tcp_down_socket", kbps(got, lwip_now_ms() - t0), "KiB/s");
    close_socket(sock);
}

static void tcp_up_socket(uint32_t total)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_SINK, NULL, 20000);
    uint32_t sent = 0, t0;
    size_t n;
    if (!check("tcp upload connect", sock != NULL)) return;
    t0 = lwip_now_ms();
    while (sent < total)
    {
        size_t chunk = total - sent > 1024 ? 1024 : total - sent;
        for (size_t i = 0; i < chunk; i++) buf[i] = pattern(sent + i);
        if (!write_all(sock, buf, chunk)) break;
        sent += chunk;
        sample_heap();
    }
    lwip_socket_shutdown(sock);
    n = read_exact(sock, buf, 32, 60000);
    buf[n] = '\0';
    note("  sink: %s", (char *)buf);
    snprintf(line, sizeof(line), "%lu ok", (unsigned long)total);
    check("tcp upload 512 KiB acknowledged intact", !strcmp((char *)buf, line));
    metric("tcp_up_socket", kbps(sent, lwip_now_ms() - t0), "KiB/s");
    lwip_socket_destroy(sock);
}

/* ---- TCP throughput, raw API --------------------------------------------- */

struct raw_dl { uint32_t got, bad; bool connected, error, closed; };

static err_t dl_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct raw_dl *s = arg;
    (void)err;
    if (!p)
    {
        s->closed = true;
        return ERR_OK;
    }
    for (u16_t i = 0; i < p->tot_len; i += 61)
        if (pbuf_get_at(p, i) != pattern(s->got + i)) s->bad++;
    s->got += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t dl_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    ((struct raw_dl *)arg)->connected = err == ERR_OK;
    return ERR_OK;
}

static void dl_err(void *arg, err_t err)
{
    (void)err;
    ((struct raw_dl *)arg)->error = true;
}

static bool dl_ready(void *arg) { return ((struct raw_dl *)arg)->connected || ((struct raw_dl *)arg)->error; }
static bool dl_done(void *arg) { return ((struct raw_dl *)arg)->closed || ((struct raw_dl *)arg)->error; }

static void tcp_down_raw(uint32_t total)
{
    static struct raw_dl s;
    struct tcp_pcb *pcb = tcp_new();
    ip_addr_t host;
    uint8_t req[4] = {(uint8_t)(total >> 24), (uint8_t)(total >> 16), (uint8_t)(total >> 8), (uint8_t)total};
    uint32_t t0;
    memset(&s, 0, sizeof(s));
    ipaddr_aton(HOST, &host);
    tcp_arg(pcb, &s);
    tcp_recv(pcb, dl_recv);
    tcp_err(pcb, dl_err);
    tcp_connect(pcb, &host, PORT_SIZED_BULK, dl_connected);
    if (!check("raw tcp download connect", pump(dl_ready, &s, 15000) && s.connected)) return;
    tcp_write(pcb, req, 4, TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
    t0 = lwip_now_ms();
    while (s.got < total && !s.error && lwip_now_ms() - t0 < 600000) lwip_service_events();
    metric("tcp_down_raw", kbps(s.got, lwip_now_ms() - t0), "KiB/s");
    check("raw tcp download 1 MiB intact", s.got == total && !s.bad);
    if (!s.error)
    {
        tcp_close(pcb);
        pump(dl_done, &s, 5000);
    }
}

/* ---- latency ------------------------------------------------------------- */

static void tcp_connect_latency(void)
{
    uint32_t total = 0, worst = 0;
    unsigned ok = 0;
    for (unsigned i = 0; i < 10; i++)
    {
        uint32_t t0 = lwip_now_ms(), ms;
        struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_ECHO, NULL, 10000);
        ms = lwip_now_ms() - t0;
        if (!sock) continue;
        ok++;
        total += ms;
        if (ms > worst) worst = ms;
        close_socket(sock);
    }
    check("10 TCP connects", ok == 10);
    if (ok)
    {
        metric("tcp_connect_avg", total / ok, "ms");
        metric("tcp_connect_max", worst, "ms");
    }
}

static void echo_rtt(const char *name, lwip_socket_type_t type, uint16_t port, const char *path)
{
    struct lwip_socket *sock = open_socket(type, HOST, port, path, 15000);
    uint32_t total = 0, worst = 0, best = 0xffffffff;
    unsigned ok = 0;
    snprintf(line, sizeof(line), "%s rtt session", name);
    if (!check(line, sock != NULL)) return;
    for (unsigned i = 0; i < 30; i++)
    {
        uint32_t t0 = lwip_now_ms(), ms;
        memset(buf, 'a' + (i % 26), 64);
        if (lwip_socket_write(sock, buf, 64) != LWIP_OK || read_exact(sock, buf + 64, 64, 5000) != 64) continue;
        ms = lwip_now_ms() - t0;
        ok++;
        total += ms;
        if (ms > worst) worst = ms;
        if (ms < best) best = ms;
    }
    snprintf(line, sizeof(line), "%s 30 round trips", name);
    check(line, ok >= 29);
    if (ok)
    {
        snprintf(line, sizeof(line), "%s_rtt_avg", name);
        metric(line, total / ok, "ms");
        snprintf(line, sizeof(line), "%s_rtt_min", name);
        metric(line, best, "ms");
        snprintf(line, sizeof(line), "%s_rtt_max", name);
        metric(line, worst, "ms");
    }
    if (type == LWIP_SOCKET_UDP) lwip_socket_destroy(sock);
    else close_socket(sock);
}

static void ws_throughput(void)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_ALTCP_WS, HOST, PORT_WS, "/echo", 15000);
    uint32_t moved = 0, t0;
    if (!check("ws throughput session", sock != NULL)) return;
    t0 = lwip_now_ms();
    while (moved < 65536)
    {
        for (size_t i = 0; i < 1000; i++) buf[i] = pattern(moved + i);
        if (!write_all(sock, buf, 1000) || read_exact(sock, buf + 1000, 1000, 10000) != 1000 ||
            memcmp(buf, buf + 1000, 1000))
            break;
        moved += 1000;
    }
    check("ws echo 64 KB", moved >= 65000);
    metric("ws_echo_throughput", kbps(moved * 2, lwip_now_ms() - t0), "KiB/s");
    close_socket(sock);
}

/* ---- UDP --------------------------------------------------------------- */

struct blast { uint32_t got, bytes, first_ms, last_ms; uint8_t seen[128]; };

static void blast_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    struct blast *b = arg;
    uint8_t seq[4];
    uint32_t n;
    (void)pcb; (void)addr; (void)port;
    pbuf_copy_partial(p, seq, 4, 0);
    n = ((uint32_t)seq[0] << 24) | ((uint32_t)seq[1] << 16) | ((uint32_t)seq[2] << 8) | seq[3];
    if (n < 1024 && !(b->seen[n >> 3] & (1u << (n & 7))))
    {
        b->seen[n >> 3] |= (uint8_t)(1u << (n & 7));
        b->got++;
        b->bytes += p->tot_len;
        if (!b->first_ms) b->first_ms = lwip_now_ms();
        b->last_ms = lwip_now_ms();
    }
    pbuf_free(p);
}

static void udp_download(void)
{
    static struct blast b;
    struct udp_pcb *pcb = udp_new();
    uint32_t t0;
    memset(&b, 0, sizeof(b));
    if (!check("udp blast bind", pcb && udp_bind(pcb, IP_ANY_TYPE, PORT_BLAST) == ERR_OK)) return;
    udp_recv(pcb, blast_recv, &b);
    host_call("udp-blast 1000 512 7050 500", NULL, 0, 10000);
    t0 = lwip_now_ms();
    while (lwip_now_ms() - t0 < 30000 && b.got < 1000)
    {
        uint32_t before = b.got;
        settle(2000);
        if (b.got == before && b.got) break;
    }
    note("  udp received %lu/1000", (unsigned long)b.got);
    check("udp blast mostly received", b.got >= 900);
    metric("udp_down_received", b.got, "of1000");
    metric("udp_down", kbps(b.bytes, b.last_ms - b.first_ms), "KiB/s");
    udp_remove(pcb);
}

/* ---- loopback (stack cost without the USB adapter) ---------------------- */

static void loopback_throughput(void)
{
    struct lwip_socket *listener = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_LOOP, NULL, 0);
    struct lwip_socket *client = NULL, *peer = NULL;
    uint32_t moved = 0, t0;
    if (!check("loopback perf listen", listener && lwip_socket_listen(listener, PORT_LOOP) == LWIP_OK)) return;
    client = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_LOOP, NULL, 10000);
    lwip_socket_connect(client, "127.0.0.1", PORT_LOOP);
    t0 = lwip_now_ms();
    while (!peer && lwip_now_ms() - t0 < 10000)
    {
        lwip_service_events();
        peer = lwip_socket_accept(listener);
    }
    pump(not_connecting, client, 10000);
    if (check("loopback perf connected", peer && lwip_socket_status(client) == LWIP_STATUS_CONNECTED))
    {
        t0 = lwip_now_ms();
        while (moved < 262144ul && lwip_now_ms() - t0 < 300000)
        {
            size_t n;
            if (lwip_socket_write(client, buf, 512) != LWIP_OK && lwip_socket_available(peer) == 0)
                lwip_service_events();
            lwip_service_events();
            n = lwip_socket_read(peer, buf + 1024, 1024);
            moved += n;
        }
        check("loopback moved 256 KiB", moved >= 262144ul);
        metric("tcp_loopback", kbps(moved, lwip_now_ms() - t0), "KiB/s");
    }
    close_socket(peer);
    close_socket(client);
    lwip_socket_destroy(listener);
}

/* ---- TLS ----------------------------------------------------------------- */

static struct lwip_socket *psk_socket(void)
{
    struct lwip_socket *sock = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 30000);
    if (!sock) return NULL;
    lwip_socket_set_tls_psk(sock, psk, (const uint8_t *)PSK_IDENTITY, strlen(PSK_IDENTITY));
    if (lwip_socket_connect(sock, HOST, PORT_PSK) != LWIP_OK)
    {
        lwip_socket_destroy(sock);
        return NULL;
    }
    while (!not_connecting(sock))
    {
        lwip_service_events();
        sample_heap();
    }
    if (lwip_socket_status(sock) != LWIP_STATUS_CONNECTED)
    {
        lwip_socket_destroy(sock);
        return NULL;
    }
    return sock;
}

static void tls_handshakes(void)
{
    uint32_t total = 0;
    unsigned ok = 0;
    size_t before = heap_used();
    heap_peak = before;
    for (unsigned i = 0; i < 3; i++)
    {
        uint32_t t0 = lwip_now_ms();
        struct lwip_socket *sock;
        host_call("psk-server gcm x25519 rev", NULL, 0, 15000);
        sock = psk_socket();
        if (!sock) continue;
        total += lwip_now_ms() - t0;
        ok++;
        close_socket(sock);
    }
    check("3 TLS PSK handshakes", ok == 3);
    if (ok) metric("tls_psk_x25519_handshake_avg", total / ok, "ms");
    metric("tls_handshake_heap_peak", heap_peak - before, "bytes");
}

static void tls_download(const char *cipher)
{
    char cmd[48];
    struct lwip_socket *sock;
    uint32_t body = 0, t0;
    bool header = false;
    snprintf(cmd, sizeof(cmd), "psk-server %s x25519 www4k", cipher);
    host_call(cmd, NULL, 0, 15000);
    sock = psk_socket();
    snprintf(line, sizeof(line), "tls %s download session", cipher);
    if (!check(line, sock != NULL)) return;
    heap_peak = heap_used();
    write_all(sock, (const uint8_t *)"GET /bulk.bin HTTP/1.0\r\n\r\n", 26);
    t0 = lwip_now_ms();
    while (lwip_now_ms() - t0 < 600000)
    {
        size_t n = lwip_socket_read(sock, buf, sizeof(buf) - 1), off = 0;
        lwip_service_events();
        sample_heap();
        if (!header && n)
        {
            char *end;
            buf[n] = '\0';
            end = strstr((char *)buf, "\r\n\r\n");
            if (!end) continue;
            header = true;
            off = (size_t)(end + 4 - (char *)buf);
            t0 = lwip_now_ms();
        }
        body += n - off;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    snprintf(line, sizeof(line), "tls %s download 128 KiB", cipher);
    check(line, body == 131072ul);
    snprintf(line, sizeof(line), "tls_down_%s", cipher);
    metric(line, kbps(body, lwip_now_ms() - t0), "KiB/s");
    snprintf(line, sizeof(line), "tls_down_%s_heap_peak", cipher);
    metric(line, heap_peak, "bytes");
    lwip_socket_destroy(sock);
}

static void tls_upload(void)
{
    struct lwip_socket *sock;
    uint32_t sent = 0, t0;
    char reply[32];
    host_call("psk-server gcm x25519 plain", NULL, 0, 15000);
    sock = psk_socket();
    if (!check("tls upload session", sock != NULL)) return;
    memset(buf, 'U', 1023);
    buf[1023] = '\n';
    t0 = lwip_now_ms();
    while (sent < 65536ul && write_all(sock, buf, 1024)) sent += 1024;
    check("tls upload reached server", host_call("psk-count U", reply, sizeof(reply), 60000) && atol(reply) >= 65536l - 64);
    metric("tls_up_gcm", kbps(sent, lwip_now_ms() - t0), "KiB/s");
    close_socket(sock);
}

int main(void)
{
    for (uint8_t i = 0; i < 32; i++) psk[i] = pattern(i);
    if (net_begin("perf"))
    {
        size_t base = heap_used();
        metric("heap_idle", base, "bytes");
        heap_peak = base;
        tcp_down_socket(1048576ul);
        metric("tcp_down_heap_peak", heap_peak - base, "bytes");
        tcp_down_raw(1048576ul);
        heap_peak = base;
        tcp_up_socket(524288ul);
        metric("tcp_up_heap_peak", heap_peak - base, "bytes");
        udp_download();
        tcp_connect_latency();
        echo_rtt("tcp", LWIP_SOCKET_TCP, PORT_ECHO, NULL);
        echo_rtt("udp", LWIP_SOCKET_UDP, PORT_UDP, NULL);
        echo_rtt("ws", LWIP_SOCKET_ALTCP_WS, PORT_WS, "/echo");
        ws_throughput();
        loopback_throughput();
        tls_handshakes();
        tls_download("gcm");
        tls_download("ccm");
        tls_upload();
    }
    return net_end();
}
