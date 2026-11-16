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
    check("raw tcp download 1 MiB intact", s.got == total && !s.bad);
    metric("tcp_down_raw", kbps(s.got, lwip_now_ms() - t0), "KiB/s");
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

/* `gap_us` is the host's wall-clock gap between datagrams. UDP has no flow
 * control, so the flood run only records how much the calc keeps up with. */
static void udp_download(const char *name, unsigned gap_us, uint32_t need)
{
    static struct blast b;
    struct udp_pcb *pcb = udp_new();
    uint32_t t0;
    char cmd[48];
    memset(&b, 0, sizeof(b));
    if (!check("udp blast bind", pcb && udp_bind(pcb, IP_ANY_TYPE, PORT_BLAST) == ERR_OK)) return;
    udp_recv(pcb, blast_recv, &b);
    snprintf(cmd, sizeof(cmd), "udp-blast 1000 512 7050 %u", gap_us);
    host_call(cmd, NULL, 0, 10000);
    /* Emulated time runs well ahead of the host's wall clock while the calc
     * idles, so wait for the stream to go quiet rather than a fixed window. */
    t0 = lwip_now_ms();
    while (lwip_now_ms() - t0 < 600000 && b.got < 1000)
    {
        uint32_t before = b.got;
        settle(15000);
        if (b.got == before && b.got) break;
    }
    note("  %s received %lu/1000", name, (unsigned long)b.got);
    snprintf(line, sizeof(line), "%s received >= %lu/1000", name, (unsigned long)need);
    check(line, b.got >= need);
    snprintf(line, sizeof(line), "%s_received", name);
    metric(line, b.got, "of1000");
    snprintf(line, sizeof(line), "%s", name);
    metric(line, kbps(b.bytes, b.last_ms - b.first_ms), "KiB/s");
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
    struct http_head head = {0};
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
        size_t n, off = 0;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf));
        sample_heap();
        if (!head.done)
        {
            off = http_header_bytes(&head, buf, n);
            if (head.done) t0 = lwip_now_ms();
        }
        body += n - off;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  tls %s body %lu bytes, header %s", cipher, (unsigned long)body, head.done ? "seen" : "missing");
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

/* ---- rate ramp ------------------------------------------------------------
 *
 * Each socket sends upstream at a paced target rate that starts at
 * RAMP_START_KBPS and rises by RAMP_STEP_KBPS per window up to RAMP_CAP_KBPS.
 * The host sniffs the calc's traffic. Datagrams carry their window number in
 * byte 0, so the host attributes them exactly; TCP windows are split at the
 * ramp-mark sent when each window starts. Results are read back once, after
 * the last window: the autotester's suite timeout is in emulated time, which
 * runs far ahead of wall time while the calc waits on the host.
 *
 * Datagram drop = scheduled datagrams that never reached the host, including
 * ones the calc could not queue; stream drop = retransmitted segments / data
 * segments. A socket that never loses anything but cannot reach the target
 * is sender-limited, not unstable. The ramp is a profile, not a gate: only
 * session setup is checked. */

#define PORT_RAMP_UDP   7051
#define PORT_RAMP_TCP   7052
#define PORT_RAMP_WSS   7053
#define RAMP_PROTO      253 /* RFC 3692 experimental IP protocol */
#define RAMP_START_KBPS 64
#define RAMP_STEP_KBPS  64
#define RAMP_CAP_KBPS   1024
#define RAMP_WINDOW_MS  2000
#define RAMP_CHUNK      512
#define RAMP_STEPS      ((RAMP_CAP_KBPS - RAMP_START_KBPS) / RAMP_STEP_KBPS + 1)

enum { RAMP_SENT, RAMP_BLOCKED, RAMP_FATAL };

struct ramp_step { uint16_t kbps, achieved, want, drop_x100; };
static struct ramp_step steps[RAMP_STEPS];

static int ramp_send_socket(void *ctx)
{
    lwip_error_t err = lwip_socket_write(ctx, buf, RAMP_CHUNK);
    if (err == LWIP_OK) return RAMP_SENT;
    return err == LWIP_ERR_MEM ? RAMP_BLOCKED : RAMP_FATAL;
}

static int ramp_send_raw(void *ctx)
{
    ip_addr_t host;
    struct pbuf *p = pbuf_alloc(PBUF_IP, RAMP_CHUNK, PBUF_RAM);
    err_t err;
    if (!p) return RAMP_BLOCKED;
    pbuf_take(p, buf, RAMP_CHUNK);
    ipaddr_aton(HOST, &host);
    err = raw_sendto(ctx, p, &host);
    pbuf_free(p);
    return err == ERR_OK ? RAMP_SENT : RAMP_BLOCKED;
}

/* Runs paced window `i`. False if the connection failed. */
static bool ramp_window(const char *kind, uint16_t port, int (*send)(void *), void *ctx, bool datagram, unsigned i)
{
    char cmd[40];
    struct ramp_step *step = &steps[i];
    uint32_t scheduled = 0, accepted = 0, t0, el;
    snprintf(cmd, sizeof(cmd), "ramp-mark %s %u %u", kind, port, i);
    if (!host_call(cmd, NULL, 0, 15000)) return false;
    buf[0] = (uint8_t)i;
    t0 = lwip_now_ms();
    while ((el = lwip_now_ms() - t0) < RAMP_WINDOW_MS)
    {
        lwip_service_events();
        while (scheduled + RAMP_CHUNK <= (uint32_t)step->kbps * el / 8)
        {
            int r = send(ctx);
            if (r == RAMP_FATAL) return false;
            /* A datagram the calc could not queue is lost; a stream write
             * that would block just leaves the socket behind schedule. */
            if (r == RAMP_BLOCKED && !datagram) break;
            scheduled += RAMP_CHUNK;
            if (r == RAMP_SENT) accepted += RAMP_CHUNK;
        }
    }
    step->achieved = (uint16_t)(accepted * 8 / RAMP_WINDOW_MS);
    step->want = (uint16_t)(scheduled / RAMP_CHUNK);
    return true;
}

/* Fills in window `i`'s drop rate from the host's "<packets> <bytes> <retransmits>". */
static bool ramp_result(const char *kind, uint16_t port, bool datagram, unsigned i)
{
    char cmd[40], reply[48], *p = reply;
    unsigned long seen[3];
    struct ramp_step *step = &steps[i];
    snprintf(cmd, sizeof(cmd), "ramp-result %s %u %u", kind, port, i);
    if (!host_call(cmd, reply, sizeof(reply), 30000)) return false;
    for (int k = 0; k < 3; k++) seen[k] = strtoul(p, &p, 10);
    if (datagram)
    {
        unsigned long got = seen[0] < step->want ? seen[0] : step->want;
        step->drop_x100 = step->want ? (uint16_t)((step->want - got) * 10000 / step->want) : 0;
    }
    else
        step->drop_x100 = seen[0] ? (uint16_t)(seen[2] * 10000 / seen[0]) : 0;
    return true;
}

static void ramp(const char *name, const char *kind, uint16_t port, int (*send)(void *), void *ctx, bool datagram)
{
    unsigned ran = 0, loss = RAMP_STEPS, stable = 0, peak = 0;
    for (unsigned i = 0; i < RAMP_STEPS; i++)
    {
        steps[i].kbps = RAMP_START_KBPS + i * RAMP_STEP_KBPS;
        if (!ramp_window(kind, port, send, ctx, datagram, i))
        {
            note("  %s ramp stopped at %u kbps", name, steps[i].kbps);
            break;
        }
        ran++;
    }
    settle(500);
    for (unsigned i = 0; i < ran; i++)
        if (!ramp_result(kind, port, datagram, i))
        {
            note("  %s ramp results lost from %u kbps", name, steps[i].kbps);
            ran = i;
            break;
        }
    snprintf(line, sizeof(line), "%s rate ramp, %u windows", name, RAMP_STEPS);
    check(line, ran == RAMP_STEPS);
    if (!ran) return;

    /* R = the highest rate actually delivered before the first loss. */
    for (unsigned i = 0; i < ran; i++)
    {
        if (steps[i].achieved > peak) peak = steps[i].achieved;
        if (loss == RAMP_STEPS && steps[i].drop_x100) loss = i;
        if (loss == RAMP_STEPS && steps[i].achieved > stable) stable = steps[i].achieved;
    }
    if (loss < RAMP_STEPS)
    {
        note("RAMP %s stable till %u kbps, loss from %u kbps", name, stable, steps[loss].kbps);
        snprintf(line, sizeof(line), "ramp_%s_stable", name);
        metric(line, stable, "kbps");
        for (unsigned i = loss ? loss - 1 : 0; i < ran; i++)
        {
            note("  %4u kbps => %u.%02u%% drop (sent %u kbps)", steps[i].kbps, steps[i].drop_x100 / 100,
                 steps[i].drop_x100 % 100, steps[i].achieved);
            if (i < loss) continue;
            snprintf(line, sizeof(line), "ramp_%s_%uk_drop", name, steps[i].kbps);
            metric(line, steps[i].drop_x100, "pct_x100");
        }
    }
    else if (peak * 100 < (unsigned)RAMP_CAP_KBPS * 95)
    {
        note("RAMP %s no loss; sender-limited at %u kbps", name, peak);
        snprintf(line, sizeof(line), "ramp_%s_limited", name);
        metric(line, peak, "kbps");
    }
    else
    {
        note("RAMP %s no loss through %u kbps", name, RAMP_CAP_KBPS);
        snprintf(line, sizeof(line), "ramp_%s_stable", name);
        metric(line, peak, "kbps");
    }
}

static void ramp_sessions(void);

static void ramp_all(void)
{
    uint32_t t0 = lwip_now_ms();

    if (!observe("ramp host counters", host_call("ramp-mark udp 7051 0", NULL, 0, 15000)))
    {
        note("  ramp skipped: host has no sniffer (needs root and scapy)");
        return;
    }
    ramp_sessions();
    /* The autotester's suite timeout is in emulated time; keep an eye on
     * how much of it the ramp uses. */
    metric("ramp_total", (lwip_now_ms() - t0) / 1000, "s");
}

static void ramp_sessions(void)
{
    struct lwip_socket *sock;
    struct raw_pcb *pcb;
    char reply[8];

    for (size_t i = 0; i < RAMP_CHUNK; i++) buf[i] = pattern(i);

    sock = open_socket(LWIP_SOCKET_UDP, HOST, PORT_RAMP_UDP, NULL, 15000);
    if (check("ramp udp session", sock != NULL))
    {
        ramp("udp", "udp", PORT_RAMP_UDP, ramp_send_socket, sock, true);
        lwip_socket_destroy(sock);
    }

    pcb = raw_new(RAMP_PROTO);
    if (check("ramp raw pcb", pcb != NULL))
    {
        ramp("raw", "raw", 0, ramp_send_raw, pcb, true);
        raw_remove(pcb);
    }

    sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_RAMP_TCP, NULL, 15000);
    if (check("ramp tcp session", sock != NULL))
    {
        ramp("tcp", "tcp", PORT_RAMP_TCP, ramp_send_socket, sock, false);
        close_socket(sock);
    }

    sock = open_socket(LWIP_SOCKET_ALTCP, HOST, PORT_RAMP_TCP, NULL, 15000);
    if (check("ramp altcp session", sock != NULL))
    {
        ramp("altcp", "tcp", PORT_RAMP_TCP, ramp_send_socket, sock, false);
        close_socket(sock);
    }

    host_call("psk-server gcm x25519 plain", NULL, 0, 15000);
    sock = psk_socket();
    if (check("ramp altcp_tls session", sock != NULL))
    {
        ramp("altcp_tls", "tcp", PORT_PSK, ramp_send_socket, sock, false);
        close_socket(sock);
    }

    sock = open_socket(LWIP_SOCKET_ALTCP_WS, HOST, PORT_WS, "/sink", 15000);
    if (check("ramp ws session", sock != NULL))
    {
        ramp("ws", "tcp", PORT_WS, ramp_send_socket, sock, false);
        close_socket(sock);
    }

    /* WSS is certificate-only, so it needs the runner-local test CA in the
     * truststore; without --truststore-signer it is skipped. */
    if (!host_call("local-trust", reply, sizeof(reply), 5000) || strcmp(reply, "1"))
    {
        observe("ramp wss (no runner-local truststore)", false);
        return;
    }
    sock = open_socket(LWIP_SOCKET_ALTCP_WSS, HOST, PORT_RAMP_WSS, "/sink", 60000);
    if (check("ramp wss session", sock != NULL))
    {
        ramp("wss", "tcp", PORT_RAMP_WSS, ramp_send_socket, sock, false);
        close_socket(sock);
    }
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
        udp_download("udp_down_paced", 5000, 950);
        udp_download("udp_down_flood", 500, 1);
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
        ramp_all();
    }
    return net_end();
}
