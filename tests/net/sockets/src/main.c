/* NETTEST: the lwip_socket_* API end to end against tests/net/run.py. */
#include <stdio.h>
#include <string.h>

#include "net.h"

#define PORT_HALFCLOSE 7009
#define PORT_RESET     7010
#define PORT_CLOSER    7011
#define PORT_LOOP      7300
#define PORT_SOCKET_PSK  7103
#define PORT_SOCKET_CERT 7104
#define PSK_IDENTITY "lwip-ce-nettest"
#define CERT_PASSWORD "lwip-ce-test-password"

static char cert_password[] = CERT_PASSWORD;
static uint8_t cert_password_calls;

static char *cert_password_input(void)
{
    cert_password_calls++;
    return cert_password;
}

static void test_echo(const char *name, lwip_socket_type_t type, uint16_t port, const char *ws_path, size_t total)
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
    close_socket(sock);
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
    unsigned served = 0;
    uint32_t start;
    char reply[48];
    if (!check("server listen", listener && lwip_socket_listen(listener, PORT_SERVER) == LWIP_OK)) return;
    check("listen twice rejected", lwip_socket_listen(listener, PORT_SERVER) != LWIP_OK);
    check("host connects", host_call("connect 7003 3", NULL, 0, 5000));
    start = lwip_now_ms();
    while (served < 3 && lwip_now_ms() - start < 60000)
    {
        struct lwip_socket *peer;
        lwip_service_events();
        peer = lwip_socket_accept(listener);
        if (!peer) continue;
        if (read_exact(peer, buf, 16, 10000) == 16 && !memcmp(buf, "lwip-ce-server-", 15) && write_all(peer, buf, 16))
            served++;
        close_socket(peer);
    }
    check("server accepted 3 clients", served == 3);
    check("host saw 3 echoes", host_call("connect-result", reply, sizeof(reply), 15000) && !strcmp(reply, "3/3"));
    lwip_socket_destroy(listener);
}

static void exercise_tls_socket_server(struct lwip_socket *listener,
                                       const char *mode, uint16_t port,
                                       const char *message)
{
    struct lwip_socket *peer = NULL;
    char command[48], reply[32];
    uint32_t start;
    size_t message_len = strlen(message);

    snprintf(command, sizeof(command), "socket-tls-start %s %u", mode, port);
    if (!check("host starts socket TLS client",
               host_call(command, NULL, 0, 15000)))
        return;

    start = lwip_now_ms();
    while (!peer && lwip_now_ms() - start < 120000)
    {
        lwip_service_events();
        peer = lwip_socket_accept(listener);
    }
    snprintf(line, sizeof(line), "socket TLS %s accept", mode);
    if (check(line, peer != NULL))
    {
        bool echoed = read_exact(peer, buf, message_len, 30000) == message_len &&
                      !memcmp(buf, message, message_len) &&
                      write_all(peer, buf, message_len);
        snprintf(line, sizeof(line), "socket TLS %s read/write", mode);
        check(line, echoed);
        close_socket(peer);
    }
    snprintf(line, sizeof(line), "socket TLS %s host echo", mode);
    check(line, host_call("socket-tls-result", reply, sizeof(reply), 30000) &&
                !strcmp(reply, "echo"));
}

static void test_tls_socket_servers(void)
{
    struct lwip_socket *listener;
    uint8_t psk[32];

    listener = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 0);
    if (!check("socket TLS PSK listener create", listener != NULL)) return;
    for (uint8_t i = 0; i < sizeof(psk); i++) psk[i] = pattern(i);
    if (check("socket TLS PSK configure",
              lwip_socket_set_tls_psk(listener, psk,
                                      (const uint8_t *)PSK_IDENTITY,
                                      strlen(PSK_IDENTITY)) == LWIP_OK) &&
        check("socket TLS PSK listen selects server mode",
              lwip_socket_listen(listener, PORT_SOCKET_PSK) == LWIP_OK))
    {
        check("socket TLS PSK setter locked after listen",
              lwip_socket_set_tls_psk(listener, psk,
                                      (const uint8_t *)PSK_IDENTITY,
                                      strlen(PSK_IDENTITY)) == LWIP_ERR_STATE);
        exercise_tls_socket_server(listener, "psk", PORT_SOCKET_PSK,
                                   "lwip-ce psk server check\n");
    }
    close_socket(listener);

    listener = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 0);
    if (!check("socket TLS cert listener create", listener != NULL)) return;
    bool cert_ready =
        check("socket TLS cert configure",
              lwip_socket_set_tls_cert(listener, "lwIPSKEY", "lwIPSCRT") == LWIP_OK) &&
        check("encrypted cert key fails closed without TTY",
              lwip_socket_listen(listener, PORT_SOCKET_CERT) == LWIP_ERR_MEM);
    bool cert_attempted = cert_ready;
    if (cert_ready)
    {
        uint32_t started = lwip_now_ms();
        lwip_set_tty(cert_password_input);
        lwip_error_t result = lwip_socket_listen(listener, PORT_SOCKET_CERT);
        note("  encrypted cert listen result %u, callback calls %u, %lu ms",
             result, cert_password_calls,
             (unsigned long)(lwip_now_ms() - started));
        check("encrypted cert TTY callback invoked", cert_password_calls == 1);
        cert_ready = result == LWIP_OK;
    }
    if (cert_attempted &&
        check("socket TLS cert listen selects server mode", cert_ready))
    {
        bool password_cleared = true;
        for (size_t i = 0; i < sizeof(cert_password) - 1; i++)
            password_cleared &= cert_password[i] == '\0';
        check("encrypted cert password buffer wiped after use", password_cleared);
        struct lwip_socket *tty_probe =
            lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 0);
        bool probe_ready =
            check("socket TLS one-shot TTY probe create", tty_probe != NULL) &&
            check("socket TLS one-shot TTY probe configure",
                  lwip_socket_set_tls_cert(tty_probe, "lwIPSKEY", "lwIPSCRT") == LWIP_OK);
        if (probe_ready)
        {
            check("encrypted cert TTY callback consumed after use",
                  lwip_socket_listen(tty_probe, PORT_SOCKET_CERT + 1) == LWIP_ERR_MEM);
        }
        close_socket(tty_probe);
        check("socket TLS cert setter locked after listen",
              lwip_socket_set_tls_cert(listener, "lwIPSKEY", "lwIPSCRT") == LWIP_ERR_STATE);
        exercise_tls_socket_server(listener, "cert", PORT_SOCKET_CERT,
                                   "lwip-ce cert server check\n");
    }
    lwip_set_tty(NULL);
    close_socket(listener);
}

static void test_churn(void)
{
    unsigned ok = 0;
    for (unsigned i = 0; i < 16; i++)
    {
        struct lwip_socket *sock =
            open_socket(i & 1 ? LWIP_SOCKET_ALTCP : LWIP_SOCKET_TCP, HOST, PORT_ECHO, NULL, 10000);
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

static void on_error(struct lwip_socket *sock, lwip_socket_event_type_t type, const void *ev_data, void *arg)
{
    (void)sock;
    if (type == LWIP_SOCKET_EV_ERROR && ev_data) *(lwip_socket_error_data_t *)arg = *(const lwip_socket_error_data_t *)ev_data;
}

static void expect_failure(const char *name, lwip_socket_type_t type, const char *host, uint16_t port,
                           uint32_t timeout_ms, lwip_error_t want)
{
    struct lwip_socket *sock = lwip_socket_create(type, LWIP_NETIF_EXT, NULL, timeout_ms);
    lwip_socket_error_data_t error = {0};
    uint32_t start = lwip_now_ms();
    if (sock) lwip_socket_on_event(sock, LWIP_SOCKET_EVENTF_ERROR, on_error, &error);
    if (!check(name, sock && lwip_socket_connect(sock, host, port) == LWIP_OK)) return;
    pump(not_connecting, sock, timeout_ms + 30000);
    settle(200);
    note("  status %u err %u comp %u raw %d in %lu ms", lwip_socket_status(sock), lwip_socket_last_error(sock),
         error.component, error.raw_error, (unsigned long)(lwip_now_ms() - start));
    snprintf(line, sizeof(line), "%s rejected", name);
    check(line, lwip_socket_status(sock) != LWIP_STATUS_CONNECTED &&
                    (want == LWIP_OK || lwip_socket_last_error(sock) == want));
    lwip_socket_destroy(sock);
}

static void test_failures(void)
{
    char reply[64];
    expect_failure("tcp refused", LWIP_SOCKET_TCP, HOST, PORT_CLOSED, 20000, LWIP_OK);
    expect_failure("dns nxdomain", LWIP_SOCKET_TCP, "lwip-ce-nettest.invalid", 80, 20000, LWIP_ERR_DNS);
    expect_failure("tls untrusted cert", LWIP_SOCKET_ALTCP_TLS, HOST, PORT_TLS_BAD, 20000, LWIP_ERR_CONNECT);
    check("tls alert sent to untrusted server",
          host_call("tls-bad-result", reply, sizeof(reply), 5000) && strstr(reply, "UNKNOWN_CA"));
    expect_failure("connect timeout", LWIP_SOCKET_TCP, "10.255.255.1", 9, 3000, LWIP_OK);
}

static void test_halfclose(void)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_HALFCLOSE, NULL, 10000);
    size_t n;
    if (!check("half-close connect", sock != NULL)) return;
    for (size_t i = 0; i < 3000; i++) buf[i % 1000] = pattern(i);
    write_all(sock, buf, 1000);
    write_all(sock, buf, 1000);
    write_all(sock, buf, 1000);
    check("shutdown write side", lwip_socket_shutdown(sock) == LWIP_OK);
    check("write after shutdown rejected", lwip_socket_write(sock, buf, 1) != LWIP_OK);
    n = read_exact(sock, buf, 32, 15000);
    buf[n] = '\0';
    note("  host replied \"%s\"", (char *)buf);
    check("peer read 3000 bytes then EOF", !strcmp((char *)buf, "3000 bye"));
    pump(not_active, sock, 10000);
    check("peer close after half-close", lwip_socket_status(sock) == LWIP_STATUS_CLOSED);
    lwip_socket_destroy(sock);
}

static void test_peer_close_and_reset(void)
{
    struct lwip_socket *sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_CLOSER, NULL, 10000);
    size_t n;
    if (check("peer close connect", sock != NULL))
    {
        n = read_exact(sock, buf, 3, 10000);
        pump(not_active, sock, 10000);
        check("data before FIN delivered", n == 3 && !memcmp(buf, "bye", 3));
        check("status CLOSED on FIN", lwip_socket_status(sock) == LWIP_STATUS_CLOSED);
        check("read after close is empty", lwip_socket_read(sock, buf, 4) == 0);
        lwip_socket_destroy(sock);
    }
    sock = open_socket(LWIP_SOCKET_TCP, HOST, PORT_RESET, NULL, 10000);
    if (check("peer reset connect", sock != NULL))
    {
        write_all(sock, (const uint8_t *)"x", 1);
        pump(not_active, sock, 10000);
        note("  status %u err %u", lwip_socket_status(sock), lwip_socket_last_error(sock));
        check("status RESET on RST", lwip_socket_status(sock) == LWIP_STATUS_RESET);
        lwip_socket_destroy(sock);
    }
}

static void test_backpressure(void)
{
    struct lwip_socket *sock = lwip_socket_create_ex(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 20000, 1024);
    uint32_t got = 0, bad = 0, start;
    size_t peak = 0;
    if (!check("create_ex rx_ring_max 1024", sock != NULL)) return;
    if (!check("hold connect", lwip_socket_connect(sock, HOST, PORT_HOLD) == LWIP_OK &&
                                   pump(not_connecting, sock, 20000) &&
                                   lwip_socket_status(sock) == LWIP_STATUS_CONNECTED))
    {
        lwip_socket_destroy(sock);
        return;
    }
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 4000)
    {
        lwip_service_events();
        if (lwip_socket_available(sock) > peak) peak = lwip_socket_available(sock);
    }
    note("  buffered %u bytes without reading", (unsigned)peak);
    check("rx ring bounded by rx_ring_max", peak > 0 && peak <= 1024);
    check("connection alive under backpressure", lwip_socket_status(sock) == LWIP_STATUS_CONNECTED);
    check("resize rx_ring_max", lwip_socket_resize_rx_max(sock, 4096) == LWIP_OK);
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 60000)
    {
        size_t n;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf));
        for (size_t i = 0; i < n; i++)
            if (buf[i] != pattern(got + i)) bad++;
        got += n;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  drained %lu bytes", (unsigned long)got);
    check("32 KiB delivered intact after backpressure", got == 32768ul && !bad);
    lwip_socket_destroy(sock);
}

struct events { unsigned connected, closed, readable, writable, polls, errors; lwip_status_t last; };

static void on_event(struct lwip_socket *sock, lwip_socket_event_type_t type, const void *ev_data, void *arg)
{
    struct events *ev = arg;
    (void)sock;
    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st = ev_data;
        ev->last = st->current;
        if (st->current == LWIP_STATUS_CONNECTED) ev->connected++;
        if (st->current == LWIP_STATUS_CLOSED || st->current == LWIP_STATUS_CLOSING) ev->closed++;
    }
    else if (type == LWIP_SOCKET_EV_IO)
    {
        const lwip_socket_io_data_t *io = ev_data;
        if (io->flags & LWIP_SOCKET_IO_READABLE) ev->readable++;
        if (io->flags & LWIP_SOCKET_IO_WRITABLE) ev->writable++;
        if (io->flags & LWIP_SOCKET_IO_POLL) ev->polls++;
    }
    else
    {
        ev->errors++;
    }
}

static void test_events(void)
{
    struct events ev = {0}, peer = {0};
    struct lwip_socket *sock = lwip_socket_create(LWIP_SOCKET_ALTCP, LWIP_NETIF_EXT, NULL, 10000);
    if (!check("events create", sock != NULL)) return;
    lwip_socket_on_event(sock, LWIP_SOCKET_EVENTF_ALL, on_event, &ev);
    lwip_socket_connect(sock, HOST, PORT_ECHO);
    pump(not_connecting, sock, 15000);
    write_all(sock, (const uint8_t *)"event-test", 10);
    read_exact(sock, buf, 10, 5000);
    settle(1500);
    close_socket(sock);
    note("  conn %u rd %u wr %u poll %u err %u", ev.connected, ev.readable, ev.writable, ev.polls, ev.errors);
    check("STATE_CHANGE to CONNECTED", ev.connected == 1);
    check("IO READABLE", ev.readable > 0);
    check("IO WRITABLE", ev.writable > 0);
    check("no ERROR events", ev.errors == 0);

    sock = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 10000);
    if (!sock) return;
    lwip_socket_on_event(sock, LWIP_SOCKET_EVENTF_STATE_CHANGE, on_event, &peer);
    lwip_socket_connect(sock, HOST, PORT_CLOSER);
    pump(not_connecting, sock, 15000);
    read_exact(sock, buf, 3, 15000);
    pump(not_active, sock, 15000);
    settle(500); /* events are delivered from lwip_service_events() after the status flips */
    note("  peer close events %u last status %u", peer.closed, peer.last);
    check("STATE_CHANGE to CLOSED on peer FIN", peer.closed > 0 && peer.last == LWIP_STATUS_CLOSED);
    lwip_socket_destroy(sock);
}

static void test_loopback(void)
{
    struct lwip_socket *listener = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_LOOP, NULL, 0);
    struct lwip_socket *client = NULL, *peer = NULL;
    uint32_t start;
    bool ok = false;
    if (!check("loopback listen", listener && lwip_socket_listen(listener, PORT_LOOP) == LWIP_OK)) return;
    client = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_LOOP, NULL, 10000);
    if (check("loopback connect", client && lwip_socket_connect(client, "127.0.0.1", PORT_LOOP) == LWIP_OK))
    {
        start = lwip_now_ms();
        while (!peer && lwip_now_ms() - start < 10000)
        {
            lwip_service_events();
            peer = lwip_socket_accept(listener);
        }
        pump(not_connecting, client, 10000);
        if (check("loopback accept", peer && lwip_socket_status(client) == LWIP_STATUS_CONNECTED))
        {
            for (size_t i = 0; i < 1000; i++) buf[i] = pattern(i);
            write_all(client, buf, 1000);
            ok = read_exact(peer, buf + 1024, 1000, 10000) == 1000 && !memcmp(buf, buf + 1024, 1000);
            write_all(peer, (const uint8_t *)"pong", 4);
            ok = ok && read_exact(client, buf, 4, 10000) == 4 && !memcmp(buf, "pong", 4);
        }
        check("loopback exchange both ways", ok);
        check("loopback netif", lwip_socket_get_netif(client) != NULL);
    }
    close_socket(peer);
    close_socket(client);
    lwip_socket_destroy(listener);
}

static void test_concurrent(void)
{
    struct lwip_socket *tcp = open_socket(LWIP_SOCKET_TCP, HOST, PORT_ECHO, NULL, 10000);
    struct lwip_socket *udp = open_socket(LWIP_SOCKET_UDP, HOST, PORT_UDP, NULL, 10000);
    struct lwip_socket *ws = open_socket(LWIP_SOCKET_ALTCP_WS, HOST, PORT_WS, "/echo", 10000);
    unsigned rounds = 0;
    if (check("three concurrent sockets", tcp && udp && ws))
    {
        for (unsigned i = 0; i < 10; i++)
        {
            uint8_t t[8], u[8], w[8];
            snprintf((char *)buf, 9, "tcp-%04u", i);
            write_all(tcp, buf, 8);
            snprintf((char *)buf, 9, "udp-%04u", i);
            lwip_socket_write(udp, buf, 8);
            snprintf((char *)buf, 9, "ws--%04u", i);
            write_all(ws, buf, 8);
            if (read_exact(tcp, t, 8, 5000) == 8 && read_exact(udp, u, 8, 5000) == 8 &&
                read_exact(ws, w, 8, 5000) == 8 && !memcmp(t, "tcp-", 4) && !memcmp(u, "udp-", 4) &&
                !memcmp(w, "ws--", 4))
                rounds++;
        }
        check("interleaved traffic stays separated", rounds >= 9);
    }
    close_socket(tcp);
    lwip_socket_destroy(udp);
    close_socket(ws);
}

static void test_api_contract(void)
{
    struct lwip_socket *tcp = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 1000);
    struct lwip_socket *udp = lwip_socket_create(LWIP_SOCKET_UDP, LWIP_NETIF_EXT, NULL, 1000);
    struct lwip_socket *tls = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 1000);
    static const uint8_t psk[32] = {1};
    check("create returns sockets", tcp && udp && tls);
    check("status INIT", lwip_socket_status(tcp) == LWIP_STATUS_INIT);
    check("set_timeout", lwip_socket_set_timeout(tcp, 5000) == LWIP_OK);
    check("ws config on TCP rejected", lwip_socket_set_ws_config(tcp, "/", NULL) != LWIP_OK);
    check("psk on TCP rejected", lwip_socket_set_tls_psk(tcp, psk, (const uint8_t *)"id", 2) == LWIP_ERR_ARG);
    check("cert on TCP rejected", lwip_socket_set_tls_cert(tcp, "KEY", "CERT") == LWIP_ERR_ARG);
    check("write before connect rejected", lwip_socket_write(tcp, buf, 1) != LWIP_OK);
    check("read before connect empty", lwip_socket_read(tcp, buf, 1) == 0);
    check("listen on UDP rejected", lwip_socket_listen(udp, 7400) == LWIP_ERR_PROTO);
    check("TLS listen without credentials rejected", lwip_socket_listen(tls, 7401) == LWIP_ERR_ARG);
    check("connect NULL host rejected", lwip_socket_connect(tcp, NULL, 1) == LWIP_ERR_ARG);
    check("destroy NULL rejected", lwip_socket_destroy(NULL) == LWIP_ERR_ARG);
    check("accept on non-listener empty", lwip_socket_accept(tcp) == NULL);
    lwip_socket_destroy(tcp);
    lwip_socket_destroy(udp);
    lwip_socket_destroy(tls);
}

int main(void)
{
    if (net_begin("sockets"))
    {
        size_t baseline, steady;
        test_api_contract();
        baseline = heap_used();
        metric("heap_baseline", baseline, "bytes");
        test_echo("tcp echo", LWIP_SOCKET_TCP, PORT_ECHO, NULL, 8192);
        test_echo("altcp echo", LWIP_SOCKET_ALTCP, PORT_ECHO, NULL, 4096);
        test_echo("ws echo", LWIP_SOCKET_ALTCP_WS, PORT_WS, "/echo", 2048);
        test_udp();
        test_bulk();
        test_server();
        test_tls_socket_servers();
        test_churn();
        test_halfclose();
        test_peer_close_and_reset();
        test_backpressure();
        test_events();
        test_loopback();
        test_concurrent();
        test_failures();
        settle(3000);
        steady = heap_used();
        metric("heap_after_suite", steady, "bytes");
        metric("heap_retained", steady > baseline ? steady - baseline : 0, "bytes");
        test_churn();
        settle(3000);
        note("  heap after churn %u", (unsigned)heap_used());
        test_echo("tcp echo again", LWIP_SOCKET_TCP, PORT_ECHO, NULL, 2048);
        settle(3000);
        note("  heap after tcp echo %u", (unsigned)heap_used());
        test_echo("ws echo again", LWIP_SOCKET_ALTCP_WS, PORT_WS, "/echo", 1024);
        settle(3000);
        note("  heap after ws echo %u", (unsigned)heap_used());
        test_peer_close_and_reset();
        settle(3000);
        note("  heap after close/reset %u", (unsigned)heap_used());
        expect_failure("tls untrusted again", LWIP_SOCKET_ALTCP_TLS, HOST, PORT_TLS_BAD, 20000, LWIP_ERR_CONNECT);
        settle(3000);
        note("  heap after tls failure %u", (unsigned)heap_used());
        metric("heap_growth_second_pass", heap_used() > steady ? heap_used() - steady : 0, "bytes");
        note("  heap %u -> %u -> %u", (unsigned)baseline, (unsigned)steady, (unsigned)heap_used());
        check("no heap growth on a repeated pass", heap_used() <= steady + 256);
    }
    return net_end();
}
