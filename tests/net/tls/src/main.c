/* NETTLS: TLS 1.3 client and server paths.
 *
 * External-PSK handshakes run against openssl s_server / s_client driven by
 * tests/net/run.py, which lets every cipher suite, key-exchange group,
 * ALPN, KeyUpdate and failure mode be forced from the host. Gating certificate
 * validation uses runner-local CA-signed chains and a temporary lwIPCERT whose
 * envelope is signed by the normal GitHub truststore key. Public endpoints are
 * optional, non-gating observations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lwip/core/sntp_time.h>

#include "net.h"

#define PSK_IDENTITY "lwip-ce-nettest"

static uint8_t psk[32];

/* ---- socket API with external PSK -------------------------------------- */

static struct lwip_socket *psk_socket(uint32_t *handshake_ms)
{
    struct lwip_socket *sock = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 30000);
    uint32_t t0 = lwip_now_ms();
    if (!sock) return NULL;
    if (lwip_socket_set_tls_psk(sock, psk, (const uint8_t *)PSK_IDENTITY, strlen(PSK_IDENTITY)) != LWIP_OK ||
        lwip_socket_connect(sock, HOST, PORT_PSK) != LWIP_OK)
    {
        lwip_socket_destroy(sock);
        return NULL;
    }
    pump(not_connecting, sock, 40000);
    if (handshake_ms) *handshake_ms = lwip_now_ms() - t0;
    if (lwip_socket_status(sock) != LWIP_STATUS_CONNECTED)
    {
        note("  status %u err %u", lwip_socket_status(sock), lwip_socket_last_error(sock));
        lwip_socket_destroy(sock);
        return NULL;
    }
    return sock;
}

static void psk_matrix(const char *cipher, const char *group, const char *expect_suite, const char *expect_group)
{
    char cmd[64], reply[64], name[48];
    struct lwip_socket *sock;
    uint32_t ms = 0;
    bool echoed = false;
    snprintf(cmd, sizeof(cmd), "psk-server %s %s rev", cipher, group);
    snprintf(name, sizeof(name), "psk %s %s", cipher, group);
    if (!check(name, host_call(cmd, NULL, 0, 15000))) return;
    sock = psk_socket(&ms);
    snprintf(line, sizeof(line), "%s handshake", name);
    if (check(line, sock != NULL))
    {
        snprintf(line, sizeof(line), "tls_psk_%s_%s_handshake", cipher, group);
        metric(line, ms, "ms");
        write_all(sock, (const uint8_t *)"lwip-ce\n", 8);
        echoed = read_exact(sock, buf, 8, 15000) == 8 && !memcmp(buf, "ec-piwl\n", 8);
        close_socket(sock);
    }
    snprintf(line, sizeof(line), "%s echo", name);
    check(line, echoed);
    snprintf(line, sizeof(line), "%s negotiated %s %s", name, expect_suite, group);
    check(line, host_call("psk-result", reply, sizeof(reply), 10000) &&
                    !strncmp(reply, expect_suite, strlen(expect_suite)) && strstr(reply, expect_group));
}

static void psk_reject(const char *name, const char *server)
{
    char cmd[64];
    struct lwip_socket *sock;
    snprintf(cmd, sizeof(cmd), "psk-server %s", server);
    if (!host_call(cmd, NULL, 0, 15000))
    {
        check(name, false);
        return;
    }
    sock = psk_socket(NULL);
    check(name, sock == NULL);
    if (sock) close_socket(sock);
}

static void test_psk_key_update(void)
{
    struct lwip_socket *sock;
    if (!host_call("psk-server gcm x25519 plain", NULL, 0, 15000)) return;
    sock = psk_socket(NULL);
    if (!check("keyupdate session", sock != NULL)) return;
    host_call("psk-send before-ku", NULL, 0, 5000);
    check("data before KeyUpdate", read_exact(sock, buf, 10, 15000) == 10 && !memcmp(buf, "before-ku\n", 10));
    host_call("keyupdate requested", NULL, 0, 5000);
    host_call("psk-send after-ku", NULL, 0, 5000);
    check("data after peer KeyUpdate", read_exact(sock, buf, 9, 15000) == 9 && !memcmp(buf, "after-ku\n", 9));
    write_all(sock, (const uint8_t *)"calc-after-ku\n", 14);
    check("data after answering update_requested", host_call("psk-seen calc-after-ku", NULL, 0, 15000));
    close_socket(sock);
}

static void test_psk_bulk(const char *server, const char *name)
{
    struct lwip_socket *sock;
    uint32_t body = 0, bad = 0, start;
    struct http_head head = {0};
    if (!host_call(server, NULL, 0, 15000)) return;
    sock = psk_socket(NULL);
    if (!check("tls bulk session", sock != NULL)) return;
    write_all(sock, (const uint8_t *)"GET /bulk.bin HTTP/1.0\r\n\r\n", 26);
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 300000)
    {
        size_t n, off;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf));
        off = http_header_bytes(&head, buf, n);
        for (size_t i = off; i < n; i++)
            if (buf[i] != pattern(body + i - off)) bad++;
        body += n - off;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  tls body %lu bytes in %lu ms", (unsigned long)body, (unsigned long)(lwip_now_ms() - start));
    check(name, body == 131072ul && !bad);
    lwip_socket_destroy(sock);
}

static void test_tls12_rejected(void)
{
    const char *name = "TLS 1.2-only server rejected";
    struct lwip_socket *sock;

    if (!host_call("tls12-server", NULL, 0, 15000))
    {
        check(name, false);
        return;
    }
    sock = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 30000);
    if (!sock || lwip_socket_connect(sock, HOST, PORT_PSK) != LWIP_OK)
    {
        check(name, false);
        if (sock) lwip_socket_destroy(sock);
        return;
    }
    pump(not_connecting, sock, 40000);
    note("  TLS 1.2 peer: status %u err %u", lwip_socket_status(sock),
         lwip_socket_last_error(sock));
    check(name, lwip_socket_status(sock) != LWIP_STATUS_CONNECTED);
    lwip_socket_destroy(sock);
}

/* ---- raw altcp TLS API ------------------------------------------------- */

struct atls { bool connected, error, closed; size_t rx; char data[64]; };

static err_t a_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct atls *s = arg;
    (void)err;
    if (!p)
    {
        s->closed = true;
        return ERR_OK;
    }
    if (s->rx + p->tot_len < sizeof(s->data)) s->rx += pbuf_copy_partial(p, s->data + s->rx, p->tot_len, 0);
    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t a_connected(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)pcb;
    ((struct atls *)arg)->connected = err == ERR_OK;
    return ERR_OK;
}

static void a_err(void *arg, err_t err)
{
    (void)err;
    ((struct atls *)arg)->error = true;
}

static bool a_ready(void *arg) { return ((struct atls *)arg)->connected || ((struct atls *)arg)->error; }
static bool a_has_line(void *arg) { return memchr(((struct atls *)arg)->data, '\n', ((struct atls *)arg)->rx) != NULL; }

static struct altcp_pcb *atls_open(struct altcp_tls_config *conf, struct atls *s, struct altcp_tls_session *session)
{
    struct altcp_pcb *pcb = altcp_tls_new(conf, IPADDR_TYPE_V4);
    ip_addr_t host;
    memset(s, 0, sizeof(*s));
    if (!pcb) return NULL;
    ipaddr_aton(HOST, &host);
    altcp_arg(pcb, s);
    altcp_recv(pcb, a_recv);
    altcp_err(pcb, a_err);
    if (session) altcp_tls_set_session(pcb, session);
    if (altcp_connect(pcb, &host, PORT_PSK, a_connected) != ERR_OK || !pump(a_ready, s, 40000) || !s->connected)
    {
        if (!s->error) altcp_abort(pcb);
        return NULL;
    }
    return pcb;
}

static bool atls_echo(struct altcp_pcb *pcb, struct atls *s)
{
    altcp_write(pcb, "resume\n", 7, TCP_WRITE_FLAG_COPY);
    altcp_output(pcb);
    return pump(a_has_line, s, 15000) && !memcmp(s->data, "emuser\n", 7);
}

static struct tls_psk_identity identity(void)
{
    struct tls_psk_identity id = {0};
    memcpy(id.identity, PSK_IDENTITY, strlen(PSK_IDENTITY));
    id.identity_len = strlen(PSK_IDENTITY);
    return id;
}

static void test_raw_alpn_and_resumption(void)
{
    static struct atls s;
    static const char *protos[] = {"lwip/1", NULL};
    struct tls_psk_identity id = identity();
    struct altcp_tls_config *conf = altcp_tls_create_config_psk_client(psk, &id);
    struct altcp_tls_session session;
    struct altcp_pcb *pcb;
    char reply[64];
    uint32_t t0;

    if (!check("altcp_tls_create_config_psk_client", conf != NULL)) return;
    check("configure ALPN", altcp_tls_configure_alpn_protocols(conf, protos) == 0);
    host_call("psk-server gcm x25519 alpn", NULL, 0, 15000);
    pcb = atls_open(conf, &s, NULL);
    if (check("raw altcp TLS handshake", pcb != NULL))
    {
        check("raw altcp TLS echo", atls_echo(pcb, &s));
        altcp_close(pcb);
        settle(1000);
        check("ALPN lwip/1 negotiated", host_call("psk-result", reply, sizeof(reply), 15000) && strstr(reply, " lwip/1"));
    }

    host_call("psk-server gcm x25519 rev good good 2", NULL, 0, 15000);
    t0 = lwip_now_ms();
    pcb = atls_open(conf, &s, NULL);
    if (check("ticket session handshake", pcb != NULL))
    {
        metric("tls_psk_full_handshake", lwip_now_ms() - t0, "ms");
        atls_echo(pcb, &s);
        altcp_tls_init_session(&session);
        settle(500);
        check("altcp_tls_get_session", altcp_tls_get_session(pcb, &session) == ERR_OK && session.valid);
        note("  ticket identity %u bytes", (unsigned)session.identity.identity_len);
        check("session holds a server ticket",
              session.identity.identity_len && (session.identity.identity_len != strlen(PSK_IDENTITY) ||
                                                memcmp(session.identity.identity, PSK_IDENTITY, strlen(PSK_IDENTITY))));
        altcp_close(pcb);
        settle(1000);
        t0 = lwip_now_ms();
        pcb = atls_open(conf, &s, &session);
        if (check("resumed handshake with ticket", pcb != NULL))
        {
            metric("tls_psk_resumed_handshake", lwip_now_ms() - t0, "ms");
            check("resumed session echo", atls_echo(pcb, &s));
            altcp_close(pcb);
        }
        altcp_tls_free_session(&session);
    }
    altcp_tls_free_config(conf);
}

/* ---- optional, non-gating observations against public hosts ------------- */

static void https(const char *name, const char *host, const char *path, bool want_ok, bool body)
{
    /* Public certificate chains can approach a minute on the calculator. */
    struct lwip_socket *sock = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 120000);
    uint32_t t0 = lwip_now_ms(), got = 0, header_end = 0, length = 0, start;
    bool connected, last_chunk = false;
    if (!sock || lwip_socket_connect(sock, host, 443) != LWIP_OK)
    {
        observe(name, false);
        if (sock) lwip_socket_destroy(sock);
        return;
    }
    pump(not_connecting, sock, 125000);
    connected = lwip_socket_status(sock) == LWIP_STATUS_CONNECTED;
    note("  %s: status %u err %u in %lu ms", host, lwip_socket_status(sock), lwip_socket_last_error(sock),
         (unsigned long)(lwip_now_ms() - t0));
    if (!want_ok)
    {
        observe(name, !connected);
        lwip_socket_destroy(sock);
        return;
    }
    if (!observe(name, connected))
    {
        lwip_socket_destroy(sock);
        return;
    }
    snprintf(line, sizeof(line), "tls_cert_handshake_%.20s", host);
    for (char *c = line; *c; c++)
        if (*c == '.' || *c == '-') *c = '_';
    metric(line, lwip_now_ms() - t0, "ms");
    snprintf((char *)buf, sizeof(buf), "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: lwip-ce\r\n\r\n",
             body ? "GET" : "HEAD", path, host);
    write_all(sock, buf, strlen((char *)buf));
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 180000)
    {
        size_t n;
        lwip_service_events();
        n = lwip_socket_read(sock, buf + (got < 1024 ? got : 1100), got < 1024 ? 1024 - got : 900);
        if (got < 1024) buf[got + n] = '\0';
        if (n >= 5 && !memcmp(buf + (got < 1024 ? got : 1100) + n - 5, "0\r\n\r\n", 5)) last_chunk = true;
        got += n;
        if (!header_end)
        {
            char *end = strstr((char *)buf, "\r\n\r\n"), *cl = strstr((char *)buf, "ontent-Length:");
            if (!cl) cl = strstr((char *)buf, "ontent-length:");
            if (end)
            {
                header_end = (uint32_t)(end + 4 - (char *)buf);
                if (cl) length = strtoul(cl + 14, NULL, 10);
                if (!body) break;
            }
        }
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  %.40s", (char *)buf);
    snprintf(line, sizeof(line), "%s answers HTTP", name);
    observe(line, !strncmp((char *)buf, "HTTP/1.1 ", 9));
    if (body)
    {
        bool chunked = strstr((char *)buf, "hunked") != NULL;
        note("  body %lu of %lu%s", (unsigned long)(got - header_end), (unsigned long)length, chunked ? " chunked" : "");
        snprintf(line, sizeof(line), "%s full body", name);
        /* Content-Length, chunked, or delimited by the server closing. */
        observe(line, length ? got - header_end == length
                             : got > header_end && !lwip_socket_is_active(sock) && (!chunked || last_chunk));
    }
    lwip_socket_destroy(sock);
}

static bool select_endpoint(const char *pool, char *host, size_t host_len,
                            char *path, size_t path_len)
{
    char cmd[48];
    snprintf(cmd, sizeof(cmd), "endpoint-pick %s", pool);
    if (!host_call(cmd, host, host_len, 20000)) return false;
    snprintf(cmd, sizeof(cmd), "endpoint-path %s", pool);
    return host_call(cmd, path, path_len, 5000);
}

static void pooled_https(const char *pool, const char *suffix, bool want_ok, bool body)
{
    char host[96], path[128], name[160];
    if (!select_endpoint(pool, host, sizeof(host), path, sizeof(path)))
    {
        snprintf(name, sizeof(name), "select %s endpoint", pool);
        observe(name, false);
        return;
    }
    snprintf(name, sizeof(name), "https %s%s", host, suffix);
    https(name, host, path, want_ok, body);
}

static void test_wss(const char *pool, const char *connect_name,
                     const char *metric_name, uint32_t timeout_ms)
{
    uint32_t start;
    char host[96], path[128], name[160];
    if (!select_endpoint(pool, host, sizeof(host), path, sizeof(path)))
    {
        snprintf(name, sizeof(name), "select %s endpoint", pool);
        observe(name, false);
        return;
    }
    start = lwip_now_ms();
    struct lwip_socket *sock =
        open_socket(LWIP_SOCKET_ALTCP_WSS, host, 443, path, timeout_ms);
    size_t got = 0;
    snprintf(name, sizeof(name), "%s %s", connect_name, host);
    if (!observe(name, sock != NULL)) return;
    metric(metric_name, lwip_now_ms() - start, "ms");
    write_all(sock, (const uint8_t *)"lwip-ce wss echo", 16);
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 30000 && got < sizeof(buf) - 1)
    {
        lwip_service_events();
        got += lwip_socket_read(sock, buf + got, sizeof(buf) - 1 - got);
        buf[got] = '\0';
        if (strstr((char *)buf, "lwip-ce wss echo")) break;
    }
    snprintf(name, sizeof(name), "wss echo %s", host);
    observe(name, strstr((char *)buf, "lwip-ce wss echo") != NULL);
    close_socket(sock);
}

/* Connect to a runner-local server with a leaf signed by the ephemeral test
 * CA.  tests/net/run.py adds that CA to a v3 truststore signed by the normal
 * GitHub TRUSTSTORE_SIGNER, so this exercises the complete production trust
 * and handshake path without a public endpoint. */
static void test_suite_forced(const char *suite_name, const char *cipher_arg,
                              const char *key_type)
{
    char cmd[48], name[80], result[80];
    struct lwip_socket *sock;

    snprintf(cmd, sizeof(cmd), "suite-server %s %s", cipher_arg, key_type);
    snprintf(name, sizeof(name), "%s %s local chain", suite_name, key_type);
    if (!host_call(cmd, NULL, 0, 15000))
    {
        check(name, false);
        return;
    }
    sock = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT, NULL, 30000);
    if (!sock || lwip_socket_connect(sock, HOST, PORT_PSK) != LWIP_OK)
    {
        check(name, false);
        if (sock) lwip_socket_destroy(sock);
        return;
    }
    pump(not_connecting, sock, 40000);
    note("  %s: status %u err %u", suite_name,
         lwip_socket_status(sock), lwip_socket_last_error(sock));
    check(name, lwip_socket_status(sock) == LWIP_STATUS_CONNECTED);
    close_socket(sock);

    snprintf(name, sizeof(name), "%s %s host handshake", suite_name, key_type);
    if (!host_call("suite-result", result, sizeof(result), 10000))
    {
        check(name, false);
        return;
    }
    check(name, strstr(result, "handshake completed") != NULL);
}

int main(void)
{
    char test_mode[12] = {0};
    char local_trust[4] = {0};
    char runner_time[16] = {0};
    for (uint8_t i = 0; i < 32; i++) psk[i] = pattern(i);
    if (net_begin("tls"))
    {
        bool external = host_call("test-mode", test_mode, sizeof(test_mode), 5000) &&
                        !strcmp(test_mode, "external");
        bool time_ok = host_call("time", runner_time, sizeof(runner_time), 5000) &&
                       strtoul(runner_time, NULL, 10) != 0;
        if (time_ok)
            lwip_sntp_set_time(strtoul(runner_time, NULL, 10));

        if (external)
        {
            observe("runner time installed", time_ok && lwip_sntp_time_was_set());
            pooled_https("tls13", "", true, false);
            pooled_https("rsa2048", " (RSA-2048)", true, false);
            pooled_https("ecdsa256", " (ECDSA P-256)", true, false);
            pooled_https("body", "", true, true);
            pooled_https("starfield", " (Starfield)", true, false);
            pooled_https("p384", " (P-384 chain rejected)", false, false);
            test_wss("wss", "wss connect", "wss_connect", 60000);
            test_wss("wss_long", "wss long-handshake connect",
                     "wss_long_connect", 120000);
            return net_end();
        }

        check("runner time installed", time_ok && lwip_sntp_time_was_set());
        psk_matrix("gcm", "x25519", "TLS_AES_128_GCM_SHA256", "X25519");
        psk_matrix("ccm", "x25519", "TLS_AES_128_CCM_SHA256", "X25519");
        psk_reject("wrong PSK rejected", "gcm x25519 rev bad good");
        psk_reject("unknown PSK identity rejected", "gcm x25519 rev good bad");
        psk_reject("AES-256 only server rejected", "aes256 x25519 rev");
        psk_reject("P-384 only server rejected", "gcm p384 rev");
        psk_matrix("gcm", "p256", "TLS_AES_128_GCM_SHA256", "P-256");
        psk_matrix("ccm", "p256", "TLS_AES_128_CCM_SHA256", "P-256");
        test_psk_key_update();
        test_psk_bulk("psk-server gcm x25519 www4k", "128 KiB over TLS in 4 KiB records");
        test_raw_alpn_and_resumption();

        if (check("runner-local CA truststore provisioned",
                  host_call("local-trust", local_trust, sizeof(local_trust), 5000) &&
                  local_trust[0] == '1'))
        {
            test_suite_forced("AES-128-GCM-SHA256", "gcm", "ecdsa");
            test_suite_forced("AES-128-GCM-SHA256", "gcm", "rsa");
            test_suite_forced("AES-128-CCM-SHA256", "ccm", "ecdsa");
            test_suite_forced("AES-128-CCM-SHA256", "ccm", "rsa");
            test_suite_forced("AES-256-GCM-SHA384", "aes256", "ecdsa");
            test_suite_forced("AES-256-GCM-SHA384", "aes256", "rsa");
        }
        test_tls12_rejected();
    }
    return net_end();
}
