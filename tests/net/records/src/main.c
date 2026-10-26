/* NETREC: TLS records at the RFC 8446 maximum (2^14 bytes of plaintext).
 * OpenSSL ignores record_size_limit (RFC 8449), so s_server -WWW sends
 * full-size records, which every TLS 1.3 client has to accept. */
#include <stdio.h>
#include <string.h>

#include "net.h"

#define PSK_IDENTITY "lwip-ce-nettest"

static uint8_t psk[32];

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
        note_traceback(4);
        lwip_socket_destroy(sock);
        return NULL;
    }
    return sock;
}

static void test_psk_bulk(const char *server, const char *name)
{
    struct lwip_socket *sock;
    uint32_t body = 0, bad = 0, start;
    bool header = false;
    if (!host_call(server, NULL, 0, 15000)) return;
    sock = psk_socket(NULL);
    if (!check("tls bulk session", sock != NULL)) return;
    write_all(sock, (const uint8_t *)"GET /bulk.bin HTTP/1.0\r\n\r\n", 26);
    start = lwip_now_ms();
    while (lwip_now_ms() - start < 300000)
    {
        size_t n, off = 0;
        lwip_service_events();
        n = lwip_socket_read(sock, buf, sizeof(buf) - 1);
        if (!header && n)
        {
            char *end;
            buf[n] = '\0';
            end = strstr((char *)buf, "\r\n\r\n");
            if (!end) continue;
            header = true;
            off = (size_t)(end + 4 - (char *)buf);
        }
        for (size_t i = off; i < n; i++)
            if (buf[i] != pattern(body + i - off)) bad++;
        body += n - off;
        if (!n && !lwip_socket_is_active(sock)) break;
    }
    note("  tls body %lu bytes in %lu ms", (unsigned long)body, (unsigned long)(lwip_now_ms() - start));
    check(name, body == 131072ul && !bad);
    lwip_socket_destroy(sock);
}

int main(void)
{
    for (uint8_t i = 0; i < 32; i++) psk[i] = pattern(i);
    if (net_begin("records"))
    {
        test_psk_bulk("psk-server gcm x25519 www", "128 KiB over TLS in 16 KiB records (GCM)");
        test_psk_bulk("psk-server ccm x25519 www", "128 KiB over TLS in 16 KiB records (CCM)");
    }
    return net_end();
}
