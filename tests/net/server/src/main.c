/* NETSRV: lwIP-CE as a TLS 1.3 server (external PSK), checked with
 * openssl s_client driven by tests/net/run.py. */
#include <string.h>

#include "net.h"

#define PSK_IDENTITY "lwip-ce-nettest"

static uint8_t psk[32];

static struct altcp_pcb *server_peer;

static err_t srv_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg; (void)err;
    if (!p)
    {
        altcp_close(pcb);
        return ERR_OK;
    }
    for (struct pbuf *q = p; q; q = q->next) altcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
    altcp_output(pcb);
    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t srv_accept(void *arg, struct altcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !pcb) return ERR_VAL;
    server_peer = pcb;
    altcp_recv(pcb, srv_recv);
    return ERR_OK;
}

static void test_psk_server(void)
{
    struct tls_psk_identity id = {0};
    memcpy(id.identity, PSK_IDENTITY, strlen(PSK_IDENTITY));
    id.identity_len = strlen(PSK_IDENTITY);
    struct altcp_tls_config *conf = altcp_tls_create_config_psk_server(psk, &id);
    struct altcp_pcb *l;
    char reply[64];
    err_t err;
    if (!check("altcp_tls_create_config_psk_server", conf != NULL)) return;
    l = altcp_tls_new(conf, IPADDR_TYPE_V4);
    if (check("TLS server bind", l && altcp_bind(l, IP_ANY_TYPE, PORT_PSK + 1) == ERR_OK))
    {
        l = altcp_listen_with_backlog_and_err(l, 1, &err);
        if (check("TLS server listen", l != NULL))
        {
            altcp_accept(l, srv_accept);
            server_peer = NULL;
            check("openssl s_client PSK echo via calc server",
                  host_call("psk-client 7101 gcm x25519", reply, sizeof(reply), 120000) && !strcmp(reply, "echo"));
            check("TLS server accepted", server_peer != NULL);
            altcp_close(l);
        }
    }
    altcp_tls_free_config(conf);
}

int main(void)
{
    for (uint8_t i = 0; i < 32; i++) psk[i] = pattern(i);
    if (net_begin("server")) test_psk_server();
    return net_end();
}
