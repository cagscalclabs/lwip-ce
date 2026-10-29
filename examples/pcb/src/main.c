#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <ti/getcsc.h>
#include <ti/screen.h>

#include <lwip.h>

#define ECHO_PORT 8080

static struct tcp_pcb *listener;
static struct tcp_pcb *peer;

static void show(uint8_t row, const char *text)
{
    os_SetCursorPos(row, 0);
    os_PutStrFull(text);
}

static void close_pcb(struct tcp_pcb *pcb)
{
    if (pcb && tcp_close(pcb) != ERR_OK)
        tcp_abort(pcb);
}

static void peer_error(void *arg, err_t err)
{
    (void)arg;
    (void)err;
    peer = NULL; /* lwIP has already freed the PCB. */
    show(5, "peer error");
}

static err_t peer_receive(void *arg, struct tcp_pcb *pcb,
                          struct pbuf *data, err_t err)
{
    (void)arg;

    if (!data)
    {
        peer = NULL;
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        close_pcb(pcb);
        show(5, "peer closed");
        return ERR_OK;
    }
    if (err != ERR_OK)
    {
        pbuf_free(data);
        return err;
    }
    if (data->tot_len > tcp_sndbuf(pcb))
        return ERR_MEM; /* Keep the pbuf; lwIP will retry this callback. */

    for (struct pbuf *part = data; part; part = part->next)
    {
        if (tcp_write(pcb, part->payload, part->len,
                      TCP_WRITE_FLAG_COPY) != ERR_OK)
        {
            pbuf_free(data);
            tcp_abort(pcb);
            peer = NULL;
            return ERR_ABRT;
        }
    }
    tcp_recved(pcb, data->tot_len);
    pbuf_free(data);
    tcp_output(pcb);
    show(5, "echoed data");
    return ERR_OK;
}

static err_t accept_peer(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !pcb)
        return ERR_VAL;
    if (peer)
    {
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    peer = pcb;
    tcp_recv(peer, peer_receive);
    tcp_err(peer, peer_error);
    show(5, "peer connected");
    return ERR_OK;
}

int main(void)
{
    lwip_netif_info_t info = {0};
    char address[32];
    struct tcp_pcb *pcb;
    int result = 1;

    os_ClrHome();
    show(0, "lwIP PCB echo server");
    show(8, "Clear exits");

    if (!lwip_start() || !lwip_network_up())
    {
        show(2, "lwIP start failed");
        return 1;
    }

    show(2, "waiting for address");
    while (!lwip_default_netif_info(&info) || !info.has_ipv4)
    {
        lwip_service_events();
        if (os_GetCSC() == sk_Clear)
            goto done;
    }

    pcb = tcp_new();
    if (!pcb || tcp_bind(pcb, IP_ADDR_ANY, ECHO_PORT) != ERR_OK)
    {
        if (pcb)
            tcp_abort(pcb);
        show(2, "TCP bind failed");
        goto done;
    }
    listener = tcp_listen(pcb);
    if (!listener)
    {
        tcp_abort(pcb);
        show(2, "TCP listen failed");
        goto done;
    }
    tcp_accept(listener, accept_peer);

    snprintf(address, sizeof address, "%u.%u.%u.%u:%u",
             info.ipv4_addr[0], info.ipv4_addr[1],
             info.ipv4_addr[2], info.ipv4_addr[3], ECHO_PORT);
    show(2, "listening on");
    show(3, address);
    result = 0;

    while (os_GetCSC() != sk_Clear)
        lwip_service_events();

done:
    if (peer)
    {
        tcp_arg(peer, NULL);
        tcp_recv(peer, NULL);
        tcp_err(peer, NULL);
        close_pcb(peer);
        peer = NULL;
    }
    if (listener)
    {
        tcp_accept(listener, NULL);
        close_pcb(listener);
        listener = NULL;
    }
    lwip_stop();
    return result;
}

