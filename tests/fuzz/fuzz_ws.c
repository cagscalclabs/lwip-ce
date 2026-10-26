#include "../host/altcp_ws/mock.h"
#include "ws_unit.c"

static err_t receive(void *arg, struct altcp_pcb *p, struct pbuf *b, err_t e)
{
    (void)arg; (void)p; (void)e;
    if (b) pbuf_free(b);
    return ERR_OK;
}

static err_t on_connect(void *arg, struct altcp_pcb *p, err_t e)
{
    (void)arg; (void)p; (void)e;
    return ERR_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static altcp_ws_config_t cfg = {"localhost", "/", NULL};
    struct altcp_pcb *p;
    altcp_ws_state_t *s;
    size_t off = 1, chunk;
    err_t err = ERR_OK;

    if (!size) return 0;
    chunk = (data[0] >> 1) + 1;
    p = calloc(1, sizeof(*p));
    p->inner_conn = calloc(1, sizeof(*p));
    s = calloc(1, sizeof(*s));
    p->state = s;
    s->conn = p;
    s->conf = &cfg;
    if (data[0] & 1) s->flags = ALTCP_WS_FLAGS_UPGRADE_DONE;
    p->recv = receive;
    p->connected = on_connect;
    altcp_ws_setup_callbacks(p, p->inner_conn);
    while (off < size && err != ERR_ABRT)
    {
        size_t n = size - off < chunk ? size - off : chunk;
        struct pbuf *b = pbuf_alloc(0, (u16_t)n, 0);
        memcpy(b->payload, data + off, n);
        off += n;
        err = altcp_ws_lower_recv(p, p->inner_conn, b, ERR_OK);
        if (err == ERR_MEM) pbuf_free(b);
    }
    if (err != ERR_ABRT && altcp_ws_lower_poll(p, p->inner_conn) != ERR_ABRT)
        altcp_ws_close(p);
    return 0;
}
