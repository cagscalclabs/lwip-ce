#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lwip/core.h>
#include <lwip/conn.h>

#include "common/lwip_example.h"

#define TLS_HOST "www.microsoft.com"
#define TLS_PORT 443
#define TLS_TIMEOUT_SECONDS 75

static const char http_request[] =
    "GET / HTTP/1.1\r\n"
    "Host: " TLS_HOST "\r\n"
    "Connection: close\r\n"
    "\r\n";

struct tls_state
{
    bool done;
    bool ok;
    lwip_error_t err;
    char rx[128];
    size_t rx_len;
};

static void on_connected(void *arg, struct lwip_conn *conn)
{
    struct tls_state *state = (struct tls_state *)arg;
    lwip_error_t err = lwip_conn_write(conn, (const uint8_t *)http_request,
                                       sizeof http_request - 1);
    if (err != LWIP_OK)
    {
        state->err = err;
        state->done = true;
    }
}

static void on_recv(void *arg, struct lwip_conn *conn, struct pbuf *p)
{
    struct tls_state *state = (struct tls_state *)arg;
    size_t space;
    uint16_t copied;

    if (!p)
    {
        state->done = true;
        return;
    }

    space = sizeof state->rx - state->rx_len - 1;
    copied = pbuf_copy_partial(p, state->rx + state->rx_len,
                               (uint16_t)space, 0);
    state->rx_len += copied;
    state->rx[state->rx_len] = '\0';

    lwip_conn_recved(conn, p->tot_len);
    pbuf_free(p);

    if (strstr(state->rx, "HTTP/"))
    {
        state->ok = true;
        state->done = true;
    }
}

static void on_err(void *arg, struct lwip_conn *conn, lwip_error_t err)
{
    struct tls_state *state = (struct tls_state *)arg;
    (void)conn;
    state->err = err;
    state->done = true;
}

static void on_closed(void *arg, struct lwip_conn *conn)
{
    struct tls_state *state = (struct tls_state *)arg;
    (void)conn;
    state->done = true;
}

int main(void)
{
    struct lwip_conn conn = {0};
    struct tls_state state = {0};
    clock_t start;
    lwip_error_t err;

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    lwip_example_show("TLS RSA", "creating");
    err = lwip_conn_create(&conn, NULL, LWIP_PROTO_ALTCP_TLS,
                           LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_DNS);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("TLS create", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_conn_set_arg(&conn, &state);
    lwip_conn_set_connected(&conn, on_connected);
    lwip_conn_set_recv(&conn, on_recv);
    lwip_conn_set_err(&conn, on_err);
    lwip_conn_set_closed(&conn, on_closed);

    lwip_example_show("TLS RSA", "connecting");
    err = lwip_conn_connect(&conn, TLS_HOST, TLS_PORT);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("TLS connect", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    start = clock();
    while (!state.done && !lwip_example_timed_out(start, TLS_TIMEOUT_SECONDS))
    {
        if (lwip_example_cancelled())
        {
            break;
        }
        lwip_poll_network_events();
    }

    if (!state.ok)
    {
        lwip_example_show_conn_error("TLS failed", &conn, state.err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_example_show_and_wait("TLS OK", state.rx);
    lwip_conn_destroy(&conn);
    return lwip_example_finish(0);
}
