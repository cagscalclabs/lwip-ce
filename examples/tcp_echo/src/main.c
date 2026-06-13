#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lwip/core.h>
#include <lwip/conn.h>

#include "common/lwip_example.h"

#define ECHO_HOST "45.79.112.203"
#define ECHO_PORT 4242
#define ECHO_TIMEOUT_SECONDS 45

static const char echo_message[] = "lwip-ce echo\r\n";

struct echo_state
{
    bool done;
    bool ok;
    lwip_error_t err;
    char rx[96];
    size_t rx_len;
};

static void on_connected(void *arg, struct lwip_conn *conn)
{
    struct echo_state *state = (struct echo_state *)arg;
    lwip_error_t err = lwip_conn_write(conn, (const uint8_t *)echo_message,
                                       sizeof echo_message - 1);
    if (err != LWIP_OK)
    {
        state->err = err;
        state->done = true;
    }
}

static void on_recv(void *arg, struct lwip_conn *conn, struct pbuf *p)
{
    struct echo_state *state = (struct echo_state *)arg;
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

    if (strstr(state->rx, "lwip-ce echo"))
    {
        state->ok = true;
        state->done = true;
    }
}

static void on_err(void *arg, struct lwip_conn *conn, lwip_error_t err)
{
    struct echo_state *state = (struct echo_state *)arg;
    (void)conn;
    state->err = err;
    state->done = true;
}

static void on_closed(void *arg, struct lwip_conn *conn)
{
    struct echo_state *state = (struct echo_state *)arg;
    (void)conn;
    state->done = true;
}

int main(void)
{
    struct lwip_conn conn = {0};
    struct echo_state state = {0};
    clock_t start;
    lwip_error_t err;

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    err = lwip_conn_create(&conn, NULL, LWIP_PROTO_TCP,
                           LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_DNS);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("TCP create", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_conn_set_arg(&conn, &state);
    lwip_conn_set_connected(&conn, on_connected);
    lwip_conn_set_recv(&conn, on_recv);
    lwip_conn_set_err(&conn, on_err);
    lwip_conn_set_closed(&conn, on_closed);

    lwip_example_show("TCP echo", "connecting");
    err = lwip_conn_connect(&conn, ECHO_HOST, ECHO_PORT);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("TCP connect", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    start = clock();
    while (!state.done && !lwip_example_timed_out(start, ECHO_TIMEOUT_SECONDS))
    {
        if (lwip_example_cancelled())
        {
            break;
        }
        lwip_poll_network_events();
        lwip_example_mem_stats_tick();
    }

    if (!state.ok)
    {
        lwip_example_show_conn_error("TCP failed", &conn, state.err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_example_show_and_wait("TCP echo OK", state.rx);
    lwip_conn_destroy(&conn);
    return lwip_example_finish(0);
}
