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
    "HEAD / HTTP/1.1\r\n"
    "Host: " TLS_HOST "\r\n"
    "User-Agent: lwip-ce/0\r\n"
    "Accept: */*\r\n"
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
    lwip_error_t err;

    lwip_example_line("conn established");
    err = lwip_conn_write(conn, (const uint8_t *)http_request,
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
    lwip_example_linef("conn failed e%u", (unsigned)err);
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

    lwip_example_dbg_console_begin("TLS RSA");
    err = lwip_conn_create(&conn, NULL, LWIP_PROTO_ALTCP_TLS,
                           LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_DNS);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("TLS create", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }
    lwip_example_line("tls initialize ok");

    lwip_conn_set_arg(&conn, &state);
    lwip_conn_set_connected(&conn, on_connected);
    lwip_conn_set_recv(&conn, on_recv);
    lwip_conn_set_err(&conn, on_err);
    lwip_conn_set_closed(&conn, on_closed);

    /* Route TLS (and all) debug events to the on-screen console. Depth 1
     * (verbose) also traces the record/decrypt path, which localizes where
     * the Certificate handling stalls. Drop to LWIP_DBG_DEPTH_MILESTONE for a
     * clean high-level progress view. The console shares the home-screen text
     * surface with lwip_example_show(). */
    lwip_set_debug(lwip_example_dbg_console_cb, LWIP_DBG_INFO,
                   LWIP_DBG_DEPTH_VERBOSE);

    lwip_example_linef("attempting conn to:");
    lwip_example_linef("%s:%u", TLS_HOST, (unsigned)TLS_PORT);
    err = lwip_conn_connect(&conn, TLS_HOST, TLS_PORT);
    if (err != LWIP_OK)
    {
        lwip_example_linef("conn failed e%u", (unsigned)err);
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
        lwip_example_mem_stats_tick();
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
