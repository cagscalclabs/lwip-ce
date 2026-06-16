#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lwip.h>

#include "../../common/lwip_example.h"

#define TLS_HOST "tls13.akamai.io"
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
    bool         ok;
    lwip_error_t err;
    char         rx[128];
    size_t       rx_len;
};

static void on_event(struct lwip_socket *sock,
                     lwip_socket_event_type_t type,
                     const void *ev_data,
                     void *arg)
{
    struct tls_state *state = (struct tls_state *)arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (st && st->current == LWIP_STATUS_CONNECTED)
        {
            lwip_example_line("conn established");
            lwip_error_t err = lwip_socket_write(
                sock, (const uint8_t *)http_request, sizeof http_request - 1);
            if (err != LWIP_OK)
            {
                state->err = err;
                lwip_socket_abort(sock);
            }
        }
        return;
    }

    if (type == LWIP_SOCKET_EV_ERROR)
    {
        const lwip_socket_error_data_t *err =
            (const lwip_socket_error_data_t *)ev_data;
        state->err = err ? err->err : sock->last_error;
        if (err)
        {
            lwip_example_linef("fail c%u o%u r%d e%u",
                               (unsigned)err->component,
                               (unsigned)err->operation,
                               err->raw_error,
                               (unsigned)err->err);
        }
    }
}

int main(void)
{
    struct lwip_socket sock  = {0};
    struct tls_state   state = {0};
    lwip_error_t err;

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    lwip_example_dbg_console_begin("TLS HTTPS");

    err = lwip_socket_create(&sock, LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT,
                             NULL, 60000);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("HTTPS create", &sock, err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }
    lwip_example_line("tls initialize ok");

    lwip_socket_on_event(&sock, LWIP_SOCKET_EVENTF_ALL, on_event, &state);

    lwip_example_linef("connecting to %s:%u", TLS_HOST, (unsigned)TLS_PORT);
    err = lwip_socket_connect(&sock, TLS_HOST, TLS_PORT);
    /* Enable milestone debug output after connect is initiated so debug
     * events don't fire re-entrantly during socket setup. */
    lwip_set_debug(lwip_example_dbg_console_cb, LWIP_DBG_INFO,
                   LWIP_DBG_DEPTH_MILESTONE);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("HTTPS connect", &sock, err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }

    uint32_t start = lwip_example_now_ms();
    while (lwip_socket_is_active(&sock) &&
           !lwip_example_timed_out(start, TLS_TIMEOUT_SECONDS) &&
           !lwip_example_cancelled())
    {
        lwip_poll_network_events();

        size_t space = sizeof(state.rx) - state.rx_len - 1;
        if (space)
        {
            size_t got = lwip_socket_read(
                &sock,
                (uint8_t *)state.rx + state.rx_len,
                space);
            if (got)
            {
                state.rx_len += got;
                state.rx[state.rx_len] = '\0';
                if (strstr(state.rx, "HTTP/"))
                {
                    state.ok = true;
                    lwip_socket_close(&sock);
                }
            }
        }

        lwip_example_mem_stats_tick();
    }

    if (!state.ok)
    {
        if (state.err == LWIP_OK)
        {
            state.err = LWIP_ERR_CONNECT;
        }
        lwip_example_show_socket_error("HTTPS failed", &sock, state.err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }

    lwip_example_show("HTTPS OK", NULL);
    lwip_example_lines_crlf(state.rx, state.rx_len);
    lwip_example_draw_mem_stats();
    lwip_example_wait_key();
    lwip_socket_destroy(&sock);
    return lwip_example_finish(0);
}
