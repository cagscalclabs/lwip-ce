#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lwip.h>

#include "common/lwip_example.h"

#define ECHO_HOST "45.79.112.203"
#define ECHO_PORT 4242
#define ECHO_TIMEOUT_SECONDS 45

static const char echo_message[] = "lwip-ce echo\r\n";

struct echo_state
{
    bool     ok;
    lwip_error_t err;
    char     rx[96];
    size_t   rx_len;
};

/* Event callback: owns all lifecycle responses.
 * Data reading happens in the main loop via available()/read(). */
static void on_event(struct lwip_socket *sock,
                     lwip_socket_event_type_t type,
                     const void *ev_data,
                     void *arg)
{
    struct echo_state *state = (struct echo_state *)arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (st && st->current == LWIP_STATUS_CONNECTED)
        {
            lwip_error_t err = lwip_socket_write(
                sock, (const uint8_t *)echo_message, sizeof echo_message - 1);
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
            lwip_example_linef("err c%u o%u r%d e%u",
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
    struct echo_state  state = {0};
    lwip_error_t err;

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    err = lwip_socket_create(&sock, LWIP_SOCKET_TCP, LWIP_NETIF_EXT,
                             NULL, 30000);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("TCP create", &sock, err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }

    lwip_socket_on_event(&sock, LWIP_SOCKET_EVENTF_ALL, on_event, &state);

    lwip_example_show("TCP echo", "connecting");
    err = lwip_socket_connect(&sock, ECHO_HOST, ECHO_PORT);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("TCP connect", &sock, err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }

    uint32_t start = lwip_example_now_ms();
    while (lwip_socket_is_active(&sock) &&
           !lwip_example_timed_out(start, ECHO_TIMEOUT_SECONDS) &&
           !lwip_example_cancelled())
    {
        lwip_poll_network_events();

        size_t avail = lwip_socket_available(&sock);
        if (avail && state.rx_len < sizeof(state.rx) - 1)
        {
            state.rx_len += lwip_socket_read(
                &sock,
                (uint8_t *)state.rx + state.rx_len,
                avail);
            state.rx[state.rx_len] = '\0';
            if (strstr(state.rx, "lwip-ce echo"))
            {
                state.ok = true;
                lwip_socket_close(&sock);
            }
        }

        lwip_example_mem_stats_tick();
    }

    /* Drain any bytes that arrived after the loop condition turned false. */
    size_t avail;
    while (!state.ok && (avail = lwip_socket_available(&sock)) &&
           state.rx_len < sizeof(state.rx) - 1)
    {
        state.rx_len += lwip_socket_read(
            &sock, (uint8_t *)state.rx + state.rx_len, avail);
        state.rx[state.rx_len] = '\0';
        if (strstr(state.rx, "lwip-ce echo"))
        {
            state.ok = true;
        }
    }

    if (!state.ok)
    {
        if (state.err == LWIP_OK)
        {
            state.err = LWIP_ERR_CONNECT;
        }
        lwip_example_show_socket_error("TCP failed", &sock, state.err);
        lwip_socket_destroy(&sock);
        return lwip_example_finish(1);
    }

    lwip_example_show_and_wait("TCP echo OK", state.rx);
    lwip_socket_destroy(&sock);
    return lwip_example_finish(0);
}
