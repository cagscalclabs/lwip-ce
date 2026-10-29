#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ti/getcsc.h>
#include <ti/screen.h>

#include <lwip.h>

#define HTTPS_HOST "example.com"
#define HTTPS_PORT 443
#define TIMEOUT_MS 60000u

static const char request[] =
    "HEAD / HTTP/1.1\r\n"
    "Host: " HTTPS_HOST "\r\n"
    "Connection: close\r\n\r\n";

struct request_state
{
    bool closed;
    bool failed;
};

static void show(uint8_t row, const char *text)
{
    os_SetCursorPos(row, 0);
    os_PutStrFull(text);
}

static void socket_event(struct lwip_socket *socket,
                         lwip_socket_event_type_t type,
                         const void *event_data, void *arg)
{
    struct request_state *state = arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *change = event_data;
        if (change && change->current == LWIP_STATUS_CONNECTED)
        {
            show(3, "TLS connected");
            if (lwip_socket_write(socket, (const uint8_t *)request,
                                  sizeof request - 1) != LWIP_OK)
                state->failed = true;
        }
        else if (change && (change->current == LWIP_STATUS_CLOSED ||
                            change->current == LWIP_STATUS_RESET))
        {
            state->closed = true;
        }
    }
    else if (type == LWIP_SOCKET_EV_ERROR)
    {
        state->failed = true;
    }
}

int main(void)
{
    struct lwip_socket *socket = NULL;
    struct request_state state = {0};
    char response[160] = {0};
    size_t response_len = 0;
    uint32_t started;
    int result = 1;

    os_ClrHome();
    show(0, "lwIP TLS socket");
    show(2, "connecting...");
    show(8, "Clear exits");

    if (!lwip_start() || !lwip_network_up())
    {
        show(3, "lwIP start failed");
        return 1;
    }

    socket = lwip_socket_create(LWIP_SOCKET_ALTCP_TLS, LWIP_NETIF_EXT,
                                NULL, TIMEOUT_MS);
    if (!socket)
    {
        show(3, "socket create failed");
        goto done;
    }
    lwip_socket_on_event(socket, LWIP_SOCKET_EVENTF_ALL,
                         socket_event, &state);
    if (lwip_socket_connect(socket, HTTPS_HOST, HTTPS_PORT) != LWIP_OK)
    {
        show(3, "connect rejected");
        goto done;
    }

    started = lwip_now_ms();
    while (!state.failed && lwip_now_ms() - started < TIMEOUT_MS)
    {
        lwip_service_events();

        size_t space = sizeof response - response_len - 1;
        if (space)
        {
            response_len += lwip_socket_read(
                socket, (uint8_t *)response + response_len, space);
            response[response_len] = '\0';
        }
        if (strstr(response, "HTTP/"))
        {
            show(5, response);
            show(7, "request complete");
            result = 0;
            break;
        }
        if (state.closed || os_GetCSC() == sk_Clear)
            break;
    }

    if (result)
        show(7, "request failed");

done:
    if (socket)
        lwip_socket_destroy(socket);
    lwip_stop();
    return result;
}

