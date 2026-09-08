#ifndef LWIP_CHAT_CLIENT_H
#define LWIP_CHAT_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lwip.h>

#include "lwip_example.h"

struct lwip_chat_state
{
    struct lwip_example_chat chat;
    bool connected;
    bool done;
    bool exiting;
    lwip_error_t err;
};

static struct lwip_chat_state *lwip_chat_debug_state;

static void lwip_chat_append_system(struct lwip_chat_state *state,
                                    const char *message)
{
    lwip_example_chat_append(&state->chat, "* ", message, strlen(message));
    lwip_example_chat_render(&state->chat);
}

static void lwip_chat_debug_cb(const struct lwip_event *ev)
{
    struct lwip_chat_state *state = lwip_chat_debug_state;
    char line[48];

    if (!ev || !state)
    {
        return;
    }

    switch (ev->kind)
    {
    case LWIP_EV_INFO:
        snprintf(line, sizeof(line), "%s: %s",
                 lwip_debug_module_name(ev->module),
                 ev->data.msg ? ev->data.msg : "");
        break;
    case LWIP_EV_DEBUG:
        snprintf(line, sizeof(line), "%s %s:%u",
                 lwip_debug_module_name(ev->module),
                 lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                 (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc));
        break;
    case LWIP_EV_WARN:
        snprintf(line, sizeof(line), "!%s %s:%u x%u",
                 lwip_debug_module_name(ev->module),
                 lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                 (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                 (unsigned)ev->data.code.extra);
        break;
    case LWIP_EV_ERROR:
        snprintf(line, sizeof(line), "X%s %s:%u x%u",
                 lwip_debug_module_name(ev->module),
                 lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                 (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                 (unsigned)ev->data.code.extra);
        break;
    case LWIP_EV_STATE_CHG:
        snprintf(line, sizeof(line), "%s -> %s",
                 lwip_debug_module_name(ev->module),
                 lwip_debug_state_change_name(ev->data.state.change_event));
        break;
    case LWIP_EV_IO_FILE:
        snprintf(line, sizeof(line), "%s io:%s %s %u",
                 lwip_debug_module_name(ev->module),
                 ev->data.file.name ? ev->data.file.name : "?",
                 ev->data.file.dir == LWIP_IO_WRITE ? "w" : "r",
                 (unsigned)ev->data.file.bytes);
        break;
    case LWIP_EV_IO_ETH:
        snprintf(line, sizeof(line), "%s io:eth %s %u",
                 lwip_debug_module_name(ev->module),
                 ev->data.eth.dir == LWIP_IO_TX ? "tx" : "rx",
                 (unsigned)ev->data.eth.bytes);
        break;
    default:
        return;
    }
    lwip_chat_append_system(state, line);
}

static void lwip_chat_on_readable(struct lwip_chat_state *state,
                                  struct lwip_socket *sock)
{
    char buf[64];

    for (;;)
    {
        size_t got = lwip_socket_read(sock, (uint8_t *)buf, sizeof(buf) - 1);
        if (!got)
        {
            break;
        }
        buf[got] = '\0';
        lwip_example_chat_append(&state->chat, NULL, buf, got);
    }
    lwip_example_chat_render(&state->chat);
}

static void lwip_chat_on_event(struct lwip_socket *sock,
                               lwip_socket_event_type_t type,
                               const void *ev_data,
                               void *arg)
{
    struct lwip_chat_state *state = (struct lwip_chat_state *)arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (!st) return;
        if (st->current == LWIP_STATUS_CONNECTED)
        {
            state->connected = true;
            lwip_chat_append_system(state, "connected");
        }
        else if (st->current == LWIP_STATUS_CLOSED ||
                 st->current == LWIP_STATUS_RESET)
        {
            if (!state->exiting)
            {
                lwip_chat_append_system(state,
                    st->current == LWIP_STATUS_RESET ?
                        "connection reset" : "socket closed");
            }
            state->connected = false;
            state->done = true;
        }
        (void)sock;
        return;
    }

    if (type == LWIP_SOCKET_EV_ERROR)
    {
        const lwip_socket_error_data_t *err =
            (const lwip_socket_error_data_t *)ev_data;
        char line[40];
        state->err = err ? err->err : sock->last_error;
        state->connected = false;
        if (!state->exiting)
        {
            if (err)
                snprintf(line, sizeof(line), "err c%u o%u r%d e%u",
                         (unsigned)err->component, (unsigned)err->operation,
                         err->raw_error, (unsigned)err->err);
            else
                snprintf(line, sizeof(line), "socket error e%u",
                         (unsigned)state->err);
            lwip_chat_append_system(state, line);
        }
        state->done = true;
    }
}

static int lwip_chat_run(lwip_socket_type_t protocol,
                         const char *title,
                         const char *host,
                         uint16_t port,
                         bool debug)
{
    static struct lwip_socket sock;
    struct lwip_chat_state *state = NULL;
    lwip_error_t err;
    bool socket_created = false;
    int result = 1;

    memset(&sock, 0, sizeof(sock));

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    state = (struct lwip_chat_state *)mem_request(sizeof(*state));
    if (!state)
    {
        lwip_example_show_and_wait("chat mem request", "failed");
        return lwip_example_finish(1);
    }
    memset(state, 0, sizeof(*state));

    /* Smoke-test resize accounting without changing the final live size. */
    {
        void *resized = mem_resize(state, sizeof(*state) + 64u);
        if (!resized)
        {
            lwip_example_show_and_wait("chat mem resize", "failed");
            mem_release(state);
            return lwip_example_finish(1);
        }
        state = (struct lwip_chat_state *)resized;
        resized = mem_resize(state, sizeof(*state));
        if (!resized)
        {
            lwip_example_show_and_wait("chat mem shrink", "failed");
            mem_release(state);
            return lwip_example_finish(1);
        }
        state = (struct lwip_chat_state *)resized;
    }

    lwip_example_chat_begin(&state->chat, title);
    if (debug)
    {
        lwip_chat_debug_state = state;
        lwip_set_event_cb(lwip_chat_debug_cb);
    }

    err = lwip_socket_create(&sock, protocol, LWIP_NETIF_EXT, NULL, 30000);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("chat create", &sock, err);
        goto cleanup;
    }
    socket_created = true;

    lwip_socket_on_event(&sock, LWIP_SOCKET_EVENTF_ALL,
                         lwip_chat_on_event, state);

    lwip_example_chat_append(&state->chat, "* ", "connecting", 10);
    lwip_example_chat_append(&state->chat, "  ", host, strlen(host));
    lwip_example_chat_render(&state->chat);

    err = lwip_socket_connect(&sock, host, port);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("chat connect", &sock, err);
        goto cleanup;
    }

    while (!state->done)
    {
        char outbound[LWIP_EXAMPLE_CHAT_INPUT + 2];
        uint8_t key;

        lwip_service_events();

        /* Scan the keypad once per iteration -- os_GetCSC() reports a press
         * exactly once, so multiple independent callers each calling it
         * would race for the same event and silently drop it. */
        key = os_GetCSC();

        /* Drain inbound data each iteration — callbacks own lifecycle,
         * the loop owns data. */
        if (state->connected && lwip_socket_available(&sock))
        {
            lwip_chat_on_readable(state, &sock);
        }

        if (lwip_example_cancelled(key))
            state->exiting = true;

        if (lwip_example_mem_stats_tick(key))
        {
            lwip_example_chat_invalidate(&state->chat);
            lwip_example_chat_render(&state->chat);
        }

        if (state->exiting)
            break;

        if (!state->connected)
            continue;

        switch (key)
        {
        case sk_Alpha:
            state->chat.input_mode = (uint8_t)((state->chat.input_mode + 1u) % 3u);
            state->chat.input_upper_once = false;
            lwip_example_chat_render_input(&state->chat);
            break;
        case sk_GraphVar:
            state->chat.input_upper_once = true;
            lwip_example_chat_render_input(&state->chat);
            break;
        case sk_Del:
            if (state->chat.input_len)
            {
                state->chat.input[--state->chat.input_len] = '\0';
                lwip_example_chat_render_input(&state->chat);
            }
            break;
        case sk_Enter:
            if (state->chat.input_len)
            {
                snprintf(outbound, sizeof(outbound) - 1, "%s", state->chat.input);
                state->chat.input[0] = '\0';
                state->chat.input_len = 0;
                lwip_example_chat_render_input(&state->chat);

                {
                    size_t len = strlen(outbound);
                    outbound[len++] = '\n';
                    outbound[len] = '\0';
                    err = lwip_socket_write(&sock, (const uint8_t *)outbound, len);
                    if (err != LWIP_OK)
                    {
                        char line[32];
                        state->err = err;
                        snprintf(line, sizeof(line), "send error e%u", (unsigned)err);
                        lwip_chat_append_system(state, line);
                        state->done = true;
                    }
                }
            }
            break;
        default:
            if (key < 0x0A || key > 0x2F)
                break;
            uint8_t input_mode = state->chat.input_upper_once
                ? (uint8_t)LWIP_EXAMPLE_CHAT_MODE_UPPER
                : state->chat.input_mode;
            char c = key_to_char(key, input_mode);
            if (c)
            {
                state->chat.input_upper_once = false;
            }
            if (c && state->chat.input_len + 1 < sizeof(state->chat.input))
            {
                state->chat.input[state->chat.input_len++] = c;
                state->chat.input[state->chat.input_len] = '\0';
                lwip_example_chat_render_input(&state->chat);
            }
            break;
        }

        if (state->exiting)
        {
            break;
        }
    }

    if (!state->exiting && state->err != LWIP_OK)
    {
        lwip_example_show_socket_error("chat failed", &sock, state->err);
        goto cleanup;
    }

    result = 0;

cleanup:
    if (debug)
    {
        lwip_set_event_cb(NULL);
        lwip_chat_debug_state = NULL;
    }
    if (state && state->exiting && socket_created)
    {
        err = lwip_socket_close(&sock);
        if (err == LWIP_OK || sock.status == LWIP_STATUS_CLOSED)
        {
            socket_created = false;
        }
    }
    if (socket_created)
    {
        lwip_socket_destroy(&sock);
    }
    if (state)
    {
        mem_release(state);
    }
    return lwip_example_finish(result);
}

#endif /* LWIP_CHAT_CLIENT_H */
