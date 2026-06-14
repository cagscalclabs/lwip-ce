#ifndef LWIP_CHAT_CLIENT_H
#define LWIP_CHAT_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lwip.h>

#include "common/lwip_example.h"

#ifndef CHAT_CONNECT_TIMEOUT_SECONDS
#define CHAT_CONNECT_TIMEOUT_SECONDS 60
#endif

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

static void lwip_chat_debug_cb(const struct lwip_debug_info *info)
{
    struct lwip_chat_state *state = lwip_chat_debug_state;
    char line[48];

    if (!info || !state)
    {
        return;
    }

#ifdef LWIP_DBG_SEV_ALERT
    if (info->severity == LWIP_DBG_SEV_ALERT)
    {
        snprintf(line, sizeof(line), "!%s:%s a%d",
                 lwip_debug_module_name(info->module),
                 lwip_debug_state_name(info->module_state),
                 info->errnum);
        lwip_chat_append_system(state, line);
        return;
    }
    if (info->severity == LWIP_DBG_SEV_ERROR)
    {
        snprintf(line, sizeof(line), "X%s:%s e%d",
                 lwip_debug_module_name(info->module),
                 lwip_debug_state_name(info->module_state),
                 info->errnum);
        lwip_chat_append_system(state, line);
        return;
    }
#endif

    if (info->errnum == 0)
    {
        snprintf(line, sizeof(line), "%s:%s ok",
                 lwip_debug_module_name(info->module),
                 lwip_debug_state_name(info->module_state));
    }
    else
    {
        snprintf(line, sizeof(line), "%s:%s e%d",
                 lwip_debug_module_name(info->module),
                 lwip_debug_state_name(info->module_state),
                 info->errnum);
    }
    lwip_chat_append_system(state, line);
}

static void lwip_chat_on_connected(void *arg, struct lwip_conn *conn)
{
    struct lwip_chat_state *state = (struct lwip_chat_state *)arg;
    (void)conn;
    state->connected = true;
    lwip_chat_append_system(state, "connected");
}

static void lwip_chat_on_recv(void *arg, struct lwip_conn *conn, struct pbuf *p)
{
    struct lwip_chat_state *state = (struct lwip_chat_state *)arg;
    size_t offset = 0;
    char buf[64];

    if (!p)
    {
        if (!state->exiting)
        {
            lwip_chat_append_system(state, "server closed");
        }
        state->connected = false;
        state->done = true;
        return;
    }

    while (offset < p->tot_len)
    {
        uint16_t take = (uint16_t)(p->tot_len - offset);
        if (take > sizeof(buf) - 1)
        {
            take = sizeof(buf) - 1;
        }
        pbuf_copy_partial(p, buf, take, (u16_t)offset);
        buf[take] = '\0';
        lwip_example_chat_append(&state->chat, NULL, buf, take);
        offset += take;
    }
    lwip_conn_recved(conn, p->tot_len);
    pbuf_free(p);
    lwip_example_chat_render(&state->chat);
}

static void lwip_chat_on_err(void *arg, struct lwip_conn *conn, lwip_error_t err)
{
    struct lwip_chat_state *state = (struct lwip_chat_state *)arg;
    char line[32];
    (void)conn;

    state->err = err;
    state->connected = false;
    if (!state->exiting)
    {
        snprintf(line, sizeof(line), "conn error e%u", (unsigned)err);
        lwip_chat_append_system(state, line);
    }
    state->done = true;
}

static void lwip_chat_on_closed(void *arg, struct lwip_conn *conn)
{
    struct lwip_chat_state *state = (struct lwip_chat_state *)arg;
    (void)conn;
    if (!state->exiting)
    {
        lwip_chat_append_system(state, "connection closed");
    }
    state->connected = false;
    state->done = true;
}

static int lwip_chat_run(lwip_protocol_t protocol,
                         const char *title,
                         const char *host,
                         uint16_t port,
                         bool debug)
{
    static struct lwip_conn conn;
    struct lwip_chat_state *state = NULL;
    clock_t start;
    lwip_error_t err;
    bool conn_created = false;
    int result = 1;

    memset(&conn, 0, sizeof(conn));

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
        lwip_set_debug(lwip_chat_debug_cb, LWIP_DBG_INFO,
                       LWIP_DBG_DEPTH_VERBOSE);
    }

    err = lwip_conn_create(&conn, NULL, protocol,
                           LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_DNS);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("chat create", &conn, err);
        goto cleanup;
    }
    conn_created = true;

    lwip_conn_set_arg(&conn, state);
    lwip_conn_set_connected(&conn, lwip_chat_on_connected);
    lwip_conn_set_recv(&conn, lwip_chat_on_recv);
    lwip_conn_set_err(&conn, lwip_chat_on_err);
    lwip_conn_set_closed(&conn, lwip_chat_on_closed);

    lwip_example_chat_append(&state->chat, "* ", "connecting", 10);
    lwip_example_chat_append(&state->chat, "  ", host, strlen(host));
    lwip_example_chat_render(&state->chat);

    err = lwip_conn_connect(&conn, host, port);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("chat connect", &conn, err);
        goto cleanup;
    }

    start = clock();
    while (!state->done)
    {
        char outbound[LWIP_EXAMPLE_CHAT_INPUT + 2];
        bool cancel = false;

        if (!state->connected && lwip_example_cancelled())
        {
            state->exiting = true;
            break;
        }

        lwip_poll_network_events();
        lwip_example_mem_stats_tick();

        if (!state->connected &&
            lwip_example_timed_out(start, CHAT_CONNECT_TIMEOUT_SECONDS))
        {
            state->err = LWIP_ERR_CONNECT;
            lwip_chat_append_system(state, "connect timeout");
            state->done = true;
            break;
        }

        if (!state->connected)
        {
            continue;
        }

        if (lwip_example_chat_poll_input(&state->chat, outbound,
                                         sizeof(outbound) - 1, &cancel))
        {
            size_t len = strlen(outbound);
            outbound[len++] = '\n';
            outbound[len] = '\0';
            err = lwip_conn_write(&conn, (const uint8_t *)outbound, len);
            if (err != LWIP_OK)
            {
                char line[32];
                state->err = err;
                snprintf(line, sizeof(line), "send error e%u", (unsigned)err);
                lwip_chat_append_system(state, line);
                state->done = true;
            }
        }
        if (cancel)
        {
            state->exiting = true;
            break;
        }
    }

    if (!state->exiting && state->err != LWIP_OK)
    {
        lwip_example_show_conn_error("chat failed", &conn, state->err);
        goto cleanup;
    }

    result = 0;

cleanup:
    if (debug)
    {
        lwip_set_debug(NULL, LWIP_DBG_INFO, LWIP_DBG_DEPTH_MILESTONE);
        lwip_chat_debug_state = NULL;
    }
    if (state && state->exiting && conn_created)
    {
        err = lwip_conn_close(&conn);
        if (err == LWIP_OK || conn.status == LWIP_STATUS_CLOSED)
        {
            conn_created = false;
        }
    }
    if (conn_created)
    {
        lwip_conn_destroy(&conn);
    }
    if (state)
    {
        mem_release(state);
    }
    return lwip_example_finish(result);
}

#endif /* LWIP_CHAT_CLIENT_H */
