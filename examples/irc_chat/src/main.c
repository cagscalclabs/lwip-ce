#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fileioc.h>
#include <lwip.h>
#include <lwip/core/logging.h>

#include "../../common/lwip_example.h"

#ifndef IRC_HOST
#define IRC_HOST "irc.efnet.org"
#endif

#ifndef IRC_PORT
#define IRC_PORT 6667
#endif

#ifndef IRC_TLS_PORT
#define IRC_TLS_PORT 6697
#endif

#ifndef IRC_CHANNEL
#define IRC_CHANNEL "#cemetech"
#endif

#ifndef IRC_NICK
#define IRC_NICK "acags"
#endif

#ifndef IRC_DEBUG
#define IRC_DEBUG 1
#endif

#define IRC_CONNECT_TIMEOUT_MS 45000u
#define IRC_RX_TMP 96
#define IRC_LINE_MAX 512
#define IRC_SERVER_MAX 128
#define IRC_CHANNEL_MAX 64
#define IRC_CONFIG_APPVAR "IRCCFG"
#define IRC_CONFIG_VERSION 1u

#if IRC_DEBUG
static struct irc_state *irc_debug_state;
#endif

enum irc_input_mode
{
    IRC_INPUT_LOWER,
    IRC_INPUT_UPPER,
    IRC_INPUT_NUM
};

struct irc_state
{
    struct lwip_example_chat chat;
    bool connected;
    bool registered;
    bool joined;
    bool exiting;
    bool quit_sent;
    bool done;
    uint8_t done_reason;
    bool redraw;
    uint8_t last_status;
    lwip_error_t err;
#if IRC_DEBUG
    uint16_t err_component;
    uint16_t err_operation;
    int err_raw;
    lwip_status_t err_status;
    uint8_t last_debug_kind;
    uint8_t last_debug_module;
    uint8_t last_debug_file;
    uint32_t last_debug_line;
    uint16_t last_debug_extra;
    uint8_t last_tls_kind;
    uint8_t last_tls_file;
    uint32_t last_tls_line;
    uint16_t last_tls_extra;
#endif
    char *msg_buf;
    char server[IRC_SERVER_MAX];
    char channel[IRC_CHANNEL_MAX];
    char nick[16];
    bool use_tls;
    char line[IRC_LINE_MAX];
    size_t line_len;
    uint8_t setup_field;
};

enum irc_setup_field
{
    IRC_SETUP_SERVER,
    IRC_SETUP_NICK,
    IRC_SETUP_CHANNEL,
    IRC_SETUP_TLS
};

struct irc_saved_config
{
    char magic[4];
    uint8_t version;
    uint8_t use_tls;
    char server[IRC_SERVER_MAX];
    char nick[16];
    char channel[IRC_CHANNEL_MAX];
};

static const char *irc_input_mode_name(uint8_t mode)
{
    switch ((enum irc_input_mode)mode)
    {
    case IRC_INPUT_UPPER: return "ABC";
    case IRC_INPUT_NUM:   return "123";
    case IRC_INPUT_LOWER:
    default:              return "abc";
    }
}

static void irc_normalize_channel(char *channel, size_t channel_len);

static void irc_set_defaults(struct irc_state *state)
{
    snprintf(state->server, sizeof(state->server), "%s", IRC_HOST);
    snprintf(state->channel, sizeof(state->channel), "%s", IRC_CHANNEL);
    snprintf(state->nick, sizeof(state->nick), "%s", IRC_NICK);
    state->use_tls = false;
    state->chat.input_mode = IRC_INPUT_LOWER;
    state->chat.input_upper_once = false;
    state->setup_field = IRC_SETUP_SERVER;
}

static bool irc_config_load(struct irc_state *state)
{
    struct irc_saved_config cfg;
    uint8_t handle;

    handle = ti_Open(IRC_CONFIG_APPVAR, "r");
    if (!handle)
    {
        return false;
    }
    if (ti_Read(&cfg, sizeof(cfg), 1, handle) != 1)
    {
        ti_Close(handle);
        return false;
    }
    ti_Close(handle);

    if (memcmp(cfg.magic, "IRCC", sizeof(cfg.magic)) != 0 ||
        cfg.version != IRC_CONFIG_VERSION)
    {
        return false;
    }

    snprintf(state->server, sizeof(state->server), "%s", cfg.server);
    snprintf(state->nick, sizeof(state->nick), "%s", cfg.nick);
    snprintf(state->channel, sizeof(state->channel), "%s", cfg.channel);
    state->use_tls = cfg.use_tls ? true : false;
    if (!state->server[0])
    {
        snprintf(state->server, sizeof(state->server), "%s", IRC_HOST);
    }
    if (!state->nick[0])
    {
        snprintf(state->nick, sizeof(state->nick), "%s", IRC_NICK);
    }
    irc_normalize_channel(state->channel, sizeof(state->channel));
    return true;
}

static bool irc_config_save(const struct irc_state *state)
{
    struct irc_saved_config cfg;
    uint8_t handle;

    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.magic, "IRCC", sizeof(cfg.magic));
    cfg.version = IRC_CONFIG_VERSION;
    cfg.use_tls = state->use_tls ? 1u : 0u;
    snprintf(cfg.server, sizeof(cfg.server), "%s", state->server);
    snprintf(cfg.nick, sizeof(cfg.nick), "%s", state->nick);
    snprintf(cfg.channel, sizeof(cfg.channel), "%s", state->channel);

    handle = ti_Open(IRC_CONFIG_APPVAR, "w");
    if (!handle)
    {
        return false;
    }
    ti_SetArchiveStatus(false, handle);
    if (ti_Write(&cfg, sizeof(cfg), 1, handle) != 1)
    {
        ti_Close(handle);
        return false;
    }
    ti_SetArchiveStatus(true, handle);
    ti_Close(handle);
    return true;
}

static void irc_setup_next_field(struct irc_state *state)
{
    state->setup_field = (uint8_t)((state->setup_field + 1u) % 4u);
}

static void irc_setup_prev_field(struct irc_state *state)
{
    state->setup_field = (uint8_t)((state->setup_field + 3u) % 4u);
}

static void irc_normalize_channel(char *channel, size_t channel_len)
{
    size_t len;

    if (!channel || channel_len < 2)
    {
        return;
    }
    if (!channel[0])
    {
        snprintf(channel, channel_len, "%s", IRC_CHANNEL);
        return;
    }
    if (channel[0] == '#')
    {
        return;
    }
    len = strlen(channel);
    if (len + 1 >= channel_len)
    {
        len = channel_len - 2;
        channel[len] = '\0';
    }
    memmove(channel + 1, channel, len + 1);
    channel[0] = '#';
}

static lwip_socket_type_t irc_socket_type(const struct irc_state *state)
{
    return state->use_tls ? LWIP_SOCKET_ALTCP_TLS : LWIP_SOCKET_TCP;
}

static uint16_t irc_port(const struct irc_state *state)
{
    return state->use_tls ? (uint16_t)IRC_TLS_PORT : (uint16_t)IRC_PORT;
}

static void irc_setup_render(const struct irc_state *state)
{
    const char *server_cursor =
        state->setup_field == IRC_SETUP_SERVER ? "> server:" : "  server:";
    const char *nick_cursor =
        state->setup_field == IRC_SETUP_NICK ? "> nick:" : "  nick:";
    const char *channel_cursor =
        state->setup_field == IRC_SETUP_CHANNEL ? "> channel:" : "  channel:";
    const char *tls_cursor =
        state->setup_field == IRC_SETUP_TLS ? "> tls:" : "  tls:";

    lwip_example_clear();
    lwip_example_line("===== IRC setup =====");
    lwip_example_line(server_cursor);
    lwip_example_line(state->server);
    lwip_example_line(nick_cursor);
    lwip_example_line(state->nick);
    lwip_example_line(channel_cursor);
    lwip_example_line(state->channel);
    lwip_example_linef("%s %s", tls_cursor, state->use_tls ? "yes" : "no");
    lwip_example_line("");
    lwip_example_linef("mode %s", irc_input_mode_name(state->chat.input_mode));
    lwip_example_line("Enter next/start");
    lwip_example_line("Left/right tls");
    lwip_example_line("Clear exits");
    lwip_example_draw_mem_stats();
    lwip_example_present();
}

static char *irc_setup_active_text(struct irc_state *state, size_t *cap)
{
    if (state->setup_field == IRC_SETUP_NICK)
    {
        *cap = sizeof(state->nick);
        return state->nick;
    }
    if (state->setup_field == IRC_SETUP_CHANNEL)
    {
        *cap = sizeof(state->channel);
        return state->channel;
    }
    *cap = sizeof(state->server);
    return state->server;
}

static bool irc_setup_append_char(struct irc_state *state, char c)
{
    char *text;
    size_t cap;
    size_t len;

    if (state->setup_field == IRC_SETUP_TLS)
    {
        return false;
    }
    if (!c)
    {
        return false;
    }
    if (c == ' ')
    {
        return false;
    }
    if (state->setup_field == IRC_SETUP_CHANNEL)
    {
        if (c == '/')
        {
            return false;
        }
        if (!state->channel[0])
        {
            state->channel[0] = '#';
            state->channel[1] = '\0';
        }
    }
    text = irc_setup_active_text(state, &cap);
    len = strlen(text);
    if (len + 1 >= cap)
    {
        return false;
    }
    text[len++] = c;
    text[len] = '\0';
    return true;
}

static bool irc_setup_backspace(struct irc_state *state)
{
    char *text;
    size_t cap;
    size_t len;

    if (state->setup_field == IRC_SETUP_TLS)
    {
        return false;
    }
    text = irc_setup_active_text(state, &cap);
    (void)cap;
    len = strlen(text);
    if (len == 0)
    {
        return false;
    }
    if (state->setup_field == IRC_SETUP_CHANNEL && len == 1 && text[0] == '#')
    {
        return false;
    }
    text[len - 1] = '\0';
    return true;
}

static bool irc_setup_run(struct irc_state *state)
{
    bool redraw = true;

    while (true)
    {
        uint8_t key;

        lwip_service_events();
        key = os_GetCSC();
        if (lwip_example_mem_stats_tick(key))
        {
            lwip_example_chat_invalidate(&state->chat);
            redraw = true;
        }

        if (key == sk_Clear)
        {
            return false;
        }
        else if (key == sk_Stat)
        {
            /* Stats was handled above. */
        }
        else if (key == sk_Alpha)
        {
            state->chat.input_mode =
                (uint8_t)((state->chat.input_mode + 1u) % 3u);
            state->chat.input_upper_once = false;
            redraw = true;
        }
        else if (key == sk_GraphVar)
        {
            state->chat.input_upper_once = true;
            redraw = true;
        }
        else if (key == sk_Left || key == sk_Right)
        {
            if (state->setup_field == IRC_SETUP_TLS)
            {
                state->use_tls = !state->use_tls;
                redraw = true;
            }
        }
        else if (key == sk_Up)
        {
            irc_setup_prev_field(state);
            redraw = true;
        }
        else if (key == sk_Down)
        {
            irc_setup_next_field(state);
            redraw = true;
        }
        else if (key == sk_Del)
        {
            redraw = irc_setup_backspace(state) || redraw;
        }
        else if (key == sk_Enter)
        {
            if (state->setup_field == IRC_SETUP_SERVER)
            {
                if (!state->server[0])
                {
                    snprintf(state->server, sizeof(state->server), "%s",
                             IRC_HOST);
                }
                irc_setup_next_field(state);
                redraw = true;
            }
            else if (state->setup_field == IRC_SETUP_NICK)
            {
                if (!state->nick[0])
                {
                    snprintf(state->nick, sizeof(state->nick), "%s",
                             IRC_NICK);
                }
                irc_setup_next_field(state);
                redraw = true;
            }
            else if (state->setup_field == IRC_SETUP_CHANNEL)
            {
                irc_normalize_channel(state->channel, sizeof(state->channel));
                irc_setup_next_field(state);
                redraw = true;
            }
            else
            {
                if (!state->server[0])
                {
                    snprintf(state->server, sizeof(state->server), "%s",
                             IRC_HOST);
                }
                if (!state->nick[0])
                {
                    snprintf(state->nick, sizeof(state->nick), "%s",
                             IRC_NICK);
                }
                irc_normalize_channel(state->channel, sizeof(state->channel));
                return true;
            }
        }
        else
        {
            uint8_t input_mode = state->chat.input_upper_once
                                     ? (uint8_t)LWIP_EXAMPLE_CHAT_MODE_UPPER
                                     : state->chat.input_mode;
            char c = key_to_char(key, input_mode);
            if (c)
            {
                state->chat.input_upper_once = false;
            }
            redraw = irc_setup_append_char(state, c) || redraw;
        }

        if (redraw)
        {
            irc_setup_render(state);
            redraw = false;
        }
    }
}

static void irc_append_system(struct irc_state *state, const char *msg)
{
    lwip_example_chat_append(&state->chat, "* ", msg, strlen(msg));
    state->redraw = true;
}

static void irc_note_status(struct irc_state *state, const struct lwip_socket *sock)
{
    char msg[32];
    lwip_status_t status;

    if (!state || !sock)
    {
        return;
    }
    status = lwip_socket_status(sock);
    if (state->last_status == (uint8_t)status)
    {
        return;
    }
    state->last_status = (uint8_t)status;
    snprintf(msg, sizeof(msg), "status %s",
             lwip_example_socket_status_name(status));
    irc_append_system(state, msg);
}

static lwip_error_t irc_writef(struct lwip_socket *sock,
                               const char *fmt, ...)
{
    char buf[192];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
    {
        return LWIP_ERR_ARG;
    }
    if ((size_t)n >= sizeof(buf))
    {
        n = (int)sizeof(buf) - 1;
    }
    return lwip_socket_write(sock, (const uint8_t *)buf, (size_t)n);
}

static const char *irc_command_arg(const char *input, const char *cmd)
{
    size_t cmd_len;

    if (!input || !cmd)
    {
        return NULL;
    }
    cmd_len = strlen(cmd);
    if (strncmp(input, cmd, cmd_len) != 0)
    {
        return NULL;
    }
    if (input[cmd_len] == '\0')
    {
        return "";
    }
    if (input[cmd_len] == ' ')
    {
        return input + cmd_len + 1;
    }
    return NULL;
}

static void irc_register(struct irc_state *state, struct lwip_socket *sock)
{
    lwip_error_t err;
    char line[40];

    err = irc_writef(sock, "NICK %s\r\n", state->nick);
    if (err == LWIP_OK)
    {
        err = irc_writef(sock, "USER %s 0 * :lwIP CE IRC\r\n", state->nick);
    }
    if (err != LWIP_OK)
    {
        state->err = err;
        state->done = true;
        state->done_reason = 1; /* irc_register: NICK/USER write failed */
        return;
    }
    snprintf(line, sizeof(line), "nick %s", state->nick);
    irc_append_system(state, line);
}

static const char *irc_trailing(const char *line)
{
    const char *p = strstr(line, " :");

    return p ? p + 2 : NULL;
}

static void irc_display_line(struct irc_state *state, const char *line)
{
    const char *text = irc_trailing(line);

    if (text)
    {
        lwip_example_chat_append(&state->chat, "< ", text, strlen(text));
    }
    else
    {
        lwip_example_chat_append(&state->chat, "< ", line, strlen(line));
    }
    state->redraw = true;
}

static bool irc_parse_prefix_nick(const char *line, char *nick, size_t nick_len)
{
    const char *p;
    size_t len;

    if (!line || line[0] != ':' || !nick || nick_len == 0)
    {
        return false;
    }

    p = line + 1;
    len = 0;
    while (p[len] && p[len] != '!' && p[len] != ' ')
    {
        len++;
    }
    if (len == 0)
    {
        return false;
    }
    if (len >= nick_len)
    {
        len = nick_len - 1;
    }
    memcpy(nick, p, len);
    nick[len] = '\0';
    return true;
}

static bool irc_handle_privmsg(struct irc_state *state, const char *line)
{
    const char *text;
    char nick[16];
    size_t msg_len = IRC_LINE_MAX + 24u;

    if (!line || !strstr(line, " PRIVMSG "))
    {
        return false;
    }

    text = irc_trailing(line);
    if (!text)
    {
        return true;
    }

    if (!irc_parse_prefix_nick(line, nick, sizeof(nick)))
    {
        snprintf(nick, sizeof(nick), "?");
    }
    if (!state->msg_buf)
    {
        irc_append_system(state, "privmsg mem failed");
        return true;
    }
    snprintf(state->msg_buf, msg_len, "%s: %s", nick, text);
    lwip_example_chat_append(&state->chat, "< ", state->msg_buf,
                             strlen(state->msg_buf));
    state->redraw = true;
    return true;
}

static void irc_handle_line(struct irc_state *state,
                            struct lwip_socket *sock,
                            const char *line)
{
    char status[48];

    if (strncmp(line, "PING ", 5) == 0)
    {
        (void)irc_writef(sock, "PONG %s\r\n", line + 5);
        irc_append_system(state, "pong");
        return;
    }

    if (strstr(line, " 001 "))
    {
        state->registered = true;
        irc_append_system(state, "registered");
        (void)irc_writef(sock, "JOIN %s\r\n", state->channel);
        return;
    }

    if (strstr(line, " JOIN ") && strstr(line, state->nick))
    {
        state->joined = true;
        snprintf(status, sizeof(status), "joined %s", state->channel);
        irc_append_system(state, status);
        return;
    }

    if (strstr(line, " 433 "))
    {
        irc_append_system(state, "nick in use");
        return;
    }

    if (irc_handle_privmsg(state, line))
    {
        return;
    }

    irc_display_line(state, line);
}

static void irc_on_readable(struct irc_state *state,
                            struct lwip_socket *sock)
{
    char buf[IRC_RX_TMP];

    while (lwip_socket_available(sock))
    {
        size_t got = lwip_socket_read(sock, (uint8_t *)buf, sizeof(buf));
        size_t i;

        for (i = 0; i < got; i++)
        {
            char c = buf[i];

            if (c == '\r')
            {
                continue;
            }
            if (c == '\n')
            {
                state->line[state->line_len] = '\0';
                if (state->line_len)
                {
                    irc_handle_line(state, sock, state->line);
                }
                state->line_len = 0;
                continue;
            }
            if (state->line_len + 1 < sizeof(state->line))
            {
                state->line[state->line_len++] =
                    (c >= 32 && c <= 126) ? c : '.';
            }
        }
    }
}

static void irc_on_event(struct lwip_socket *sock,
                         lwip_socket_event_type_t type,
                         const void *ev_data,
                         void *arg)
{
    struct irc_state *state = (struct irc_state *)arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (!st)
        {
            return;
        }
        if (st->current == LWIP_STATUS_CONNECTED)
        {
            state->connected = true;
            irc_append_system(state, "connected");
            irc_register(state, sock);
        }
        else if (st->current == LWIP_STATUS_CLOSED ||
                 st->current == LWIP_STATUS_RESET)
        {
            state->connected = false;
            state->err = sock->last_error ? sock->last_error : LWIP_ERR_CLOSED;
            state->done = true;
            state->done_reason = (uint8_t)(st->current == LWIP_STATUS_RESET
                                                ? 2  /* STATE_CHANGE: RESET */
                                                : 3); /* STATE_CHANGE: CLOSED */
        }
        return;
    }

    if (type == LWIP_SOCKET_EV_ERROR)
    {
        const lwip_socket_error_data_t *err =
            (const lwip_socket_error_data_t *)ev_data;
#if IRC_DEBUG
        if (err)
        {
            state->err_component = err->component;
            state->err_operation = err->operation;
            state->err_raw = err->raw_error;
            state->err_status = err->status;
            lwip_example_linef("sock err c%u o%u r%d e%u s%u",
                               (unsigned)err->component,
                               (unsigned)err->operation,
                               err->raw_error,
                               (unsigned)err->err,
                               (unsigned)err->status);
            lwip_example_draw_mem_stats();
        }
#endif
        state->err = err ? err->err : sock->last_error;
        state->connected = false;
        state->done = true;
        state->done_reason = 4; /* EV_ERROR */
    }
}

static void irc_send_input(struct irc_state *state, struct lwip_socket *sock)
{
    lwip_error_t err;
    const char *quit_msg;

    if (!state->chat.input_len)
    {
        return;
    }

    quit_msg = irc_command_arg(state->chat.input, "/quit");
    if (!quit_msg)
    {
        quit_msg = irc_command_arg(state->chat.input, "/leave");
    }

    if (quit_msg)
    {
        if (!quit_msg[0])
        {
            quit_msg = "leaving";
        }
        err = irc_writef(sock, "QUIT :%s\r\n", quit_msg);
        if (err == LWIP_OK)
        {
            state->quit_sent = true;
            state->exiting = true;
            state->done = true;
            state->done_reason = 6; /* user quit command */
            irc_append_system(state, "quitting");
        }
    }
    else if (strncmp(state->chat.input, "/raw ", 5) == 0)
    {
        err = irc_writef(sock, "%s\r\n", state->chat.input + 5);
    }
    else if (strncmp(state->chat.input, "/nick ", 6) == 0)
    {
        const char *nick = state->chat.input + 6;
        err = irc_writef(sock, "NICK %s\r\n", nick);
        if (err == LWIP_OK)
        {
            char msg[40];
            snprintf(state->nick, sizeof(state->nick), "%s", nick);
            snprintf(msg, sizeof(msg), "nick requested %.20s", nick);
            irc_append_system(state, msg);
        }
    }
    else if (strncmp(state->chat.input, "/join ", 6) == 0)
    {
        char msg[48];

        snprintf(state->channel, sizeof(state->channel), "%s",
                 state->chat.input + 6);
        irc_normalize_channel(state->channel, sizeof(state->channel));
        err = irc_writef(sock, "JOIN %s\r\n", state->channel);
        if (err == LWIP_OK)
        {
            snprintf(state->chat.title, sizeof(state->chat.title),
                     "===== IRC %.15s =====", state->channel);
            snprintf(msg, sizeof(msg), "joining %.24s", state->channel);
            irc_append_system(state, msg);
        }
    }
    else
    {
        err = irc_writef(sock, "PRIVMSG %s :%s\r\n",
                         state->channel, state->chat.input);
        if (err == LWIP_OK)
        {
            lwip_example_chat_append(&state->chat, "> ",
                                     state->chat.input,
                                     state->chat.input_len);
            state->redraw = true;
        }
    }

    state->chat.input[0] = '\0';
    state->chat.input_len = 0;
    state->redraw = true;

    if (err != LWIP_OK)
    {
        state->err = err;
        irc_append_system(state, "send failed");
        state->done = true;
        state->done_reason = 5; /* irc_send_input: write failed */
    }
}

static void irc_session_reset(struct irc_state *state)
{
    uint8_t input_mode = state->chat.input_mode;
    char title[24];

    state->connected = false;
    state->registered = false;
    state->joined = false;
    state->exiting = false;
    state->quit_sent = false;
    state->done = false;
    state->done_reason = 0;
    state->redraw = false;
    state->last_status = 0xffu;
    state->err = LWIP_OK;
#if IRC_DEBUG
    state->err_component = 0;
    state->err_operation = 0;
    state->err_raw = 0;
    state->err_status = LWIP_STATUS_INIT;
    state->last_debug_kind = 0;
    state->last_debug_module = 0;
    state->last_debug_file = 0;
    state->last_debug_line = 0;
    state->last_debug_extra = 0;
    state->last_tls_kind = 0;
    state->last_tls_file = 0;
    state->last_tls_line = 0;
    state->last_tls_extra = 0;
#endif
    state->line_len = 0;
    state->line[0] = '\0';
    snprintf(title, sizeof(title), "===== IRC %.15s =====", state->channel);
    lwip_example_chat_begin(&state->chat, title);
    state->chat.input_mode = input_mode;
}

#if IRC_DEBUG
static void irc_debug_cb(const struct lwip_event *ev)
{
    lwip_example_dbg_console_cb(ev);
    if (!ev || !irc_debug_state)
    {
        return;
    }
    if (ev->kind == LWIP_EV_DEBUG ||
        ev->kind == LWIP_EV_WARN ||
        ev->kind == LWIP_EV_ERROR)
    {
        irc_debug_state->last_debug_kind = ev->kind;
        irc_debug_state->last_debug_module = ev->module;
        irc_debug_state->last_debug_file =
            LWIP_EVENT_CODE_FILE(ev->data.code.loc);
        irc_debug_state->last_debug_line =
            LWIP_EVENT_CODE_LINE(ev->data.code.loc);
        irc_debug_state->last_debug_extra = ev->data.code.extra;
        if (ev->module == LWIP_DBG_MOD_TLS)
        {
            irc_debug_state->last_tls_kind = ev->kind;
            irc_debug_state->last_tls_file =
                LWIP_EVENT_CODE_FILE(ev->data.code.loc);
            irc_debug_state->last_tls_line =
                LWIP_EVENT_CODE_LINE(ev->data.code.loc);
            irc_debug_state->last_tls_extra = ev->data.code.extra;
        }
    }
}

static void irc_show_traceback(void)
{
    const struct lwip_traceback_entry *trace;
    uint8_t count = 0;

    trace = lwip_get_traceback(&count);
    for (uint8_t i = 0; i < count && i < 16u; i++)
    {
        const struct lwip_traceback_entry *entry = &trace[i];

        if (entry->file)
        {
            lwip_example_linef("%u %s %s:%u x%u",
                               (unsigned)i,
                               lwip_debug_module_name(entry->module),
                               lwip_debug_file_name(entry->file),
                               (unsigned)entry->line,
                               (unsigned)entry->extra);
        }
        else
        {
            lwip_example_linef("%u sock c%u o%u r%d e%u s%u",
                               (unsigned)i,
                               (unsigned)entry->component,
                               (unsigned)entry->operation,
                               entry->raw_error,
                               (unsigned)entry->mapped_error,
                               (unsigned)entry->status);
        }
    }
}
#endif

static void irc_session_close(struct irc_state *state, struct lwip_socket *sock)
{
    uint32_t start;

    if (state->connected && !state->quit_sent)
    {
        (void)irc_writef(sock, "QUIT :leaving\r\n");
        state->quit_sent = true;
    }
    (void)lwip_socket_close(sock);
    start = lwip_example_now_ms();
    while ((sock->status == LWIP_STATUS_CONNECTED ||
            sock->status == LWIP_STATUS_CLOSING) &&
           (uint32_t)(lwip_example_now_ms() - start) < 500u)
    {
        lwip_service_events();
    }
    lwip_socket_destroy(sock);
}

static void irc_session_run(struct irc_state *state)
{
    static struct lwip_socket sock;
    lwip_error_t err;
    char connect_line[48];

    memset(&sock, 0, sizeof(sock));
    irc_session_reset(state);

    err = lwip_socket_create(&sock, irc_socket_type(state), LWIP_NETIF_EXT,
                             NULL, IRC_CONNECT_TIMEOUT_MS);
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("IRC create", &sock, err);
        return;
    }

    lwip_socket_on_event(&sock, LWIP_SOCKET_EVENTF_ALL,
                         irc_on_event, state);

    lwip_example_chat_append(&state->chat, "* ", "connecting", 10);
    snprintf(connect_line, sizeof(connect_line), "%s:%u %s",
             state->server, (unsigned)irc_port(state),
             state->use_tls ? "tls" : "tcp");
    lwip_example_chat_append(&state->chat, "  ", connect_line,
                             strlen(connect_line));
    lwip_example_chat_render(&state->chat);

#if IRC_DEBUG
    lwip_example_dbg_console_begin("IRC debug");
    lwip_example_linef("connecting %s:%u %s",
                       state->server, (unsigned)irc_port(state),
                       state->use_tls ? "tls" : "tcp");
#endif

    err = lwip_socket_connect(&sock, state->server, irc_port(state));
#if IRC_DEBUG
    irc_debug_state = state;
    lwip_set_event_cb(irc_debug_cb);
#endif
    if (err != LWIP_OK)
    {
        lwip_example_show_socket_error("IRC connect", &sock, err);
        goto cleanup;
    }
    irc_note_status(state, &sock);

    while (!state->done)
    {
        uint8_t key = 0;

        lwip_service_events();
        key = os_GetCSC();
        irc_note_status(state, &sock);

        if (state->connected && lwip_socket_available(&sock))
        {
            irc_on_readable(state, &sock);
        }

        if (lwip_example_cancelled(key))
        {
            state->exiting = true;
            break;
        }
        if (lwip_example_mem_stats_tick(key))
        {
            lwip_example_chat_invalidate(&state->chat);
            state->redraw = true;
        }

        if (state->redraw)
        {
            lwip_example_chat_render(&state->chat);
            state->redraw = false;
        }

        if (!state->connected)
        {
            continue;
        }

        switch (key)
        {
        case sk_Alpha:
            state->chat.input_mode =
                (uint8_t)((state->chat.input_mode + 1u) % 3u);
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
            irc_send_input(state, &sock);
            break;
        default:
            {
                uint8_t input_mode = state->chat.input_upper_once
                                         ? (uint8_t)LWIP_EXAMPLE_CHAT_MODE_UPPER
                                         : state->chat.input_mode;
                char c = key_to_char(key, input_mode);
                if (c)
                {
                    state->chat.input_upper_once = false;
                }
                if (c &&
                    state->chat.input_len + 1 < sizeof(state->chat.input))
                {
                    state->chat.input[state->chat.input_len++] = c;
                    state->chat.input[state->chat.input_len] = '\0';
                    lwip_example_chat_render_input(&state->chat);
                }
            }
            break;
        }

        if (state->redraw)
        {
            lwip_example_chat_render(&state->chat);
            state->redraw = false;
        }
        lwip_example_draw_mem_stats();
    }

cleanup:
    if (state && state->done && !state->exiting)
    {
#if IRC_DEBUG
        lwip_example_clear();
        lwip_example_line("IRC disconnected");
        lwip_example_linef("reason %u err %u",
                           (unsigned)state->done_reason,
                           (unsigned)state->err);
        lwip_example_linef("sock c%u o%u raw%d st%u",
                           (unsigned)state->err_component,
                           (unsigned)state->err_operation,
                           state->err_raw,
                           (unsigned)state->err_status);
        irc_show_traceback();
        lwip_example_draw_mem_stats();
        lwip_example_wait_key();
#else
        char reason[24];
        snprintf(reason, sizeof(reason), "reason %u", (unsigned)state->done_reason);
        lwip_example_show_and_wait("IRC disconnected", reason);
        lwip_example_show_socket_error("IRC disconnected", &sock, state->err);
#endif
    }
    if (state->exiting)
    {
        irc_session_close(state, &sock);
    }
    else
    {
        lwip_socket_destroy(&sock);
    }
#if IRC_DEBUG
    lwip_set_event_cb(NULL);
    irc_debug_state = NULL;
#endif
}

int main(void)
{
    struct irc_state *state;
    int result = 0;

    if (!lwip_example_stack_start())
    {
        lwip_example_show_and_wait("Stack failed to start", NULL);
        return 1;
    }
    state = (struct irc_state *)mem_request(sizeof(struct irc_state));
    if (!state)
    {
        lwip_example_show_and_wait("IRC mem", "failed");
        return lwip_example_finish(1);
    }
    memset(state, 0, sizeof(struct irc_state));
    state->msg_buf = (char *)mem_request(IRC_LINE_MAX + 24u);
    if (!state->msg_buf)
    {
        lwip_example_show_and_wait("IRC msg mem", "failed");
        mem_release(state);
        return lwip_example_finish(1);
    }
    irc_set_defaults(state);
    (void)irc_config_load(state);

    while (irc_setup_run(state))
    {
        irc_session_run(state);
    }

    (void)irc_config_save(state);
    mem_release(state->msg_buf);
    mem_release(state);
    return lwip_example_finish(result);
}
