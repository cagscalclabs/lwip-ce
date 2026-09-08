/**
 * lwIP-CE Discord Relay Client — self-contained UI
 *
 * Connects to relay.py over TLS TCP.  The relay bridges to Discord.
 *
 * Line protocol:
 *   Calc → Relay:  AUTH <user> <pin>\n
 *                  SEND <text>\n
 *                  CHAN <#name>\n
 *   Relay → Calc:  OK\n
 *                  DENIED\n
 *                  RELAY_CHAN <#ch1>,<#ch2>,...\n
 *                  RELAY_ACTIVE <#name>\n
 *                  MSG <author>: <text>\n
 *                  SYS <text>\n
 *
 * Screen layout (320x240, 8x8 font):
 *
 *   x=0       x=64 x=66                         x=319
 *   +---------+--+-------------------------------+
 *   | Channels|  | #general | username        y=0-7 (title bar)
 *   +---------+  +-------------------------------+
 *   | #general|  | <alice> hello there       y=8
 *   | #random |  | * connected               y=16
 *   | #gaming |  | ...                       ...
 *   |         |  |                               |
 *   |         |  +-------------------------------+
 *   |         |  | a hello_                  y=input
 *   +---------+--+-------------------------------+
 *
 * Controls:
 *   [alpha]    cycle input mode: abc -> ABC -> 123
 *   [2nd]      shift-once to upper for next char
 *   [enter]    send message
 *   [del]      backspace
 *   [clear]    clear input line
 *   [up/down]  scroll channel list and switch active channel
 *   [stat]     toggle memory overlay
 *   [mode]     disconnect and exit
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <ti/getcsc.h>
#include <fileioc.h>
#include <graphx.h>

#include <lwip.h>
#include "../../common/lwip_example.h"

/* ---------------------------------------------------------------------- */
/* Build-time configuration                                                */
/* ---------------------------------------------------------------------- */

#ifndef RELAY_DEFAULT_HOST
#define RELAY_DEFAULT_HOST ""
#endif

#ifndef RELAY_DEFAULT_PORT
#define RELAY_DEFAULT_PORT "8443"
#endif

#ifndef RELAY_CONNECT_TIMEOUT_MS
#define RELAY_CONNECT_TIMEOUT_MS 20000u
#endif

/* ---------------------------------------------------------------------- */
/* Layout constants                                                        */
/* ---------------------------------------------------------------------- */

#define FONT_W       8
#define FONT_H       8
#define LCD_W        320
#define LCD_H        240

/* Sidebar */
#define SIDEBAR_W    64          /* pixels */
#define SIDEBAR_X    0
#define DIVIDER_X    64
#define DIVIDER_W    2

/* Chat area */
#define CHAT_X       (DIVIDER_X + DIVIDER_W)  /* 66 */
#define CHAT_W       (LCD_W - CHAT_X)         /* 254 */
#define CHAT_COLS    (CHAT_W / FONT_W)         /* 31 chars */

/* Vertical regions */
#define TITLE_Y      0
#define TITLE_H      FONT_H                   /* 8 */
#define CONTENT_Y    (TITLE_Y + TITLE_H)      /* 8 */
#define CONTENT_H    (LCD_H - CONTENT_Y)      /* 232 */
#define INPUT_ROWS   2
#define INPUT_H      (INPUT_ROWS * FONT_H)    /* 16 */
#define INPUT_Y      (LCD_H - INPUT_H)        /* 224 */
#define TRANS_Y      CONTENT_Y                /* 8 */
#define TRANS_H      (INPUT_Y - TRANS_Y)      /* 216 */
#define TRANS_ROWS   (TRANS_H / FONT_H)       /* 27 */

/* Sidebar rows */
#define SIDEBAR_ROWS ((LCD_H - CONTENT_Y) / FONT_H) /* 29 */

/* ---------------------------------------------------------------------- */
/* Colors                                                                  */
/* ---------------------------------------------------------------------- */

#define COL_BG       0xFF   /* white */
#define COL_FG       0x00   /* black */
#define COL_SIDEBAR  0xE0   /* light blue-ish (gfx palette index) */
#define COL_DIVIDER  0x00   /* black */
#define COL_TITLE_BG 0x10   /* blue */
#define COL_TITLE_FG 0xFF   /* white */
#define COL_SYSTEM   0x10   /* blue */
#define COL_SENT     0x03   /* green */
#define COL_RECV     0x00   /* black */
#define COL_ERROR    0xE0   /* red */
#define COL_CHAN_SEL 0x10   /* blue: selected channel highlight */
#define COL_CHAN_FG  0x00   /* black: unselected channel text */
#define COL_UNREAD   0x03   /* green: channel with unread marker */

/* ---------------------------------------------------------------------- */
/* Saved configuration                                                     */
/* ---------------------------------------------------------------------- */

#define CONFIG_APPVAR   "DISCRD"
#define CONFIG_MAGIC    "DRC2"
#define CONFIG_VERSION  2u

#define HOST_MAX    128
#define PORT_MAX    6
#define USER_MAX    32
#define PIN_MAX     16

struct saved_config
{
    char    magic[4];
    uint8_t version;
    char    host[HOST_MAX];
    char    port[PORT_MAX];
    char    username[USER_MAX];
    char    pin[PIN_MAX];
};

/* ---------------------------------------------------------------------- */
/* Channel list                                                            */
/* ---------------------------------------------------------------------- */

#define MAX_CHANNELS 24
#define CHAN_NAME_MAX 24

typedef struct
{
    char name[CHAN_NAME_MAX];   /* without '#' */
    bool unread;
} channel_t;

/* ---------------------------------------------------------------------- */
/* Transcript ring                                                         */
/* ---------------------------------------------------------------------- */

#define RING_LINES  TRANS_ROWS   /* one backing row per visible line */
#define RING_ROW    (CHAT_COLS + 1)

typedef struct
{
    char    rows[RING_LINES][RING_ROW];
    uint8_t colors[RING_LINES];
    uint8_t head;       /* index of most recently pushed row */
    uint8_t count;      /* how many rows are valid */
    /* diff cache */
    char    shown[RING_LINES][RING_ROW];
    uint8_t shown_valid;
} ring_t;

/* ---------------------------------------------------------------------- */
/* Input modes                                                             */
/* ---------------------------------------------------------------------- */

#define MODE_LOWER   0
#define MODE_UPPER   1
#define MODE_NUMERIC 2

#define INPUT_BUF_MAX (CHAT_COLS * INPUT_ROWS + 1)  /* 63 */

/* ---------------------------------------------------------------------- */
/* Setup fields                                                            */
/* ---------------------------------------------------------------------- */

typedef enum { SF_HOST=0, SF_PORT, SF_USER, SF_PIN, SF_COUNT } setup_field_t;

/* ---------------------------------------------------------------------- */
/* App state                                                               */
/* ---------------------------------------------------------------------- */

#define RX_MAX 4096u

typedef struct
{
    /* Config */
    char host[HOST_MAX];
    char port[PORT_MAX];
    char username[USER_MAX];
    char pin[PIN_MAX];

    /* Setup UI */
    setup_field_t setup_field;
    uint8_t setup_input_mode;

    /* Channel list */
    channel_t channels[MAX_CHANNELS];
    uint8_t   chan_count;
    uint8_t   chan_sel;        /* index of currently highlighted channel */
    uint8_t   chan_active;     /* index of channel we are actually in */
    char      active_name[CHAN_NAME_MAX]; /* name without '#' */

    /* Transcript */
    ring_t    ring;

    /* Input */
    char    input[INPUT_BUF_MAX];
    uint8_t input_len;
    uint8_t input_mode;
    bool    input_upper_once;

    /* Socket */
    struct lwip_socket sock;
    bool connected;
    bool authed;
    bool done;

    /* RX accumulator */
    char   rx_buf[RX_MAX];
    size_t rx_len;

    /* Misc */
    lwip_error_t last_err;
    bool         need_full_redraw;
    bool         need_sidebar_redraw;
    bool         need_trans_redraw;
    bool         need_input_redraw;
} app_t;

static app_t g;

/* ---------------------------------------------------------------------- */
/* Config persist                                                          */
/* ---------------------------------------------------------------------- */

static void config_load(void)
{
    uint8_t fh = ti_Open(CONFIG_APPVAR, "r");
    if (!fh) goto defaults;

    struct saved_config cfg;
    if (ti_Read(&cfg, sizeof(cfg), 1, fh) != 1)               goto close;
    if (memcmp(cfg.magic, CONFIG_MAGIC, 4) != 0)              goto close;
    if (cfg.version != CONFIG_VERSION)                        goto close;

    snprintf(g.host,     sizeof(g.host),     "%s", cfg.host);
    snprintf(g.port,     sizeof(g.port),     "%s", cfg.port);
    snprintf(g.username, sizeof(g.username), "%s", cfg.username);
    snprintf(g.pin,      sizeof(g.pin),      "%s", cfg.pin);
    ti_Close(fh);
    return;

close:
    ti_Close(fh);
defaults:
    snprintf(g.host, sizeof(g.host), "%s", RELAY_DEFAULT_HOST);
    snprintf(g.port, sizeof(g.port), "%s", RELAY_DEFAULT_PORT);
    g.username[0] = '\0';
    g.pin[0]      = '\0';
}

static void config_save(void)
{
    struct saved_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.magic, CONFIG_MAGIC, 4);
    cfg.version = CONFIG_VERSION;
    snprintf(cfg.host,     sizeof(cfg.host),     "%s", g.host);
    snprintf(cfg.port,     sizeof(cfg.port),     "%s", g.port);
    snprintf(cfg.username, sizeof(cfg.username), "%s", g.username);
    snprintf(cfg.pin,      sizeof(cfg.pin),      "%s", g.pin);

    uint8_t fh = ti_Open(CONFIG_APPVAR, "w");
    if (!fh) return;
    ti_Write(&cfg, sizeof(cfg), 1, fh);
    ti_SetArchiveStatus(true, fh);
    ti_Close(fh);
}

/* ---------------------------------------------------------------------- */
/* Transcript ring                                                         */
/* ---------------------------------------------------------------------- */

static void ring_push(const char *text, uint8_t color)
{
    g.ring.head = (uint8_t)((g.ring.head + 1u) % RING_LINES);
    snprintf(g.ring.rows[g.ring.head], RING_ROW, "%s", text ? text : "");
    g.ring.colors[g.ring.head] = color;
    if (g.ring.count < RING_LINES) g.ring.count++;
}

/* Word-wrap one logical message (prefix + body) into CHAT_COLS rows and
 * push each onto the ring.  Long words are hard-broken. */
static void ring_push_msg(const char *prefix, const char *text,
                          size_t text_len, uint8_t color)
{
    bool first = true;
    size_t remain = text_len;
    const char *src = text;

    while (remain > 0 || first)
    {
        char row[RING_ROW];
        const char *p    = first ? (prefix ? prefix : "") : "";
        size_t plen      = strlen(p);
        size_t avail     = plen < CHAT_COLS ? CHAT_COLS - plen : 0;
        size_t take      = remain > avail ? avail : remain;

        /* try to break at a space */
        if (take < remain && take > 0)
        {
            size_t last_sp = 0;
            for (size_t i = 0; i < take; i++)
                if (src[i] == ' ') last_sp = i;
            if (last_sp > 0) take = last_sp;
        }

        snprintf(row, sizeof(row), "%s%.*s", p, (int)take, src ? src : "");
        ring_push(row, color);

        first = false;
        if (take >= remain) break;

        src    += take;
        remain -= take;
        while (remain > 0 && *src == ' ') { src++; remain--; }
    }
}

/* ---------------------------------------------------------------------- */
/* Chat helpers (append to ring + mark redraw)                            */
/* ---------------------------------------------------------------------- */

static void chat_sys(const char *text)
{
    ring_push_msg("* ", text, strlen(text), COL_SYSTEM);
    g.need_trans_redraw = true;
}

static void chat_sysf(const char *fmt, ...)
{
    char buf[80];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    chat_sys(buf);
}

static void chat_msg(const char *author, const char *text)
{
    char prefix[USER_MAX + 4];
    snprintf(prefix, sizeof(prefix), "<%s> ", author);
    ring_push_msg(prefix, text, strlen(text), COL_RECV);
    g.need_trans_redraw = true;
}

static void chat_sent(const char *text)
{
    ring_push_msg("> ", text, strlen(text), COL_SENT);
    g.need_trans_redraw = true;
}

static void chat_err(const char *text)
{
    ring_push_msg("! ", text, strlen(text), COL_ERROR);
    g.need_trans_redraw = true;
}

static void chat_errf(const char *fmt, ...)
{
    char buf[80];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    chat_err(buf);
}

/* ---------------------------------------------------------------------- */
/* Channel list helpers                                                    */
/* ---------------------------------------------------------------------- */

static void channels_clear(void)
{
    g.chan_count = 0;
    g.chan_sel   = 0;
    g.need_sidebar_redraw = true;
}

static void channel_add(const char *name)
{
    if (g.chan_count >= MAX_CHANNELS) return;
    snprintf(g.channels[g.chan_count].name,
             sizeof(g.channels[g.chan_count].name), "%s", name);
    g.channels[g.chan_count].unread = false;
    g.chan_count++;
}

/* Parse "RELAY_CHAN #ch1,#ch2,..." and populate channel list. */
static void parse_chan_list(const char *list)
{
    channels_clear();
    const char *p = list;
    while (*p)
    {
        if (*p == '#') p++;
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len > 0 && g.chan_count < MAX_CHANNELS)
        {
            char name[CHAN_NAME_MAX];
            size_t take = len < sizeof(name) - 1 ? len : sizeof(name) - 1;
            memcpy(name, p, take);
            name[take] = '\0';
            channel_add(name);
        }
        if (!comma) break;
        p = comma + 1;
    }
    g.need_sidebar_redraw = true;
}

/* Find channel index by name (without '#'). Returns MAX_CHANNELS if not found. */
static uint8_t channel_find(const char *name)
{
    for (uint8_t i = 0; i < g.chan_count; i++)
        if (strcmp(g.channels[i].name, name) == 0) return i;
    return MAX_CHANNELS;
}

/* ---------------------------------------------------------------------- */
/* Draw primitives                                                         */
/* ---------------------------------------------------------------------- */

static void draw_fill(int x, int y, int w, int h, uint8_t color)
{
    gfx_SetColor(color);
    gfx_FillRectangle(x, y, w, h);
}

static void draw_text(int x, int y, uint8_t fg, uint8_t bg, const char *text)
{
    gfx_SetTextFGColor(fg);
    gfx_SetTextBGColor(bg);
    gfx_PrintStringXY(text, x, y);
}

/* Erase a full-width area of the chat column at given y, h pixels. */
static void erase_chat_row(int y)
{
    draw_fill(CHAT_X, y, CHAT_W, FONT_H, COL_BG);
}

/* ---------------------------------------------------------------------- */
/* Title bar                                                               */
/* ---------------------------------------------------------------------- */

static void draw_title(void)
{
    /* Sidebar label */
    draw_fill(SIDEBAR_X, TITLE_Y, SIDEBAR_W, TITLE_H, COL_TITLE_BG);
    draw_text(SIDEBAR_X + 2, TITLE_Y, COL_TITLE_FG, COL_TITLE_BG, "Channels");

    /* Divider header */
    draw_fill(DIVIDER_X, TITLE_Y, DIVIDER_W, LCD_H, COL_DIVIDER);

    /* Chat title: "#channel | username" */
    draw_fill(CHAT_X, TITLE_Y, CHAT_W, TITLE_H, COL_TITLE_BG);
    char title[CHAT_COLS + 1];
    if (g.active_name[0])
        snprintf(title, sizeof(title), "#%s | %s", g.active_name, g.username);
    else
        snprintf(title, sizeof(title), "Discord | %s", g.username);
    draw_text(CHAT_X + 2, TITLE_Y, COL_TITLE_FG, COL_TITLE_BG, title);
}

/* ---------------------------------------------------------------------- */
/* Sidebar                                                                 */
/* ---------------------------------------------------------------------- */

static void draw_sidebar(void)
{
    /* Clear sidebar content area */
    draw_fill(SIDEBAR_X, CONTENT_Y, SIDEBAR_W, CONTENT_H, COL_BG);

    for (uint8_t i = 0; i < g.chan_count && i < SIDEBAR_ROWS; i++)
    {
        int y = CONTENT_Y + i * FONT_H;
        bool selected = (i == g.chan_sel);
        bool active   = (i == g.chan_active);

        uint8_t bg = selected ? COL_CHAN_SEL : COL_BG;
        uint8_t fg = g.channels[i].unread ? COL_UNREAD : COL_CHAN_FG;
        if (selected) fg = COL_TITLE_FG;

        draw_fill(SIDEBAR_X, y, SIDEBAR_W, FONT_H, bg);

        /* "#name" truncated to 7 chars (64px / 8px - 1 for '#') */
        char label[9];
        snprintf(label, sizeof(label), "#%.7s", g.channels[i].name);
        draw_text(SIDEBAR_X + 2, y, fg, bg, label);

        /* Active channel marker: '*' on right edge */
        if (active)
        {
            gfx_SetTextFGColor(COL_SENT);
            gfx_SetTextBGColor(bg);
            gfx_PrintStringXY("*", SIDEBAR_X + SIDEBAR_W - FONT_W - 2, y);
        }
    }
    g.need_sidebar_redraw = false;
}

/* ---------------------------------------------------------------------- */
/* Transcript                                                              */
/* ---------------------------------------------------------------------- */

static void draw_transcript_full(void)
{
    uint8_t visible = g.ring.count < TRANS_ROWS ? g.ring.count : TRANS_ROWS;
    uint8_t blank   = (uint8_t)(TRANS_ROWS - visible);

    /* blank rows at top */
    for (uint8_t i = 0; i < blank; i++)
    {
        erase_chat_row(TRANS_Y + i * FONT_H);
        g.ring.shown[i][0] = '\0';
    }

    for (uint8_t i = 0; i < visible; i++)
    {
        uint8_t ri = (uint8_t)((g.ring.head + RING_LINES - (visible - 1u - i))
                                % RING_LINES);
        uint8_t row = (uint8_t)(blank + i);
        int y = TRANS_Y + row * FONT_H;
        const char *line = g.ring.rows[ri];
        uint8_t color = g.ring.colors[ri];

        erase_chat_row(y);
        gfx_SetTextFGColor(color);
        gfx_SetTextBGColor(COL_BG);
        gfx_PrintStringXY(line, CHAT_X + 2, y);
        snprintf(g.ring.shown[row], RING_ROW, "%s", line);
    }

    g.ring.shown_valid  = TRANS_ROWS;
    g.need_trans_redraw = false;
}

static void draw_transcript_diff(void)
{
    uint8_t visible = g.ring.count < TRANS_ROWS ? g.ring.count : TRANS_ROWS;
    uint8_t blank   = (uint8_t)(TRANS_ROWS - visible);

    for (uint8_t i = 0; i < visible; i++)
    {
        uint8_t ri = (uint8_t)((g.ring.head + RING_LINES - (visible - 1u - i))
                                % RING_LINES);
        uint8_t row = (uint8_t)(blank + i);
        int y = TRANS_Y + row * FONT_H;
        const char *line = g.ring.rows[ri];

        if (row < g.ring.shown_valid &&
            strcmp(g.ring.shown[row], line) == 0)
            continue;

        erase_chat_row(y);
        gfx_SetTextFGColor(g.ring.colors[ri]);
        gfx_SetTextBGColor(COL_BG);
        gfx_PrintStringXY(line, CHAT_X + 2, y);
        snprintf(g.ring.shown[row], RING_ROW, "%s", line);
    }
    g.ring.shown_valid  = TRANS_ROWS;
    g.need_trans_redraw = false;
}

/* ---------------------------------------------------------------------- */
/* Input area                                                              */
/* ---------------------------------------------------------------------- */

static void draw_input(void)
{
    /* Erase input rows */
    draw_fill(CHAT_X, INPUT_Y, CHAT_W, INPUT_H, COL_BG);

    /* Mode indicator char */
    char prompt[3];
    switch (g.input_upper_once ? MODE_UPPER : g.input_mode)
    {
    case MODE_UPPER:   prompt[0] = 'A'; break;
    case MODE_NUMERIC: prompt[0] = '0'; break;
    default:           prompt[0] = 'a'; break;
    }
    prompt[1] = ' ';
    prompt[2] = '\0';

    /* Build display string "a <input>" — truncate to fit two rows */
    char display[INPUT_BUF_MAX + 3];
    snprintf(display, sizeof(display), "%s%s", prompt, g.input);

    /* Print up to two rows */
    size_t total = strlen(display);
    size_t col1  = total > CHAT_COLS ? CHAT_COLS : total;
    char row1[CHAT_COLS + 1];
    snprintf(row1, sizeof(row1), "%.*s", (int)col1, display);
    gfx_SetTextFGColor(COL_FG);
    gfx_SetTextBGColor(COL_BG);
    gfx_PrintStringXY(row1, CHAT_X + 2, INPUT_Y);

    if (total > CHAT_COLS)
    {
        char row2[CHAT_COLS + 1];
        snprintf(row2, sizeof(row2), "%.*s", (int)CHAT_COLS,
                 display + CHAT_COLS);
        gfx_PrintStringXY(row2, CHAT_X + 2, INPUT_Y + FONT_H);
    }

    g.need_input_redraw = false;
}

/* ---------------------------------------------------------------------- */
/* Full screen redraw                                                      */
/* ---------------------------------------------------------------------- */

static void draw_all(void)
{
    gfx_SetColor(COL_BG);
    gfx_FillScreen(COL_BG);

    draw_title();
    draw_sidebar();
    draw_transcript_full();
    draw_input();
    gfx_BlitBuffer();

    g.need_full_redraw    = false;
    g.need_sidebar_redraw = false;
    g.need_trans_redraw   = false;
    g.need_input_redraw   = false;
}

/* Incremental update — only repaint what's dirty. */
static void draw_update(void)
{
    if (g.need_full_redraw) { draw_all(); return; }
    if (g.need_sidebar_redraw) draw_sidebar();
    if (g.need_trans_redraw)   draw_transcript_diff();
    if (g.need_input_redraw)   draw_input();
    gfx_BlitBuffer();
}

/* ---------------------------------------------------------------------- */
/* RX: parse lines from the relay                                          */
/* ---------------------------------------------------------------------- */

static void relay_handle_line(const char *line)
{
    if (strcmp(line, "OK") == 0)
    {
        g.authed = true;
        chat_sysf("authed as %s", g.username);
        return;
    }

    if (strcmp(line, "DENIED") == 0)
    {
        chat_err("auth denied");
        g.done = true;
        return;
    }

    if (strncmp(line, "RELAY_CHAN ", 11) == 0)
    {
        parse_chan_list(line + 11);
        return;
    }

    if (strncmp(line, "RELAY_ACTIVE ", 13) == 0)
    {
        const char *name = line + 13;
        if (*name == '#') name++;
        snprintf(g.active_name, sizeof(g.active_name), "%s", name);

        uint8_t idx = channel_find(name);
        if (idx < g.chan_count)
        {
            g.chan_active = idx;
            g.chan_sel    = idx;
            g.channels[idx].unread = false;
        }
        draw_title();
        g.need_sidebar_redraw = true;
        return;
    }

    if (strncmp(line, "MSG ", 4) == 0)
    {
        const char *rest = line + 4;
        const char *sep  = strchr(rest, ':');
        if (sep && sep > rest && sep[1] == ' ')
        {
            char author[USER_MAX + 1];
            size_t alen = (size_t)(sep - rest);
            if (alen >= sizeof(author)) alen = sizeof(author) - 1;
            memcpy(author, rest, alen);
            author[alen] = '\0';
            chat_msg(author, sep + 2);
        }
        else
        {
            chat_msg("?", rest);
        }
        return;
    }

    if (strncmp(line, "SYS ", 4) == 0)
    {
        chat_sys(line + 4);
        return;
    }
}

static void relay_on_readable(void)
{
    uint8_t tmp[128];
    while (lwip_socket_available(&g.sock))
    {
        size_t got = lwip_socket_read(&g.sock, tmp, sizeof(tmp));
        for (size_t i = 0; i < got; i++)
        {
            char c = (char)tmp[i];
            if (c == '\n')
            {
                if (g.rx_len > 0 && g.rx_buf[g.rx_len - 1] == '\r')
                    g.rx_len--;
                g.rx_buf[g.rx_len] = '\0';
                relay_handle_line(g.rx_buf);
                g.rx_len = 0;
            }
            else if (g.rx_len + 1 < RX_MAX)
            {
                g.rx_buf[g.rx_len++] = c;
            }
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Socket TX helpers                                                       */
/* ---------------------------------------------------------------------- */

static void relay_writef(const char *fmt, ...)
{
    char buf[256];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < sizeof(buf))
        lwip_socket_write(&g.sock, (const uint8_t *)buf, (size_t)n);
}

static void relay_send_auth(void)
{
    relay_writef("AUTH %s %s\n", g.username, g.pin);
}

static void relay_send_text(const char *text)
{
    relay_writef("SEND %s\n", text);
}

static void relay_switch_chan(const char *name)
{
    relay_writef("CHAN #%s\n", name);
}

/* ---------------------------------------------------------------------- */
/* Socket event callback                                                   */
/* ---------------------------------------------------------------------- */

static void relay_on_event(struct lwip_socket *sock,
                           lwip_socket_event_type_t type,
                           const void *ev_data, void *arg)
{
    (void)sock; (void)arg;
    switch (type)
    {
    case LWIP_SOCKET_EV_STATE_CHANGE:
    {
        const lwip_socket_state_data_t *st = ev_data;
        if (st->current == LWIP_STATUS_RESOLVING)
            chat_sys("resolving...");
        else if (st->current == LWIP_STATUS_CONNECTING)
            chat_sys("connecting...");
        else if (st->current == LWIP_STATUS_CONNECTED)
        {
            chat_sys("TLS ok");
            g.connected = true;
            relay_send_auth();
        }
        else if (st->current == LWIP_STATUS_CLOSED ||
                 st->current == LWIP_STATUS_RESET)
        {
            g.done = true;
        }
        break;
    }
    case LWIP_SOCKET_EV_ERROR:
    {
        const lwip_socket_error_data_t *e = ev_data;
        g.last_err = e->err;
        g.done     = true;
        chat_errf("err %d", (int)e->err);
        break;
    }
    case LWIP_SOCKET_EV_IO:
    {
        const lwip_socket_io_data_t *io = ev_data;
        if (io->flags & LWIP_SOCKET_IO_READABLE)
            relay_on_readable();
        break;
    }
    default: break;
    }
}

/* ---------------------------------------------------------------------- */
/* Input handling                                                          */
/* ---------------------------------------------------------------------- */

static void input_handle_key(uint8_t key)
{
    if (key == sk_Alpha)
    {
        g.input_mode       = (uint8_t)((g.input_mode + 1u) % 3u);
        g.input_upper_once = false;
        g.need_input_redraw = true;
        return;
    }
    if (key == sk_2nd)
    {
        g.input_upper_once  = true;
        g.need_input_redraw = true;
        return;
    }
    if (key == sk_Del)
    {
        if (g.input_len > 0)
        {
            g.input[--g.input_len] = '\0';
            g.need_input_redraw = true;
        }
        return;
    }
    if (key == sk_Clear)
    {
        g.input_len = 0;
        g.input[0]  = '\0';
        g.need_input_redraw = true;
        return;
    }
    if (key == sk_Enter)
    {
        if (g.input_len == 0 || !g.authed) return;
        char msg[INPUT_BUF_MAX];
        size_t mlen = g.input_len;
        memcpy(msg, g.input, mlen);
        msg[mlen]   = '\0';
        g.input_len = 0;
        g.input[0]  = '\0';
        g.need_input_redraw = true;
        relay_send_text(msg);
        chat_sent(msg);
        return;
    }
    /* Up/Down: navigate channel list */
    if (key == sk_Up && g.chan_count > 0)
    {
        g.chan_sel = (uint8_t)((g.chan_sel + g.chan_count - 1u) % g.chan_count);
        g.need_sidebar_redraw = true;
        return;
    }
    if (key == sk_Down && g.chan_count > 0)
    {
        g.chan_sel = (uint8_t)((g.chan_sel + 1u) % g.chan_count);
        g.need_sidebar_redraw = true;
        return;
    }
    /* Right: switch to highlighted channel */
    if (key == sk_Right && g.chan_count > 0 && g.chan_sel != g.chan_active)
    {
        /* Clear transcript for the new channel */
        memset(&g.ring, 0, sizeof(g.ring));
        g.need_full_redraw = true;
        relay_switch_chan(g.channels[g.chan_sel].name);
        return;
    }

    /* Printable character */
    uint8_t mode = g.input_upper_once ? MODE_UPPER : g.input_mode;
    char c = key_to_char(key, mode);
    if (c && g.input_len + 1 < INPUT_BUF_MAX)
    {
        g.input[g.input_len++] = c;
        g.input[g.input_len]   = '\0';
        if (g.input_upper_once) g.input_upper_once = false;
        g.need_input_redraw = true;
    }
}

/* ---------------------------------------------------------------------- */
/* Setup screen                                                            */
/* ---------------------------------------------------------------------- */

/* Print a text field row in setup context using lwip_example_line* */
static void setup_field_row(bool active, const char *label,
                            const char *value, bool hidden, const char *hint)
{
    if (active)
        lwip_example_linef("> %s  (%s)", label, hint);
    else
        lwip_example_linef("  %s", label);

    if (hidden)
    {
        size_t n = strlen(value);
        char stars[PIN_MAX + 1];
        if (n >= sizeof(stars)) n = sizeof(stars) - 1;
        memset(stars, '*', n);
        stars[n] = '\0';
        lwip_example_line_wrapped(stars);
    }
    else
    {
        lwip_example_line_wrapped(value);
    }
    lwip_example_line("");
}

static void setup_render(void)
{
    const char *hint;
    switch (g.setup_input_mode)
    {
    case MODE_UPPER:   hint = "ABC"; break;
    case MODE_NUMERIC: hint = "123"; break;
    default:           hint = "abc"; break;
    }

    lwip_example_clear();
    lwip_example_line("=== Discord Relay ===");
    lwip_example_line("");
    setup_field_row(g.setup_field == SF_HOST, "relay host:", g.host,
                    false, hint);
    setup_field_row(g.setup_field == SF_PORT, "port:", g.port,
                    false, "123");
    setup_field_row(g.setup_field == SF_USER, "username:", g.username,
                    false, hint);
    setup_field_row(g.setup_field == SF_PIN, "PIN:", g.pin,
                    true, "123");
    lwip_example_line("Enter: next/connect  Clear: exit");
    lwip_example_draw_mem_stats();
    lwip_example_present();
}

static char *setup_active(size_t *cap)
{
    switch (g.setup_field)
    {
    case SF_PORT: *cap = sizeof(g.port);     return g.port;
    case SF_USER: *cap = sizeof(g.username); return g.username;
    case SF_PIN:  *cap = sizeof(g.pin);      return g.pin;
    default:      *cap = sizeof(g.host);     return g.host;
    }
}

static bool setup_append(char c)
{
    if (g.setup_field == SF_PORT && !isdigit((unsigned char)c)) return false;
    if (g.setup_field == SF_PIN  && !isdigit((unsigned char)c)) return false;
    if (c == ' ' || !c) return false;

    size_t cap;
    char *buf = setup_active(&cap);
    size_t len = strlen(buf);
    if (len + 1 >= cap) return false;
    buf[len++] = c;
    buf[len]   = '\0';
    return true;
}

static bool setup_backspace(void)
{
    size_t cap;
    char *buf = setup_active(&cap);
    (void)cap;
    size_t len = strlen(buf);
    if (!len) return false;
    buf[len - 1] = '\0';
    return true;
}

static bool setup_run(void)
{
    g.setup_field      = SF_HOST;
    g.setup_input_mode = MODE_LOWER;
    bool redraw = true;

    while (true)
    {
        lwip_service_events();
        uint8_t key = os_GetCSC();
        if (lwip_example_mem_stats_tick(key)) redraw = true;

        if (key == sk_Clear) return false;

        if (key == sk_Alpha)
        {
            if (g.setup_field != SF_PORT && g.setup_field != SF_PIN)
            {
                g.setup_input_mode = (uint8_t)((g.setup_input_mode + 1u) % 3u);
                redraw = true;
            }
        }
        else if (key == sk_Up)
        {
            g.setup_field = (setup_field_t)
                ((g.setup_field + SF_COUNT - 1u) % SF_COUNT);
            redraw = true;
        }
        else if (key == sk_Down)
        {
            g.setup_field = (setup_field_t)((g.setup_field + 1u) % SF_COUNT);
            redraw = true;
        }
        else if (key == sk_Del)
        {
            redraw = setup_backspace() || redraw;
        }
        else if (key == sk_Enter)
        {
            if (g.setup_field < SF_PIN)
            {
                g.setup_field = (setup_field_t)(g.setup_field + 1);
                redraw = true;
            }
            else
            {
                if (!g.host[0])
                    snprintf(g.host, sizeof(g.host), "%s", RELAY_DEFAULT_HOST);
                if (!g.port[0])
                    snprintf(g.port, sizeof(g.port), "%s", RELAY_DEFAULT_PORT);
                if (g.host[0] && g.username[0] && g.pin[0])
                    return true;
                redraw = true;
            }
        }
        else
        {
            uint8_t mode = g.setup_input_mode;
            char c = key_to_char(key, mode);
            redraw = setup_append(c) || redraw;
        }

        if (redraw) { setup_render(); redraw = false; }
    }
}

/* ---------------------------------------------------------------------- */
/* Connection                                                              */
/* ---------------------------------------------------------------------- */

static bool relay_connect(void)
{
    uint16_t port = (uint16_t)atoi(g.port);
    if (!port) port = 8443;

    memset(&g.sock, 0, sizeof(g.sock));
    lwip_error_t e = lwip_socket_create(&g.sock, LWIP_SOCKET_ALTCP_TLS,
                                        LWIP_NETIF_EXT, NULL,
                                        RELAY_CONNECT_TIMEOUT_MS);
    if (e != LWIP_OK) { chat_errf("create:%d", (int)e); return false; }

    lwip_socket_on_event(&g.sock, LWIP_SOCKET_EVENTF_ALL,
                         relay_on_event, NULL);

    e = lwip_socket_connect(&g.sock, g.host, port);
    if (e != LWIP_OK)
    {
        chat_errf("connect:%d", (int)e);
        lwip_socket_destroy(&g.sock);
        return false;
    }
    return true;
}

static void relay_disconnect(void)
{
    if (lwip_socket_is_active(&g.sock))
    {
        lwip_socket_close(&g.sock);
        uint32_t t = lwip_now_ms() + 3000u;
        while (lwip_socket_is_active(&g.sock) && lwip_now_ms() < t)
            lwip_service_events();
    }
    lwip_socket_destroy(&g.sock);
}

/* ---------------------------------------------------------------------- */
/* Main chat loop                                                          */
/* ---------------------------------------------------------------------- */

static void relay_run(void)
{
    /* Initial draw */
    draw_all();

    while (!g.done)
    {
        lwip_service_events();

        uint8_t key = os_GetCSC();
        if (key == sk_Mode) { chat_sys("quit"); break; }

        if (key == sk_Stat)
        {
            lwip_example_mem_stats_tick(sk_Stat);
            g.need_full_redraw = true;
        }
        else if (key)
        {
            input_handle_key(key);
        }

        /* Redraw anything dirty */
        if (g.need_full_redraw || g.need_sidebar_redraw ||
            g.need_trans_redraw || g.need_input_redraw)
        {
            draw_update();
        }
    }
}

/* ---------------------------------------------------------------------- */
/* main                                                                    */
/* ---------------------------------------------------------------------- */

int main(void)
{
    lwip_example_gfx_start();
    lwip_example_show("Discord Relay", NULL);

    if (!lwip_start())
    {
        lwip_example_show_and_wait("lwIP failed", NULL);
        lwip_example_gfx_stop();
        return 0;
    }
    lwip_example_gfx_blit_start();

    /* Wait for DHCP + DNS */
    {
        uint8_t flags = LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS;
        uint32_t t = lwip_now_ms() + 20000u;
        while (!lwip_are_services_ready(NULL, flags) && lwip_now_ms() < t)
            lwip_service_events();
        if (!lwip_are_services_ready(NULL, flags))
        {
            lwip_example_show_and_wait("net timeout", NULL);
            goto done;
        }
    }

    config_load();
    if (!setup_run()) goto done;
    config_save();

    /* Switch to custom layout — clear to bg color */
    gfx_SetColor(COL_BG);
    gfx_FillScreen(COL_BG);
    gfx_SetTextBGColor(COL_BG);
    gfx_SetTextTransparentColor(COL_BG);
    g.need_full_redraw = true;

    chat_sysf("connecting %s:%s...", g.host, g.port);

    if (!relay_connect())
    {
        draw_update();
        lwip_example_wait_key();
        goto done;
    }

    relay_run();
    relay_disconnect();

    if (g.last_err)
        chat_errf("closed (err %d)", (int)g.last_err);
    else
        chat_sys("disconnected");

    draw_update();
    lwip_example_wait_key();

done:
    lwip_stop();
    lwip_example_gfx_stop();
    return 0;
}
