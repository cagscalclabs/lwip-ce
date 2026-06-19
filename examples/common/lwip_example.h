#ifndef LWIP_EXAMPLE_H
#define LWIP_EXAMPLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <string.h>

#include <ti/getcsc.h>
#include <ti/getkey.h>
#include <graphx.h>

#include <lwip.h>

/* ----------------------------------------------------------------------
 * graphx text surface
 *
 * All example output draws into the graphx back buffer (gfx_SetDrawBuffer())
 * with the library's built-in 8x8 font, instead of the OS small font drawn
 * straight to the LCD. This gives every drawing call a real, clipped
 * rectangle-fill primitive for erasing (gfx_FillRectangle) instead of the
 * old approach of overdrawing with a blank text string and hoping its pixel
 * width covered whatever it was replacing.
 *
 * The back buffer is only made visible on screen by a periodic blit, driven
 * by a self-rearming sys_timeout (the only timer primitive exposed to dylib
 * consumers per the public API manifest -- no internal lwIP-CE dispatcher
 * access here). This decouples "when example code draws" from "when the
 * screen updates": app code can draw as often as it wants without tearing
 * or visible flicker, and a burst of redraws between two ticks collapses
 * into a single visible update.
 * -------------------------------------------------------------------- */

#define LWIP_EXAMPLE_TOP 4      /* first line y (px), below the status row */
#define LWIP_EXAMPLE_BOTTOM 240 /* last usable y (px); full LCD height      */
#define LWIP_EXAMPLE_LEFT 2     /* left margin (px)                         */
#define LWIP_EXAMPLE_LCD_W 320
#define LWIP_EXAMPLE_STATS_X 188
#define LWIP_EXAMPLE_STATS_LINES 6
#define LWIP_EXAMPLE_STATS_LOOP_INTERVAL 12
#define LWIP_EXAMPLE_BLIT_INTERVAL_MS 15u

#define LWIP_EXAMPLE_COLOR_BG     0xFF /* gfx_white */
#define LWIP_EXAMPLE_COLOR_FG     0x00 /* gfx_black */
#define LWIP_EXAMPLE_COLOR_SYSTEM 0x10 /* gfx_blue:   "* " system lines */
#define LWIP_EXAMPLE_COLOR_SENT   0x03 /* gfx_green:  "> " our own messages */
#define LWIP_EXAMPLE_COLOR_RECV   0x00 /* gfx_black:  "< " remote messages */
#define LWIP_EXAMPLE_COLOR_ERROR  0xE0 /* gfx_red:    errors/alerts */

static uint8_t lwip_example_row = LWIP_EXAMPLE_TOP;
static uint8_t lwip_example_stats_loop_count = 0;
static bool lwip_example_stack_running = false;
static bool lwip_example_gfx_running = false;
static bool lwip_example_blit_armed = false;

static void lwip_example_present(void);

static void lwip_example_blit_tick(void *arg)
{
    (void)arg;
    if (!lwip_example_gfx_running || !lwip_example_blit_armed)
    {
        return;
    }
    gfx_BlitBuffer();
    sys_timeout(LWIP_EXAMPLE_BLIT_INTERVAL_MS, lwip_example_blit_tick, NULL);
}

/* Brings up graphx and points it at the back buffer. Safe to call before
 * lwip_start() -- it touches no lwIP state. */
static void lwip_example_gfx_start(void)
{
    if (lwip_example_gfx_running)
    {
        return;
    }
    gfx_Begin();
    gfx_SetDefaultPalette(gfx_8bpp);
    gfx_SetDrawBuffer();
    gfx_FillScreen(LWIP_EXAMPLE_COLOR_BG);
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    gfx_SetTextBGColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_SetTextTransparentColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_BlitBuffer();
    lwip_example_gfx_running = true;
}

/* Arms the periodic blit. Must only be called after lwip_start() has run --
 * sys_timeout() writes into lwIP's timeout list, which sys_timeouts_init()
 * (called from inside lwip_start()) hasn't set up yet otherwise. Calling
 * this too early crashes instantly on hardware. */
static void lwip_example_gfx_blit_start(void)
{
    if (!lwip_example_gfx_running || lwip_example_blit_armed)
    {
        return;
    }
    lwip_example_blit_armed = true;
    sys_timeout(LWIP_EXAMPLE_BLIT_INTERVAL_MS, lwip_example_blit_tick, NULL);
}

static void lwip_example_gfx_stop(void)
{
    if (!lwip_example_gfx_running)
    {
        return;
    }
    if (lwip_example_blit_armed)
    {
        sys_untimeout(lwip_example_blit_tick, NULL);
        lwip_example_blit_armed = false;
    }
    lwip_example_gfx_running = false;
    gfx_End();
}

static uint8_t lwip_example_line_h(void)
{
    return 8;
}

static void lwip_example_stats_invalidate(void);

/* Clear the back buffer and reset the cursor to the top. */
static void lwip_example_clear(void)
{
    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillScreen(LWIP_EXAMPLE_COLOR_BG);
    lwip_example_row = LWIP_EXAMPLE_TOP;
    lwip_example_stats_invalidate();
}

/* Draw one line at the current row and advance. Wraps to the top (clearing)
 * when the next line would run off the bottom. */
static void lwip_example_line(const char *text)
{
    uint8_t h = lwip_example_line_h();
    if ((unsigned)lwip_example_row + h > LWIP_EXAMPLE_BOTTOM)
    {
        lwip_example_clear();
        h = lwip_example_line_h();
    }
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    gfx_PrintStringXY(text ? text : "", LWIP_EXAMPLE_LEFT, lwip_example_row);
    lwip_example_row = (uint8_t)(lwip_example_row + h);
}

/* printf-style line. */
#define lwip_example_linef(...)                        \
    do                                                 \
    {                                                  \
        char _lebuf[64];                               \
        snprintf(_lebuf, sizeof(_lebuf), __VA_ARGS__); \
        lwip_example_line(_lebuf);                     \
    } while (0)

static unsigned lwip_example_pct(size_t used, size_t total)
{
    if (total == 0)
    {
        return 0;
    }
    if (used > total)
    {
        used = total;
    }
    return (unsigned)((used * 100u) / total);
}

static void lwip_example_format_k(char *buf, size_t buf_len, size_t bytes)
{
    unsigned whole = (unsigned)(bytes / 1024u);
    unsigned tenth = (unsigned)(((bytes % 1024u) * 10u) / 1024u);
    snprintf(buf, buf_len, "%u.%uK", whole, tenth);
}

static void lwip_example_stats_erase_row(uint8_t y)
{
    /* Stats text is right-aligned to LWIP_EXAMPLE_LCD_W, so the erase must
     * span the full row from LWIP_EXAMPLE_STATS_X to the screen edge. A
     * real rect fill, so there's no font-metric guessing about coverage. */
    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillRectangle(LWIP_EXAMPLE_STATS_X, y,
                      LWIP_EXAMPLE_LCD_W - LWIP_EXAMPLE_STATS_X,
                      lwip_example_line_h());
}

static void lwip_example_stats_invalidate(void)
{
}

static void lwip_example_stats_line(uint8_t y, const char *text)
{
    int width;

    lwip_example_stats_erase_row(y);
    width = (int)gfx_GetStringWidth(text);
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    gfx_PrintStringXY(text, LWIP_EXAMPLE_LCD_W - 2 - width, y);
}

static bool lwip_example_stats_visible = false;

static void lwip_example_draw_mem_stats(void)
{
    if (!lwip_example_stats_visible)
        return;
    struct mem_accounting_stats stats;
    char used[12];
    char total[12];
    char line[32];
    uint8_t h;
    uint8_t y;
    size_t h_limit;

    if (!mem_get_stats(&stats))
    {
        return;
    }

    h = lwip_example_line_h();
    y = (uint8_t)(LWIP_EXAMPLE_BOTTOM - (h * LWIP_EXAMPLE_STATS_LINES));

    lwip_example_format_k(used, sizeof(used), stats.pbuf_pool_used);
    lwip_example_format_k(total, sizeof(total), stats.pbuf_pool_size);
    snprintf(line, sizeof(line), "P:%s/%s %u%%", used, total,
             lwip_example_pct(stats.pbuf_pool_used, stats.pbuf_pool_size));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    lwip_example_format_k(used, sizeof(used), stats.tls_used);
    lwip_example_format_k(total, sizeof(total), stats.tls_limit);
    snprintf(line, sizeof(line), "T:%s/%s %u%%", used, total,
             lwip_example_pct(stats.tls_used, stats.tls_limit));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    h_limit = stats.heap_limit;
    lwip_example_format_k(used, sizeof(used), stats.heap_used);
    lwip_example_format_k(total, sizeof(total), h_limit);
    snprintf(line, sizeof(line), "H:%s/%s %u%%", used, total,
             lwip_example_pct(stats.heap_used, h_limit));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    lwip_example_format_k(used, sizeof(used), stats.rx_ring_used);
    lwip_example_format_k(total, sizeof(total), stats.rx_ring_size);
    snprintf(line, sizeof(line), "R:%s/%s %u%%", used, total,
             lwip_example_pct(stats.rx_ring_used, stats.rx_ring_size));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    lwip_example_format_k(used, sizeof(used), stats.socket_ring_used);
    lwip_example_format_k(total, sizeof(total), stats.socket_ring_size);
    snprintf(line, sizeof(line), "C:%s/%s %u%%", used, total,
             lwip_example_pct(stats.socket_ring_used, stats.socket_ring_size));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    lwip_example_format_k(used, sizeof(used), stats.user_reserved);
    snprintf(line, sizeof(line), "U:%s", used);
    lwip_example_stats_line(y, line);
}

static bool lwip_example_stats_toggle(void)
{
    lwip_example_stats_visible = !lwip_example_stats_visible;
    if (!lwip_example_stats_visible)
    {
        /* Erase the stats area by blanking those rows */
        uint8_t h = lwip_example_line_h();
        uint8_t y = (uint8_t)(LWIP_EXAMPLE_BOTTOM - (h * LWIP_EXAMPLE_STATS_LINES));
        uint8_t i;
        for (i = 0; i < LWIP_EXAMPLE_STATS_LINES; i++)
        {
            lwip_example_stats_erase_row(y);
            y = (uint8_t)(y + h);
        }
        lwip_example_stats_invalidate();
        lwip_example_present();
        return true;
    }
    else
    {
        lwip_example_stats_invalidate();
        lwip_example_draw_mem_stats();
        lwip_example_present();
        return false;
    }
}

static void lwip_example_stats_redraw_tick(void)
{
    if (!lwip_example_stats_visible)
        return;
    if (++lwip_example_stats_loop_count >= LWIP_EXAMPLE_STATS_LOOP_INTERVAL)
    {
        lwip_example_stats_loop_count = 0;
        lwip_example_draw_mem_stats();
        lwip_example_present();
    }
}

static bool lwip_example_mem_stats_tick(uint8_t key)
{
    if (key == sk_Stat)
    {
        return lwip_example_stats_toggle();
    }
    lwip_example_stats_redraw_tick();
    return false;
}

/* Make whatever's been drawn into the back buffer actually visible right
 * now. The periodic blit timer (armed once lwip_start() has initialized
 * lwIP's timeout list -- see lwip_example_gfx_blit_start()) covers steady
 * -state rendering, but anything drawn before that point, or right before
 * a blocking os_GetKey() wait, needs an immediate manual blit or the user
 * never sees it. */
static void lwip_example_present(void)
{
    if (lwip_example_gfx_running)
    {
        gfx_BlitBuffer();
    }
}

static void lwip_example_wait_key(void)
{
    lwip_example_line("");
    lwip_example_line("Press any key");
    lwip_example_present();
    os_GetKey();
}

/* Clear and show a title line (+ optional second line). */
static void lwip_example_show(const char *line1, const char *line2)
{
    lwip_example_clear();
    lwip_example_line(line1);
    if (line2)
    {
        lwip_example_line(line2);
    }
    lwip_example_present();
}

static void lwip_example_show_and_wait(const char *line1, const char *line2)
{
    lwip_example_show(line1, line2);
    if (lwip_example_stack_running)
    {
        lwip_example_draw_mem_stats();
    }
    lwip_example_wait_key();
}

/* Print a (possibly multi-line) text buffer, breaking on CRLF / LF so HTTP
 * header lines land on their own rows instead of rendering the \r\n bytes as
 * stray glyphs. \r is swallowed; \n ends a line; any other non-printable byte
 * becomes '.'. Each output line is length-bounded to the text surface. */
static void lwip_example_lines_crlf(const char *text, size_t len)
{
    char line[44];
    size_t col = 0;
    size_t i;

    if (!text)
    {
        return;
    }
    for (i = 0; i < len; i++)
    {
        char c = text[i];

        if (c == '\r')
        {
            continue; /* part of CRLF; the \n ends the line */
        }
        if (c == '\n' || col + 1 >= sizeof(line))
        {
            line[col] = '\0';
            lwip_example_line(line);
            col = 0;
            if (c == '\n')
            {
                continue;
            }
        }
        line[col++] = (c >= 32 && c <= 126) ? c : '.';
    }
    if (col > 0)
    {
        line[col] = '\0';
        lwip_example_line(line);
    }
}

/* ----------------------------------------------------------------------
 * Chat console
 *
 * Nonblocking, incrementally-redrawn chat surface for live examples.
 *
 * The transcript is a ring buffer of already-wrapped display rows (not a
 * raw character stream): appending a message wraps it into 1+ fixed-width
 * rows and pushes each onto the ring head, evicting from the tail once full.
 * This makes appends O(wrapped rows) instead of O(buffer size), and means a
 * redraw never has to re-wrap the whole transcript from scratch. Each ring
 * row also carries a color tag (system/sent/received/error) set at append
 * time, so e.g. "* connected" and "< someone: hi" render in different colors
 * without any extra bookkeeping at render time.
 *
 * The input area is pinned to the bottom of the screen and grows upward:
 * the transcript/input boundary only moves (and forces a one-time full
 * repaint of the rows above it) when the input's wrapped row count changes.
 * Otherwise, only the on-screen rows whose backing content actually changed
 * since the last render get redrawn (mirroring the per-row diff cache the
 * stats panel already uses) -- no full-screen clear per message. That full
 * clear is reserved for chat_begin()'s first paint and for input-height
 * transitions, both rare compared to message volume.
 * -------------------------------------------------------------------- */

#define LWIP_EXAMPLE_CHAT_COLS 42
#define LWIP_EXAMPLE_CHAT_LINES 27
#define LWIP_EXAMPLE_CHAT_INPUT 88
#define LWIP_EXAMPLE_CHAT_INPUT_ROWS 3

typedef enum
{
    LWIP_EXAMPLE_CHAT_MODE_LOWER = 0,
    LWIP_EXAMPLE_CHAT_MODE_UPPER,
    LWIP_EXAMPLE_CHAT_MODE_NUMERIC,
} lwip_example_chat_input_mode_t;

static char key_to_char(uint8_t key, uint8_t mode)
{
    static const char ascii_mapping[3][38] = {
        "\"wrmh\0\0?\0vqlg\0\0.zupkfc\0 ytojeb\0\0xsnida",
        "\"WRMH\0\0?\0VQLG\0\0:ZUPKFC\0 YTOJEB\0\0XSNIDA",
        ("+-*/^\0\0?369)\0\0\0.258(\0\0\0"
         "0147,")};

    if (mode > LWIP_EXAMPLE_CHAT_MODE_NUMERIC || key < 0x0A || key > 0x2F)
    {
        return '\0';
    }
    return ascii_mapping[mode][key - 0x0A];
}

/* Message class -> color tag, applied to a whole logical message (and thus
 * to every wrapped row it produces). */
typedef enum
{
    LWIP_EXAMPLE_CHAT_CLASS_RECV = 0, /* "< " remote messages, default color */
    LWIP_EXAMPLE_CHAT_CLASS_SYSTEM,   /* "* " connection/status lines */
    LWIP_EXAMPLE_CHAT_CLASS_SENT,     /* "> " our own messages */
    LWIP_EXAMPLE_CHAT_CLASS_ERROR,    /* failures/alerts */
} lwip_example_chat_class_t;

static uint8_t lwip_example_chat_class_color(lwip_example_chat_class_t cls)
{
    switch (cls)
    {
    case LWIP_EXAMPLE_CHAT_CLASS_SYSTEM: return LWIP_EXAMPLE_COLOR_SYSTEM;
    case LWIP_EXAMPLE_CHAT_CLASS_SENT:   return LWIP_EXAMPLE_COLOR_SENT;
    case LWIP_EXAMPLE_CHAT_CLASS_ERROR:  return LWIP_EXAMPLE_COLOR_ERROR;
    case LWIP_EXAMPLE_CHAT_CLASS_RECV:
    default:                            return LWIP_EXAMPLE_COLOR_RECV;
    }
}

struct lwip_example_chat
{
    char title[24];

    /* Transcript ring: row [head] is the most recently pushed line; rows
     * wrap backward from there. `count` saturates at LWIP_EXAMPLE_CHAT_LINES. */
    char ring[LWIP_EXAMPLE_CHAT_LINES][LWIP_EXAMPLE_CHAT_COLS + 1];
    uint8_t ring_color[LWIP_EXAMPLE_CHAT_LINES];
    uint8_t ring_head;
    uint8_t ring_count;

    /* What's currently painted on screen, indexed top-to-bottom by visible
     * transcript row. Compared against the ring each render to skip rows
     * that haven't changed. shown_valid tracks how many of these are
     * actually populated (vs. blank/never-drawn). */
    char shown[LWIP_EXAMPLE_CHAT_LINES][LWIP_EXAMPLE_CHAT_COLS + 1];
    uint8_t shown_valid;

    char input[LWIP_EXAMPLE_CHAT_INPUT];
    uint8_t input_len;
    uint8_t input_mode;
    bool input_upper_once;
    uint8_t rendered_input_y;
    uint8_t rendered_input_rows;
};

static char lwip_example_chat_prompt_char(const struct lwip_example_chat *chat)
{
    if (chat && chat->input_upper_once)
    {
        return 'A';
    }
    switch (chat ? (lwip_example_chat_input_mode_t)chat->input_mode
                 : LWIP_EXAMPLE_CHAT_MODE_LOWER)
    {
    case LWIP_EXAMPLE_CHAT_MODE_UPPER: return 'A';
    case LWIP_EXAMPLE_CHAT_MODE_NUMERIC: return '0';
    case LWIP_EXAMPLE_CHAT_MODE_LOWER:
    default: return 'a';
    }
}

static void lwip_example_chat_invalidate(struct lwip_example_chat *chat)
{
    if (!chat)
    {
        return;
    }
    chat->shown_valid = 0;
    chat->rendered_input_rows = 0;
}

/* Push one already-bounded display row onto the transcript ring head. */
static void lwip_example_chat_ring_push(struct lwip_example_chat *chat,
                                        const char *line, uint8_t color)
{
    chat->ring_head = (uint8_t)((chat->ring_head + 1u) % LWIP_EXAMPLE_CHAT_LINES);
    snprintf(chat->ring[chat->ring_head], LWIP_EXAMPLE_CHAT_COLS + 1, "%s",
             line ? line : "");
    chat->ring_color[chat->ring_head] = color;
    if (chat->ring_count < LWIP_EXAMPLE_CHAT_LINES)
    {
        chat->ring_count++;
    }
}

/* Wrap one logical message (prefix + text, no embedded newlines) into
 * LWIP_EXAMPLE_CHAT_COLS-wide rows and push each onto the ring, breaking on
 * the last space when a row would otherwise split a word. */
static void lwip_example_chat_ring_push_wrapped(struct lwip_example_chat *chat,
                                                 const char *prefix,
                                                 const char *text,
                                                 size_t len,
                                                 uint8_t color)
{
    bool first = true;

    while (len > 0 || first)
    {
        char line[LWIP_EXAMPLE_CHAT_COLS + 1];
        const char *p = first ? (prefix ? prefix : "") : "";
        size_t prefix_len = strlen(p);
        size_t avail = prefix_len < LWIP_EXAMPLE_CHAT_COLS
                           ? LWIP_EXAMPLE_CHAT_COLS - prefix_len
                           : LWIP_EXAMPLE_CHAT_COLS;
        size_t take = len > avail ? avail : len;
        size_t line_len;
        size_t i;

        if (take < len)
        {
            size_t last_space = 0;
            for (i = 0; i < take; i++)
            {
                if (text[i] == ' ')
                {
                    last_space = i;
                }
            }
            if (last_space > 0)
            {
                take = last_space;
            }
        }
        snprintf(line, sizeof(line), "%s", p);
        line_len = strlen(line);
        for (i = 0; i < take && line_len + 1 < sizeof(line); i++)
        {
            char c = text ? text[i] : '\0';
            line[line_len++] = (c >= 32 && c <= 126) ? c : '.';
        }
        line[line_len] = '\0';
        lwip_example_chat_ring_push(chat, line, color);

        first = false;
        if (take >= len)
        {
            break;
        }
        text += take;
        len -= take;
        while (len > 0 && *text == ' ')
        {
            text++;
            len--;
        }
    }
}

/* Append one message to the transcript: split on CRLF/LF into logical
 * lines, wrap each into rows, push onto the ring. Only the first line gets
 * `prefix` (e.g. "< ", "* ", "> "); continuation lines after an embedded
 * newline start fresh at column 0. `cls` selects the color for every row
 * this message produces. */
static void lwip_example_chat_append_class(struct lwip_example_chat *chat,
                                           const char *prefix,
                                           const char *text,
                                           size_t len,
                                           lwip_example_chat_class_t cls)
{
    size_t start = 0;
    bool first = true;
    uint8_t color = lwip_example_chat_class_color(cls);

    if (!chat || !text)
    {
        return;
    }

    while (start <= len)
    {
        size_t end = start;

        while (end < len && text[end] != '\r' && text[end] != '\n')
        {
            end++;
        }
        lwip_example_chat_ring_push_wrapped(chat, first ? prefix : NULL,
                                            text + start, end - start, color);
        if (end >= len)
        {
            break;
        }
        start = end + 1;
        if (text[end] == '\r' && start < len && text[start] == '\n')
        {
            start++;
        }
        first = false;
    }
}

/* Back-compat default: recv-colored append, for callers that don't care
 * about message classification (e.g. raw passthrough chat clients). */
static void lwip_example_chat_append(struct lwip_example_chat *chat,
                                     const char *prefix,
                                     const char *text,
                                     size_t len)
{
    lwip_example_chat_append_class(chat, prefix, text, len,
                                   LWIP_EXAMPLE_CHAT_CLASS_RECV);
}

static uint8_t lwip_example_chat_input_rows(const struct lwip_example_chat *chat)
{
    size_t len = 2u + (chat ? chat->input_len : 0u);
    uint8_t rows = (uint8_t)((len + LWIP_EXAMPLE_CHAT_COLS - 1u) /
                             LWIP_EXAMPLE_CHAT_COLS);
    if (rows == 0)
    {
        rows = 1;
    }
    if (rows > LWIP_EXAMPLE_CHAT_INPUT_ROWS)
    {
        rows = LWIP_EXAMPLE_CHAT_INPUT_ROWS;
    }
    return rows;
}

static uint8_t lwip_example_chat_draw_wrapped(uint8_t y,
                                              const char *prefix,
                                              const char *text,
                                              size_t len)
{
    uint8_t h = lwip_example_line_h();
    bool first = true;

    while (len > 0 || first)
    {
        char line[LWIP_EXAMPLE_CHAT_COLS + 1];
        const char *p = first ? (prefix ? prefix : "") : "";
        size_t prefix_len = strlen(p);
        size_t avail = prefix_len < LWIP_EXAMPLE_CHAT_COLS
                           ? LWIP_EXAMPLE_CHAT_COLS - prefix_len
                           : LWIP_EXAMPLE_CHAT_COLS;
        size_t take = len > avail ? avail : len;

        if (take < len)
        {
            size_t i;
            size_t last_space = 0;
            for (i = 0; i < take; i++)
            {
                if (text[i] == ' ')
                {
                    last_space = i;
                }
            }
            if (last_space > 0)
            {
                take = last_space;
            }
        }
        snprintf(line, sizeof(line), "%s%.*s", p, (int)take,
                 text ? text : "");
        gfx_PrintStringXY(line, LWIP_EXAMPLE_LEFT, y);
        y = (uint8_t)(y + h);
        first = false;
        if (take >= len)
        {
            break;
        }
        text += take;
        len -= take;
        while (len > 0 && *text == ' ')
        {
            text++;
            len--;
        }
    }
    return y;
}

/* Blank one row in place with a real rectangle fill -- no font-metric
 * guessing about coverage width. */
static void lwip_example_chat_erase_row(uint8_t y)
{
    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillRectangle(LWIP_EXAMPLE_LEFT, y,
                      LWIP_EXAMPLE_LCD_W - LWIP_EXAMPLE_LEFT,
                      lwip_example_line_h());
}

/* Repaint only the transcript rows whose ring content differs from what's
 * currently shown on screen. `top_y`/`transcript_rows` describe the
 * transcript's current screen region; `force` repaints every row (used
 * after a full clear or when the region itself moved). */
static void lwip_example_chat_render_transcript(struct lwip_example_chat *chat,
                                                 uint8_t top_y,
                                                 uint8_t transcript_rows,
                                                 bool force)
{
    uint8_t h = lwip_example_line_h();
    uint8_t visible = chat->ring_count < transcript_rows
                          ? chat->ring_count : transcript_rows;
    uint8_t blank_rows = (uint8_t)(transcript_rows - visible);
    uint8_t i;

    /* Oldest-shown row first, newest last -- matches ring order read
     * backward from head. */
    for (i = 0; i < visible; i++)
    {
        uint8_t ring_idx = (uint8_t)((chat->ring_head + LWIP_EXAMPLE_CHAT_LINES
                                       - (visible - 1u - i)) % LWIP_EXAMPLE_CHAT_LINES);
        uint8_t row = (uint8_t)(blank_rows + i);
        uint8_t y = (uint8_t)(top_y + row * h);
        const char *line = chat->ring[ring_idx];

        if (!force && row < chat->shown_valid &&
            strcmp(chat->shown[row], line) == 0)
        {
            continue;
        }
        lwip_example_chat_erase_row(y);
        gfx_SetTextFGColor(chat->ring_color[ring_idx]);
        gfx_PrintStringXY(line, LWIP_EXAMPLE_LEFT, y);
        snprintf(chat->shown[row], sizeof chat->shown[row], "%s", line);
    }

    for (i = 0; i < blank_rows; i++)
    {
        uint8_t y = (uint8_t)(top_y + i * h);
        if (!force && i < chat->shown_valid && chat->shown[i][0] == '\0')
        {
            continue;
        }
        lwip_example_chat_erase_row(y);
        chat->shown[i][0] = '\0';
    }

    chat->shown_valid = transcript_rows;
}

/* Full redraw: clears the screen and repaints title, transcript, input.
 * Only needed for the first paint and when the input/transcript boundary
 * moves -- normal message traffic goes through chat_render(), which only
 * touches transcript rows that actually changed. */
static void lwip_example_chat_render_full(struct lwip_example_chat *chat)
{
    uint8_t h;
    uint8_t y;
    uint8_t rows_total;
    uint8_t input_rows;
    uint8_t transcript_rows;
    uint8_t transcript_top;
    char prompt[4];

    if (!chat)
        return;

    lwip_example_clear();
    h = lwip_example_line_h();
    y = LWIP_EXAMPLE_TOP;

    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    gfx_PrintStringXY(chat->title, LWIP_EXAMPLE_LEFT, y);
    y = (uint8_t)(y + h);

    rows_total = (uint8_t)((LWIP_EXAMPLE_BOTTOM > y)
                               ? ((LWIP_EXAMPLE_BOTTOM - y) / h)
                               : 0);
    input_rows = lwip_example_chat_input_rows(chat);
    transcript_rows = rows_total > input_rows ? rows_total - input_rows : 0;
    if (transcript_rows > LWIP_EXAMPLE_CHAT_LINES)
    {
        transcript_rows = LWIP_EXAMPLE_CHAT_LINES;
    }
    transcript_top = y;

    chat->shown_valid = 0;
    lwip_example_chat_render_transcript(chat, transcript_top, transcript_rows,
                                        true);
    y = (uint8_t)(transcript_top + transcript_rows * h);

    prompt[0] = lwip_example_chat_prompt_char(chat);
    prompt[1] = ' ';
    prompt[2] = '\0';
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    (void)lwip_example_chat_draw_wrapped(y, prompt, chat->input, chat->input_len);
    chat->rendered_input_y = y;
    chat->rendered_input_rows = input_rows;
    lwip_example_draw_mem_stats();
    lwip_example_present();
}

/* Render the transcript + input. Cheap path: if the input's row count
 * hasn't changed since the last render, the transcript/input boundary is
 * stable, so only repaint transcript rows whose ring content actually
 * changed (no full-screen clear, no full repaint). Falls back to a full
 * redraw on the first render or whenever the boundary moves. */
static void lwip_example_chat_render_input(struct lwip_example_chat *chat);

static void lwip_example_chat_render(struct lwip_example_chat *chat)
{
    uint8_t h;
    uint8_t y;
    uint8_t rows_total;
    uint8_t input_rows;
    uint8_t transcript_rows;
    uint8_t transcript_top;

    if (!chat)
        return;

    if (chat->rendered_input_rows == 0)
    {
        lwip_example_chat_render_full(chat);
        return;
    }

    h = lwip_example_line_h();
    y = (uint8_t)(LWIP_EXAMPLE_TOP + h);
    rows_total = (uint8_t)((LWIP_EXAMPLE_BOTTOM > y)
                               ? ((LWIP_EXAMPLE_BOTTOM - y) / h)
                               : 0);
    input_rows = lwip_example_chat_input_rows(chat);
    if (input_rows != chat->rendered_input_rows)
    {
        lwip_example_chat_render_full(chat);
        return;
    }

    transcript_rows = rows_total > input_rows ? rows_total - input_rows : 0;
    if (transcript_rows > LWIP_EXAMPLE_CHAT_LINES)
    {
        transcript_rows = LWIP_EXAMPLE_CHAT_LINES;
    }
    transcript_top = y;
    lwip_example_chat_render_transcript(chat, transcript_top, transcript_rows,
                                        false);
    lwip_example_chat_render_input(chat);
    lwip_example_draw_mem_stats();
    lwip_example_present();
}

/* Redraw only the prompt rows while typing (or once the input is sent and
 * cleared). If the input wraps to a different row count, the transcript
 * reservation changes, so fall back to full redraw. */
static void lwip_example_chat_render_input(struct lwip_example_chat *chat)
{
    uint8_t h;
    uint8_t rows;
    uint8_t i;
    char prompt[4];

    if (!chat)
        return;

    rows = lwip_example_chat_input_rows(chat);
    if (rows != chat->rendered_input_rows)
    {
        lwip_example_chat_render_full(chat);
        return;
    }

    h = lwip_example_line_h();
    for (i = 0; i < rows && (unsigned)(chat->rendered_input_y + i * h) < LWIP_EXAMPLE_BOTTOM; i++)
    {
        lwip_example_chat_erase_row((uint8_t)(chat->rendered_input_y + i * h));
    }

    prompt[0] = lwip_example_chat_prompt_char(chat);
    prompt[1] = ' ';
    prompt[2] = '\0';
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    (void)lwip_example_chat_draw_wrapped(chat->rendered_input_y, prompt,
                                         chat->input, chat->input_len);
    lwip_example_present();
}

static void lwip_example_chat_begin(struct lwip_example_chat *chat,
                                    const char *title)
{
    if (!chat)
    {
        return;
    }
    memset(chat, 0, sizeof(*chat));
    snprintf(chat->title, sizeof(chat->title), "%s", title ? title : "== Chat ==");
    lwip_example_chat_render(chat);
}

static void lwip_example_line_ipv4(const char *prefix, const uint8_t ip[4])
{
    lwip_example_linef("%s%u.%u.%u.%u", prefix ? prefix : "",
                       (unsigned)ip[0], (unsigned)ip[1],
                       (unsigned)ip[2], (unsigned)ip[3]);
}

static const char *lwip_example_socket_status_name(lwip_status_t status)
{
    switch (status)
    {
    case LWIP_STATUS_INIT:             return "init";
    case LWIP_STATUS_WAITING_SERVICES: return "waiting";
    case LWIP_STATUS_RESOLVING:        return "resolving";
    case LWIP_STATUS_CONNECTING:       return "connecting";
    case LWIP_STATUS_CONNECTED:        return "connected";
    case LWIP_STATUS_CLOSING:          return "closing";
    case LWIP_STATUS_CLOSED:           return "closed";
    case LWIP_STATUS_RESET:            return "reset";
    case LWIP_STATUS_ERROR:            return "error";
    default:                           return "unknown";
    }
}

/* ----------------------------------------------------------------------
 * Debug console
 *
 * A reusable sink for the unified lwIP event callback (lwip_event_fn). It
 * draws on the same text surface as the rest of these helpers, so it stays
 * visually consistent. Begin with the example-name header; each event then
 * prints one line beneath it, shaped by its kind.
 *
 * Usage:
 *   lwip_example_dbg_console_begin("TLS RSA");
 *   lwip_set_event_cb(lwip_example_dbg_console_cb);
 * -------------------------------------------------------------------- */

/* Clear the screen and draw the example-name header. */
static void lwip_example_dbg_console_begin(const char *title)
{
    lwip_example_clear();
    if (title)
    {
        lwip_example_line(title);
    }
    lwip_example_draw_mem_stats();
}

/* lwip_event_fn: draw one event line, shaped by its kind. */
static void lwip_example_dbg_console_cb(const struct lwip_event *ev)
{
    if (!ev)
    {
        return;
    }

    switch (ev->kind)
    {
    case LWIP_EV_INFO:
        lwip_example_linef("%s: %s",
                           lwip_debug_module_name(ev->module),
                           ev->data.msg ? ev->data.msg : "");
        break;
    case LWIP_EV_DEBUG:
        lwip_example_linef("%s %s:%u",
                           lwip_debug_module_name(ev->module),
                           lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                           (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc));
        break;
    case LWIP_EV_WARN:
        lwip_example_linef("!%s %s:%u x%u",
                           lwip_debug_module_name(ev->module),
                           lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                           (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                           (unsigned)ev->data.code.extra);
        break;
    case LWIP_EV_ERROR:
        lwip_example_linef("X%s %s:%u x%u",
                           lwip_debug_module_name(ev->module),
                           lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                           (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                           (unsigned)ev->data.code.extra);
        break;
    case LWIP_EV_STATE_CHG:
        lwip_example_linef("%s -> %s",
                           lwip_debug_module_name(ev->module),
                           lwip_debug_state_change_name(ev->data.state.change_event));
        break;
    case LWIP_EV_IO_FILE:
        lwip_example_linef("%s io:%s %s %u",
                           lwip_debug_module_name(ev->module),
                           ev->data.file.name ? ev->data.file.name : "?",
                           ev->data.file.dir == LWIP_IO_WRITE ? "w" : "r",
                           (unsigned)ev->data.file.bytes);
        break;
    case LWIP_EV_IO_ETH:
        lwip_example_linef("%s io:eth %s %u",
                           lwip_debug_module_name(ev->module),
                           ev->data.eth.dir == LWIP_IO_TX ? "tx" : "rx",
                           (unsigned)ev->data.eth.bytes);
        break;
    default:
        break;
    }
    lwip_example_draw_mem_stats();
}

/* lwip_event_fn: same rendering as lwip_example_dbg_console_cb, but only
 * for WARN/ERROR events — everything else (INFO/DEBUG/STATE_CHG/IO_*) is
 * dropped. For apps (like the browser) that own the full screen and have
 * no dedicated console area, so routine traffic doesn't clobber the UI. */
static void lwip_example_dbg_console_cb_errors_only(const struct lwip_event *ev)
{
    if (!ev || (ev->kind != LWIP_EV_WARN && ev->kind != LWIP_EV_ERROR))
    {
        return;
    }
    lwip_example_dbg_console_cb(ev);
}

static void lwip_example_show_socket_error(const char *label,
                                         const struct lwip_socket *sock,
                                         lwip_error_t err)
{
    lwip_netif_info_t info = {0};

    lwip_example_clear();
    lwip_example_line(label);
    lwip_example_linef("st:%u err:%u",
                       sock ? (unsigned)sock->status : 0u,
                       err ? (unsigned)err
                           : (sock ? (unsigned)sock->last_error : 0u));
    if (lwip_default_netif_info(&info))
    {
        lwip_example_linef("u:%u l:%u dh:%u",
                           (unsigned)info.up,
                           (unsigned)info.link_up,
                           (unsigned)info.dhcp_state);
        lwip_example_linef("ip:%u gw:%u",
                           (unsigned)info.has_ipv4,
                           (unsigned)info.has_ipv4_gateway);
        lwip_example_line_ipv4("IP ", info.ipv4_addr);
        lwip_example_line_ipv4("GW ", info.ipv4_gateway);
    }
    else
    {
        lwip_example_line("no netif");
    }
    lwip_example_draw_mem_stats();
    lwip_example_wait_key();
}

static uint32_t lwip_example_now_ms(void);
static bool lwip_example_timed_out(uint32_t start, uint16_t seconds);
static bool lwip_example_cancelled(uint8_t key);

static void lwip_example_stack_stop(void)
{
    if (lwip_example_stack_running)
    {
        lwip_example_stack_running = false;
        lwip_stop();
    }
    lwip_example_gfx_stop();
}

static bool lwip_example_stack_start(void)
{
    lwip_example_gfx_start();
    lwip_example_show("lwIP runtime", NULL);

    if (!lwip_start()) /* bootstrap + stack init (no network yet) */
    {
        lwip_example_show_and_wait("lwIP failed", lwip_get_start_errstring());
        return false;
    }
    lwip_example_gfx_blit_start();

    lwip_example_show("lwIP network up", NULL);

    if (!lwip_network_up())
    {
        switch (lwip_start_last_error())
        {
        case 1:
            lwip_example_show_and_wait("lwIP failed", "start init");
            break;
        case 2:
            lwip_example_show_and_wait("lwIP failed", "start usb");
            break;
        default:
            lwip_example_show_and_wait("lwIP failed", "start");
            break;
        }
        return false;
    }

    lwip_example_stack_running = true;
    lwip_example_draw_mem_stats();
    return true;
}

static int lwip_example_finish(int code)
{
    lwip_example_stack_stop();
    return code;
}

static uint32_t lwip_example_now_ms(void)
{
    return lwip_now_ms();
}

static bool lwip_example_timed_out(uint32_t start, uint16_t seconds)
{
    return (uint32_t)(lwip_example_now_ms() - start) >=
        (uint32_t)seconds * 1000u;
}

static bool lwip_example_cancelled(uint8_t key)
{
    return key == sk_Clear;
}

#endif /* LWIP_EXAMPLE_H */
