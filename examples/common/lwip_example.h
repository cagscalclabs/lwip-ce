#ifndef LWIP_EXAMPLE_H
#define LWIP_EXAMPLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <string.h>

#include <ti/getcsc.h>
#include <ti/getkey.h>
#include <ti/screen.h>

#include <lwip.h>

/* ----------------------------------------------------------------------
 * Small-font text surface
 *
 * All example output uses the OS small font (os_FontSelect(os_SmallFont) +
 * os_FontDrawText) drawn straight to the LCD — no graphx, no large/home-screen
 * font. The OS font routines don't track a cursor, so we keep our own row
 * position and advance it by the font height per line, wrapping back to the
 * top when we run off the bottom.
 * -------------------------------------------------------------------- */

#define LWIP_EXAMPLE_TOP 30     /* first line y (px), below the status row */
#define LWIP_EXAMPLE_BOTTOM 228 /* last usable y (px); LCD is 240 tall      */
#define LWIP_EXAMPLE_LEFT 2     /* left margin (px)                         */
#define LWIP_EXAMPLE_LCD_W 320
#define LWIP_EXAMPLE_STATS_X 188
#define LWIP_EXAMPLE_STATS_LINES 5
#define LWIP_EXAMPLE_STATS_LOOP_INTERVAL 12

static uint8_t lwip_example_row = LWIP_EXAMPLE_TOP;
static uint8_t lwip_example_stats_loop_count = 0;
static bool lwip_example_stack_running = false;

static uint8_t lwip_example_line_h(void)
{
    uint8_t h;
    os_FontSelect(os_SmallFont);
    h = (uint8_t)os_FontGetHeight();
    return h ? h : 8;
}

/* Clear the screen and reset the cursor to the top. */
static void lwip_example_clear(void)
{
    os_ClrLCDFull();
    lwip_example_row = LWIP_EXAMPLE_TOP;
}

/* Draw one small-font line at the current row and advance. Wraps to the top
 * (clearing) when the next line would run off the bottom. */
static void lwip_example_line(const char *text)
{
    uint8_t h = lwip_example_line_h();
    uint8_t text_bottom = (uint8_t)(LWIP_EXAMPLE_BOTTOM -
                                    (h * LWIP_EXAMPLE_STATS_LINES));
    if ((unsigned)lwip_example_row + h > text_bottom)
    {
        lwip_example_clear();
        h = lwip_example_line_h();
    }
    os_FontSelect(os_SmallFont);
    os_FontDrawText(text ? text : "", LWIP_EXAMPLE_LEFT, lwip_example_row);
    lwip_example_row = (uint8_t)(lwip_example_row + h);
}

/* printf-style small-font line. */
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

static void lwip_example_stats_line(uint8_t y, const char *text)
{
    int width;
    os_FontSelect(os_SmallFont);
    os_FontDrawText("                      ", LWIP_EXAMPLE_STATS_X, y);
    width = (int)os_FontGetWidth(text);
    os_FontDrawText(text, LWIP_EXAMPLE_LCD_W - 2 - width, y);
}

static void lwip_example_draw_mem_stats(void)
{
    struct mem_accounting_stats stats;
    char used[12];
    char total[12];
    char line[32];
    uint8_t h;
    uint8_t y;
    size_t user_limit;

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
    lwip_example_format_k(used, sizeof(used), stats.rx_ring_used);
    lwip_example_format_k(total, sizeof(total), stats.rx_ring_size);
    snprintf(line, sizeof(line), "R:%s/%s %u%%", used, total,
             lwip_example_pct(stats.rx_ring_used, stats.rx_ring_size));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    user_limit = 0;
    if (stats.total_heap > stats.pbuf_pool_size + stats.heap_used)
    {
        user_limit = stats.total_heap - stats.pbuf_pool_size - stats.heap_used;
    }
    lwip_example_format_k(used, sizeof(used), stats.user_reserved);
    lwip_example_format_k(total, sizeof(total), user_limit);
    snprintf(line, sizeof(line), "U:%s/%s %u%%", used, total,
             lwip_example_pct(stats.user_reserved, user_limit));
    lwip_example_stats_line(y, line);

    y = (uint8_t)(y + h);
    lwip_example_format_k(used, sizeof(used), stats.socket_ring_used);
    lwip_example_format_k(total, sizeof(total), stats.socket_ring_size);
    snprintf(line, sizeof(line), "C:%s/%s %u%%", used, total,
             lwip_example_pct(stats.socket_ring_used, stats.socket_ring_size));
    lwip_example_stats_line(y, line);
}

static void lwip_example_mem_stats_tick(void)
{
    if (++lwip_example_stats_loop_count >= LWIP_EXAMPLE_STATS_LOOP_INTERVAL)
    {
        lwip_example_stats_loop_count = 0;
        lwip_example_draw_mem_stats();
    }
}

static void lwip_example_wait_key(void)
{
    lwip_example_line("");
    lwip_example_line("Press any key");
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
 * becomes '.'. Each output line is length-bounded to the small-font surface. */
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
 * Nonblocking, redraw-based chat surface for live examples. The transcript
 * stores already-wrapped small-font lines. The input line is rendered after
 * the transcript on every redraw, so inbound text arriving while the user is
 * typing pushes the prompt downward/scrolls older lines instead of overwriting
 * or splitting the input mid-word.
 * -------------------------------------------------------------------- */

#define LWIP_EXAMPLE_CHAT_COLS 42
#define LWIP_EXAMPLE_CHAT_LINES 20
#define LWIP_EXAMPLE_CHAT_INPUT 88

typedef enum
{
    LWIP_EXAMPLE_CHAT_MODE_LOWER = 0,
    LWIP_EXAMPLE_CHAT_MODE_UPPER,
    LWIP_EXAMPLE_CHAT_MODE_NUMERIC,
} lwip_example_chat_input_mode_t;

struct lwip_example_chat
{
    char title[24];
    char lines[LWIP_EXAMPLE_CHAT_LINES][LWIP_EXAMPLE_CHAT_COLS + 1];
    char input[LWIP_EXAMPLE_CHAT_INPUT];
    uint8_t line_count;
    uint8_t last_key;
    uint8_t input_len;
    uint8_t input_mode;
};

static void lwip_example_chat_append_line(struct lwip_example_chat *chat,
                                          const char *line)
{
    if (!chat)
    {
        return;
    }
    if (chat->line_count >= LWIP_EXAMPLE_CHAT_LINES)
    {
        memmove(chat->lines[0], chat->lines[1],
                (LWIP_EXAMPLE_CHAT_LINES - 1) * sizeof chat->lines[0]);
        chat->line_count = LWIP_EXAMPLE_CHAT_LINES - 1;
    }
    snprintf(chat->lines[chat->line_count], sizeof chat->lines[0],
             "%s", line ? line : "");
    chat->line_count++;
}

static void lwip_example_chat_append_segment(struct lwip_example_chat *chat,
                                             const char *first_prefix,
                                             const char *cont_prefix,
                                             const char *text,
                                             size_t len)
{
    bool first = true;

    if (!chat || !text)
    {
        return;
    }

    while (len > 0)
    {
        const char *prefix = first ? (first_prefix ? first_prefix : "")
                                  : (cont_prefix ? cont_prefix : "");
        size_t prefix_len = strlen(prefix);
        size_t avail = (prefix_len < LWIP_EXAMPLE_CHAT_COLS)
                           ? LWIP_EXAMPLE_CHAT_COLS - prefix_len
                           : 0;
        size_t take = len;
        size_t i;
        char line[LWIP_EXAMPLE_CHAT_COLS + 1];

        if (avail == 0)
        {
            avail = LWIP_EXAMPLE_CHAT_COLS;
            prefix = "";
            prefix_len = 0;
        }
        if (take > avail)
        {
            size_t last_space = 0;
            take = avail;
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
        if (take == 0)
        {
            take = len < avail ? len : avail;
            if (take == 0)
            {
                break;
            }
        }

        snprintf(line, sizeof(line), "%s%.*s",
                 prefix, (int)take, text);
        lwip_example_chat_append_line(chat, line);

        text += take;
        len -= take;
        while (len > 0 && *text == ' ')
        {
            text++;
            len--;
        }
        first = false;
    }
}

static void lwip_example_chat_append(struct lwip_example_chat *chat,
                                     const char *prefix,
                                     const char *text,
                                     size_t len)
{
    size_t start = 0;
    bool first_line = true;

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
        if (end > start)
        {
            lwip_example_chat_append_segment(
                chat,
                first_line ? prefix : NULL,
                prefix && first_line ? "    " : NULL,
                text + start,
                end - start);
        }
        else if (first_line && prefix)
        {
            lwip_example_chat_append_line(chat, prefix);
        }
        first_line = false;
        if (end >= len)
        {
            break;
        }
        start = end + 1;
        if (text[end] == '\r' && start < len && text[start] == '\n')
        {
            start++;
        }
    }
}

static uint8_t lwip_example_chat_input_rows(const struct lwip_example_chat *chat)
{
    size_t len = 2u + (chat ? chat->input_len : 0u);
    uint8_t rows = (uint8_t)((len + LWIP_EXAMPLE_CHAT_COLS - 1u) /
                             LWIP_EXAMPLE_CHAT_COLS);
    return rows ? rows : 1;
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
        os_FontDrawText(line, LWIP_EXAMPLE_LEFT, y);
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

static void lwip_example_chat_render(struct lwip_example_chat *chat)
{
    uint8_t h;
    uint8_t y;
    uint8_t stats_y;
    uint8_t rows_total;
    uint8_t input_rows;
    uint8_t transcript_rows;
    uint8_t start = 0;
    uint8_t i;
    char prompt[4];

    if (!chat)
    {
        return;
    }

    lwip_example_clear();
    os_FontSelect(os_SmallFont);
    h = lwip_example_line_h();
    y = LWIP_EXAMPLE_TOP;
    stats_y = (uint8_t)(LWIP_EXAMPLE_BOTTOM -
                        (h * LWIP_EXAMPLE_STATS_LINES));

    os_FontDrawText(chat->title, LWIP_EXAMPLE_LEFT, y);
    y = (uint8_t)(y + h);

    rows_total = (uint8_t)((stats_y > y) ? ((stats_y - y) / h) : 0);
    input_rows = lwip_example_chat_input_rows(chat);
    transcript_rows = rows_total > input_rows ? rows_total - input_rows : 0;
    if (chat->line_count > transcript_rows)
    {
        start = (uint8_t)(chat->line_count - transcript_rows);
    }

    for (i = start; i < chat->line_count && y + h <= stats_y; i++)
    {
        os_FontDrawText(chat->lines[i], LWIP_EXAMPLE_LEFT, y);
        y = (uint8_t)(y + h);
    }

    switch ((lwip_example_chat_input_mode_t)chat->input_mode)
    {
    case LWIP_EXAMPLE_CHAT_MODE_UPPER:
        prompt[0] = 'A';
        break;
    case LWIP_EXAMPLE_CHAT_MODE_NUMERIC:
        prompt[0] = '0';
        break;
    case LWIP_EXAMPLE_CHAT_MODE_LOWER:
    default:
        prompt[0] = 'a';
        break;
    }
    prompt[1] = ' ';
    prompt[2] = '\0';
    (void)lwip_example_chat_draw_wrapped(y, prompt,
                                         chat->input, chat->input_len);
    lwip_example_draw_mem_stats();
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

static char lwip_example_chat_key_alpha(uint8_t key)
{
    switch (key)
    {
    case sk_Math: return 'A';
    case sk_Apps: return 'B';
    case sk_Prgm: return 'C';
    case sk_Recip: return 'D';
    case sk_Sin: return 'E';
    case sk_Cos: return 'F';
    case sk_Tan: return 'G';
    case sk_Power: return 'H';
    case sk_Square: return 'I';
    case sk_Comma: return 'J';
    case sk_LParen: return 'K';
    case sk_RParen: return 'L';
    case sk_Div: return 'M';
    case sk_Log: return 'N';
    case sk_7: return 'O';
    case sk_8: return 'P';
    case sk_9: return 'Q';
    case sk_Mul: return 'R';
    case sk_Ln: return 'S';
    case sk_4: return 'T';
    case sk_5: return 'U';
    case sk_6: return 'V';
    case sk_Sub: return 'W';
    case sk_Store: return 'X';
    case sk_1: return 'Y';
    case sk_2: return 'Z';
    case sk_0: return ' ';
    case sk_DecPnt: return '.';
    default: return 0;
    }
}

static char lwip_example_chat_key_lower(uint8_t key)
{
    char c = lwip_example_chat_key_alpha(key);
    if (c >= 'A' && c <= 'Z')
    {
        c = (char)(c + ('a' - 'A'));
    }
    return c;
}

static char lwip_example_chat_key_normal(uint8_t key)
{
    switch (key)
    {
    case sk_0: return '0';
    case sk_1: return '1';
    case sk_2: return '2';
    case sk_3: return '3';
    case sk_4: return '4';
    case sk_5: return '5';
    case sk_6: return '6';
    case sk_7: return '7';
    case sk_8: return '8';
    case sk_9: return '9';
    case sk_DecPnt: return '.';
    case sk_Sub: return '-';
    case sk_Add: return '+';
    case sk_Div: return '/';
    case sk_Mul: return '*';
    case sk_Comma: return ',';
    case sk_LParen: return '(';
    case sk_RParen: return ')';
    default: return 0;
    }
}

static bool lwip_example_chat_poll_input(struct lwip_example_chat *chat,
                                         char *out,
                                         size_t out_len,
                                         bool *cancel)
{
    uint8_t key;
    char c;

    if (cancel)
    {
        *cancel = false;
    }
    if (!chat || !out || out_len == 0)
    {
        return false;
    }

    key = os_GetCSC();
    if (key == 0)
    {
        chat->last_key = 0;
        return false;
    }
    if (key == chat->last_key)
    {
        return false;
    }
    chat->last_key = key;

    if (key == sk_Alpha)
    {
        chat->input_mode = (uint8_t)((chat->input_mode + 1u) % 3u);
        lwip_example_chat_render(chat);
        return false;
    }
    if (key == sk_Del || key == sk_Left ||
        (key == sk_Clear && chat->input_len > 0))
    {
        if (chat->input_len > 0)
        {
            chat->input[--chat->input_len] = '\0';
            lwip_example_chat_render(chat);
        }
        return false;
    }
    if (key == sk_Clear)
    {
        if (cancel)
        {
            *cancel = true;
        }
        return false;
    }
    if (key == sk_Enter)
    {
        if (chat->input_len == 0)
        {
            return false;
        }
        snprintf(out, out_len, "%s", chat->input);
        chat->input[0] = '\0';
        chat->input_len = 0;
        lwip_example_chat_render(chat);
        return true;
    }

    switch ((lwip_example_chat_input_mode_t)chat->input_mode)
    {
    case LWIP_EXAMPLE_CHAT_MODE_UPPER:
        c = lwip_example_chat_key_alpha(key);
        break;
    case LWIP_EXAMPLE_CHAT_MODE_NUMERIC:
        c = lwip_example_chat_key_normal(key);
        break;
    case LWIP_EXAMPLE_CHAT_MODE_LOWER:
    default:
        c = lwip_example_chat_key_lower(key);
        break;
    }
    if (c && chat->input_len + 1 < sizeof(chat->input))
    {
        chat->input[chat->input_len++] = c;
        chat->input[chat->input_len] = '\0';
        lwip_example_chat_render(chat);
    }
    return false;
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
 * A reusable sink for the unified lwIP debug callback (lwip_debug_fn). It
 * draws on the same small-font surface as the rest of these helpers, so it
 * stays visually consistent. Begin with the example-name header; each debug
 * event then prints one "module:state ok|errno" small-font line beneath it.
 *
 * Usage:
 *   lwip_example_dbg_console_begin("TLS RSA");
 *   lwip_set_debug(lwip_example_dbg_console_cb, LWIP_DBG_INFO,
 *                  LWIP_DBG_DEPTH_MILESTONE);
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

/* lwip_debug_fn: draw one event line. Severity is shown as a short tag so an
 * ALERT (problematic but proceeding) is distinguishable from a plain ERROR. */
static void lwip_example_dbg_console_cb(const struct lwip_debug_info *info)
{
    if (!info)
    {
        return;
    }

#ifdef LWIP_DBG_SEV_ALERT
    switch (info->severity)
    {
    case LWIP_DBG_SEV_ALERT:
        lwip_example_linef("!%s:%s a%d",
                           lwip_debug_module_name(info->module),
                           lwip_debug_state_name(info->module_state),
                           info->errnum);
        break;
    case LWIP_DBG_SEV_ERROR:
        lwip_example_linef("X%s:%s e%d",
                           lwip_debug_module_name(info->module),
                           lwip_debug_state_name(info->module_state),
                           info->errnum);
        break;
    default: /* LWIP_DBG_SEV_INFO */
#endif
        if (info->errnum == 0)
        {
            lwip_example_linef("%s:%s ok",
                               lwip_debug_module_name(info->module),
                               lwip_debug_state_name(info->module_state));
        }
        else
        {
            lwip_example_linef("%s:%s e%d",
                               lwip_debug_module_name(info->module),
                               lwip_debug_state_name(info->module_state),
                               info->errnum);
        }
#ifdef LWIP_DBG_SEV_ALERT
        break;
    }
#endif
    lwip_example_draw_mem_stats();
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
static bool lwip_example_cancelled(void);

static void lwip_example_stack_stop(void)
{
    if (lwip_example_stack_running)
    {
        lwip_example_stack_running = false;
        lwip_stop();
    }
}

static bool lwip_example_stack_start(void)
{
    lwip_example_show("lwIP runtime", NULL);

    uint8_t rt = lwip_init_runtime(); /* 0 = success */
    if (rt != 0)
    {
        switch (rt)
        {
        case 1:
            lwip_example_show_and_wait("lwIP failed", "app missing");
            break;
        case 2:
            lwip_example_show_and_wait("lwIP failed", "export error");
            break;
        default:
            lwip_example_show_and_wait("lwIP failed", "runtime init");
            break;
        }
        return false;
    }

    lwip_example_show("lwIP start", NULL);

    if (!lwip_start())
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

static bool lwip_example_cancelled(void)
{
    return os_GetCSC() == sk_Clear;
}

#endif /* LWIP_EXAMPLE_H */
