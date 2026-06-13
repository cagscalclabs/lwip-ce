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

#include <lwip/core.h>
#include <lwip/conn.h>

/* ----------------------------------------------------------------------
 * Small-font text surface
 *
 * All example output uses the OS small font (os_FontSelect(os_SmallFont) +
 * os_FontDrawText) drawn straight to the LCD — no graphx, no large/home-screen
 * font. The OS font routines don't track a cursor, so we keep our own row
 * position and advance it by the font height per line, wrapping back to the
 * top when we run off the bottom.
 * -------------------------------------------------------------------- */

#define LWIP_EXAMPLE_TOP     30   /* first line y (px), below the status row */
#define LWIP_EXAMPLE_BOTTOM  228  /* last usable y (px); LCD is 240 tall      */
#define LWIP_EXAMPLE_LEFT    2    /* left margin (px)                         */

static uint8_t lwip_example_row = LWIP_EXAMPLE_TOP;

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
    if ((unsigned)lwip_example_row + h > LWIP_EXAMPLE_BOTTOM)
    {
        lwip_example_clear();
        h = lwip_example_line_h();
    }
    os_FontSelect(os_SmallFont);
    os_FontDrawText(text ? text : "", LWIP_EXAMPLE_LEFT, lwip_example_row);
    lwip_example_row = (uint8_t)(lwip_example_row + h);
}

/* printf-style small-font line. */
#define lwip_example_linef(...) do {                       \
        char _lebuf[64];                                   \
        snprintf(_lebuf, sizeof(_lebuf), __VA_ARGS__);     \
        lwip_example_line(_lebuf);                         \
    } while (0)

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
    lwip_example_wait_key();
}

static void lwip_example_line_ipv4(const char *prefix, const uint8_t ip[4])
{
    lwip_example_linef("%s%u.%u.%u.%u", prefix ? prefix : "",
                       (unsigned)ip[0], (unsigned)ip[1],
                       (unsigned)ip[2], (unsigned)ip[3]);
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
}

/* lwip_debug_fn: draw one event line. */
static void lwip_example_dbg_console_cb(const struct lwip_debug_info *info)
{
    if (!info)
    {
        return;
    }

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
}

static void lwip_example_show_conn_error(const char *label,
                                         const struct lwip_conn *conn,
                                         lwip_error_t err)
{
    lwip_netif_info_t info = {0};

    lwip_example_clear();
    lwip_example_line(label);
    lwip_example_linef("st:%u err:%u",
                       conn ? (unsigned)conn->status : 0u,
                       err ? (unsigned)err
                           : (conn ? (unsigned)conn->last_error : 0u));
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
    lwip_example_wait_key();
}

static bool lwip_example_timed_out(clock_t start, uint16_t seconds);
static bool lwip_example_cancelled(void);

static bool lwip_example_stack_running = false;

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

    if (!lwip_init_runtime())
    {
        switch (lwip_runtime_last_error())
        {
        case 1:
            lwip_example_show_and_wait("lwIP failed", "app missing");
            break;
        case 2:
            lwip_example_show_and_wait("lwIP failed", "runtime table");
            break;
        case 3:
            lwip_example_show_and_wait("lwIP failed", "runtime count");
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
    return true;
}

static int lwip_example_finish(int code)
{
    lwip_example_stack_stop();
    return code;
}

static bool lwip_example_timed_out(clock_t start, uint16_t seconds)
{
    return (clock_t)(clock() - start) >= (clock_t)seconds * CLOCKS_PER_SEC;
}

static bool lwip_example_cancelled(void)
{
    return os_GetCSC() == sk_Clear;
}

#endif /* LWIP_EXAMPLE_H */
