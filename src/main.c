#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ti/getcsc.h>
#include <ti/screen.h>
#include <ti/vars.h>
#include <sys/rtc.h>
#include <usbdrvce.h>
#include <fileioc.h>

#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"
#include "lwip/ip_addr.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/sntp.h"
#include "lwip/sntp_time.h"
#include "lwip/app_config.h"
#include "lwip/dns.h"
#include "lwip/icmp.h"
#include "lwip/raw.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcp.h"
#include "lwip/logging.h"
#include "lwip/teardown.h"
#include "lwip/dispatch.h"

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"

#include "drivers/mem.h"
#include "drivers/usb_ethernet.h"
#include "lwip-imports.h"
#include "tls/includes/handshake.h"
#include "apps/altcp_tls/altcp_tls_ce.h"

#define LWIP_CFG_TZ_MIN_MINUTES (-12 * 60)
#define LWIP_CFG_TZ_MAX_MINUTES (14 * 60)
#define LWIP_CFG_TZ_STEP_MINUTES 15

#define LWIP_CFG_LOG_MIN_BYTES 1024u
#define LWIP_CFG_LOG_MAX_BYTES 16384u
#define LWIP_CFG_LOG_STEP_BYTES 512u

#ifndef LWIP_APP_ENABLE_SERVICE_EXAMPLES
#define LWIP_APP_ENABLE_SERVICE_EXAMPLES 0
#endif

typedef enum
{
    F_TYPE_BOOL_TOGGLE,
    F_TYPE_STRING,
    F_TYPE_INT_SLIDER,
    F_TYPE_ACTION,
    F_TYPE_LABEL,
    F_TYPE_SEPARATOR
} f_type;

typedef enum
{
    OPT_SEP_MEMORY = 0,
    OPT_MEM_CAP,
    OPT_SEP_SERVICES,
    OPT_AUTO_NTP,
    OPT_DNS,
    OPT_IP_MODE,
    OPT_EDIT_IP,
    OPT_HOSTNAME,
    OPT_TZ_OFFSET,
    OPT_DST,
    OPT_SEP_SECURITY,
    OPT_TLS_CHAIN_MODE,
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
    OPT_SEP_TESTS,
    OPT_NTP_TEST,
    OPT_HTTP_TEST,
    OPT_DNS_TEST,
    OPT_PING_TEST,
    OPT_TCP_ECHO_TEST,
    OPT_TLS_TEST,
#endif
    OPT_COUNT
} config_option_id;

typedef enum
{
    EDIT_NONE = 0,
    EDIT_MEM_CAP,
    EDIT_TZ
} edit_mode_t;

struct config_option;
typedef bool (*config_setter_fn)(struct config_option *opt);

struct config_option
{
    const char *name;
    config_option_id id;
    f_type type;
    config_setter_fn setter;
    uint8_t value[4];
};

static bool run_main = true;
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
static bool dhcp_started = false;
static bool httpd_running = false;
static bool sntp_started = false;
static bool manual_ip_applied = false;
static bool lwip_started = false;
static volatile bool netif_unavailable = false;
#endif

static lwip_app_config_t g_cfg;

// Legacy color constants (used by test functions)
#define COLOR_WHITE 0xFFFF
#define COLOR_BLACK 0x0000
#define COLOR_LIGHT_GRAY 0xD6BA

// New UI color palette
#define UI_COLOR_BG         0xFFFF  // White background
#define UI_COLOR_FG         0x0000  // Black text
#define UI_COLOR_ACCENT     0x001F  // Blue accent (RGB565)
#define UI_COLOR_SELECTED   0x7BEF  // Light blue selection
#define UI_COLOR_SEPARATOR  0xC618  // Gray for separators
#define UI_COLOR_HEADER     0x0000  // Black header
#define UI_COLOR_EDIT_BG    0xFFE0  // Yellow for edit mode

static void delay_ms(unsigned int ms)
{
    for (unsigned int i = 0; i < ms; i++)
    {
        for (volatile unsigned int j = 0; j < 1500; j++) { }
    }
}

// Forward declarations
static void format_tz_offset(char *buf, size_t buf_len, int16_t minutes);
static void edit_ip_config(lwip_app_config_t *cfg);
static void edit_hostname_config(lwip_app_config_t *cfg);
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
static bool start_lwip_stack(const lwip_app_config_t *cfg);
static void apply_network_config(const lwip_app_config_t *cfg);
#endif
static void fill_rect(int x, int y, int w, int h, uint16_t color);
static void ui_draw_header(const char *title);
static void ui_draw_footer(const char *line1, const char *line2);

static bool config_toggle_option(struct config_option *opt);
static bool config_edit_ip(struct config_option *opt);
static bool config_edit_hostname(struct config_option *opt);
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
static bool config_run_ntp_test(struct config_option *opt);
static bool config_run_http_test(struct config_option *opt);
static bool config_run_dns_test(struct config_option *opt);
static bool config_run_ping_test(struct config_option *opt);
static bool config_run_tcp_echo_test(struct config_option *opt);
static bool config_run_tls_test(struct config_option *opt);
#endif
static size_t config_required_lwip_floor(const lwip_app_config_t *cfg);
static uint16_t config_mem_cap_max(void);
static bool config_clamp_mem_cap(lwip_app_config_t *cfg);
static void ui_draw_mem_breakdown(void);
static void format_option_value(const struct config_option *opt, char *buf, size_t buf_len);

#if LWIP_APP_ENABLE_SERVICE_EXAMPLES && LWIP_DHCP
static bool dhcp_client_running(const struct netif *netif)
{
    struct dhcp *dhcp = netif ? netif_dhcp_data(netif) : NULL;
    return dhcp && dhcp->state != DHCP_STATE_OFF;
}
#endif

static struct config_option config_options[] = {
    {"-- Memory --",    OPT_SEP_MEMORY,   F_TYPE_SEPARATOR,    NULL, {0}},
    {"lwIP Heap",       OPT_MEM_CAP,      F_TYPE_INT_SLIDER,   NULL, {0}},
    {"-- Services --",  OPT_SEP_SERVICES, F_TYPE_SEPARATOR,    NULL, {0}},
    {"DHCP",            OPT_IP_MODE,      F_TYPE_BOOL_TOGGLE,  config_toggle_option, {0}},
    {"DNS",             OPT_DNS,          F_TYPE_BOOL_TOGGLE,  config_toggle_option, {0}},
    {"NTP",             OPT_AUTO_NTP,     F_TYPE_BOOL_TOGGLE,  config_toggle_option, {0}},
    {"IP Config",       OPT_EDIT_IP,      F_TYPE_ACTION,       config_edit_ip, {0}},
    {"Hostname",        OPT_HOSTNAME,     F_TYPE_ACTION,       config_edit_hostname, {0}},
    {"Timezone",        OPT_TZ_OFFSET,    F_TYPE_INT_SLIDER,   NULL, {0}},
    {"DST",             OPT_DST,          F_TYPE_BOOL_TOGGLE,  config_toggle_option, {0}},
    {"-- Security --",  OPT_SEP_SECURITY, F_TYPE_SEPARATOR,    NULL, {0}},
    /* Chain mode placeholder. Full-chain validation is not implemented
     * yet, so this remains visible but forced to SPKI-pin mode. */
    {"Full Chain Verify", OPT_TLS_CHAIN_MODE,        F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
    {"-- Tests --",     OPT_SEP_TESTS,    F_TYPE_SEPARATOR,    NULL, {0}},
    {"NTP Test",        OPT_NTP_TEST,     F_TYPE_ACTION,       config_run_ntp_test, {0}},
    {"HTTP Test",       OPT_HTTP_TEST,    F_TYPE_ACTION,       config_run_http_test, {0}},
    {"DNS Test",        OPT_DNS_TEST,     F_TYPE_ACTION,       config_run_dns_test, {0}},
    {"Ping Test",       OPT_PING_TEST,    F_TYPE_ACTION,       config_run_ping_test, {0}},
    {"TCP Echo",        OPT_TCP_ECHO_TEST,F_TYPE_ACTION,       config_run_tcp_echo_test, {0}},
    {"TLS Test",        OPT_TLS_TEST,     F_TYPE_ACTION,       config_run_tls_test, {0}},
#endif
};

#define CONFIG_OPTION_COUNT (sizeof(config_options) / sizeof(config_options[0]))

static void option_set_u16(uint8_t value[4], uint16_t v)
{
    value[0] = (uint8_t)(v & 0xFF);
    value[1] = (uint8_t)((v >> 8) & 0xFF);
    value[2] = 0;
    value[3] = 0;
}

static uint16_t option_get_u16(const uint8_t value[4])
{
    return (uint16_t)(value[0] | ((uint16_t)value[1] << 8));
}

static void option_set_i16(uint8_t value[4], int16_t v)
{
    option_set_u16(value, (uint16_t)v);
}

static int16_t option_get_i16(const uint8_t value[4])
{
    return (int16_t)option_get_u16(value);
}

static void option_set_bool(uint8_t value[4], bool v)
{
    value[0] = v ? 1u : 0u;
    value[1] = 0;
    value[2] = 0;
    value[3] = 0;
}

static bool option_get_bool(const uint8_t value[4])
{
    return value[0] != 0;
}

static void option_set_u8(uint8_t value[4], uint8_t v)
{
    value[0] = v;
    value[1] = 0;
    value[2] = 0;
    value[3] = 0;
}

static uint8_t option_get_u8(const uint8_t value[4])
{
    return value[0];
}

static size_t config_required_lwip_floor(const lwip_app_config_t *cfg)
{
    (void)cfg;
    return LWIP_TLS_FLOOR_BYTES;
}

/* Maximum cap = all current free RAM (user gets nothing).
 * Capped at UINT16_MAX since lwip_mem_cap is stored as uint16_t. */
static uint16_t config_mem_cap_max(void)
{
    void *free_block = NULL;
    size_t free_ram = os_MemChk(&free_block);
    return (free_ram > UINT16_MAX) ? UINT16_MAX : (uint16_t)free_ram;
}

static bool config_clamp_mem_cap(lwip_app_config_t *cfg)
{
    size_t floor = config_required_lwip_floor(cfg);
    uint16_t cap_max = config_mem_cap_max();
    bool changed = false;
    if (cfg->lwip_mem_cap < (uint16_t)floor)
    {
        cfg->lwip_mem_cap = (uint16_t)floor;
        changed = true;
    }
    if (cfg->lwip_mem_cap > cap_max)
    {
        cfg->lwip_mem_cap = cap_max;
        changed = true;
    }
    return changed;
}
// ============================================================================
// NEW CLEAN UI DESIGN - Single scrollable menu
// ============================================================================

#define VRAM_BASE ((uint16_t *)0xD40000)

// Layout constants
#define UI_HEADER_H     22
#define UI_FOOTER_H     28
#define UI_CONTENT_Y    (UI_HEADER_H)
#define UI_CONTENT_H    (LCD_HEIGHT - UI_HEADER_H - UI_FOOTER_H)
#define UI_ROW_H        16
#define UI_VISIBLE_ROWS (UI_CONTENT_H / UI_ROW_H)
#define UI_MARGIN       8
#define UI_VALUE_X      180
#define UI_FOOTER_LINE_H 12

// Fill rectangle with clipping
static void ui_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > LCD_WIDTH) w = LCD_WIDTH - x;
    if (y + h > LCD_HEIGHT) h = LCD_HEIGHT - y;
    if (w <= 0 || h <= 0) return;

    for (int row = y; row < y + h; row++)
    {
        uint16_t *ptr = VRAM_BASE + row * LCD_WIDTH + x;
        for (int col = 0; col < w; col++)
            *ptr++ = color;
    }
}

// Alias for backward compatibility with test functions
static void fill_rect(int x, int y, int w, int h, uint16_t color)
{
    ui_fill_rect(x, y, w, h, color);
}

// Draw horizontal line
static void ui_hline(int x, int y, int w, uint16_t color)
{
    ui_fill_rect(x, y, w, 1, color);
}

// Draw box with border
static void ui_box(int x, int y, int w, int h, uint16_t bg, uint16_t border)
{
    ui_fill_rect(x, y, w, h, bg);
    ui_fill_rect(x, y, w, 2, border);           // top
    ui_fill_rect(x, y + h - 2, w, 2, border);   // bottom
    ui_fill_rect(x, y, 2, h, border);           // left
    ui_fill_rect(x + w - 2, y, 2, h, border);   // right
}

// Scroll content area by shifting VRAM pixels
// amount > 0: scroll down by N rows (content moves up, new rows appear at bottom)
// amount < 0: scroll up by N rows (content moves down, new rows appear at top)
static void ui_scroll_content(int amount)
{
    if (amount == 0) return;

    int pixel_shift = (amount > 0 ? amount : -amount) * UI_ROW_H;
    if (pixel_shift >= UI_CONTENT_H)
    {
        // Scrolling more than visible area, just clear
        ui_fill_rect(0, UI_CONTENT_Y, LCD_WIDTH, UI_CONTENT_H, UI_COLOR_BG);
        return;
    }

    uint16_t *vram = VRAM_BASE;

    if (amount > 0)
    {
        // Scroll down: shift pixels up
        uint16_t *dst = vram + UI_CONTENT_Y * LCD_WIDTH;
        uint16_t *src = vram + (UI_CONTENT_Y + pixel_shift) * LCD_WIDTH;
        int copy_pixels = (UI_CONTENT_H - pixel_shift) * LCD_WIDTH;
        memmove(dst, src, copy_pixels * sizeof(uint16_t));
        // Clear the newly exposed area at bottom
        ui_fill_rect(0, UI_CONTENT_Y + UI_CONTENT_H - pixel_shift, LCD_WIDTH, pixel_shift, UI_COLOR_BG);
    }
    else
    {
        // Scroll up: shift pixels down
        uint16_t *dst = vram + (UI_CONTENT_Y + pixel_shift) * LCD_WIDTH;
        uint16_t *src = vram + UI_CONTENT_Y * LCD_WIDTH;
        int copy_pixels = (UI_CONTENT_H - pixel_shift) * LCD_WIDTH;
        memmove(dst, src, copy_pixels * sizeof(uint16_t));
        // Clear the newly exposed area at top
        ui_fill_rect(0, UI_CONTENT_Y, LCD_WIDTH, pixel_shift, UI_COLOR_BG);
    }
}

// Draw header bar
static void ui_draw_header(const char *title)
{
    ui_fill_rect(0, 0, LCD_WIDTH, UI_HEADER_H, UI_COLOR_HEADER);
    os_SetDrawFGColor(UI_COLOR_BG);
    int tw = (int)os_FontGetWidth(title);
    os_FontDrawTransText(title, (LCD_WIDTH - tw) / 2, 5);
}

// Draw footer with help text (supports two lines)
static void ui_draw_footer(const char *line1, const char *line2)
{
    int y = LCD_HEIGHT - UI_FOOTER_H;
    ui_fill_rect(0, y, LCD_WIDTH, UI_FOOTER_H, UI_COLOR_SEPARATOR);
    ui_hline(0, y, LCD_WIDTH, UI_COLOR_FG);
    os_SetDrawFGColor(UI_COLOR_FG);

    // Center each line
    if (line1)
    {
        int w1 = (int)os_FontGetWidth(line1);
        os_FontDrawTransText(line1, (LCD_WIDTH - w1) / 2, y + 2);
    }
    if (line2)
    {
        int w2 = (int)os_FontGetWidth(line2);
        os_FontDrawTransText(line2, (LCD_WIDTH - w2) / 2, y + 2 + UI_FOOTER_LINE_H);
    }
}

// Draw a single menu row
static void ui_draw_row(int row_y, const char *label, const char *value,
                        bool selected, bool editing, bool is_separator)
{
    uint16_t bg = UI_COLOR_BG;
    uint16_t fg = UI_COLOR_FG;

    if (is_separator)
    {
        // Separator: centered text with lines
        ui_fill_rect(0, row_y, LCD_WIDTH, UI_ROW_H, UI_COLOR_BG);
        os_SetDrawFGColor(UI_COLOR_SEPARATOR);
        int lw = (int)os_FontGetWidth(label);
        int lx = (LCD_WIDTH - lw) / 2;
        ui_hline(UI_MARGIN, row_y + UI_ROW_H/2, lx - UI_MARGIN - 4, UI_COLOR_SEPARATOR);
        ui_hline(lx + lw + 4, row_y + UI_ROW_H/2, LCD_WIDTH - lx - lw - UI_MARGIN - 4, UI_COLOR_SEPARATOR);
        os_FontDrawTransText(label, lx, row_y + 2);
        return;
    }

    if (selected)
    {
        bg = editing ? UI_COLOR_EDIT_BG : UI_COLOR_SELECTED;
    }

    ui_fill_rect(0, row_y, LCD_WIDTH, UI_ROW_H, bg);

    // Selection indicator
    if (selected)
    {
        ui_fill_rect(2, row_y + 2, 4, UI_ROW_H - 4, UI_COLOR_ACCENT);
    }

    // Label
    os_SetDrawFGColor(fg);
    os_FontDrawTransText(label, UI_MARGIN + 6, row_y + 2);

    // Value (right-aligned area)
    if (value && value[0])
    {
        int vw = (int)os_FontGetWidth(value);
        int vx = LCD_WIDTH - UI_MARGIN - vw;
        if (vx < UI_VALUE_X) vx = UI_VALUE_X;
        os_FontDrawTransText(value, vx, row_y + 2);
    }
}

// Calculate visible row Y position
static int ui_row_y(int visible_idx)
{
    return UI_CONTENT_Y + visible_idx * UI_ROW_H;
}

// Draw scrollbar if needed
static void ui_draw_scrollbar(int scroll_pos, int total_items)
{
    if (total_items <= UI_VISIBLE_ROWS) return;

    int sb_x = LCD_WIDTH - 6;
    int sb_h = UI_CONTENT_H;
    int thumb_h = (sb_h * UI_VISIBLE_ROWS) / total_items;
    if (thumb_h < 10) thumb_h = 10;
    int thumb_y = UI_CONTENT_Y + (scroll_pos * (sb_h - thumb_h)) / (total_items - UI_VISIBLE_ROWS);

    ui_fill_rect(sb_x, UI_CONTENT_Y, 4, sb_h, UI_COLOR_SEPARATOR);
    ui_fill_rect(sb_x, thumb_y, 4, thumb_h, UI_COLOR_FG);
}

// Draw a single option row by index (for optimized redraws)
static void ui_draw_single_option(int idx, int scroll_pos, int selected_idx, bool editing)
{
    int v = idx - scroll_pos;
    if (v < 0 || v >= UI_VISIBLE_ROWS) return;
    if (idx < 0 || idx >= (int)CONFIG_OPTION_COUNT) return;

    const struct config_option *opt = &config_options[idx];
    char value[32] = {0};

    bool is_sep = (opt->type == F_TYPE_SEPARATOR);
    if (!is_sep)
    {
        format_option_value(opt, value, sizeof(value));
    }

    ui_draw_row(ui_row_y(v), opt->name, value,
                idx == selected_idx, editing && idx == selected_idx, is_sep);
}

// Draw entire menu
static void ui_draw_menu(int selected_idx, int scroll_pos, bool editing)
{
    // Clear content area
    ui_fill_rect(0, UI_CONTENT_Y, LCD_WIDTH, UI_CONTENT_H, UI_COLOR_BG);

    // Draw visible rows
    for (int v = 0; v < UI_VISIBLE_ROWS; v++)
    {
        int idx = scroll_pos + v;
        if (idx >= (int)CONFIG_OPTION_COUNT) break;

        const struct config_option *opt = &config_options[idx];
        char value[32] = {0};

        bool is_sep = (opt->type == F_TYPE_SEPARATOR);
        if (!is_sep)
        {
            format_option_value(opt, value, sizeof(value));
        }

        ui_draw_row(ui_row_y(v), opt->name, value,
                    idx == selected_idx, editing && idx == selected_idx, is_sep);
    }

    ui_draw_scrollbar(scroll_pos, (int)CONFIG_OPTION_COUNT);
}

// Draw footer based on current mode
static void ui_draw_mode_footer(bool editing, edit_mode_t edit_mode)
{
    if (editing)
    {
        if (edit_mode == EDIT_MEM_CAP)
        {
            ui_draw_footer("<left/right> Adjust lwIP heap",
                           "Min 24k (TLS ready)");
        }
        else
        {
            ui_draw_footer("<left/right> Adjust value",
                           "<enter> Confirm  <clear> Cancel");
        }
    }
    else
    {
        ui_draw_footer("<up/down> Navigate  <enter> Select",
                       "<2nd> Save  <clear> Exit");
    }
}

// Full screen redraw
static void ui_draw_full(int selected_idx, int scroll_pos, edit_mode_t edit_mode)
{
    bool editing = edit_mode != EDIT_NONE;
    ui_draw_header("lwIP Configuration");
    ui_draw_menu(selected_idx, scroll_pos, editing);
    ui_draw_mode_footer(editing, edit_mode);
}

// Ensure selected item is visible, returns new scroll position
static int ui_ensure_visible(int selected_idx, int scroll_pos)
{
    if (selected_idx < scroll_pos)
        return selected_idx;
    if (selected_idx >= scroll_pos + UI_VISIBLE_ROWS)
        return selected_idx - UI_VISIBLE_ROWS + 1;
    return scroll_pos;
}

/* Draw memory breakdown rows in the content area.
 * Called while EDIT_MEM_CAP is active, replacing the normal menu. */
static void ui_draw_mem_breakdown(void)
{
    void *free_block = NULL;
    size_t free_ram  = os_MemChk(&free_block);
    size_t fixed     = LWIP_TLS_FLOOR_BYTES;
    size_t cap       = g_cfg.lwip_mem_cap;
    size_t pbuf_pool = LWIP_PBUF_POOL_BYTES;
    size_t heap_budget = (cap > pbuf_pool) ? (cap - pbuf_pool) : 0u;
    size_t usermem   = (free_ram > cap) ? (free_ram - cap) : 0u;

    ui_fill_rect(0, UI_CONTENT_Y, LCD_WIDTH, UI_CONTENT_H, UI_COLOR_BG);

    int y = UI_CONTENT_Y + 4;
    char buf[40];
    os_SetDrawFGColor(UI_COLOR_FG);

#define MEM_ROW(label, bytes) \
    do { \
        os_FontDrawTransText((label), UI_MARGIN + 6, y); \
        snprintf(buf, sizeof(buf), "%u B", (unsigned)(bytes)); \
        int vw = (int)os_FontGetWidth(buf); \
        os_FontDrawTransText(buf, LCD_WIDTH - UI_MARGIN - vw, y); \
        y += UI_ROW_H; \
    } while (0)

    MEM_ROW("TLS-capable floor:", fixed);
    MEM_ROW("pbuf pool:", pbuf_pool);
    MEM_ROW("Non-pool heap:", heap_budget);

    /* Divider above the slider row */
    y += 2;
    ui_hline(UI_MARGIN, y, LCD_WIDTH - 2 * UI_MARGIN, UI_COLOR_SEPARATOR);
    y += 4;

    /* Slider row — highlighted */
    ui_fill_rect(0, y, LCD_WIDTH, UI_ROW_H, UI_COLOR_EDIT_BG);
    ui_fill_rect(2, y + 2, 4, UI_ROW_H - 4, UI_COLOR_ACCENT);
    os_SetDrawFGColor(UI_COLOR_FG);
    os_FontDrawTransText("lwIP Heap:", UI_MARGIN + 6, y);
    snprintf(buf, sizeof(buf), "%u B", (unsigned)cap);
    int vw = (int)os_FontGetWidth(buf);
    os_FontDrawTransText(buf, LCD_WIDTH - UI_MARGIN - vw, y);
    y += UI_ROW_H + 4;

    ui_hline(UI_MARGIN, y, LCD_WIDTH - 2 * UI_MARGIN, UI_COLOR_SEPARATOR);
    y += 4;

    MEM_ROW("Usermem remaining:", usermem);
#undef MEM_ROW
}

static void option_sync_from_cfg(struct config_option *opt)
{
    switch (opt->id)
    {
    case OPT_MEM_CAP:
        option_set_u16(opt->value, g_cfg.lwip_mem_cap);
        break;
    case OPT_TZ_OFFSET:
        option_set_i16(opt->value, g_cfg.tz_offset_minutes);
        break;
    case OPT_DST:
        option_set_bool(opt->value, g_cfg.dst_enabled != 0);
        break;
    case OPT_AUTO_NTP:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_AUTO_NTP) != 0);
        break;
    case OPT_DNS:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_DNS) != 0);
        break;
    case OPT_IP_MODE:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_DHCP) != 0);
        break;
    case OPT_TLS_CHAIN_MODE:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_FULL_CHAIN_VERIFY) != 0);
        break;
    default:
        // Action/separator types, no sync needed
        break;
    }
}

static void apply_logging_config(void)
{
    /* The appvar-backed log system was replaced by the unified debug callback
     * (lwip_set_debug). The persisted log_* config fields are retained for
     * layout stability but no longer drive any runtime logging here. */
}

static void config_sync_from_cfg(void)
{
    for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
    {
        option_sync_from_cfg(&config_options[i]);
    }
    apply_logging_config();
}

static bool option_is_selectable(const struct config_option *opt)
{
    return opt->type != F_TYPE_LABEL && opt->type != F_TYPE_SEPARATOR;
}

static int find_first_selectable(void)
{
    for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
    {
        if (option_is_selectable(&config_options[i]))
        {
            return (int)i;
        }
    }
    return -1;
}

static int find_next_selectable(int current, int dir)
{
    int i = current;
    while (1)
    {
        i += dir;
        if (i < 0 || i >= (int)CONFIG_OPTION_COUNT)
        {
            break;
        }
        if (option_is_selectable(&config_options[i]))
        {
            return i;
        }
    }
    return current;
}

static void format_option_value(const struct config_option *opt, char *buf, size_t buf_len)
{
    switch (opt->id)
    {
    case OPT_MEM_CAP:
        snprintf(buf, buf_len, "%uk", option_get_u16(opt->value) / 1024u);
        break;
    case OPT_TZ_OFFSET:
        format_tz_offset(buf, buf_len, option_get_i16(opt->value));
        break;
    case OPT_DST:
    case OPT_AUTO_NTP:
    case OPT_DNS:
        snprintf(buf, buf_len, "%s", option_get_bool(opt->value) ? "ON" : "OFF");
        break;
    case OPT_TLS_CHAIN_MODE:
        /* Show "Full" or "Pin" so the menu reads as a mode-picker
         * rather than a yes/no toggle. */
        snprintf(buf, buf_len, "%s",
                 option_get_bool(opt->value) ? "Full" : "Pin");
        break;
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
    case OPT_NTP_TEST:
    case OPT_HTTP_TEST:
    case OPT_DNS_TEST:
    case OPT_PING_TEST:
    case OPT_TCP_ECHO_TEST:
    case OPT_TLS_TEST:
        snprintf(buf, buf_len, ">");
        break;
#endif
    case OPT_IP_MODE:
        snprintf(buf, buf_len, "%s", option_get_bool(opt->value) ? "ON" : "OFF");
        break;
    case OPT_EDIT_IP:
        if (g_cfg.flags & LWIP_CFG_DHCP)
        {
            snprintf(buf, buf_len, "(DHCP)");
        }
        else
        {
            snprintf(buf, buf_len, "%u.%u.%u.%u",
                     g_cfg.ip_addr[0], g_cfg.ip_addr[1],
                     g_cfg.ip_addr[2], g_cfg.ip_addr[3]);
        }
        break;
    case OPT_HOSTNAME:
        snprintf(buf, buf_len, "%s", g_cfg.hostname);
        break;
    default:
        buf[0] = '\0';
        break;
    }
}

static bool config_toggle_option(struct config_option *opt)
{
    switch (opt->id)
    {
    case OPT_DST:
        g_cfg.dst_enabled = (uint8_t)!g_cfg.dst_enabled;
        option_sync_from_cfg(opt);
        return true;
    case OPT_AUTO_NTP:
        g_cfg.flags ^= LWIP_CFG_AUTO_NTP;
        option_sync_from_cfg(opt);
        return true;
    case OPT_DNS:
        g_cfg.flags ^= LWIP_CFG_DNS;
        option_sync_from_cfg(opt);
        return true;
    case OPT_IP_MODE:
        g_cfg.flags ^= LWIP_CFG_DHCP;
        option_sync_from_cfg(opt);
        return true;
    case OPT_TLS_CHAIN_MODE:
        g_cfg.flags &= (uint8_t)~LWIP_CFG_FULL_CHAIN_VERIFY;
        option_sync_from_cfg(opt);
        return true;
    default:
        return false;
    }
}

static bool config_edit_ip(struct config_option *opt)
{
    (void)opt;
    edit_ip_config(&g_cfg);
    return true;
}

static bool config_edit_hostname(struct config_option *opt)
{
    (void)opt;
    edit_hostname_config(&g_cfg);
    return true;
}

#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
// Common test network state - callbacks set these
static volatile bool test_link_up = false;
static volatile bool test_has_ip = false;

NETIF_DECLARE_EXT_CALLBACK(netif_ext_cb);

static void netif_ext_callback(struct netif *netif, netif_nsc_reason_t reason,
                               const netif_ext_callback_args_t *args)
{
    if ((reason & LWIP_NSC_NETIF_REMOVED) != 0)
    {
        netif_unavailable = true;
    }
    if ((reason & LWIP_NSC_LINK_CHANGED) != 0)
    {
        if (!args || args->link_changed.state == 0)
        {
            netif_unavailable = true;
        }
        else
        {
            netif_unavailable = false;
        }
    }
    if ((reason & LWIP_NSC_STATUS_CHANGED) != 0)
    {
        if (!args || args->status_changed.state == 0)
        {
            netif_unavailable = true;
        }
    }

    if (netif_unavailable)
    {
        if (netif)
        {
            dhcp_stop(netif);
        }
        if (sntp_started || sntp_enabled())
        {
            sntp_stop();
            sntp_started = false;
        }
        httpd_running = false;
        dhcp_started = false;
        manual_ip_applied = false;
    }
}

static struct netif *find_first_ethernet_netif(void)
{
    struct netif *netif;
    NETIF_FOREACH(netif)
    {
        if ((netif->flags & NETIF_FLAG_ETHERNET) != 0)
        {
            return netif;
        }
    }
    return NULL;
}

static void test_link_callback(struct netif *netif)
{
    (void)netif;
    test_link_up = netif_is_link_up(netif);
}

static void test_status_callback(struct netif *netif)
{
    (void)netif;
    if (netif_is_up(netif) && !ip4_addr_isany(netif_ip4_addr(netif))
        && !ip4_addr_isloopback(netif_ip4_addr(netif)))
    {
        test_has_ip = true;
    }
}

// Common cleanup for all tests - waits for Clear key and clears screen
static void cleanup_test_screen(void)
{
    os_FontDrawText("Press Clear to exit", 10, 180);

    // Clear any pending keys
    while (os_GetCSC())
        ;

    // Wait for Clear key
    while (1)
    {
        usb_HandleEvents();
        sys_check_timeouts();

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            break;
        }
        delay_ms(10);
    }

    // Clear screen before returning to wizard
    fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);
}

static void cleanup_test_screen_fast(void)
{
    while (os_GetCSC())
        ;
    fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);
}

static bool test_network_available(void)
{
    if (netif_unavailable || !netif_default)
    {
        return false;
    }
    return netif_is_link_up(netif_default);
}

// Common network setup for all tests
// Returns true on success, false on failure/cancel
static bool setup_test_network(const char *test_name)
{
    // Reset state
    test_link_up = false;
    test_has_ip = false;

    // Start network stack
    if (!start_lwip_stack(&g_cfg))
    {
        return false;
    }

    // Clear screen
    fill_rect(0, 0, 320, 240, COLOR_WHITE);
    os_SetDrawFGColor(COLOR_BLACK);

    char title[32];
    snprintf(title, sizeof(title), "%s Running", test_name);
    os_FontDrawText(title, 10, 10);
    os_FontDrawText("Waiting for network...", 10, 50);

    // Wait for netif to be created (device enumeration)
    int timeout = 1000; // 10 seconds at 10ms intervals
    struct netif *found_netif = NULL;
    while (timeout > 0 && !found_netif)
    {
        usb_HandleEvents();
        sys_check_timeouts();

        if (netif_unavailable)
        {
            os_FontDrawText("Network unavailable", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            os_FontDrawText("Test cancelled", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        delay_ms(10);
        timeout--;
        found_netif = find_first_ethernet_netif();
    }

    if (!found_netif)
    {
        os_FontDrawText("No network device found", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return false;
    }

    if (!netif_default || ((netif_default->flags & NETIF_FLAG_ETHERNET) == 0))
    {
        netif_set_default(found_netif);
    }

    // Register callbacks for async notifications
    netif_set_link_callback(netif_default, test_link_callback);
    netif_set_status_callback(netif_default, test_status_callback);

    // Check initial state (callbacks only fire on changes)
    test_link_up = netif_is_link_up(netif_default);
    if (netif_is_up(netif_default) && !ip4_addr_isany(netif_ip4_addr(netif_default))
        && !ip4_addr_isloopback(netif_ip4_addr(netif_default)))
    {
        test_has_ip = true;
    }

    // Apply network config (starts DHCP if enabled)
    apply_network_config(&g_cfg);

    fill_rect(0, 50, 320, 20, COLOR_WHITE);
    os_FontDrawText("Waiting for link...", 10, 50);

    // Wait for link up (callback sets test_link_up)
    timeout = 1000; // 10 seconds at 10ms intervals
    while (timeout > 0 && !test_link_up)
    {
        usb_HandleEvents();
        sys_check_timeouts();

        if (netif_unavailable)
        {
            os_FontDrawText("Network unavailable", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            os_FontDrawText("Test cancelled", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        delay_ms(10);
        timeout--;
    }

    if (!test_link_up)
    {
        os_FontDrawText("Link not detected", 10, 70);
        os_FontDrawText("Check cable connection", 10, 90);
        os_FontDrawText("Press any key", 10, 110);
        os_GetKey();
        cleanup_test_screen_fast();
        return false;
    }

    fill_rect(0, 50, 320, 20, COLOR_WHITE);
    os_FontDrawText("Link up! Getting IP...", 10, 50);

    // Wait for IP address (callback sets test_has_ip)
    timeout = 3000; // 30 seconds for DHCP at 10ms intervals
    while (timeout > 0 && !test_has_ip)
    {
        usb_HandleEvents();
        sys_check_timeouts();

        if (netif_unavailable)
        {
            os_FontDrawText("Network unavailable", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            os_FontDrawText("Test cancelled", 10, 70);
            delay_ms(100);
            cleanup_test_screen_fast();
            return false;
        }

        delay_ms(10);
        timeout--;
    }

    if (!test_has_ip)
    {
        os_FontDrawText("Failed to get IP address", 10, 70);
        os_FontDrawText("Check DHCP/network config", 10, 90);
        os_FontDrawText("Press any key", 10, 110);
        os_GetKey();
        cleanup_test_screen_fast();
        return false;
    }

    // Clear waiting messages and display IP
    fill_rect(0, 30, 320, 40, COLOR_WHITE);
    const ip4_addr_t *ip = netif_ip4_addr(netif_default);
    char ip_buf[64];
    snprintf(ip_buf, sizeof(ip_buf), "IP: %d.%d.%d.%d",
             ip4_addr1(ip), ip4_addr2(ip), ip4_addr3(ip), ip4_addr4(ip));
    os_FontDrawText(ip_buf, 10, 30);

    return true;
}

static bool config_run_ntp_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("NTP Test"))
    {
        return true;
    }

    if (sntp_enabled())
    {
        sntp_stop();
        sntp_started = false;
    }

    // Start SNTP
    os_FontDrawText("Starting SNTP...", 10, 50);

    // Apply timezone and DST settings before starting SNTP
    lwip_sntp_set_timezone_offset((int32_t)g_cfg.tz_offset_minutes * 60);
    lwip_sntp_set_dst_enabled(g_cfg.dst_enabled != 0);
    lwip_sntp_reset_flag();

    ip_addr_t ntp_server;
    const ip_addr_t *dhcp_server = sntp_getserver(0);
    if (dhcp_server && !ip_addr_isany(dhcp_server))
    {
        ntp_server = *dhcp_server;
    }
    else
    {
        IP_ADDR4(&ntp_server, 162, 159, 200, 1); // time.cloudflare.com
    }

    sntp_servermode_dhcp(0);
    sntp_setserver(0, &ntp_server);
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_init();

    os_FontDrawText("Waiting for time sync...", 10, 70);
    os_FontDrawText("This may take up to 30 seconds", 10, 90);

    // Wait for time sync (flag set by lwip_sntp_set_time callback)
    // Allow time for initial request (15s timeout) + at least one retry
    int timeout = 4500; // 45 seconds at 10ms intervals

    while (timeout > 0 && !lwip_sntp_time_was_set())
    {
        usb_HandleEvents();
        sys_check_timeouts();

        if (!test_network_available())
        {
            os_FontDrawText("Network lost", 10, 110);
            sntp_stop();
            sntp_started = false;
            cleanup_test_screen_fast();
            return true;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            break;
        }

        delay_ms(10);
        timeout--;
    }

    if (lwip_sntp_time_was_set())
    {
        fill_rect(0, 70, 320, 40, COLOR_WHITE);
        os_FontDrawText("Time synced!", 10, 70);

        // Read the time that was just set
        uint8_t sec, min, hr;
        boot_GetTime(&sec, &min, &hr);

        char time_buf[32];
        snprintf(time_buf, sizeof(time_buf), "Time: %02u:%02u:%02u (Local)", hr, min, sec);
        os_FontDrawText(time_buf, 10, 90);
    }
    else
    {
        fill_rect(0, 70, 320, 40, COLOR_WHITE);
        os_FontDrawText("Time sync timeout", 10, 70);
    }

    // Shutdown
    sntp_stop();
    sntp_started = false;

    cleanup_test_screen();
    return true;
}

static bool config_run_http_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("HTTP Test"))
    {
        return true;
    }

    // Start HTTP server
    g_cfg.flags |= LWIP_CFG_TEST_HTTP;
    apply_network_config(&g_cfg);

    if (httpd_running)
    {
        os_FontDrawText("HTTP server started", 10, 50);
        os_FontDrawText("Port: 80", 10, 70);
    }
    else
    {
        os_FontDrawText("HTTP server failed", 10, 50);
    }

    os_FontDrawText("Press Clear to exit", 10, 100);

    // Run server loop until Clear is pressed
    // Clear any pending keys first
    while (os_GetCSC())
        ;

    while (1)
    {
        // Service network events frequently for good performance
        for (int i = 0; i < 10; i++)
        {
            usb_HandleEvents();
            sys_check_timeouts();
            delay_ms(1);
        }

        // Check for Clear key every ~10ms
        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            break;
        }
    }

    // Shutdown HTTP server
    g_cfg.flags &= (uint8_t)~LWIP_CFG_TEST_HTTP;
    httpd_running = false;

    os_FontDrawText("Shutting down...", 10, 120);
    delay_ms(100);

    // Clear screen before returning to wizard
    fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);

    return true;
}

// DNS Test - callback state
static volatile bool dns_result_ready = false;
static volatile ip_addr_t dns_resolved_ip;
static volatile err_t dns_result_err;

static void dns_test_callback(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    (void)name;
    (void)callback_arg;

    if (ipaddr != NULL)
    {
        dns_resolved_ip = *ipaddr;
        dns_result_err = ERR_OK;
    }
    else
    {
        dns_result_err = ERR_TIMEOUT;
    }
    dns_result_ready = true;
}

static bool config_run_dns_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("DNS Test"))
    {
        return true;
    }

    os_FontDrawText("Target: example.com", 10, 50);

    // Start DNS lookup
    int timeout;
    dns_result_ready = false;
    os_FontDrawText("Resolving example.com...", 10, 50);

    ip_addr_t addr;
    err_t err = dns_gethostbyname("example.com", &addr, dns_test_callback, NULL);

    if (err == ERR_OK)
    {
        // Immediate result (cached)
        dns_resolved_ip = addr;
        dns_result_ready = true;
        dns_result_err = ERR_OK;
    }
    else if (err == ERR_INPROGRESS)
    {
        // Wait for callback
        timeout = 1000; // 10 seconds at 10ms intervals
        while (timeout > 0 && !dns_result_ready)
        {
            usb_HandleEvents();
            sys_check_timeouts();

            if (!test_network_available())
            {
                os_FontDrawText("Network lost", 10, 70);
                cleanup_test_screen_fast();
                return true;
            }

            uint8_t key = os_GetCSC();
            if (key == sk_Clear)
            {
                os_FontDrawText("Cancelled", 10, 70);
                delay_ms(1000);
                cleanup_test_screen_fast();
                return true;
            }

            delay_ms(10);
            timeout--;
        }
    }
    else
    {
        dns_result_err = err;
        dns_result_ready = true;
    }

    fill_rect(0, 50, 320, 40, COLOR_WHITE);
    if (dns_result_ready && dns_result_err == ERR_OK)
    {
        os_FontDrawText("DNS lookup successful!", 10, 50);
        char result_buf[64];
        snprintf(result_buf, sizeof(result_buf), "example.com = %d.%d.%d.%d",
                 ip4_addr1(&dns_resolved_ip.u_addr.ip4),
                 ip4_addr2(&dns_resolved_ip.u_addr.ip4),
                 ip4_addr3(&dns_resolved_ip.u_addr.ip4),
                 ip4_addr4(&dns_resolved_ip.u_addr.ip4));
        os_FontDrawText(result_buf, 10, 70);
    }
    else
    {
        os_FontDrawText("DNS lookup failed", 10, 50);
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "Error: %d", dns_result_err);
        os_FontDrawText(err_buf, 10, 70);
    }

    cleanup_test_screen();
    return true;
}

// Ping test state
static volatile bool ping_reply_received = false;
static volatile uint32_t ping_start_time = 0;
static volatile uint32_t ping_rtt_ms = 0;
static uint16_t ping_seq_num = 0;

static uint8_t ping_recv_callback(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
    (void)arg;
    (void)pcb;
    (void)addr;

    if (!p || p->len < (sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr)))
    {
        if (p) pbuf_free(p);
        return 0; // don't eat packet if invalid
    }

    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    uint16_t iphdr_len = IPH_HL_BYTES(iphdr);
    if (p->len < (iphdr_len + sizeof(struct icmp_echo_hdr)))
    {
        pbuf_free(p);
        return 0; // don't eat packet if invalid
    }

    struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)((uint8_t *)p->payload + iphdr_len);

    if ((iecho->type == ICMP_ER) && (iecho->id == 0xABCD) && (lwip_ntohs(iecho->seqno) == ping_seq_num))
    {
        uint32_t now = sys_now();
        ping_rtt_ms = now - ping_start_time;
        ping_reply_received = true;
    }

    pbuf_free(p);
    return 1; // eat packet
}

static bool config_run_ping_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("Ping Test"))
    {
        return true;
    }

    // Create RAW socket for ICMP
    struct raw_pcb *ping_pcb = raw_new(IP_PROTO_ICMP);
    if (!ping_pcb)
    {
        os_FontDrawText("Failed to create ICMP socket", 10, 50);
        os_FontDrawText("Press any key", 10, 70);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    raw_recv(ping_pcb, ping_recv_callback, NULL);
    raw_bind_netif(ping_pcb, netif_default);

    // Target: Google DNS (8.8.8.8) - reliable ping responder
    ip_addr_t ping_target;
    IP_ADDR4(&ping_target, 8, 8, 8, 8);

    char target_buf[64];
    snprintf(target_buf, sizeof(target_buf), "Target: 8.8.8.8 (Google DNS)");
    fill_rect(0, 30, 320, 20, COLOR_WHITE);
    os_FontDrawText(target_buf, 10, 30);

    os_FontDrawText("Sending ping...", 10, 50);

    // Send 4 pings
    int timeout;
    int successful_pings = 0;
    uint32_t total_rtt = 0;

    for (int i = 0; i < 4; i++)
    {
        ping_reply_received = false;
        ping_seq_num = i + 1;

        // Allocate ICMP echo request
        struct pbuf *p = pbuf_alloc(PBUF_IP, sizeof(struct icmp_echo_hdr) + 32, PBUF_RAM);
        if (!p)
        {
            continue;
        }

        struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)p->payload;
        ICMPH_TYPE_SET(iecho, ICMP_ECHO);
        ICMPH_CODE_SET(iecho, 0);
        iecho->chksum = 0;
        iecho->id = 0xABCD;
        iecho->seqno = lwip_htons(ping_seq_num);

        // Fill data
        char *data = (char *)iecho + sizeof(struct icmp_echo_hdr);
        for (int j = 0; j < 32; j++)
        {
            data[j] = 0x61 + (j % 26); // a-z pattern
        }

        // Calculate checksum
        iecho->chksum = inet_chksum(iecho, sizeof(struct icmp_echo_hdr) + 32);

        // Send
        ping_start_time = sys_now();
        err_t err = raw_sendto(ping_pcb, p, &ping_target);
        pbuf_free(p);

        if (err != ERR_OK)
        {
            char err_buf[64];
            snprintf(err_buf, sizeof(err_buf), "Ping %d: Send failed", i + 1);
            os_FontDrawText(err_buf, 10, 70 + i * 15);
            continue;
        }

        // Wait for reply (2 second timeout)
        // Process network events frequently to avoid missing replies
        timeout = 200; // 200 iterations * 10ms = 2 seconds
        while (timeout > 0 && !ping_reply_received)
        {
            usb_HandleEvents();
            sys_check_timeouts();

            if (!test_network_available())
            {
                raw_remove(ping_pcb);
                cleanup_test_screen_fast();
                return true;
            }

            uint8_t key = os_GetCSC();
            if (key == sk_Clear)
            {
                raw_remove(ping_pcb);
                fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);
                return true;
            }

            delay_ms(10); // Shorter delay for faster network processing
            timeout--;
        }

        // Display result
        char result_buf[64];
        if (ping_reply_received)
        {
            snprintf(result_buf, sizeof(result_buf), "Ping %d: %lu ms", i + 1, (unsigned long)ping_rtt_ms);
            successful_pings++;
            total_rtt += ping_rtt_ms;
        }
        else
        {
            snprintf(result_buf, sizeof(result_buf), "Ping %d: Timeout", i + 1);
        }
        os_FontDrawText(result_buf, 10, 70 + i * 15);

        // Wait 500ms before next ping (process events while waiting)
        if (i < 3)
        {
            for (int wait = 0; wait < 50; wait++)
            {
                usb_HandleEvents();
                sys_check_timeouts();
                delay_ms(10);
            }
        }
    }

    // Display statistics
    char stats_buf[64];
    snprintf(stats_buf, sizeof(stats_buf), "Success: %d/4", successful_pings);
    os_FontDrawText(stats_buf, 10, 140);

    if (successful_pings > 0)
    {
        uint32_t avg_rtt = total_rtt / successful_pings;
        snprintf(stats_buf, sizeof(stats_buf), "Avg RTT: %lu ms", (unsigned long)avg_rtt);
        os_FontDrawText(stats_buf, 10, 155);
    }

    raw_remove(ping_pcb);

    cleanup_test_screen();
    return true;
}

// TCP Echo test state
static volatile bool tcp_echo_connected = false;
static volatile bool tcp_echo_data_received = false;
static volatile bool tcp_echo_error = false;
static char tcp_echo_recv_buf[128];
static size_t tcp_echo_recv_len = 0;

static err_t tcp_echo_connected_callback(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    (void)arg;
    (void)tpcb;

    if (err == ERR_OK)
    {
        tcp_echo_connected = true;
    }
    else
    {
        tcp_echo_error = true;
    }
    return ERR_OK;
}

static err_t tcp_echo_recv_callback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)err;

    if (p == NULL)
    {
        // Connection closed
        tcp_close(tpcb);
        return ERR_OK;
    }

    // Copy received data
    size_t to_copy = (p->tot_len < sizeof(tcp_echo_recv_buf) - 1) ? p->tot_len : (sizeof(tcp_echo_recv_buf) - 1);
    pbuf_copy_partial(p, tcp_echo_recv_buf, to_copy, 0);
    tcp_echo_recv_buf[to_copy] = '\0';
    tcp_echo_recv_len = to_copy;
    tcp_echo_data_received = true;

    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void tcp_echo_error_callback(void *arg, err_t err)
{
    (void)arg;
    (void)err;
    tcp_echo_error = true;
}

static bool config_run_tcp_echo_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("TCP Echo Test"))
    {
        return true;
    }

    os_FontDrawText("Target: tcpbin.com:4242", 10, 50);

    // Resolve tcpbin.com
    int timeout;
    os_FontDrawText("Resolving tcpbin.com...", 10, 50);
    dns_result_ready = false;

    ip_addr_t server_addr;
    err_t err = dns_gethostbyname("tcpbin.com", &server_addr, dns_test_callback, NULL);

    if (err == ERR_INPROGRESS)
    {
        timeout = 1000; // 10 seconds at 10ms intervals
        while (timeout > 0 && !dns_result_ready)
        {
            usb_HandleEvents();
            sys_check_timeouts();
            if (os_GetCSC() == sk_Clear)
            {
                os_FontDrawText("Cancelled", 10, 70);
                delay_ms(100);
                cleanup_test_screen_fast();
                return true;
            }
            delay_ms(10);
            timeout--;
        }

        if (!dns_result_ready || dns_result_err != ERR_OK)
        {
            os_FontDrawText("DNS lookup failed", 10, 70);
            os_FontDrawText("Press any key", 10, 90);
            os_GetKey();
            cleanup_test_screen_fast();
            return true;
        }
        server_addr = dns_resolved_ip;
    }
    else if (err != ERR_OK)
    {
        os_FontDrawText("DNS lookup failed", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    // Create TCP connection
    os_FontDrawText("Connecting to server...", 10, 50);

    struct tcp_pcb *tcp_pcb = tcp_new();
    if (!tcp_pcb)
    {
        os_FontDrawText("Failed to create TCP socket", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    tcp_echo_connected = false;
    tcp_echo_error = false;
    tcp_echo_data_received = false;

    tcp_arg(tcp_pcb, NULL);
    tcp_recv(tcp_pcb, tcp_echo_recv_callback);
    tcp_err(tcp_pcb, tcp_echo_error_callback);

    err = tcp_connect(tcp_pcb, &server_addr, 4242, tcp_echo_connected_callback);
    if (err != ERR_OK)
    {
        tcp_abort(tcp_pcb);
        os_FontDrawText("Connection failed", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    // Wait for connection
    timeout = 1000; // 10 seconds at 10ms intervals
    while (timeout > 0 && !tcp_echo_connected && !tcp_echo_error)
    {
        usb_HandleEvents();
        sys_check_timeouts();
        if (!test_network_available())
        {
            tcp_abort(tcp_pcb);
            cleanup_test_screen_fast();
            return true;
        }
        if (os_GetCSC() == sk_Clear)
        {
            tcp_abort(tcp_pcb);
            cleanup_test_screen_fast();
            return true;
        }
        delay_ms(10);
        timeout--;
    }

    if (tcp_echo_error || !tcp_echo_connected)
    {
        tcp_abort(tcp_pcb);
        os_FontDrawText("Connection timeout/error", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    os_FontDrawText("Connected! Sending test data...", 10, 50);

    // Send test message
    const char *test_msg = "Hello from TI-84 CE!\r\n";
    err = tcp_write(tcp_pcb, test_msg, strlen(test_msg), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
    {
        tcp_close(tcp_pcb);
        os_FontDrawText("Send failed", 10, 70);
        os_FontDrawText("Press any key", 10, 90);
        os_GetKey();
        cleanup_test_screen_fast();
        return true;
    }

    tcp_output(tcp_pcb);

    // Wait for echo response
    os_FontDrawText("Waiting for echo...", 10, 70);
    timeout = 1000; // 10 seconds at 10ms intervals
    while (timeout > 0 && !tcp_echo_data_received && !tcp_echo_error)
    {
        usb_HandleEvents();
        sys_check_timeouts();
        if (!test_network_available())
        {
            tcp_close(tcp_pcb);
            cleanup_test_screen_fast();
            return true;
        }
        if (os_GetCSC() == sk_Clear)
        {
            tcp_close(tcp_pcb);
            cleanup_test_screen_fast();
            return true;
        }
        delay_ms(10);
        timeout--;
    }

    fill_rect(0, 50, 320, 100, COLOR_WHITE);
    if (tcp_echo_data_received)
    {
        os_FontDrawText("Echo received!", 10, 50);
        os_FontDrawText("Sent:", 10, 70);
        os_FontDrawText("  Hello from TI-84 CE!", 10, 85);
        os_FontDrawText("Received:", 10, 105);

        char recv_display[40];
        snprintf(recv_display, sizeof(recv_display), "  %.30s", tcp_echo_recv_buf);
        os_FontDrawText(recv_display, 10, 120);

        // Check if our sent message is contained in the response
        // (echo servers may add extra characters like prompts)
        if (strstr(tcp_echo_recv_buf, "Hello from TI-84 CE!") != NULL)
        {
            os_FontDrawText("Test PASSED!", 10, 140);
        }
        else
        {
            os_FontDrawText("Data mismatch - Test FAILED", 10, 140);
        }
    }
    else
    {
        os_FontDrawText("No echo received (timeout)", 10, 50);
    }

    tcp_close(tcp_pcb);

    cleanup_test_screen();
    return true;
}

/* ========== TLS Connection Test ========== */

/* TLS test state */
static volatile bool tls_test_connected = false;
static volatile bool tls_test_error = false;
static volatile bool tls_test_data_received = false;
static char tls_test_recv_buf[256];
static size_t tls_test_recv_len = 0;

static err_t tls_test_connected_callback(void *arg, struct altcp_pcb *tpcb, err_t err)
{
    (void)arg;

    if (err == ERR_OK)
    {
        tls_test_connected = true;

        /* Send HTTP GET request */
        const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        err_t write_err = altcp_write(tpcb, request, (u16_t)strlen(request), TCP_WRITE_FLAG_COPY);
        if (write_err == ERR_OK)
        {
            altcp_output(tpcb);
        }
        else
        {
            tls_test_error = true;
            altcp_abort(tpcb);
            return ERR_ABRT;
        }
    }
    else
    {
        tls_test_error = true;
    }
    return ERR_OK;
}

static err_t tls_test_recv_callback(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)err;

    if (p == NULL)
    {
        altcp_close(tpcb);
        return ERR_OK;
    }

    if (!tls_test_data_received)
    {
        size_t to_copy = (p->tot_len < sizeof(tls_test_recv_buf) - 1)
                             ? p->tot_len
                             : (sizeof(tls_test_recv_buf) - 1);
        pbuf_copy_partial(p, tls_test_recv_buf, (u16_t)to_copy, 0);
        tls_test_recv_buf[to_copy] = '\0';
        tls_test_recv_len = to_copy;
        tls_test_data_received = true;
    }

    altcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void tls_test_error_callback(void *arg, err_t err)
{
    (void)arg;
    (void)err;
    tls_test_error = true;
}

static bool config_run_tls_test(struct config_option *opt)
{
    (void)opt;

    if (!setup_test_network("TLS Test"))
    {
        return true;
    }

    os_FontDrawText("Target: example.com:443", 10, 50);

    /* Resolve example.com */
    int timeout;
    fill_rect(0, 50, 320, 14, COLOR_WHITE);
    os_FontDrawText("Resolving example.com...", 10, 50);
    dns_result_ready = false;

    ip_addr_t server_addr;
    err_t err = dns_gethostbyname("example.com", &server_addr, dns_test_callback, NULL);

    if (err == ERR_INPROGRESS)
    {
        timeout = 1000;
        while (timeout > 0 && !dns_result_ready)
        {
            usb_HandleEvents();
            sys_check_timeouts();
            if (os_GetCSC() == sk_Clear)
            {
                cleanup_test_screen_fast();
                return true;
            }
            delay_ms(10);
            timeout--;
        }

        if (!dns_result_ready || dns_result_err != ERR_OK)
        {
            os_FontDrawText("DNS lookup failed", 10, 70);
            cleanup_test_screen();
            return true;
        }
        server_addr = dns_resolved_ip;
    }
    else if (err != ERR_OK)
    {
        os_FontDrawText("DNS lookup failed", 10, 70);
        cleanup_test_screen();
        return true;
    }

    /* Show resolved IP and reject loopback */
    {
        char ip_buf[48];
        snprintf(ip_buf, sizeof(ip_buf), "-> %d.%d.%d.%d",
                 ip4_addr1(&server_addr.u_addr.ip4),
                 ip4_addr2(&server_addr.u_addr.ip4),
                 ip4_addr3(&server_addr.u_addr.ip4),
                 ip4_addr4(&server_addr.u_addr.ip4));
        fill_rect(0, 50, 320, 14, COLOR_WHITE);
        os_FontDrawText(ip_buf, 10, 50);

        if (ip4_addr1(&server_addr.u_addr.ip4) == 127) {
            os_FontDrawText("Loopback addr - DNS issue", 10, 70);
            cleanup_test_screen();
            return true;
        }
    }

    /* Create ECDHE-only TLS config + connection (includes ~5s X25519 keygen) */
    os_FontDrawText("X25519 keygen (~5s)...", 10, 70);

    struct altcp_tls_ce_config *tls_conf = altcp_tls_ce_create_config_client_ecdhe("example.com");
    if (!tls_conf)
    {
        os_FontDrawText("Config creation failed", 10, 90);
        cleanup_test_screen();
        return true;
    }

    /* Flush any pending events/cleanup from prior tests */
    usb_HandleEvents();
    sys_check_timeouts();

    struct altcp_pcb *tls_pcb = altcp_tls_ce_new(tls_conf, IPADDR_TYPE_V4);
    if (!tls_pcb)
    {
        altcp_tls_ce_free_config(tls_conf);
        os_FontDrawText("TLS PCB creation failed", 10, 70);
        cleanup_test_screen();
        return true;
    }

    tls_test_connected = false;
    tls_test_error = false;
    tls_test_data_received = false;
    tls_test_recv_len = 0;

    altcp_arg(tls_pcb, NULL);
    altcp_recv(tls_pcb, tls_test_recv_callback);
    altcp_err(tls_pcb, tls_test_error_callback);

    fill_rect(0, 70, 320, 14, COLOR_WHITE);
    os_FontDrawText("Connecting + handshake...", 10, 70);

    err = altcp_connect(tls_pcb, &server_addr, 443, tls_test_connected_callback);
    if (err != ERR_OK)
    {
        altcp_abort(tls_pcb);
        altcp_tls_ce_free_config(tls_conf);
        os_FontDrawText("Connect failed", 10, 70);
        cleanup_test_screen();
        return true;
    }

    /* Wait for TLS handshake + connected callback (may take ~15-20s for ECDHE) */
    timeout = 6000; /* 60 seconds */
    while (timeout > 0 && !tls_test_connected && !tls_test_error)
    {
        usb_HandleEvents();
        sys_check_timeouts();
        if (!test_network_available())
        {
            altcp_abort(tls_pcb);
            altcp_tls_ce_free_config(tls_conf);
            cleanup_test_screen_fast();
            return true;
        }
        if (os_GetCSC() == sk_Clear)
        {
            altcp_abort(tls_pcb);
            altcp_tls_ce_free_config(tls_conf);
            cleanup_test_screen_fast();
            return true;
        }
        delay_ms(10);
        timeout--;
    }

    if (tls_test_error || !tls_test_connected)
    {
        altcp_abort(tls_pcb);
        altcp_tls_ce_free_config(tls_conf);
        fill_rect(0, 70, 320, 14, COLOR_WHITE);
        os_FontDrawText("Handshake failed/timeout", 10, 70);
        cleanup_test_screen();
        return true;
    }

    fill_rect(0, 70, 320, 14, COLOR_WHITE);
    os_FontDrawText("TLS connected! Waiting...", 10, 70);

    /* Wait for HTTP response */
    timeout = 1000; /* 10 seconds */
    while (timeout > 0 && !tls_test_data_received && !tls_test_error)
    {
        usb_HandleEvents();
        sys_check_timeouts();
        if (!test_network_available())
        {
            altcp_close(tls_pcb);
            altcp_tls_ce_free_config(tls_conf);
            cleanup_test_screen_fast();
            return true;
        }
        if (os_GetCSC() == sk_Clear)
        {
            altcp_close(tls_pcb);
            altcp_tls_ce_free_config(tls_conf);
            cleanup_test_screen_fast();
            return true;
        }
        delay_ms(10);
        timeout--;
    }

    fill_rect(0, 70, 320, 150, COLOR_WHITE);
    if (tls_test_data_received)
    {
        /* Check for HTTP 200 OK */
        if (strstr(tls_test_recv_buf, "200 OK") != NULL)
        {
            os_SetDrawFGColor(0x07E0); /* Green */
            os_FontDrawText("TLS Test PASSED!", 10, 70);
            os_SetDrawFGColor(COLOR_BLACK);
            os_FontDrawText("Got HTTP 200 from example.com", 10, 90);
        }
        else
        {
            os_FontDrawText("Got response (not 200):", 10, 70);
        }

        /* Show first line of response */
        char *newline = strchr(tls_test_recv_buf, '\r');
        if (newline) *newline = '\0';
        char status_line[48];
        snprintf(status_line, sizeof(status_line), "  %.44s", tls_test_recv_buf);
        os_FontDrawText(status_line, 10, 110);
    }
    else
    {
        os_SetDrawFGColor(0xF800); /* Red */
        os_FontDrawText("TLS Test FAILED", 10, 70);
        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawText("No response received", 10, 90);
    }

    altcp_close(tls_pcb);
    altcp_tls_ce_free_config(tls_conf);

    cleanup_test_screen();
    return true;
}
#endif

static void format_tz_offset(char *buf, size_t buf_len, int16_t minutes)
{
    char sign = '+';
    int16_t abs_min = minutes;
    if (minutes < 0)
    {
        sign = '-';
        abs_min = (int16_t)(-minutes);
    }
    if (abs_min == 0)
    {
        snprintf(buf, buf_len, "UTC");
        return;
    }
    uint8_t hours = (uint8_t)(abs_min / 60);
    uint8_t mins = (uint8_t)(abs_min % 60);
    snprintf(buf, buf_len, "UTC%c%u:%02u", sign, hours, mins);
}

// ============================================================================
// Modal Dialog Functions - Clean professional design
// ============================================================================

// Draw a modal dialog box
static void ui_dialog_box(int x, int y, int w, int h, const char *title)
{
    // Shadow effect
    ui_fill_rect(x + 3, y + 3, w, h, UI_COLOR_SEPARATOR);
    // Main box
    ui_box(x, y, w, h, UI_COLOR_BG, UI_COLOR_FG);
    // Title bar
    ui_fill_rect(x + 2, y + 2, w - 4, 18, UI_COLOR_HEADER);
    os_SetDrawFGColor(UI_COLOR_BG);
    int tw = (int)os_FontGetWidth(title);
    os_FontDrawTransText(title, x + (w - tw) / 2, y + 4);
}

// Draw text input field
static void ui_input_field(int x, int y, int w, const char *text, bool cursor)
{
    ui_fill_rect(x, y, w, 16, UI_COLOR_BG);
    ui_fill_rect(x, y + 14, w, 2, UI_COLOR_FG);
    os_SetDrawFGColor(UI_COLOR_FG);
    os_FontDrawTransText(text, x + 2, y + 2);

    // Draw block cursor after text (flush with underline)
    if (cursor)
    {
        int text_w = (int)os_FontGetWidth(text);
        ui_fill_rect(x + 2 + text_w + 1, y + 4, 8, 10, UI_COLOR_ACCENT);
    }
}

// Draw slider control
static void ui_slider(int x, int y, int w, int value, int min_val, int max_val)
{
    int range = max_val - min_val;
    int pos = range > 0 ? ((value - min_val) * (w - 12)) / range : 0;

    // Track
    ui_fill_rect(x, y + 5, w, 4, UI_COLOR_SEPARATOR);
    // Thumb
    ui_fill_rect(x + pos, y, 12, 14, UI_COLOR_ACCENT);
}

// Map scancode to digit character
static char scancode_to_digit(uint8_t key)
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
        default: return 0;
    }
}

// Helper to draw just the number input field
static void ui_draw_number_input(int x, int y, int w, const char *digits)
{
    ui_input_field(x, y, w, digits, true);
}

// Numeric entry dialog (0-255)
static bool ui_edit_number(const char *title, uint8_t *value, uint8_t max_val)
{
    char digits[4] = {0};
    int pos = 0;

    // Dialog layout
    const int dlg_x = 70, dlg_y = 80, dlg_w = 180, dlg_h = 60;
    const int input_x = 90, input_y = 110, input_w = 100;

    // Initial full draw
    ui_dialog_box(dlg_x, dlg_y, dlg_w, dlg_h, title);
    ui_draw_number_input(input_x, input_y, input_w, digits);
    ui_draw_footer("<0-9> Type  <del> Back",
                   "<enter> OK  <clear> Cancel");

    while (1)
    {
        uint8_t key = 0;
        do { key = os_GetCSC(); } while (key == 0);

        if (key == sk_Clear) return false;
        if (key == sk_Enter && pos > 0)
        {
            int val = 0;
            for (int i = 0; i < pos; i++)
                val = val * 10 + (digits[i] - '0');
            if (val <= max_val)
            {
                *value = (uint8_t)val;
                return true;
            }
            // Value too large - just continue, don't update
            continue;
        }
        if (key == sk_Del && pos > 0)
        {
            digits[--pos] = 0;
            ui_draw_number_input(input_x, input_y, input_w, digits);
            continue;
        }

        char c = scancode_to_digit(key);
        if (c && pos < 3)
        {
            digits[pos++] = c;
            digits[pos] = 0;
            ui_draw_number_input(input_x, input_y, input_w, digits);
        }
    }
}

// Input modes for text editing
typedef enum {
    INPUT_MODE_LOWER = 0,  // a-z
    INPUT_MODE_UPPER,      // A-Z
    INPUT_MODE_DIGIT,      // 0-9
    INPUT_MODE_COUNT
} input_mode_t;

static const char *input_mode_names[INPUT_MODE_COUNT] = {"a-z", "A-Z", "0-9"};

static char scancode_to_alpha(uint8_t key, input_mode_t mode)
{
    // Letter keymap (lowercase)
    static const char keymap[64] = {
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   '"', 'w', 'r', 'm', 'h', 0,
        0,   '?', '[', 'v', 'q', 'l', 'g', 0,
        0,   ':', 'z', 'u', 'p', 'k', 'f', 'c',
        0,   ' ', 'y', 't', 'o', 'j', 'e', 'b',
        0,   0,   'x', 's', 'n', 'i', 'd', 'a',
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0
    };

    // Handle digit mode
    if (mode == INPUT_MODE_DIGIT)
    {
        if (key == sk_0) return '0';
        if (key == sk_1) return '1';
        if (key == sk_2) return '2';
        if (key == sk_3) return '3';
        if (key == sk_4) return '4';
        if (key == sk_5) return '5';
        if (key == sk_6) return '6';
        if (key == sk_7) return '7';
        if (key == sk_8) return '8';
        if (key == sk_9) return '9';
        // Allow space in digit mode too
        if (key < 64 && keymap[key] == ' ') return ' ';
        return 0;
    }

    // Handle letter modes
    if (key >= 64) return 0;
    char c = keymap[key];
    if (c >= 'a' && c <= 'z' && mode == INPUT_MODE_UPPER)
    {
        c = (char)(c - 'a' + 'A');
    }
    return c;
}

// Helper to draw just the mode indicator
static void ui_draw_hostname_mode(int y, input_mode_t mode)
{
    // Clear mode area and redraw
    ui_fill_rect(55, y, 100, 14, UI_COLOR_BG);
    char mode_str[24];
    snprintf(mode_str, sizeof(mode_str), "Mode: %s", input_mode_names[mode]);
    os_SetDrawFGColor(UI_COLOR_ACCENT);
    os_FontDrawTransText(mode_str, 55, y);
}

// Helper to draw just the hostname input field
static void ui_draw_hostname_input(int y, const char *buffer)
{
    ui_input_field(55, y, 200, buffer, true);
}

static void edit_hostname_config(lwip_app_config_t *cfg)
{
    char buffer[LWIP_CFG_HOSTNAME_MAX];
    strncpy(buffer, cfg->hostname, LWIP_CFG_HOSTNAME_MAX - 1);
    buffer[LWIP_CFG_HOSTNAME_MAX - 1] = '\0';
    int pos = (int)strlen(buffer);
    input_mode_t mode = INPUT_MODE_LOWER;

    // Dialog layout constants
    const int dlg_x = 30, dlg_y = 60, dlg_w = 260, dlg_h = 70;
    const int mode_y = 82;
    const int input_y = 98;

    // Initial full draw
    ui_dialog_box(dlg_x, dlg_y, dlg_w, dlg_h, "Edit Hostname");
    ui_draw_hostname_mode(mode_y, mode);
    ui_draw_hostname_input(input_y, buffer);
    ui_draw_footer("<alpha> Mode  <del> Back",
                   "<enter> OK  <clear> Cancel");

    while (1)
    {
        uint8_t key = 0;
        do { key = os_GetCSC(); } while (key == 0);

        if (key == sk_Clear) return;
        if (key == sk_Enter)
        {
            strncpy(cfg->hostname, buffer, LWIP_CFG_HOSTNAME_MAX - 1);
            cfg->hostname[LWIP_CFG_HOSTNAME_MAX - 1] = '\0';
            return;
        }
        if (key == sk_Del && pos > 0)
        {
            buffer[--pos] = '\0';
            ui_draw_hostname_input(input_y, buffer);
            continue;
        }
        if (key == sk_Alpha)
        {
            mode = (input_mode_t)((mode + 1) % INPUT_MODE_COUNT);
            ui_draw_hostname_mode(mode_y, mode);
            continue;
        }

        char c = scancode_to_alpha(key, mode);
        if (c && pos < LWIP_CFG_HOSTNAME_MAX - 1)
        {
            buffer[pos++] = c;
            buffer[pos] = '\0';
            ui_draw_hostname_input(input_y, buffer);
        }
    }
}

// IP config layout constants
#define IP_ROW_Y(f)     (50 + (f) * 28)
#define IP_LABEL_X      20
#define IP_ADDR_X       100
#define IP_OCTET_W      38

// Draw just the octets for a single IP row (not the label)
static void ui_draw_ip_octets(int y, const uint8_t *addr, bool selected, int sel_octet)
{
    // Clear octet area
    ui_fill_rect(IP_ADDR_X - 2, y + 2, 4 * IP_OCTET_W, 18,
                 selected ? UI_COLOR_SELECTED : UI_COLOR_BG);

    for (int o = 0; o < 4; o++)
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "%u", addr[o]);
        int x = IP_ADDR_X + o * IP_OCTET_W;

        if (selected && o == sel_octet)
        {
            ui_fill_rect(x - 2, y + 2, 32, 18, UI_COLOR_ACCENT);
            os_SetDrawFGColor(UI_COLOR_BG);
        }
        else
        {
            os_SetDrawFGColor(UI_COLOR_FG);
        }
        os_FontDrawTransText(buf, x, y + 4);

        if (o < 3)
        {
            os_SetDrawFGColor(UI_COLOR_FG);
            os_FontDrawTransText(".", x + 26, y + 4);
        }
    }
}

// Draw full IP row (label + octets)
static void ui_draw_ip_row_full(int y, const char *label, const uint8_t *addr,
                                 bool selected, int sel_octet)
{
    uint16_t bg = selected ? UI_COLOR_SELECTED : UI_COLOR_BG;
    ui_fill_rect(10, y, 300, 22, bg);

    os_SetDrawFGColor(UI_COLOR_FG);
    os_FontDrawTransText(label, IP_LABEL_X, y + 4);

    ui_draw_ip_octets(y, addr, selected, sel_octet);
}

static void edit_ip_config(lwip_app_config_t *cfg)
{
    int field = 0;
    int octet = 0;
    const char *labels[3] = {"IP", "Gateway", "Netmask"};
    uint8_t *addrs[3] = {cfg->ip_addr, cfg->ip_gateway, cfg->ip_netmask};

    // Initial full draw
    boot_ClearVRAM();
    os_FontSelect(os_SmallFont);
    ui_draw_header("IP Configuration");
    for (int f = 0; f < 3; f++)
    {
        ui_draw_ip_row_full(IP_ROW_Y(f), labels[f], addrs[f], f == field, octet);
    }
    ui_draw_footer("<arrows> Navigate  <enter> Edit",
                   "<clear> Done");

    while (1)
    {
        uint8_t key = 0;
        do { key = os_GetCSC(); } while (key == 0);

        if (key == sk_Clear) return;

        int old_field = field;
        int old_octet = octet;

        if (key == sk_Up && field > 0) field--;
        else if (key == sk_Down && field < 2) field++;
        else if (key == sk_Left && octet > 0) octet--;
        else if (key == sk_Right && octet < 3) octet++;
        else if (key == sk_Enter)
        {
            if (ui_edit_number("Edit Octet", &addrs[field][octet], 255))
            {
                // Full redraw after modal dialog
                boot_ClearVRAM();
                os_FontSelect(os_SmallFont);
                ui_draw_header("IP Configuration");
                for (int f = 0; f < 3; f++)
                {
                    ui_draw_ip_row_full(IP_ROW_Y(f), labels[f], addrs[f], f == field, octet);
                }
                ui_draw_footer("<arrows> Navigate  <enter> Edit",
                               "<clear> Done");
            }
            continue;
        }

        // Only redraw changed rows
        if (field != old_field)
        {
            // Row changed - redraw old and new rows
            ui_draw_ip_row_full(IP_ROW_Y(old_field), labels[old_field], addrs[old_field], false, -1);
            ui_draw_ip_row_full(IP_ROW_Y(field), labels[field], addrs[field], true, octet);
        }
        else if (octet != old_octet)
        {
            // Just octet changed - only redraw octets on current row
            ui_draw_ip_octets(IP_ROW_Y(field), addrs[field], true, octet);
        }
    }
}

#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
static void apply_network_config(const lwip_app_config_t *cfg)
{
    lwip_sntp_set_timezone_offset((int32_t)cfg->tz_offset_minutes * 60);
    lwip_sntp_set_dst_enabled(cfg->dst_enabled != 0);

    if (cfg->flags & LWIP_CFG_DHCP)
    {
        if (netif_default && !dhcp_client_running(netif_default))
        {
            dhcp_start(netif_default);
            dhcp_started = true;
            manual_ip_applied = false;
        }
        else if (netif_default)
        {
            dhcp_started = true;
        }
    }
    else
    {
        if (netif_default && !manual_ip_applied)
        {
            ip4_addr_t ip, gw, mask;
            IP4_ADDR(&ip, cfg->ip_addr[0], cfg->ip_addr[1], cfg->ip_addr[2], cfg->ip_addr[3]);
            IP4_ADDR(&gw, cfg->ip_gateway[0], cfg->ip_gateway[1], cfg->ip_gateway[2], cfg->ip_gateway[3]);
            IP4_ADDR(&mask, cfg->ip_netmask[0], cfg->ip_netmask[1], cfg->ip_netmask[2], cfg->ip_netmask[3]);
            netif_set_addr(netif_default, &ip, &mask, &gw);
            manual_ip_applied = true;
            dhcp_started = false;
        }
    }

    if (cfg->flags & LWIP_CFG_AUTO_NTP)
    {
        if (netif_default && !sntp_started)
        {
            sntp_servermode_dhcp(1);
            const ip_addr_t *server = sntp_getserver(0);
            if (server && !ip_addr_isany(server))
            {
                sntp_setoperatingmode(SNTP_OPMODE_POLL);
                sntp_init();
                sntp_started = true;
            }
        }
    }
    else if (sntp_started)
    {
        sntp_stop();
        sntp_started = false;
    }

    if (cfg->flags & LWIP_CFG_DNS)
    {
        dns_init();
    }

    if ((cfg->flags & LWIP_CFG_TEST_HTTP) != 0)
    {
        if (netif_default && !httpd_running)
        {
            bool has_ip = false;
            if ((cfg->flags & LWIP_CFG_DHCP) != 0)
            {
                has_ip = dhcp_supplied_address(netif_default);
            }
            else
            {
                has_ip = !ip4_addr_isany(netif_ip4_addr(netif_default));
            }
            if (has_ip)
            {
                httpd_init();
                httpd_running = true;
            }
        }
    }
    else
    {
        httpd_running = false;
    }

    if (!netif_default)
    {
        dhcp_started = false;
        manual_ip_applied = false;
        if (sntp_started)
        {
            sntp_stop();
            sntp_started = false;
        }
    }
}

static void cleanup_lwip_stack(void)
{
    if (!lwip_started)
    {
        return;
    }
    lwip_started = false;

    lwip_dispatch_stop();
    eth_prepare_shutdown();

    if (sntp_started)
    {
        sntp_stop();
        sntp_started = false;
    }

    struct netif *n = NULL;
    NETIF_FOREACH(n)
    {
#if LWIP_DHCP
        if (dhcp_client_running(n))
        {
            dhcp_release_and_stop(n);
        }
#endif
    }

    lwip_teardown_abort_pcbs();

    NETIF_FOREACH(n)
    {
        netif_set_link_down(n);
        netif_set_down(n);
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ti_CloseAll();
#pragma GCC diagnostic pop
    dhcp_started = false;
    manual_ip_applied = false;
    httpd_running = false;
    eth_finish_shutdown();
    usb_Cleanup();
}

static void lwip_fatal_cleanup(void)
{
    cleanup_lwip_stack();
}

static bool start_lwip_stack(const lwip_app_config_t *cfg)
{
    (void)cfg;

    if (lwip_started)
    {
        return true;
    }

    eth_reset_shutdown();

    if (lwip_init() != ERR_OK)
    {
        os_FontDrawText("lwip/mem init failed", 2, 2);
        os_GetKey();
        return false;
    }

    netif_add_ext_callback(&netif_ext_cb, netif_ext_callback);

    if (usb_fn.init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        os_FontDrawText("usb init failed", 2, 2);
        os_GetKey();
        return false;
    }

    lwip_started = true;
    return true;
}
#endif

int main(void)
{
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
    atexit(cleanup_lwip_stack);
    lwip_debug_set_fatal_cleanup(lwip_fatal_cleanup);
#endif

    lwip_app_config_load(&g_cfg);

    /* Clamp lwip_mem_cap so it stays between the feature floor and the
     * current free RAM.  A stored config from a time when the device had
     * more free RAM shouldn't overflow what's actually available now. */
    config_clamp_mem_cap(&g_cfg);
    config_sync_from_cfg();

    // Clear screen and set up font
    boot_ClearVRAM();
    os_FontSelect(os_SmallFont);

    // New single-menu state
    int selected = find_first_selectable();
    int scroll_pos = 0;
    edit_mode_t edit_mode = EDIT_NONE;
    int edit_option = -1;
    bool needs_redraw = true;

    while (run_main)
    {
#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
        if (lwip_started)
        {
            apply_network_config(&g_cfg);
            usb_HandleEvents();
            sys_check_timeouts();
        }
#endif

        if (needs_redraw)
        {
            ui_draw_full(selected, scroll_pos, edit_mode);
            needs_redraw = false;
        }

        uint8_t key = os_GetCSC();
        if (key == 0) continue;

        // Exit
        if (key == sk_Clear && edit_mode == EDIT_NONE)
        {
            run_main = false;
            break;
        }

        // Save
        if (key == sk_2nd)
        {
            lwip_app_config_save(&g_cfg);
            config_sync_from_cfg();
            ui_draw_menu(selected, scroll_pos, false);
            continue;
        }

        // Handle edit mode (slider adjustments)
        if (edit_mode != EDIT_NONE)
        {
            if (key == sk_Clear || key == sk_Enter)
            {
                int old_edit = edit_option;
                edit_mode_t old_mode = edit_mode;
                edit_mode = EDIT_NONE;
                edit_option = -1;
                if (old_mode == EDIT_MEM_CAP)
                {
                    /* Breakdown panel was covering the menu — restore it */
                    ui_draw_menu(selected, scroll_pos, false);
                }
                else
                {
                    ui_draw_single_option(old_edit, scroll_pos, selected, false);
                }
                ui_draw_mode_footer(false, EDIT_NONE);
                continue;
            }
            bool value_changed = false;
            if (edit_mode == EDIT_MEM_CAP && edit_option >= 0 &&
                (key == sk_Left || key == sk_Right))
            {
                struct config_option *opt = &config_options[edit_option];
                /* Bounds recomputed each keystroke so the ceiling always
                 * reflects current free RAM, not a stale snapshot. */
                size_t   floor   = config_required_lwip_floor(&g_cfg);
                uint16_t cap_max = config_mem_cap_max();
                if (key == sk_Left &&
                    g_cfg.lwip_mem_cap >= (uint16_t)floor + LWIP_CFG_MEM_CAP_STEP)
                {
                    g_cfg.lwip_mem_cap = (uint16_t)(g_cfg.lwip_mem_cap - LWIP_CFG_MEM_CAP_STEP);
                    option_sync_from_cfg(opt);
                    value_changed = true;
                }
                else if (key == sk_Right &&
                         g_cfg.lwip_mem_cap + LWIP_CFG_MEM_CAP_STEP <= cap_max)
                {
                    g_cfg.lwip_mem_cap = (uint16_t)(g_cfg.lwip_mem_cap + LWIP_CFG_MEM_CAP_STEP);
                    option_sync_from_cfg(opt);
                    value_changed = true;
                }
            }
            else if (key == sk_Left && edit_mode == EDIT_TZ && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_TZ_OFFSET && g_cfg.tz_offset_minutes > LWIP_CFG_TZ_MIN_MINUTES)
                {
                    g_cfg.tz_offset_minutes = (int16_t)(g_cfg.tz_offset_minutes - LWIP_CFG_TZ_STEP_MINUTES);
                    option_sync_from_cfg(opt);
                    value_changed = true;
                }
            }
            else if (key == sk_Right && edit_mode == EDIT_TZ && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_TZ_OFFSET && g_cfg.tz_offset_minutes < LWIP_CFG_TZ_MAX_MINUTES)
                {
                    g_cfg.tz_offset_minutes = (int16_t)(g_cfg.tz_offset_minutes + LWIP_CFG_TZ_STEP_MINUTES);
                    option_sync_from_cfg(opt);
                    value_changed = true;
                }
            }
            if (value_changed)
            {
                if (edit_mode == EDIT_MEM_CAP)
                {
                    /* Breakdown panel replaces the menu while editing the cap */
                    ui_draw_mem_breakdown();
                }
                else
                {
                    ui_draw_single_option(selected, scroll_pos, selected, true);
                }
            }
            continue;
        }

        // Navigation - Up/Down
        if (key == sk_Up || key == sk_Down)
        {
            int dir = (key == sk_Up) ? -1 : 1;
            int new_sel = find_next_selectable(selected, dir);
            if (new_sel != selected)
            {
                int old_sel = selected;
                int old_scroll = scroll_pos;
                selected = new_sel;
                scroll_pos = ui_ensure_visible(selected, scroll_pos);
                if (scroll_pos != old_scroll)
                {
                    // Page shifted - use fast VRAM scroll
                    int scroll_diff = scroll_pos - old_scroll;
                    int abs_diff = scroll_diff > 0 ? scroll_diff : -scroll_diff;

                    // Redraw old selection as unselected BEFORE scroll
                    // so shifted pixels don't have selection highlight
                    ui_draw_single_option(old_sel, old_scroll, old_sel + 1, false);

                    // Shift VRAM content
                    ui_scroll_content(scroll_diff);

                    // Draw the new rows that scrolled into view
                    if (scroll_diff > 0)
                    {
                        // Scrolled down: draw new rows at bottom
                        for (int i = 0; i < abs_diff && i < UI_VISIBLE_ROWS; i++)
                        {
                            int idx = scroll_pos + UI_VISIBLE_ROWS - 1 - i;
                            if (idx < (int)CONFIG_OPTION_COUNT)
                                ui_draw_single_option(idx, scroll_pos, selected, false);
                        }
                    }
                    else
                    {
                        // Scrolled up: draw new rows at top
                        for (int i = 0; i < abs_diff && i < UI_VISIBLE_ROWS; i++)
                        {
                            int idx = scroll_pos + i;
                            if (idx >= 0)
                                ui_draw_single_option(idx, scroll_pos, selected, false);
                        }
                    }
                    // Redraw new selection
                    ui_draw_single_option(selected, scroll_pos, selected, false);
                    // Update scrollbar
                    ui_draw_scrollbar(scroll_pos, (int)CONFIG_OPTION_COUNT);
                }
                else
                {
                    // Same page, only redraw old and new rows
                    ui_draw_single_option(old_sel, scroll_pos, selected, false);
                    ui_draw_single_option(selected, scroll_pos, selected, false);
                }
            }
            continue;
        }

        // Enter - activate option
        if (key == sk_Enter && selected >= 0)
        {
            struct config_option *opt = &config_options[selected];

            if (opt->type == F_TYPE_INT_SLIDER)
            {
                // Enter edit mode for sliders
                switch (opt->id)
                {
                case OPT_MEM_CAP:
                    edit_mode = EDIT_MEM_CAP;
                    edit_option = selected;
                    break;
                case OPT_TZ_OFFSET:
                    edit_mode = EDIT_TZ;
                    edit_option = selected;
                    break;
                default:
                    break;
                }
                /* Memory cap gets a full breakdown panel; other sliders just
                 * highlight the single row as before. */
                if (edit_mode == EDIT_MEM_CAP)
                {
                    ui_draw_mem_breakdown();
                }
                else
                {
                    ui_draw_single_option(selected, scroll_pos, selected, true);
                }
                ui_draw_mode_footer(true, edit_mode);
            }
            else if (opt->type == F_TYPE_BOOL_TOGGLE && opt->setter)
            {
                opt->setter(opt);
                // Only redraw the single row that toggled.
                ui_draw_single_option(selected, scroll_pos, selected, false);
            }
            else if (opt->type == F_TYPE_ACTION && opt->setter)
            {
                // Skip IP config if DHCP is on
                if (opt->id == OPT_EDIT_IP && (g_cfg.flags & LWIP_CFG_DHCP))
                {
                    continue;
                }
                opt->setter(opt);
                // Action dialogs clear screen, redraw everything
                needs_redraw = true;
            }
            continue;
        }

        // Left/Right for slider quick adjust in edit mode is handled above
    }

#if LWIP_APP_ENABLE_SERVICE_EXAMPLES
    cleanup_lwip_stack();
#endif

    lwip_app_config_save(&g_cfg);

    // Restore OS drawing state before exit
    // Reset all OS color state variables to defaults
    os_SetDrawFGColor(0x0000); // Black
    os_SetDrawBGColor(0xFFFF); // White

    // Reset the direct OS color variables too
    os_DrawFGColor = 0x0000; // Small font FG
    os_DrawBGColor = 0xFFFF; // Small font BG
    os_TextFGColor = 0x0000; // Large font FG
    os_TextBGColor = 0xFFFF; // Large font BG
    os_DrawColorCode = 0;    // Reset color code

    // Reset font positions
    os_PenCol = 0;
    os_PenRow = 0;
    os_CurRow = 0;
    os_CurCol = 0;

    // Select OS default font
    os_FontSelect(os_LargeFont);

    // Clear text shadow area to prevent cursor artifacts
    os_ClrTxtShd();

    // Full homescreen reset with status bar
    os_ClrHomeFull();

    return 0;
}
