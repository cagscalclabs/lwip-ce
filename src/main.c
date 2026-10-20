#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ti/getcsc.h>
#include <ti/screen.h>
#include <ti/vars.h>

#include "lwip/app_config.h"
#include "drivers/pcap.h"
#include "drivers/pcap_decode.h"
#include "lwip-imports.h"
#include "lwIP.h"
#include "app/ui.h"
#include "app/wifi_screen.h"

#define TZ_MIN_MINUTES (-12 * 60)
#define TZ_MAX_MINUTES (14 * 60)
#define TZ_STEP_MINUTES 15
#define PCAP_MAX_LIST 48
#define PCAP_HEX_COLS 8
#define PCAP_LINE_ROWS 14

enum
{
    ROW_SECTION,
    ROW_WIFI,
    ROW_HOSTNAME,
    ROW_TIMEZONE,
    ROW_DST,
    ROW_TLS,
    ROW_CRYPTO_OFFLOAD,
    ROW_BRIDGE_RNG,
    ROW_PCAP_SIZE,
    ROW_PCAP_VIEW
};

static lwip_app_config_t g_cfg;
static size_t g_pcap_offsets[PCAP_MAX_LIST];

static void format_tz(char *buf, size_t size, int16_t minutes)
{
    int16_t abs_min = minutes < 0 ? (int16_t)-minutes : minutes;

    if (!minutes)
        snprintf(buf, size, "UTC");
    else
        snprintf(buf, size, "UTC%c%u:%02u", minutes < 0 ? '-' : '+', abs_min / 60, abs_min % 60);
}

static uint16_t next_pcap_size(uint16_t current, bool up)
{
    static const uint16_t sizes[] = {
        LWIP_CFG_PCAP_SIZE_4K, LWIP_CFG_PCAP_SIZE_8K, LWIP_CFG_PCAP_SIZE_16K, LWIP_CFG_PCAP_SIZE_32K
    };
    int index = 0;

    while (index < 3 && sizes[index] < current)
        index++;
    if (up && index < 3)
        index++;
    if (!up && index > 0)
        index--;
    return sizes[index];
}

static int load_pcap_offsets(void)
{
    struct pcap_reader_ctx ctx;
    struct pcap *hdr;
    const uint8_t *data;
    int count = 0;

    if (!pcap_init_reader_ctx(&ctx))
        return 0;
    while (count < PCAP_MAX_LIST && pcap_read_next(&ctx, &hdr, &data))
        g_pcap_offsets[count++] = ctx.offset - sizeof(struct pcap) - hdr->len;
    pcap_close_reader_ctx(&ctx);
    return count;
}

static const struct pcap *pcap_at(int index)
{
    var_t *var = os_GetAppVarData("lwIPPCAP", NULL);

    return var ? (const struct pcap *)((const uint8_t *)var->data + g_pcap_offsets[index]) : NULL;
}

static int pcap_detail_rows(const struct pcap_decoded *decoded)
{
    int rows = 0;

    for (unsigned i = 0; i < decoded->count; i++)
        rows += 1 + (int)((decoded->section[i].length + PCAP_HEX_COLS - 1) / PCAP_HEX_COLS);
    return rows;
}

static void pcap_detail_line(const struct pcap_decoded *decoded, const uint8_t *data, int row,
                             char *buf, size_t size)
{
    buf[0] = '\0';
    for (unsigned j = 0; j < decoded->count; j++)
    {
        const struct pcap_section *section = &decoded->section[j];
        int rows = 1 + (int)((section->length + PCAP_HEX_COLS - 1) / PCAP_HEX_COLS);

        if (row >= rows)
        {
            row -= rows;
            continue;
        }
        if (!row)
        {
            snprintf(buf, size, "%s: %s", section->name, section->detail ? section->detail : "");
            return;
        }

        size_t relative = (size_t)(row - 1) * PCAP_HEX_COLS;
        size_t offset = section->offset + relative;
        size_t n = section->length - relative;
        int pos = snprintf(buf, size, "%04X  ", (unsigned)offset);

        if (n > PCAP_HEX_COLS)
            n = PCAP_HEX_COLS;
        for (size_t i = 0; i < n; i++)
            pos += snprintf(buf + pos, size - (size_t)pos, "%02X ", data[offset + i]);
        return;
    }
}

static void pcap_detail(const struct pcap *hdr)
{
    const uint8_t *data = (const uint8_t *)hdr + sizeof(struct pcap);
    struct pcap_decoded decoded = pcap_decode(data, hdr->len);
    int total = pcap_detail_rows(&decoded);
    int scroll = 0;
    char title[32];

    snprintf(title, sizeof title, "%c%c%u %s, %u bytes", hdr->ifname[0], hdr->ifname[1], hdr->ifnum,
             hdr->direction == PCAP_DIR_TX ? "sent" : "received", hdr->len);

    for (;;)
    {
        char lines[PCAP_LINE_ROWS][48];
        const char *ptrs[PCAP_LINE_ROWS];
        int shown = 0;

        for (; shown < PCAP_LINE_ROWS && scroll + shown < total; shown++)
        {
            pcap_detail_line(&decoded, data, scroll + shown, lines[shown], sizeof lines[shown]);
            ptrs[shown] = lines[shown];
        }
        ui_frame(title, NULL, NULL, 0, "up/down: scroll   clear: back");
        ui_body_text(ptrs, shown, 0);
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Clear)
            return;
        if (key == sk_Up && scroll > 0)
            scroll--;
        if (key == sk_Down && scroll + PCAP_LINE_ROWS < total)
            scroll++;
    }
}

static void pcap_viewer(void)
{
    static ui_item_t items[PCAP_MAX_LIST];
    static char labels[PCAP_MAX_LIST][20];
    ui_list_t list = {0, 0};
    int count = load_pcap_offsets();

    if (!count)
    {
        ui_message("Packet capture", "No packets captured yet", NULL);
        return;
    }

    for (int i = 0; i < count; i++)
    {
        const struct pcap *hdr = pcap_at(i);

        if (!hdr)
            return;
        snprintf(labels[i], sizeof labels[i], "#%d  %c%c%u %s  %u B", i + 1, hdr->ifname[0], hdr->ifname[1],
                 hdr->ifnum, hdr->direction == PCAP_DIR_TX ? "TX" : "RX", hdr->len);
        items[i] = (ui_item_t){UI_ITEM_ACTION, labels[i], NULL, NULL, false, 0};
    }

    for (;;)
    {
        char right[16];

        snprintf(right, sizeof right, "%d packets", count);
        ui_frame("Packet capture", right, NULL, 0, "enter: view   clear: back");
        ui_list_draw(&list, items, count);
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Clear)
            return;
        ui_list_key(&list, items, count, key);
        if (key == sk_Enter)
        {
            const struct pcap *hdr = pcap_at(list.selected);
            if (hdr)
                pcap_detail(hdr);
        }
    }
}

static void edit_hostname(void)
{
    char buffer[LWIP_CFG_HOSTNAME_MAX];

    snprintf(buffer, sizeof buffer, "%s", g_cfg.hostname);
    if (ui_edit_text("Hostname", buffer, sizeof buffer, false) && buffer[0])
        snprintf(g_cfg.hostname, sizeof g_cfg.hostname, "%s", buffer);
}

static int build_menu(ui_item_t *items, uint8_t *roles, char *tz, size_t tz_size, char *pcap, size_t pcap_size,
                      bool has_pcap)
{
    uint8_t wifi_color;
    const char *wifi = app_wifi_summary(&wifi_color);
    int count = 0;

    format_tz(tz, tz_size, g_cfg.tz_offset_minutes);
    snprintf(pcap, pcap_size, "%u KiB", g_cfg.pcap_max_bytes / 1024u);

#define ADD(role, ...) (roles[count] = (role), items[count++] = (ui_item_t){__VA_ARGS__})
    ADD(ROW_SECTION, UI_ITEM_SECTION, "Network", NULL, NULL, false, 0);
    ADD(ROW_WIFI, UI_ITEM_ACTION, "Wi-Fi", "Saved networks and scanning", wifi, false, wifi_color);
    ADD(ROW_HOSTNAME, UI_ITEM_ACTION, "Hostname", "Name shown to the network", g_cfg.hostname, false, 0);
    ADD(ROW_SECTION, UI_ITEM_SECTION, "Time", NULL, NULL, false, 0);
    ADD(ROW_TIMEZONE, UI_ITEM_VALUE, "Timezone", "left/right to change", tz, false, 0);
    ADD(ROW_DST, UI_ITEM_TOGGLE, "Daylight saving", "Add an hour in summer", NULL, g_cfg.dst_enabled != 0, 0);
    ADD(ROW_SECTION, UI_ITEM_SECTION, "Security", NULL, NULL, false, 0);
    ADD(ROW_TLS, UI_ITEM_TOGGLE, "TLS", "Allow encrypted sockets", NULL, g_cfg.tls_enabled != 0, 0);
    ADD(ROW_CRYPTO_OFFLOAD, UI_ITEM_TOGGLE, "Crypto offload", "Bridge does TLS key math", NULL,
        g_cfg.crypto_offload != 0, 0);
    ADD(ROW_BRIDGE_RNG, UI_ITEM_TOGGLE, "Bridge TRNG", "Bridge supplies all randomness", NULL,
        g_cfg.bridge_rng != 0, 0);
    ADD(ROW_SECTION, UI_ITEM_SECTION, "Diagnostics", NULL, NULL, false, 0);
    ADD(ROW_PCAP_SIZE, UI_ITEM_VALUE, "Capture limit", "left/right to change", pcap, false, 0);
    if (has_pcap)
        ADD(ROW_PCAP_VIEW, UI_ITEM_ACTION, "Packet capture", "Inspect saved packets", NULL, false, 0);
#undef ADD
    return count;
}

static void restore_os_screen(void)
{
    os_SetDrawFGColor(0x0000);
    os_SetDrawBGColor(0xFFFF);
    os_DrawFGColor = 0x0000;
    os_DrawBGColor = 0xFFFF;
    os_TextFGColor = 0x0000;
    os_TextBGColor = 0xFFFF;
    os_DrawColorCode = 0;
    os_PenCol = 0;
    os_PenRow = 0;
    os_CurRow = 0;
    os_CurCol = 0;
    os_FontSelect(os_LargeFont);
    os_ClrTxtShd();
    os_ClrHomeFull();
}

int main(void)
{
    ui_item_t items[14];
    uint8_t roles[14];
    char tz[16];
    char pcap[16];
    char version[16];
    ui_list_t list = {1, 0};
    bool has_pcap;

    lwip_fileio_self_init();
    lwip_app_config_load(&g_cfg);
    has_pcap = load_pcap_offsets() > 0;
    snprintf(version, sizeof version, "v%s", lwip_version_string());

    ui_begin();
    ui_set_idle(app_net_idle);
    app_net_begin();

    for (;;)
    {
        int count = build_menu(items, roles, tz, sizeof tz, pcap, sizeof pcap, has_pcap);

        ui_frame("lwIP-CE Settings", version, NULL, 0, "enter: open   left/right: change   clear: save and quit");
        ui_list_draw(&list, items, count);
        ui_present();

        uint8_t key = ui_wait_key();
        uint8_t role = roles[list.selected];

        if (key == sk_Clear)
            break;
        if (ui_list_key(&list, items, count, key))
            continue;

        bool left = key == sk_Left;
        bool right = key == sk_Right;
        bool enter = key == sk_Enter;

        switch (role)
        {
        case ROW_WIFI:
            if (enter)
                app_wifi_screen();
            break;
        case ROW_HOSTNAME:
            if (enter)
                edit_hostname();
            break;
        case ROW_TIMEZONE:
            if (left && g_cfg.tz_offset_minutes > TZ_MIN_MINUTES)
                g_cfg.tz_offset_minutes = (int16_t)(g_cfg.tz_offset_minutes - TZ_STEP_MINUTES);
            if ((right || enter) && g_cfg.tz_offset_minutes < TZ_MAX_MINUTES)
                g_cfg.tz_offset_minutes = (int16_t)(g_cfg.tz_offset_minutes + TZ_STEP_MINUTES);
            break;
        case ROW_DST:
            if (enter || left || right)
                g_cfg.dst_enabled = right ? 1 : left ? 0 : (uint8_t)!g_cfg.dst_enabled;
            break;
        case ROW_TLS:
            if (enter || left || right)
                g_cfg.tls_enabled = right ? 1 : left ? 0 : (uint8_t)!g_cfg.tls_enabled;
            break;
        case ROW_CRYPTO_OFFLOAD:
            if (enter || left || right)
                g_cfg.crypto_offload = right ? 1 : left ? 0 : (uint8_t)!g_cfg.crypto_offload;
            break;
        case ROW_BRIDGE_RNG:
            if (enter || left || right)
                g_cfg.bridge_rng = right ? 1 : left ? 0 : (uint8_t)!g_cfg.bridge_rng;
            break;
        case ROW_PCAP_SIZE:
            if (left || right || enter)
                g_cfg.pcap_max_bytes = next_pcap_size(g_cfg.pcap_max_bytes, !left);
            break;
        case ROW_PCAP_VIEW:
            if (enter)
                pcap_viewer();
            break;
        default:
            break;
        }
    }

    app_net_stop();
    ui_set_idle(NULL);
    ui_end();
    lwip_app_config_save(&g_cfg);
    restore_os_screen();
    return 0;
}
