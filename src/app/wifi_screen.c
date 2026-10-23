#include <stdio.h>
#include <string.h>

#include <ti/getcsc.h>
#include <usbdrvce.h>

#include "lwip/init.h"
#include "lwip/mem.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/dispatch.h"
#include "lwip/app_config.h"
#include "lwip/log_file.h"
#include "drivers/mem.h"
#include "drivers/usb_ethernet.h"
#include "lwip-imports.h"
#include "wireless/wifi.h"
#include "../tls/includes/bytes.h"
#include "app/ui.h"
#include "app/wifi_screen.h"

#define NET_HEAP_START ((void *)0xD072C6)
#define NET_HEAP_SIZE (0xD13FD8 - 0xD072C6)
#define BRIDGE_WAIT_MS 6000
#define JOIN_WAIT_MS 12000
#define PROFILES_MAX 8
#define NETWORKS_MAX 20
#define ITEMS_MAX (PROFILES_MAX + NETWORKS_MAX + 8)

static bool g_net_started;
static bool g_net_failed;
static bool g_bridge_seen;
static volatile bool g_dirty;
static lwip_wifi_state_t g_state;
static bool g_state_valid;
static lwip_wifi_profile_t *g_profiles;
static uint8_t g_profile_count;
static lwip_wifi_network_t *g_networks;
static uint8_t g_network_count;
static ui_item_t *g_items;
static char (*g_values)[24];

static const char *const security_names[] = {
    "Open", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3"
};

#define SECURITY_COUNT (sizeof security_names / sizeof security_names[0])

static const char *security_name(uint8_t security)
{
    return security < SECURITY_COUNT ? security_names[security] : "?";
}

static void on_wifi_event(const lwip_wifi_state_t *state, void *arg)
{
    (void)arg;
    g_state = *state;
    g_state_valid = true;
    g_dirty = true;
}

static bool net_start(void)
{
    if (g_net_started)
        return true;
    if (g_net_failed)
        return false;

    g_net_failed = true;
    lwip_usb_self_init();
    if (!mem_is_ready() && !mem_init_static(NET_HEAP_START, NET_HEAP_SIZE))
        return false;
    eth_reset_shutdown();
    if (lwip_init() != ERR_OK)
        return false;
    if (lwip_app_config_get()->file_log_enabled)
        lwip_log_file_start(lwip_app_config_get()->log_archive_slots);
    g_profiles = mem_malloc(PROFILES_MAX * sizeof *g_profiles);
    g_networks = mem_malloc(NETWORKS_MAX * sizeof *g_networks);
    g_items = mem_malloc(ITEMS_MAX * sizeof *g_items);
    g_values = mem_malloc(ITEMS_MAX * sizeof *g_values);
    if (!g_profiles || !g_networks || !g_items || !g_values)
        return false;
    lwip_wifi_set_event_cb(on_wifi_event, NULL);
    if (usb_fn.init(eth_usb_event_callback, NULL, &eth_device_descriptors, USB_DEFAULT_INIT_FLAGS) != USB_SUCCESS)
        return false;
    g_net_failed = false;
    g_net_started = true;
    return true;
}

void app_net_begin(void)
{
    net_start();
}

void app_net_stop(void)
{
    if (!g_net_started)
        return;
    g_net_started = false;
    lwip_wifi_set_event_cb(NULL, NULL);
    lwip_dispatch_stop();
    lwip_log_file_stop();
    eth_prepare_shutdown();
    usb_fn.cleanup();
    eth_finish_shutdown();
}

bool app_net_idle(void)
{
    bool available;

    if (!g_net_started)
        return false;
    usb_fn.handle_events();
    sys_check_timeouts();

    available = lwip_wifi_available();
    if (available && !g_bridge_seen)
    {
        g_bridge_seen = true;
        g_state_valid = lwip_wifi_get_state(&g_state) == LWIP_WIFI_OK;
        g_dirty = true;
    }
    else if (!available && g_bridge_seen)
    {
        g_bridge_seen = false;
        g_state_valid = false;
        g_dirty = true;
    }
    if (g_dirty)
    {
        g_dirty = false;
        return true;
    }
    return false;
}

const char *app_wifi_summary(uint8_t *color)
{
    if (!g_net_started || !g_bridge_seen)
    {
        *color = UI_MUTED;
        return "No bridge";
    }
    if (!g_state_valid)
    {
        *color = UI_WARN;
        return "Checking";
    }
    if (g_state.connected)
    {
        *color = UI_GOOD;
        return g_state.ssid;
    }
    *color = UI_BAD;
    return "Offline";
}

static const char *error_text(lwip_wifi_error_t err)
{
    switch (err)
    {
    case LWIP_WIFI_OK:
        return "Done";
    case LWIP_WIFI_ERR_NO_BRIDGE:
        return "The bridge is not attached";
    case LWIP_WIFI_ERR_TIMEOUT:
        return "The bridge did not answer";
    case LWIP_WIFI_ERR_NOT_FOUND:
        return "That network is gone";
    case LWIP_WIFI_ERR_FULL:
        return "All slots are in use";
    case LWIP_WIFI_ERR_MEM:
        return "Out of memory";
    case LWIP_WIFI_ERR_BUSY:
        return "The bridge is busy, try again";
    default:
        return "The bridge refused the request";
    }
}

static const char *reason_text(uint8_t reason)
{
    switch (reason)
    {
    case LWIP_WIFI_REASON_NOT_FOUND:
        return "network not found";
    case LWIP_WIFI_REASON_AUTH:
        return "wrong password";
    case LWIP_WIFI_REASON_LOST:
        return "signal lost";
    case LWIP_WIFI_REASON_REJECTED:
        return "turned away by the network";
    case LWIP_WIFI_REASON_OTHER:
        return "connection failed";
    default:
        return NULL;
    }
}

static bool report(const char *title, lwip_wifi_error_t err)
{
    if (err == LWIP_WIFI_OK)
        return true;
    ui_message(title, error_text(err), NULL);
    return false;
}

static void status_line(char *out, size_t size, uint8_t *color)
{
    if (!g_bridge_seen)
    {
        snprintf(out, size, "Waiting for the bridge");
        *color = UI_MUTED;
    }
    else if (!g_state_valid)
    {
        snprintf(out, size, "The bridge is not answering");
        *color = UI_BAD;
    }
    else if (g_state.connected)
    {
        snprintf(out, size, "Connected to %s, %d dBm, channel %u", g_state.ssid, g_state.rssi, g_state.channel);
        *color = UI_GOOD;
    }
    else if (reason_text(g_state.reason))
    {
        snprintf(out, size, "Not connected: %s", reason_text(g_state.reason));
        *color = UI_BAD;
    }
    else
    {
        snprintf(out, size, "Not connected");
        *color = UI_BAD;
    }
}

static bool wait_for_bridge(void)
{
    uint32_t start;

    if (!net_start())
    {
        ui_message("Wi-Fi", "USB could not start", NULL);
        return false;
    }
    if (lwip_wifi_available())
        return true;

    ui_busy("Wi-Fi", "Looking for the bridge...");
    start = sys_now();
    while (!lwip_wifi_available() && sys_now() - start < BRIDGE_WAIT_MS)
    {
        app_net_idle();
        if (os_GetCSC() == sk_Clear)
            return false;
    }
    if (lwip_wifi_available())
        return true;
    ui_message("No Wi-Fi bridge", "Plug the calculator into", "the bridge's USB-A port");
    return false;
}

static void refresh(void)
{
    ui_busy("Wi-Fi", "Talking to the bridge...");
    g_state_valid = lwip_wifi_get_state(&g_state) == LWIP_WIFI_OK;
    if (lwip_wifi_list_profiles(g_profiles, PROFILES_MAX, &g_profile_count) != LWIP_WIFI_OK)
        g_profile_count = 0;
}

static bool joined(uint8_t slot)
{
    return g_state_valid && g_state.connected && (slot == LWIP_WIFI_SLOT_NONE || g_state.slot == slot);
}

static void connect_and_wait(uint8_t slot)
{
    uint32_t start;
    uint32_t last;

    ui_busy("Wi-Fi", "Connecting...");
    lwip_wifi_error_t err = lwip_wifi_connect(slot);
    if (err != LWIP_WIFI_OK && err != LWIP_WIFI_ERR_TIMEOUT)
    {
        report("Connect", err);
        return;
    }
    g_state.reason = LWIP_WIFI_REASON_NONE;
    start = last = sys_now();
    while (sys_now() - start < JOIN_WAIT_MS)
    {
        app_net_idle();
        if (joined(slot))
            return;
        if (sys_now() - last >= 1000)
        {
            last = sys_now();
            g_state_valid = lwip_wifi_get_state(&g_state) == LWIP_WIFI_OK;
        }
        if (g_state_valid && g_state.reason == LWIP_WIFI_REASON_AUTH)
            break;
        if (g_state_valid && g_state.reason == LWIP_WIFI_REASON_NOT_FOUND)
        {
            ui_message("Not connected", "The network is not in range.", NULL);
            return;
        }
    }
    ui_message("Not connected", "The network did not accept", "the bridge. Check the password.");
}

static uint8_t choose_security(uint8_t current)
{
    int choice = ui_choose("Security", security_names, SECURITY_COUNT,
                           current < SECURITY_COUNT ? current : LWIP_WIFI_SEC_WPA2);

    return choice < 0 ? LWIP_WIFI_SLOT_NONE : (uint8_t)choice;
}

static void add_network(const char *known_ssid, uint8_t security)
{
    char ssid[LWIP_WIFI_SSID_MAX + 1];
    char password[LWIP_WIFI_PASSWORD_MAX + 1] = "";
    uint8_t slot = LWIP_WIFI_SLOT_NONE;
    lwip_wifi_error_t err;

    snprintf(ssid, sizeof ssid, "%s", known_ssid ? known_ssid : "");
    if (!known_ssid && (!ui_edit_text("Network name", ssid, sizeof ssid, false) || !ssid[0]))
        return;
    if (security == LWIP_WIFI_SLOT_NONE && (security = choose_security(LWIP_WIFI_SEC_WPA2)) == LWIP_WIFI_SLOT_NONE)
        return;
    if (security != LWIP_WIFI_SEC_OPEN && !ui_edit_text("Password", password, sizeof password, true))
        return;

    ui_busy("Wi-Fi", "Saving...");
    /* A typed name may be a hidden network, which never shows up in a scan. */
    err = lwip_wifi_save_profile(LWIP_WIFI_SLOT_NONE, ssid, password, security,
                                 known_ssid ? LWIP_WIFI_PROFILE_ENABLED
                                            : LWIP_WIFI_PROFILE_ENABLED | LWIP_WIFI_PROFILE_HIDDEN,
                                 &slot);
    tls_secure_memzero(password, sizeof password);
    if (report("Save network", err))
        connect_and_wait(slot);
}

static void edit_profile(const lwip_wifi_profile_t *p, int what)
{
    char ssid[LWIP_WIFI_SSID_MAX + 1];
    char password[LWIP_WIFI_PASSWORD_MAX + 1] = "";
    uint8_t security = p->security;
    lwip_wifi_error_t err;

    snprintf(ssid, sizeof ssid, "%s", p->ssid);
    if (what == 0 && !ui_edit_text("New password", password, sizeof password, true))
        return;
    if (what == 1 && (!ui_edit_text("Rename network", ssid, sizeof ssid, false) || !ssid[0]))
        return;
    if (what == 2 && (security = choose_security(p->security)) == LWIP_WIFI_SLOT_NONE)
        return;

    ui_busy("Wi-Fi", "Saving...");
    err = lwip_wifi_save_profile(p->slot, ssid, password, security,
                                 (uint8_t)(p->flags & (LWIP_WIFI_PROFILE_ENABLED | LWIP_WIFI_PROFILE_HIDDEN)), NULL);
    tls_secure_memzero(password, sizeof password);
    report("Save network", err);
}

static void forget_profile(const lwip_wifi_profile_t *p)
{
    char question[48];

    snprintf(question, sizeof question, "Forget %s?", p->ssid);
    if (ui_confirm("Forget network", question))
        report("Forget network", lwip_wifi_forget_profile(p->slot));
}

static bool profile_connected(const lwip_wifi_profile_t *p)
{
    return g_state_valid && g_state.connected && g_state.slot == p->slot;
}

static void open_profile(const lwip_wifi_profile_t *p)
{
    bool enabled = (p->flags & LWIP_WIFI_PROFILE_ENABLED) != 0;
    const char *items[] = {
        profile_connected(p) ? "Reconnect" : "Connect now", "Change password", "Rename", "Security",
        enabled ? "Skip when joining" : "Use when joining", "Move to top", "Forget"
    };

    switch (ui_choose(p->ssid, items, 7, 0))
    {
    case 0:
        connect_and_wait(p->slot);
        break;
    case 1:
        edit_profile(p, 0);
        break;
    case 2:
        edit_profile(p, 1);
        break;
    case 3:
        edit_profile(p, 2);
        break;
    case 4:
        report("Saved network", lwip_wifi_enable_profile(p->slot, !enabled));
        break;
    case 5:
        report("Saved network", lwip_wifi_prefer_profile(p->slot));
        break;
    case 6:
        forget_profile(p);
        break;
    default:
        break;
    }
}

static int find_profile(const char *ssid)
{
    for (uint8_t i = 0; i < g_profile_count; i++)
        if (strcmp(g_profiles[i].ssid, ssid) == 0)
            return i;
    return -1;
}

static int build_networks(void)
{
    int count = 0;

    for (uint8_t i = 0; i < g_network_count; i++)
    {
        const lwip_wifi_network_t *n = &g_networks[i];
        bool saved = find_profile(n->ssid) >= 0;
        bool here = g_state_valid && g_state.connected && strcmp(g_state.ssid, n->ssid) == 0;

        snprintf(g_values[count], sizeof g_values[count], "%d dBm", n->rssi);
        g_items[count] = (ui_item_t){UI_ITEM_ACTION, n->ssid,
                                     here ? "Connected" : saved ? "Saved" : security_name(n->security),
                                     g_values[count], false,
                                     n->rssi >= -60 ? UI_GOOD : n->rssi >= -75 ? UI_WARN : UI_BAD};
        count++;
    }
    if (!count)
    {
        g_items[0] = (ui_item_t){UI_ITEM_LINE, "No networks found. Press 2nd to scan again.", NULL, NULL,
                                 false, UI_MUTED};
        count = 1;
    }
    return count;
}

static void scan_screen(void)
{
    ui_list_t list = {0, 0};
    bool rescan = true;
    char found[16];

    for (;;)
    {
        char status[64];
        uint8_t color;
        int count;

        if (rescan)
        {
            ui_busy("Wi-Fi", "Scanning, this takes a few seconds...");
            if (!report("Scan", lwip_wifi_scan(g_networks, NETWORKS_MAX, &g_network_count)))
                return;
            list.selected = 0;
            list.scroll = 0;
            rescan = false;
        }

        count = build_networks();
        status_line(status, sizeof status, &color);
        snprintf(found, sizeof found, "%u found", g_network_count);
        ui_frame("Networks in range", found, status, color, "enter: join   2nd: scan again   clear: back");
        ui_list_draw(&list, g_items, count);
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Clear)
            return;
        if (key == sk_2nd)
            rescan = true;
        ui_list_key(&list, g_items, count, key);
        if (key == sk_Enter && g_network_count)
        {
            const lwip_wifi_network_t *n = &g_networks[list.selected];
            int saved = find_profile(n->ssid);

            if (saved >= 0)
                connect_and_wait(g_profiles[saved].slot);
            else
                add_network(n->ssid, n->security);
            return;
        }
    }
}

enum
{
    ROW_PROFILE,
    ROW_ADD,
    ROW_SCAN,
    ROW_JOIN,
    ROW_OTHER
};

static int build_main(uint8_t *roles, int8_t *profile_index)
{
    int count = 0;

    g_items[count] = (ui_item_t){UI_ITEM_SECTION, "Saved networks", NULL, NULL, false, 0};
    roles[count++] = ROW_OTHER;
    for (uint8_t i = 0; i < g_profile_count; i++)
    {
        const lwip_wifi_profile_t *p = &g_profiles[i];
        bool enabled = (p->flags & LWIP_WIFI_PROFILE_ENABLED) != 0;

        snprintf(g_values[count], sizeof g_values[count], "%s%s%s", security_name(p->security),
                 enabled ? "" : ", skipped", (p->flags & LWIP_WIFI_PROFILE_HIDDEN) ? ", hidden" : "");
        g_items[count] = (ui_item_t){UI_ITEM_ACTION, p->ssid, g_values[count],
                                     profile_connected(p) ? "Connected" : NULL, false, UI_GOOD};
        profile_index[count] = (int8_t)i;
        roles[count++] = ROW_PROFILE;
    }
    if (!g_profile_count)
    {
        g_items[count] = (ui_item_t){UI_ITEM_LINE, "Nothing saved yet.", NULL, NULL, false, UI_MUTED};
        roles[count++] = ROW_OTHER;
    }
    g_items[count] = (ui_item_t){UI_ITEM_SECTION, "Actions", NULL, NULL, false, 0};
    roles[count++] = ROW_OTHER;
    g_items[count] = (ui_item_t){UI_ITEM_ACTION, "Scan for networks", "Join one that is in range", NULL, false, 0};
    roles[count++] = ROW_SCAN;
    g_items[count] = (ui_item_t){UI_ITEM_ACTION, "Add a network", "Type its name and password", NULL, false, 0};
    roles[count++] = ROW_ADD;
    if (g_state_valid && g_state.connected)
        g_items[count] = (ui_item_t){UI_ITEM_ACTION, "Disconnect", "Stay offline until you reconnect", NULL,
                                     false, 0};
    else
        g_items[count] = (ui_item_t){UI_ITEM_ACTION, "Join automatically", "Best saved network in range", NULL,
                                     false, 0};
    roles[count++] = ROW_JOIN;
    return count;
}

void app_wifi_screen(void)
{
    uint8_t roles[ITEMS_MAX];
    int8_t profile_index[ITEMS_MAX];
    ui_list_t list = {1, 0};
    bool reload = true;
    char saved[16];

    if (!wait_for_bridge())
        return;

    for (;;)
    {
        char status[64];
        uint8_t color;
        int count;

        if (reload)
        {
            refresh();
            reload = false;
        }

        count = build_main(roles, profile_index);
        status_line(status, sizeof status, &color);
        snprintf(saved, sizeof saved, "%u/%u saved", g_profile_count, PROFILES_MAX);
        ui_frame("Wi-Fi", saved, status, color, "enter: open   del: forget   2nd: refresh   clear: back");
        ui_list_draw(&list, g_items, count);
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Clear)
            return;
        if (key == sk_2nd)
            reload = true;
        ui_list_key(&list, g_items, count, key);

        uint8_t role = roles[list.selected];
        if (key == sk_Del && role == ROW_PROFILE)
        {
            forget_profile(&g_profiles[profile_index[list.selected]]);
            reload = true;
        }
        if (key != sk_Enter)
            continue;

        if (role == ROW_PROFILE)
        {
            lwip_wifi_profile_t profile = g_profiles[profile_index[list.selected]];
            open_profile(&profile);
        }
        else if (role == ROW_SCAN)
        {
            scan_screen();
        }
        else if (role == ROW_ADD)
        {
            add_network(NULL, LWIP_WIFI_SLOT_NONE);
        }
        else if (role == ROW_JOIN)
        {
            if (g_state_valid && g_state.connected)
                report("Disconnect", lwip_wifi_disconnect());
            else
                connect_and_wait(LWIP_WIFI_SLOT_NONE);
        }
        else
        {
            continue;
        }
        reload = true;
    }
}
