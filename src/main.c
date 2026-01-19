#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ti/getcsc.h>
#include <ti/screen.h>
#include <sys/rtc.h>
#include <usbdrvce.h>

#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/dhcp.h"
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

#include "drivers/mem.h"
#include "drivers/usb_ethernet.h"

#define LWIP_CFG_HEAP_MIN (8u * 1024u)
#define LWIP_CFG_HEAP_MAX (48u * 1024u)
#define LWIP_CFG_HEAP_STEP 1024u

#define LWIP_CFG_TZ_MIN_MINUTES (-12 * 60)
#define LWIP_CFG_TZ_MAX_MINUTES (14 * 60)
#define LWIP_CFG_TZ_STEP_MINUTES 15

#define LWIP_CFG_LOG_MIN_BYTES 1024u
#define LWIP_CFG_LOG_MAX_BYTES 16384u
#define LWIP_CFG_LOG_STEP_BYTES 512u

typedef enum
{
    TAB_GENERAL = 0,
    TAB_NETWORK,
    TAB_SECURITY,
    TAB_TEST,
    TAB_ABOUT,
    TAB_COUNT
} ui_tab_t;

typedef enum
{
    F_TYPE_BOOL_TOGGLE,
    F_TYPE_STRING,
    F_TYPE_INT_SLIDER,
    F_TYPE_ACTION,
    F_TYPE_LABEL
} f_type;

typedef enum
{
    OPT_MAX_HEAP = 0,
    OPT_TZ_OFFSET,
    OPT_DST,
    OPT_LOG_GROUP,
    OPT_LOG_USB,
    OPT_LOG_TLS,
    OPT_LOG_SIZE,
    OPT_VIEW_LOGS,
    OPT_AUTO_NTP,
    OPT_IP_MODE,
    OPT_EDIT_IP,
    OPT_ENABLE_TLS,
    OPT_CERT_GROUP,
    OPT_CERT_SPKI,
    OPT_CERT_DATES,
    OPT_CERT_OWNER,
    OPT_NTP_TEST,
    OPT_HTTP_TEST,
    OPT_DNS_TEST,
    OPT_PING_TEST,
    OPT_TCP_ECHO_TEST,
    OPT_COUNT
} config_option_id;

typedef enum
{
    EDIT_NONE = 0,
    EDIT_HEAP,
    EDIT_TZ,
    EDIT_LOG
} edit_mode_t;

typedef enum
{
    FOCUS_TABS = 0,
    FOCUS_OPTIONS
} focus_mode_t;

struct config_option;
typedef bool (*config_setter_fn)(struct config_option *opt);

struct config_option
{
    const char *name;
    ui_tab_t tab;
    config_option_id id;
    f_type type;
    config_setter_fn setter;
    uint8_t value[4];
};

static bool run_main = true;
static bool dhcp_started = false;
static bool httpd_running = false;
static bool sntp_started = false;
static bool manual_ip_applied = false;
static bool lwip_started = false;
static volatile bool netif_unavailable = false;

static lwip_app_config_t g_cfg;

#define COLOR_WHITE 0xFFFF
#define COLOR_BLACK 0x0000
#define COLOR_LIGHT_GRAY 0xD6BA  // Light gray for help area background

static void delay_ms(unsigned int ms)
{
    // Simple busy loop delay (approximate, based on ~15 MHz CPU)
    for (unsigned int i = 0; i < ms; i++)
    {
        for (volatile unsigned int j = 0; j < 1500; j++)
        {
            // Busy wait
        }
    }
}

static void format_tz_offset(char *buf, size_t buf_len, int16_t minutes);
static void edit_ip_config(lwip_app_config_t *cfg);
static bool start_lwip_stack(const lwip_app_config_t *cfg);
static void apply_network_config(const lwip_app_config_t *cfg);
static void fill_rect(int x, int y, int w, int h, uint16_t color);

static bool config_toggle_option(struct config_option *opt);
static bool config_edit_ip(struct config_option *opt);
static bool config_run_ntp_test(struct config_option *opt);
static bool config_run_http_test(struct config_option *opt);
static bool config_run_dns_test(struct config_option *opt);
static bool config_run_ping_test(struct config_option *opt);
static bool config_run_tcp_echo_test(struct config_option *opt);
static bool config_run_view_logs(struct config_option *opt);

static struct config_option config_options[] = {
    {"Max Heap", TAB_GENERAL, OPT_MAX_HEAP, F_TYPE_INT_SLIDER, NULL, {0}},
    {"TZ Offset", TAB_GENERAL, OPT_TZ_OFFSET, F_TYPE_INT_SLIDER, NULL, {0}},
    {"DST", TAB_GENERAL, OPT_DST, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"Logging:", TAB_GENERAL, OPT_LOG_GROUP, F_TYPE_LABEL, NULL, {0}},
    {"  USB errors", TAB_GENERAL, OPT_LOG_USB, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"  TLS errors", TAB_GENERAL, OPT_LOG_TLS, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"  Log size", TAB_GENERAL, OPT_LOG_SIZE, F_TYPE_INT_SLIDER, NULL, {0}},
    {"View Log", TAB_GENERAL, OPT_VIEW_LOGS, F_TYPE_ACTION, config_run_view_logs, {0}},

    {"Enable NTP", TAB_NETWORK, OPT_AUTO_NTP, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"Enable DHCP", TAB_NETWORK, OPT_IP_MODE, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"IP Conf", TAB_NETWORK, OPT_EDIT_IP, F_TYPE_ACTION, config_edit_ip, {0}},

    {"Enable TLS", TAB_SECURITY, OPT_ENABLE_TLS, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"Cert Trust Settings:", TAB_SECURITY, OPT_CERT_GROUP, F_TYPE_LABEL, NULL, {0}},
    {"  SPKI Hash", TAB_SECURITY, OPT_CERT_SPKI, F_TYPE_LABEL, NULL, {0}},
    {"  Lifespan", TAB_SECURITY, OPT_CERT_DATES, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},
    {"  Owner", TAB_SECURITY, OPT_CERT_OWNER, F_TYPE_BOOL_TOGGLE, config_toggle_option, {0}},

    {"NTP Test", TAB_TEST, OPT_NTP_TEST, F_TYPE_ACTION, config_run_ntp_test, {0}},
    {"HTTP Test", TAB_TEST, OPT_HTTP_TEST, F_TYPE_ACTION, config_run_http_test, {0}},
    {"DNS Test", TAB_TEST, OPT_DNS_TEST, F_TYPE_ACTION, config_run_dns_test, {0}},
    {"Ping Test", TAB_TEST, OPT_PING_TEST, F_TYPE_ACTION, config_run_ping_test, {0}},
    {"TCP Echo Test", TAB_TEST, OPT_TCP_ECHO_TEST, F_TYPE_ACTION, config_run_tcp_echo_test, {0}},
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

static void option_sync_from_cfg(struct config_option *opt)
{
    switch (opt->id)
    {
    case OPT_MAX_HEAP:
        option_set_u16(opt->value, g_cfg.max_heap_bytes);
        break;
    case OPT_TZ_OFFSET:
        option_set_i16(opt->value, g_cfg.tz_offset_minutes);
        break;
    case OPT_DST:
        option_set_bool(opt->value, g_cfg.dst_enabled != 0);
        break;
    case OPT_LOG_USB:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_LOG_USB) != 0);
        break;
    case OPT_LOG_TLS:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_LOG_TLS) != 0);
        break;
    case OPT_LOG_SIZE:
        option_set_u16(opt->value, g_cfg.log_size_bytes);
        break;
    case OPT_AUTO_NTP:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_AUTO_NTP) != 0);
        break;
    case OPT_IP_MODE:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_DHCP) != 0);
        break;
    case OPT_ENABLE_TLS:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_ENABLE_TLS) != 0);
        break;
    case OPT_CERT_DATES:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_CERT_CHECK_DATES) != 0);
        break;
    case OPT_CERT_OWNER:
        option_set_bool(opt->value, (g_cfg.flags & LWIP_CFG_CERT_CHECK_OWNER) != 0);
        break;
    case OPT_LOG_GROUP:
    case OPT_VIEW_LOGS:
    case OPT_NTP_TEST:
    case OPT_HTTP_TEST:
        // Action type, no sync needed
        break;
    default:
        break;
    }
}

static void apply_logging_config(void)
{
    uint8_t mask = 0;
    if ((g_cfg.flags & LWIP_CFG_LOG_USB) != 0)
    {
        mask |= LWIP_LOG_MODULE_USB;
    }
    if ((g_cfg.flags & LWIP_CFG_LOG_TLS) != 0)
    {
        mask |= LWIP_LOG_MODULE_TLS;
    }
    lwip_log_set_enabled(mask);
    lwip_log_set_max_bytes(g_cfg.log_size_bytes);
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
    return opt->type != F_TYPE_LABEL;
}

static int find_first_option(ui_tab_t tab)
{
    for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
    {
        if (config_options[i].tab == tab && option_is_selectable(&config_options[i]))
        {
            return (int)i;
        }
    }
    return -1;
}

static int find_next_option(ui_tab_t tab, int current, int dir)
{
    int i = current;
    while (1)
    {
        i += dir;
        if (i < 0 || i >= (int)CONFIG_OPTION_COUNT)
        {
            break;
        }
        if (config_options[i].tab == tab && option_is_selectable(&config_options[i]))
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
    case OPT_MAX_HEAP:
        snprintf(buf, buf_len, "%uk", option_get_u16(opt->value) / 1024u);
        break;
    case OPT_LOG_SIZE:
    {
        uint16_t bytes = option_get_u16(opt->value);
        uint16_t kb = (uint16_t)(bytes / 1024u);
        if ((bytes % 1024u) == 0)
        {
            snprintf(buf, buf_len, "%uk", kb);
        }
        else
        {
            snprintf(buf, buf_len, "%u.5k", kb);
        }
        break;
    }
        break;
    case OPT_TZ_OFFSET:
        format_tz_offset(buf, buf_len, option_get_i16(opt->value));
        break;
    case OPT_DST:
    case OPT_AUTO_NTP:
    case OPT_LOG_USB:
    case OPT_LOG_TLS:
    case OPT_ENABLE_TLS:
    case OPT_CERT_DATES:
    case OPT_CERT_OWNER:
        snprintf(buf, buf_len, "%s", option_get_bool(opt->value) ? "ON" : "OFF");
        break;
    case OPT_NTP_TEST:
    case OPT_HTTP_TEST:
    case OPT_DNS_TEST:
    case OPT_PING_TEST:
    case OPT_TCP_ECHO_TEST:
    case OPT_VIEW_LOGS:
        snprintf(buf, buf_len, "<Enter>");
        break;
    case OPT_IP_MODE:
        snprintf(buf, buf_len, "%s", option_get_bool(opt->value) ? "ON" : "OFF");
        break;
    case OPT_EDIT_IP:
        if (g_cfg.flags & LWIP_CFG_DHCP)
        {
            snprintf(buf, buf_len, "auto");
        }
        else
        {
            snprintf(buf, buf_len, "%u.%u.%u.%u",
                     g_cfg.ip_addr[0], g_cfg.ip_addr[1],
                     g_cfg.ip_addr[2], g_cfg.ip_addr[3]);
        }
        break;
    case OPT_CERT_SPKI:
        snprintf(buf, buf_len, "ALWAYS");
        break;
    case OPT_LOG_GROUP:
    case OPT_CERT_GROUP:
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
    case OPT_LOG_USB:
        g_cfg.flags ^= LWIP_CFG_LOG_USB;
        option_sync_from_cfg(opt);
        apply_logging_config();
        return true;
    case OPT_LOG_TLS:
        g_cfg.flags ^= LWIP_CFG_LOG_TLS;
        option_sync_from_cfg(opt);
        apply_logging_config();
        return true;
    case OPT_AUTO_NTP:
        g_cfg.flags ^= LWIP_CFG_AUTO_NTP;
        option_sync_from_cfg(opt);
        return true;
    case OPT_IP_MODE:
        g_cfg.flags ^= LWIP_CFG_DHCP;
        option_sync_from_cfg(opt);
        return true;
    case OPT_ENABLE_TLS:
        g_cfg.flags ^= LWIP_CFG_ENABLE_TLS;
        option_sync_from_cfg(opt);
        return true;
    case OPT_CERT_DATES:
        g_cfg.flags ^= LWIP_CFG_CERT_CHECK_DATES;
        option_sync_from_cfg(opt);
        return true;
    case OPT_CERT_OWNER:
        g_cfg.flags ^= LWIP_CFG_CERT_CHECK_OWNER;
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
    if (netif_is_up(netif) && !ip4_addr_isany(netif_ip4_addr(netif)))
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
    if (netif_is_up(netif_default) && !ip4_addr_isany(netif_ip4_addr(netif_default)))
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

static const char *log_code_label(uint8_t module, uint8_t code)
{
    if (module == LWIP_LOG_MODULE_USB)
    {
        switch (code)
        {
        case LWIP_LOG_USB_ENDPOINT_STALL:
            return "STALL";
        case LWIP_LOG_USB_ENDPOINT_NO_DEVICE:
            return "UNPLUG";
        case LWIP_LOG_USB_ENDPOINT_ERROR:
            return "ERROR";
        case LWIP_LOG_USB_FATAL_RETRY:
            return "FATAL";
        default:
            return "USB?";
        }
    }
    if (module == LWIP_LOG_MODULE_TLS)
    {
        switch (code)
        {
        case LWIP_LOG_TLS_FATAL_ALERT:
            return "FATAL";
        case LWIP_LOG_TLS_TRUSTSTORE_FAIL:
            return "TSTR";
        default:
            return "TLS?";
        }
    }
    return "UNK";
}

static bool config_run_view_logs(struct config_option *opt)
{
    (void)opt;

    struct lwip_log_header header;
    bool has_log = lwip_log_read_header(&header);
    uint16_t offset = 0;
    const uint16_t lines = 8;

    while (1)
    {
        fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);
        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawText("Log Viewer", 10, 10);

        if (!has_log || header.count == 0)
        {
            os_FontDrawText("No log entries", 10, 40);
            os_FontDrawText("Press Clear to exit", 10, 180);
        }
        else
        {
            char count_buf[32];
            snprintf(count_buf, sizeof(count_buf), "Entries: %u", (unsigned)header.count);
            os_FontDrawText(count_buf, 10, 30);

            for (uint16_t i = 0; i < lines; i++)
            {
                struct lwip_log_entry entry;
                if (!lwip_log_read_entry_at(&header, offset + i, &entry))
                {
                    break;
                }
                char line[40];
                char module_char = (entry.module == LWIP_LOG_MODULE_USB) ? 'U' :
                                   (entry.module == LWIP_LOG_MODULE_TLS) ? 'T' : '?';
                const char *label = log_code_label(entry.module, entry.code);
                snprintf(line, sizeof(line), "%02u/%02u %02u:%02u:%02u %c %s",
                         entry.month, entry.day, entry.hour, entry.minute, entry.second,
                         module_char, label);
                os_FontDrawText(line, 10, 50 + (int)i * 15);
            }
            os_FontDrawText("Up/Down scroll", 10, 180);
            os_FontDrawText("Clear to exit", 10, 195);
        }

        while (os_GetCSC())
            ;

        while (1)
        {
            usb_HandleEvents();
            sys_check_timeouts();

            uint8_t key = os_GetCSC();
            if (key == sk_Clear)
            {
                fill_rect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_WHITE);
                return true;
            }
            if (has_log && header.count > lines)
            {
                if (key == sk_Up && offset > 0)
                {
                    offset--;
                    break;
                }
                if (key == sk_Down && (offset + lines) < header.count)
                {
                    offset++;
                    break;
                }
            }
            delay_ms(10);
        }
    }
}

// Layout: 3 columns
// TABS: 0-85, OPTIONS: 95-250, VALUES: 250-320
#define COL_TABS_X 0
#define COL_TABS_W 85
#define COL_OPTIONS_X 95
#define COL_OPTIONS_W 155
#define COL_VALUES_X 250
#define COL_VALUES_W 70

#define CONTENT_START_Y 30
#define TAB_ROW_HEIGHT 20
#define OPT_ROW_HEIGHT 14

// VRAM is at 0xD40000, 320x240 in 8bpp mode (palette), or 16bpp (RGB565)
// TI-OS uses 16bpp by default
#define LCD_WIDTH 320
#define LCD_HEIGHT 240
#define VRAM_BASE ((uint16_t *)0xD40000)

// Fill a rectangle with a 16-bit BGR565 color
static void fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (x < 0)
    {
        w += x;
        x = 0;
    }
    if (y < 0)
    {
        h += y;
        y = 0;
    }
    if (x + w > LCD_WIDTH)
    {
        w = LCD_WIDTH - x;
    }
    if (y + h > LCD_HEIGHT)
    {
        h = LCD_HEIGHT - y;
    }
    if (w <= 0 || h <= 0)
        return;

    for (int row = y; row < y + h; row++)
    {
        uint16_t *ptr = VRAM_BASE + row * LCD_WIDTH + x;
        for (int col = 0; col < w; col++)
        {
            *ptr++ = color;
        }
    }
}

// Colors defined at top of file

#define BANNER_HEIGHT 24

// Draw a key label with rounded appearance
// Returns the width used (for chaining)
static int draw_key_label(const char *key, int x, int y)
{
    int text_w = (int)os_FontGetWidth(key);
    int box_w = text_w + 8;  // More padding
    int box_h = 17;

    // Draw white box with black border (2px thick for better visibility)
    fill_rect(x, y, box_w, box_h, COLOR_WHITE);
    fill_rect(x, y, box_w, 2, COLOR_BLACK);             // top (2px)
    fill_rect(x, y + box_h - 2, box_w, 2, COLOR_BLACK); // bottom (2px)
    fill_rect(x, y, 2, box_h, COLOR_BLACK);             // left (2px)
    fill_rect(x + box_w - 2, y, 2, box_h, COLOR_BLACK); // right (2px)

    os_SetDrawFGColor(COLOR_BLACK);
    os_FontDrawTransText(key, x + 4, y + 2);

    return box_w;
}

// Draw help text with key labels, centered
static void draw_help_line(int y, const char *items[], int count)
{
    // Calculate total width needed for all pairs
    int total_width = 0;
    for (int i = 0; i < count; i += 2)
    {
        int key_w = (int)os_FontGetWidth(items[i]) + 8;  // Match box padding
        int action_w = (int)os_FontGetWidth(items[i + 1]);
        total_width += key_w + 3 + action_w;  // 3px between key and action
        if (i > 0)
            total_width += 16;  // spacing between pairs
    }

    // Center the content
    int x = (LCD_WIDTH - total_width) / 2;

    for (int i = 0; i < count; i += 2)
    {
        if (i > 0)
            x += 16;  // spacing between pairs

        x += draw_key_label(items[i], x, y);
        x += 3;  // space between key box and action text

        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawTransText(items[i + 1], x, y + 3);

        // Move to next position
        int action_w = (int)os_FontGetWidth(items[i + 1]);
        x += action_w;
    }
}

static void draw_help_area(int y_start, const char *items[], int count)
{
    // Fill help area with light gray background
    fill_rect(0, y_start, LCD_WIDTH, LCD_HEIGHT - y_start, COLOR_LIGHT_GRAY);

    // Draw separator line (2px for better visibility)
    fill_rect(0, y_start, LCD_WIDTH, 2, COLOR_BLACK);

    // Draw centered help content
    draw_help_line(y_start + 5, items, count);
}

static const char *tab_labels[TAB_COUNT] = {
    "General", "Network", "Security", "Test", "About"};

// Draw top banner
static void draw_banner(void)
{
    fill_rect(0, 0, LCD_WIDTH, BANNER_HEIGHT, COLOR_BLACK);
    os_SetDrawFGColor(COLOR_WHITE);
    os_FontDrawTransText("lwIP Config Wizard", 4, 6);
}

// Get Y position for a tab index
static int tab_y(int idx)
{
    return CONTENT_START_Y + (idx * TAB_ROW_HEIGHT);
}

// Get Y position for an option's row within its tab
static int option_row_y(ui_tab_t tab, int opt_idx)
{
    int y = CONTENT_START_Y;
    for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
    {
        if (config_options[i].tab != tab)
            continue;
        if ((int)i == opt_idx)
            return y;
        y += OPT_ROW_HEIGHT;
    }
    return -1;
}

// Draw a single tab row
static void draw_single_tab(int idx, bool selected)
{
    int y = tab_y(idx);
    fill_rect(COL_TABS_X, y, COL_TABS_W, TAB_ROW_HEIGHT, selected ? COLOR_BLACK : COLOR_WHITE);
    os_SetDrawFGColor(selected ? COLOR_WHITE : COLOR_BLACK);
    os_FontDrawTransText(tab_labels[idx], COL_TABS_X + 4, y + 3);
}

// Draw all tabs
static void draw_tabs(ui_tab_t tab)
{
    for (int i = 0; i < TAB_COUNT; i++)
    {
        draw_single_tab(i, i == (int)tab);
    }
}

// Draw option selector marker (or clear it)
// When active, draws a black bar with white ">" to show focus is in options column
static void draw_option_marker(ui_tab_t tab, int opt_idx, bool show)
{
    int y = option_row_y(tab, opt_idx);
    if (y < 0)
        return;
    fill_rect(COL_OPTIONS_X - 1, y + 3, 6, OPT_ROW_HEIGHT, show ? COLOR_BLACK : COLOR_WHITE);
}

// Draw a single option's value (with optional edit highlight)
static void draw_option_value_ex(int opt_idx, bool editing)
{
    const struct config_option *opt = &config_options[opt_idx];
    int y = option_row_y(opt->tab, opt_idx);
    if (y < 0)
        return;

    if (opt->id == OPT_EDIT_IP)
    {
        int line_h = (int)os_FontGetHeight() + 2;
        int start_y = y + OPT_ROW_HEIGHT + 4;
        if (!(g_cfg.flags & LWIP_CFG_DHCP))
        {
            int label_x = COL_OPTIONS_X + 15;
            int value_x = COL_OPTIONS_X + 69;
            fill_rect(COL_OPTIONS_X, start_y, COL_OPTIONS_W + COL_VALUES_W,
                      line_h * 3 + 2, COLOR_WHITE);
            os_SetDrawFGColor(COLOR_BLACK);
            os_FontDrawTransText("IP:", label_x, start_y);
            os_FontDrawTransText("Mask:", label_x, start_y + line_h);
            os_FontDrawTransText("GW:", label_x, start_y + line_h * 2);

            char buf[20];
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                     g_cfg.ip_addr[0], g_cfg.ip_addr[1],
                     g_cfg.ip_addr[2], g_cfg.ip_addr[3]);
            os_FontDrawTransText(buf, value_x, start_y);
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                     g_cfg.ip_netmask[0], g_cfg.ip_netmask[1],
                     g_cfg.ip_netmask[2], g_cfg.ip_netmask[3]);
            os_FontDrawTransText(buf, value_x, start_y + line_h);
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                     g_cfg.ip_gateway[0], g_cfg.ip_gateway[1],
                     g_cfg.ip_gateway[2], g_cfg.ip_gateway[3]);
            os_FontDrawTransText(buf, value_x, start_y + line_h * 2);
            return;
        }
        fill_rect(COL_OPTIONS_X, start_y, COL_OPTIONS_W + COL_VALUES_W,
                  line_h * 3 + 2, COLOR_WHITE);
    }

    // Clear value area (add 2 extra pixels height to catch last row)
    fill_rect(COL_VALUES_X, y + 1, COL_VALUES_W, OPT_ROW_HEIGHT + 2, COLOR_WHITE);

    char value[24];
    format_option_value(opt, value, sizeof(value));

    if (editing)
    {
        // Draw black box around value to indicate editing
        int edit_w = 315 - (COL_VALUES_X + 2);
        if (edit_w < 0)
        {
            edit_w = 0;
        }
        fill_rect(COL_VALUES_X + 2, y + 1, edit_w, OPT_ROW_HEIGHT + 2, COLOR_BLACK);
        os_SetDrawFGColor(COLOR_WHITE);
    }
    else
    {
        os_SetDrawFGColor(COLOR_BLACK);
    }
    os_FontDrawTransText(value, COL_VALUES_X + 4, y + 2);
}

// Draw a single option's value
static void draw_option_value(int opt_idx)
{
    draw_option_value_ex(opt_idx, false);
}

// Draw all options and values for a tab
static void draw_tab_content(ui_tab_t tab, int selected_idx)
{
    // Clear options and values columns
    fill_rect(COL_OPTIONS_X, CONTENT_START_Y, COL_OPTIONS_W + COL_VALUES_W, OPT_ROW_HEIGHT * 10, COLOR_WHITE);

    os_SetDrawFGColor(COLOR_BLACK);

    if (tab == TAB_ABOUT)
    {
        int y = CONTENT_START_Y;
        os_FontDrawTransText("lwIP = lightweight IP", COL_OPTIONS_X + 4, y);
        os_FontDrawTransText("stack for embedded", COL_OPTIONS_X + 4, y + 12);
        os_FontDrawTransText("Ported From:", COL_OPTIONS_X + 4, y + 28);
        os_FontDrawTransText("github.com/lwip-tcpip/lwip", COL_OPTIONS_X + 9, y + 40);
        os_FontDrawTransText("Adapted by: commandblockguy", COL_OPTIONS_X + 4, y + 52);
        os_FontDrawTransText("Ethernet by: acagliano", COL_OPTIONS_X + 4, y + 64);
        os_FontDrawTransText("TLS by: acagliano,beckadam", COL_OPTIONS_X + 4, y + 76);
        os_FontDrawTransText("jacobly, calc84maniac", COL_OPTIONS_X + 14, y + 88);
        return;
    }

    int y = CONTENT_START_Y;
    for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
    {
        const struct config_option *opt = &config_options[i];
        if (opt->tab != tab)
            continue;

        // Draw option name
        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawTransText(opt->name, COL_OPTIONS_X + 9, y + 2);

        // Draw option value
        draw_option_value_ex((int)i, false);

        y += OPT_ROW_HEIGHT;
    }
    (void)selected_idx; // Not used here anymore - marker drawn separately when focused
}

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

static void draw_ip_line(int y, const char *label, const uint8_t ip[4])
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%s: %u.%u.%u.%u", label, ip[0], ip[1], ip[2], ip[3]);
    os_FontDrawText(buf, 4, y);
}

static void draw_ip_row(int y, const char *label, const uint8_t *addr,
                        bool selected_field, int selected_octet)
{
    uint16_t row_bg = selected_field ? 0xE71C : COLOR_WHITE;
    fill_rect(COL_OPTIONS_X, y - 2, 220, 26, row_bg);

    os_SetDrawFGColor(COLOR_BLACK);
    os_FontDrawTransText(label, COL_OPTIONS_X + 4, y);

    for (int o = 0; o < 4; o++)
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "%u", addr[o]);
        int x = COL_OPTIONS_X + 60 + o * 40;

        if (selected_field && o == selected_octet)
        {
            fill_rect(x - 2, y + 10, 30, 14, COLOR_BLACK);
            os_SetDrawFGColor(COLOR_WHITE);
        }
        else
        {
            os_SetDrawFGColor(COLOR_BLACK);
        }
        os_FontDrawTransText(buf, x, y + 12);

        if (o < 3)
        {
            os_SetDrawFGColor(COLOR_BLACK);
            os_FontDrawTransText(".", x + 22, y + 12);
        }
    }
}

// Slider dialog for heap size
// Returns true if value was changed
static bool show_heap_slider_dialog(uint16_t *heap_bytes)
{
    uint16_t orig = *heap_bytes;
    bool done = false;

    // Calculate slider position (0-100)
    int range = LWIP_CFG_HEAP_MAX - LWIP_CFG_HEAP_MIN;

    while (!done)
    {
        // Draw dialog
        fill_rect(40, 80, 240, 80, COLOR_WHITE);
        fill_rect(40, 80, 240, 2, COLOR_BLACK);
        fill_rect(40, 158, 240, 2, COLOR_BLACK);
        fill_rect(40, 80, 2, 80, COLOR_BLACK);
        fill_rect(278, 80, 2, 80, COLOR_BLACK);

        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawTransText("Max Heap Size", 100, 90);

        // Draw slider track
        fill_rect(60, 115, 200, 6, COLOR_BLACK);

        // Calculate position (0-192 within the track)
        int pos = ((*heap_bytes - LWIP_CFG_HEAP_MIN) * 192) / range;
        fill_rect(60 + pos, 110, 8, 16, COLOR_BLACK);

        // Draw value
        char buf[16];
        snprintf(buf, sizeof(buf), "%uk", *heap_bytes / 1024u);
        os_FontDrawTransText(buf, 140, 135);

        // Draw help with key boxes
        int hx = 55;
        hx += draw_key_label("<", hx, 146) + 1;
        hx += draw_key_label(">", hx, 146) + 3;
        os_SetDrawFGColor(COLOR_BLACK);
        os_FontDrawTransText("Adjust", hx, 147);
        hx += 42;
        hx += draw_key_label("enter", hx, 146) + 3;
        os_FontDrawTransText("OK", hx, 147);

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            *heap_bytes = orig;
            return false;
        }
        if (key == sk_Enter)
        {
            done = true;
        }
        if (key == sk_Left && *heap_bytes > LWIP_CFG_HEAP_MIN)
        {
            *heap_bytes -= LWIP_CFG_HEAP_STEP;
        }
        if (key == sk_Right && *heap_bytes + LWIP_CFG_HEAP_STEP <= LWIP_CFG_HEAP_MAX)
        {
            *heap_bytes += LWIP_CFG_HEAP_STEP;
        }
    }
    return *heap_bytes != orig;
}

// Numeric IP entry dialog with manual digit input
static bool edit_ip_octet(uint8_t *octet)
{
    char digits[4] = {0};
    int pos = 0;
    bool done = false;
    bool needs_redraw = true;
    const int box_x = 100;
    const int box_y = 100;
    const int box_w = 120;
    const int box_h = 40;
    const int text_x = 145;
    const int text_y = 115;
    const int text_w = 30;
    const int text_h = 12;

    while (!done)
    {
        if (needs_redraw)
        {
            // Draw entry box
            fill_rect(box_x, box_y, box_w, box_h, COLOR_WHITE);
            fill_rect(box_x, box_y, box_w, 2, COLOR_BLACK);
            fill_rect(box_x, box_y + box_h - 2, box_w, 2, COLOR_BLACK);
            fill_rect(box_x, box_y, 2, box_h, COLOR_BLACK);
            fill_rect(box_x + box_w - 2, box_y, 2, box_h, COLOR_BLACK);

            os_SetDrawFGColor(COLOR_BLACK);
            char buf[8];
            snprintf(buf, sizeof(buf), "%s_", digits);
            os_FontDrawTransText(buf, text_x, text_y);
            needs_redraw = false;
        }

        uint8_t key = os_GetCSC();
        if (key == 0)
        {
            continue;
        }
        if (key == sk_Clear)
        {
            return false;
        }
        if (key == sk_Enter && pos > 0)
        {
            int val = 0;
            for (int i = 0; i < pos; i++)
            {
                val = val * 10 + (digits[i] - '0');
            }
            if (val <= 255)
            {
                *octet = (uint8_t)val;
                return true;
            }
        }
        if (key == sk_Del && pos > 0)
        {
            pos--;
            digits[pos] = 0;
            fill_rect(text_x, text_y, text_w, text_h, COLOR_WHITE);
            os_SetDrawFGColor(COLOR_BLACK);
            char buf[8];
            snprintf(buf, sizeof(buf), "%s_", digits);
            os_FontDrawTransText(buf, text_x, text_y);
        }
        // Number keys 0-9
        if (pos < 3)
        {
            char c = 0;
            if (key == sk_0)
                c = '0';
            else if (key == sk_1)
                c = '1';
            else if (key == sk_2)
                c = '2';
            else if (key == sk_3)
                c = '3';
            else if (key == sk_4)
                c = '4';
            else if (key == sk_5)
                c = '5';
            else if (key == sk_6)
                c = '6';
            else if (key == sk_7)
                c = '7';
            else if (key == sk_8)
                c = '8';
            else if (key == sk_9)
                c = '9';
            if (c)
            {
                digits[pos++] = c;
                digits[pos] = 0;
                fill_rect(text_x, text_y, text_w, text_h, COLOR_WHITE);
                os_SetDrawFGColor(COLOR_BLACK);
                char buf[8];
                snprintf(buf, sizeof(buf), "%s_", digits);
                os_FontDrawTransText(buf, text_x, text_y);
            }
        }
    }
    return false;
}

static void edit_ip_config(lwip_app_config_t *cfg)
{
    int field = 0; // 0=IP, 1=GW, 2=Mask
    int octet = 0; // 0-3
    bool done = false;
    bool needs_redraw = true;
    const char *labels[3] = {"IP Addr", "Gateway", "Netmask"};
    uint8_t *addrs[3] = {cfg->ip_addr, cfg->ip_gateway, cfg->ip_netmask};

    while (!done)
    {
        if (needs_redraw)
        {
            boot_ClearVRAM();
            os_FontSelect(os_SmallFont);

            draw_banner();
            os_SetDrawFGColor(COLOR_BLACK);
            os_FontDrawTransText("IP Configuration", COL_OPTIONS_X + 20, CONTENT_START_Y);

            for (int f = 0; f < 3; f++)
            {
                int y = CONTENT_START_Y + 20 + f * 30;
                draw_ip_row(y, labels[f], addrs[f], f == field, octet);
            }

            // Draw help with key boxes
            const char *ip_help[] = {"arrows", "Move", "enter", "Edit", "clear", "Done"};
            draw_help_area(200, ip_help, 6);
            needs_redraw = false;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            done = true;
            continue;
        }
        if (key == sk_Up && field > 0)
        {
            int prev_field = field;
            field--;
            draw_ip_row(CONTENT_START_Y + 20 + prev_field * 30, labels[prev_field],
                        addrs[prev_field], false, octet);
            draw_ip_row(CONTENT_START_Y + 20 + field * 30, labels[field],
                        addrs[field], true, octet);
            continue;
        }
        if (key == sk_Down && field < 2)
        {
            int prev_field = field;
            field++;
            draw_ip_row(CONTENT_START_Y + 20 + prev_field * 30, labels[prev_field],
                        addrs[prev_field], false, octet);
            draw_ip_row(CONTENT_START_Y + 20 + field * 30, labels[field],
                        addrs[field], true, octet);
            continue;
        }
        if (key == sk_Left && octet > 0)
        {
            octet--;
            draw_ip_row(CONTENT_START_Y + 20 + field * 30, labels[field],
                        addrs[field], true, octet);
            continue;
        }
        if (key == sk_Right && octet < 3)
        {
            octet++;
            draw_ip_row(CONTENT_START_Y + 20 + field * 30, labels[field],
                        addrs[field], true, octet);
            continue;
        }
        if (key == sk_Enter)
        {
            if (edit_ip_octet(&addrs[field][octet]))
            {
                fill_rect(100, 100, 120, 40, COLOR_WHITE);
                for (int f = 0; f < 3; f++)
                {
                    int y = CONTENT_START_Y + 20 + f * 30;
                    draw_ip_row(y, labels[f], addrs[f], f == field, octet);
                }
            }
            else
            {
                fill_rect(100, 100, 120, 40, COLOR_WHITE);
                for (int f = 0; f < 3; f++)
                {
                    int y = CONTENT_START_Y + 20 + f * 30;
                    draw_ip_row(y, labels[f], addrs[f], f == field, octet);
                }
            }
        }
    }
}

static void apply_network_config(const lwip_app_config_t *cfg)
{
    lwip_sntp_set_timezone_offset((int32_t)cfg->tz_offset_minutes * 60);
    lwip_sntp_set_dst_enabled(cfg->dst_enabled != 0);

    if (cfg->flags & LWIP_CFG_DHCP)
    {
        if (netif_default && !dhcp_started)
        {
            dhcp_start(netif_default);
            dhcp_started = true;
            manual_ip_applied = false;
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

static bool start_lwip_stack(const lwip_app_config_t *cfg)
{
    if (lwip_started)
    {
        return true;
    }

    if (!mem_init(cfg->max_heap_bytes, malloc, free, realloc))
    {
        os_FontDrawText("mem init failed", 2, 2);
        os_GetKey();
        return false;
    }

    struct lwip_configurator conf = {0};
    conf.version = LWIP_CONFIGURATOR_V1;
    conf.usb_conf.reset_device = usb_ResetDevice;
    conf.usb_conf.disable_device = usb_DisableDevice;
    conf.usb_conf.ref_device = usb_RefDevice;
    conf.usb_conf.unref_device = usb_UnrefDevice;
    conf.usb_conf.set_device_data = usb_SetDeviceData;
    conf.usb_conf.get_device_data = usb_GetDeviceData;
    conf.usb_conf.get_role = usb_GetRole;
    conf.usb_conf.get_device_flags = usb_GetDeviceFlags;
    conf.usb_conf.schedule_transfer = usb_ScheduleTransfer;
    conf.usb_conf.control_transfer = usb_ControlTransfer;
    conf.usb_conf.get_config_descriptor_len = usb_GetConfigurationDescriptorTotalLength;
    conf.usb_conf.get_descriptor = usb_GetDescriptor;
    conf.usb_conf.get_string_descriptor = usb_GetStringDescriptor;
    conf.usb_conf.set_configuration = usb_SetConfiguration;
    conf.usb_conf.set_interface = usb_SetInterface;
    conf.usb_conf.get_device_endpoint = usb_GetDeviceEndpoint;
    conf.usb_conf.set_endpoint_data = usb_SetEndpointData;
    conf.usb_conf.get_endpoint_data = usb_GetEndpointData;
    conf.usb_conf.set_endpoint_flags = usb_SetEndpointFlags;
    conf.usb_conf.set_endpoint_halt = usb_SetEndpointHalt;
    conf.malloc_conf.caller_malloc = malloc;
    conf.malloc_conf.caller_free = free;

    if (lwip_init(&conf) != ERR_OK)
    {
        os_FontDrawText("lwip init failed", 2, 2);
        os_GetKey();
        return false;
    }

    netif_add_ext_callback(&netif_ext_cb, netif_ext_callback);

    if (usb_Init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        os_FontDrawText("usb init failed", 2, 2);
        os_GetKey();
        return false;
    }

    lwip_started = true;
    return true;
}

int main(void)
{
    lwip_app_config_load(&g_cfg);

    if (g_cfg.max_heap_bytes < LWIP_CFG_HEAP_MIN)
    {
        g_cfg.max_heap_bytes = LWIP_CFG_HEAP_MIN;
    }
    if (g_cfg.max_heap_bytes > LWIP_CFG_HEAP_MAX)
    {
        g_cfg.max_heap_bytes = LWIP_CFG_HEAP_MAX;
    }
    if (g_cfg.log_size_bytes < LWIP_CFG_LOG_MIN_BYTES)
    {
        g_cfg.log_size_bytes = LWIP_CFG_LOG_MIN_BYTES;
    }
    if (g_cfg.log_size_bytes > LWIP_CFG_LOG_MAX_BYTES)
    {
        g_cfg.log_size_bytes = LWIP_CFG_LOG_MAX_BYTES;
    }
    g_cfg.log_size_bytes = (uint16_t)(g_cfg.log_size_bytes -
        (g_cfg.log_size_bytes % LWIP_CFG_LOG_STEP_BYTES));
    config_sync_from_cfg();

    // Clear screen and set up font
    boot_ClearVRAM();
    os_FontSelect(os_SmallFont);

    ui_tab_t tab = TAB_GENERAL;
    int sel_index[TAB_COUNT];
    for (int i = 0; i < TAB_COUNT; i++)
    {
        sel_index[i] = find_first_option((ui_tab_t)i);
    }
    edit_mode_t edit_mode = EDIT_NONE;
    focus_mode_t focus = FOCUS_TABS;
    int edit_option = -1;

    // Initial full draw
    draw_banner();
    draw_tabs(tab);
    draw_tab_content(tab, sel_index[tab]);
    // Draw help line with key boxes
    const char *main_help[] = {"2nd", "Save", "clear", "Exit"};
    draw_help_area(200, main_help, 4);

    while (run_main)
    {
        if (lwip_started)
        {
            apply_network_config(&g_cfg);
            usb_HandleEvents();
            sys_check_timeouts();
        }

        uint8_t key = os_GetCSC();
        if (key == 0)
        {
            continue;
        }
        if (key == sk_Clear && edit_mode == EDIT_NONE)
        {
            run_main = false;
            break;
        }
        if (key == sk_2nd)
        {
            lwip_app_config_save(&g_cfg);
            config_sync_from_cfg();
            // Redraw all values in current tab
            draw_tab_content(tab, sel_index[tab]);
            continue;
        }

        if (edit_mode != EDIT_NONE)
        {
            if (key == sk_Clear || key == sk_Enter)
            {
                int prev_opt = edit_option;
                edit_mode = EDIT_NONE;
                edit_option = -1;
                draw_option_value(prev_opt); // Remove edit highlight
                continue;
            }
            bool value_changed = false;
            if (key == sk_Left && edit_mode == EDIT_HEAP && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_MAX_HEAP && g_cfg.max_heap_bytes > LWIP_CFG_HEAP_MIN)
                {
                    g_cfg.max_heap_bytes -= LWIP_CFG_HEAP_STEP;
                    option_sync_from_cfg(opt);
                    value_changed = true;
                }
            }
            else if (key == sk_Right && edit_mode == EDIT_HEAP && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_MAX_HEAP && g_cfg.max_heap_bytes + LWIP_CFG_HEAP_STEP <= LWIP_CFG_HEAP_MAX)
                {
                    g_cfg.max_heap_bytes += LWIP_CFG_HEAP_STEP;
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
            else if (key == sk_Left && edit_mode == EDIT_LOG && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_LOG_SIZE && g_cfg.log_size_bytes > LWIP_CFG_LOG_MIN_BYTES)
                {
                    g_cfg.log_size_bytes = (uint16_t)(g_cfg.log_size_bytes - LWIP_CFG_LOG_STEP_BYTES);
                    option_sync_from_cfg(opt);
                    apply_logging_config();
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
            else if (key == sk_Right && edit_mode == EDIT_LOG && edit_option >= 0)
            {
                struct config_option *opt = &config_options[edit_option];
                if (opt->id == OPT_LOG_SIZE && g_cfg.log_size_bytes + LWIP_CFG_LOG_STEP_BYTES <= LWIP_CFG_LOG_MAX_BYTES)
                {
                    g_cfg.log_size_bytes = (uint16_t)(g_cfg.log_size_bytes + LWIP_CFG_LOG_STEP_BYTES);
                    option_sync_from_cfg(opt);
                    apply_logging_config();
                    value_changed = true;
                }
            }
            if (value_changed)
            {
                draw_option_value_ex(edit_option, true); // Redraw with edit highlight
            }
            continue;
        }

        if (key == sk_Right)
        {
            if (focus == FOCUS_TABS)
            {
                if (sel_index[tab] >= 0)
                {
                    focus = FOCUS_OPTIONS;
                    draw_option_marker(tab, sel_index[tab], true);
                }
            }
            continue;
        }
        if (key == sk_Up)
        {
            if (focus == FOCUS_TABS)
            {
                ui_tab_t old_tab = tab;
                tab = (tab == 0) ? (TAB_COUNT - 1) : (ui_tab_t)(tab - 1);
                draw_single_tab((int)old_tab, false);
                draw_single_tab((int)tab, true);
                draw_tab_content(tab, sel_index[tab]);
            }
            else if (sel_index[tab] >= 0)
            {
                int old_idx = sel_index[tab];
                sel_index[tab] = find_next_option(tab, sel_index[tab], -1);
                if (old_idx != sel_index[tab])
                {
                    draw_option_marker(tab, old_idx, false);
                    draw_option_marker(tab, sel_index[tab], true);
                }
            }
            continue;
        }
        if (key == sk_Down)
        {
            if (focus == FOCUS_TABS)
            {
                ui_tab_t old_tab = tab;
                tab = (tab == (TAB_COUNT - 1)) ? 0 : (ui_tab_t)(tab + 1);
                draw_single_tab((int)old_tab, false);
                draw_single_tab((int)tab, true);
                draw_tab_content(tab, sel_index[tab]);
            }
            else if (sel_index[tab] >= 0)
            {
                int old_idx = sel_index[tab];
                sel_index[tab] = find_next_option(tab, sel_index[tab], 1);
                if (old_idx != sel_index[tab])
                {
                    draw_option_marker(tab, old_idx, false);
                    draw_option_marker(tab, sel_index[tab], true);
                }
            }
            continue;
        }
        if (key == sk_Enter)
        {
            if (focus == FOCUS_TABS)
            {
                // Enter on tab - switch to options (like Right arrow)
                if (sel_index[tab] >= 0)
                {
                    focus = FOCUS_OPTIONS;
                    draw_option_marker(tab, sel_index[tab], true);
                }
                continue;
            }
            int opt_index = sel_index[tab];
            if (opt_index >= 0)
            {
                struct config_option *opt = &config_options[opt_index];
                if (opt->type == F_TYPE_INT_SLIDER)
                {
                    if (opt->id == OPT_MAX_HEAP)
                    {
                        edit_mode = EDIT_HEAP;
                        edit_option = opt_index;
                        draw_option_value_ex(opt_index, true); // Show edit highlight
                    }
                    else if (opt->id == OPT_TZ_OFFSET)
                    {
                        edit_mode = EDIT_TZ;
                        edit_option = opt_index;
                        draw_option_value_ex(opt_index, true); // Show edit highlight
                    }
                    else if (opt->id == OPT_LOG_SIZE)
                    {
                        edit_mode = EDIT_LOG;
                        edit_option = opt_index;
                        draw_option_value_ex(opt_index, true); // Show edit highlight
                    }
                }
                else if (opt->setter)
                {
                    if (opt->type == F_TYPE_ACTION && opt->id == OPT_EDIT_IP &&
                        (g_cfg.flags & LWIP_CFG_DHCP))
                    {
                        continue;
                    }
                    if (opt->setter(opt))
                    {
                        // Full dialogs (IP config) clear the screen, so redraw everything
                        if (opt->type == F_TYPE_ACTION)
                        {
                            draw_banner();
                            draw_tabs(tab);
                            draw_tab_content(tab, sel_index[tab]);
                            const char *main_help[] = {"2nd", "Save", "clear", "Exit"};
                            draw_help_area(200, main_help, 4);
                            if (focus == FOCUS_OPTIONS)
                            {
                                draw_option_marker(tab, sel_index[tab], true);
                            }
                        }
                        else
                        {
                            draw_option_value(opt_index);
                            if (opt->id == OPT_IP_MODE)
                            {
                                for (size_t i = 0; i < CONFIG_OPTION_COUNT; i++)
                                {
                                    if (config_options[i].id == OPT_EDIT_IP)
                                    {
                                        draw_option_value((int)i);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (key == sk_Left && focus == FOCUS_OPTIONS && edit_mode == EDIT_NONE)
        {
            focus = FOCUS_TABS;
            draw_option_marker(tab, sel_index[tab], false);
        }
    }

    if (lwip_started)
    {
        usb_Cleanup();
    }

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
