#include <ti/getcsc.h>
#include <ti/screen.h>
#include <ti/vars.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/dhcp.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/sntp.h"
#include "lwip/app_config.h"

#include <sys/rtc.h>
#include <time.h>

#include <usbdrvce.h>
#include "drivers/usb_ethernet.h"

static struct lwip_app_config g_cfg;

static bool run_main = false;
static bool dhcp_started = false;
static bool httpd_running = false;
static bool sntp_started = false;

struct lwip_configurator lwip_conf = {
    LWIP_CONFIGURATOR_V1,
    {
        usb_ResetDevice,
        usb_DisableDevice,
        usb_RefDevice,
        usb_UnrefDevice,
        usb_SetDeviceData,
        usb_GetDeviceData,
        usb_GetRole,
        usb_GetDeviceFlags,
        usb_ScheduleTransfer,
        usb_ControlTransfer,
        usb_GetConfigurationDescriptorTotalLength,
        usb_GetDescriptor,
        usb_GetStringDescriptor,
        usb_SetConfiguration,
        usb_SetInterface,
        usb_GetDeviceEndpoint,
        usb_SetEndpointData,
        usb_GetEndpointData,
        usb_SetEndpointFlags
    },
    {
        malloc, free
    }
};

static void cfg_set_defaults(struct lwip_app_config *cfg)
{
    cfg->version = LWIP_CFG_VERSION;
    cfg->flags = LWIP_CFG_DEFAULT_FLAGS;
    cfg->max_heap = LWIP_CFG_DEFAULT_MAX_HEAP;
}

static void cfg_load(struct lwip_app_config *cfg)
{
    int archived = 0;
    var_t *data = os_GetAppVarData(LWIP_CFG_VAR_NAME, &archived);
    if (!data)
    {
        cfg_set_defaults(cfg);
        return;
    }

    size_t size = 0;
    if (os_GetVarSize(LWIP_CFG_VAR_NAME, &size) != 0 || size < sizeof(*cfg))
    {
        cfg_set_defaults(cfg);
        return;
    }

    memcpy(cfg, data, sizeof(*cfg));
    if (cfg->version != LWIP_CFG_VERSION)
    {
        cfg_set_defaults(cfg);
    }
}

static bool cfg_save(const struct lwip_app_config *cfg)
{
    os_DelAppVar(LWIP_CFG_VAR_NAME);
    var_t *data = os_CreateAppVar(LWIP_CFG_VAR_NAME, sizeof(*cfg));
    if (!data)
    {
        return false;
    }
    memcpy(data, cfg, sizeof(*cfg));
    return true;
}

static void draw_line(int y, const char *text)
{
    os_FontDrawText(text, 2, y);
}

static void draw_checkbox(int y, const char *label, bool enabled, bool selected)
{
    char line[32];
    snprintf(line, sizeof(line), "%c[%c] %s", selected ? '>' : ' ', enabled ? 'x' : ' ', label);
    draw_line(y, line);
}

static void draw_value(int y, const char *label, uint32_t value, bool selected)
{
    char line[32];
    snprintf(line, sizeof(line), "%c%s %lu", selected ? '>' : ' ', label, (unsigned long)value);
    draw_line(y, line);
}

static void draw_action(int y, const char *label, bool selected)
{
    char line[32];
    snprintf(line, sizeof(line), "%c%s", selected ? '>' : ' ', label);
    draw_line(y, line);
}

static void redraw_menu(uint8_t selected)
{
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    draw_checkbox(0, "Enable TLS", (g_cfg.flags & LWIP_CFG_FLAG_TLS) != 0, selected == 0);
    draw_checkbox(10, "Enable NTP", (g_cfg.flags & LWIP_CFG_FLAG_NTP) != 0, selected == 1);
    draw_checkbox(20, "Enable DNS", (g_cfg.flags & LWIP_CFG_FLAG_DNS) != 0, selected == 2);
    draw_checkbox(30, "HTTP test", (g_cfg.flags & LWIP_CFG_FLAG_HTTP_TEST) != 0, selected == 3);
    draw_value(40, "Max heap:", g_cfg.max_heap, selected == 4);
    draw_action(50, "Start NTP test", selected == 5);
    draw_action(60, "Start HTTP test", selected == 6);
    draw_action(70, "Save & Exit", selected == 7);
    draw_line(70, "48k available");
    draw_line(80, "Too high = low app RAM");
    draw_line(90, "2nd=toggle  <>=adjust");
}

static void ethif_status_callback_fn(struct netif *netif)
{
    if (dhcp_supplied_address(netif) && (!httpd_running))
    {
        httpd_init();
        printf("httpd listen on %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
        httpd_running = true;
    }
}

static void run_ntp_test(void)
{
    struct netif *ethif = NULL;

    if (lwip_init(&lwip_conf) != ERR_OK)
    {
        printf("lwIP init failed\n");
        os_GetKey();
        return;
    }

    if (usb_Init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        printf("USB init failed\n");
        os_GetKey();
        return;
    }

    printf("NTP Test Starting...\n");
    printf("Waiting for network...\n");

    run_main = true;
    bool time_synced = false;
    uint32_t timeout = 300; // 30 seconds

    do
    {
        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            run_main = false;
        }

        // Start DHCP if not started
        if (netif_default && (!dhcp_started))
        {
            dhcp_start(netif_default);
            dhcp_started = true;
        }

        // Start SNTP once we have an IP
        if (netif_default && dhcp_supplied_address(netif_default) && (!sntp_started))
        {
            printf("IP: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_default)));
            printf("Starting SNTP...\n");

            // Set NTP server (time.nist.gov: 132.163.96.1)
            ip_addr_t ntp_server;
            IP_ADDR4(&ntp_server, 132, 163, 96, 1);
            sntp_setserver(0, &ntp_server);

            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_init();
            sntp_started = true;

            printf("Waiting for time sync...\n");
            printf("This may take 5-10s\n");
        }

        // Display time once synced
        if (sntp_started && !time_synced)
        {
            // Check if we got a time (RTC should be set by SNTP_SET_SYSTEM_TIME)
            uint8_t sec, min, hr;
            boot_GetTime(&sec, &min, &hr);

            // If time looks valid (not 00:00:00), display it
            if (sec != 0 || min != 0 || hr != 0)
            {
                printf("Time synced!\n");
                printf("Current time: %02u:%02u:%02u\n", hr, min, sec);
                printf("(UTC time)\n");
                printf("\nPress Clear to exit\n");
                time_synced = true;
            }
        }

        if (!netif_default)
        {
            dhcp_started = false;
            sntp_started = false;
        }

        usb_HandleEvents();
        sys_check_timeouts();

        // Timeout check
        if (!time_synced && sntp_started)
        {
            timeout--;
            if (timeout == 0)
            {
                printf("Time sync timeout\n");
                printf("Press any key\n");
                os_GetKey();
                run_main = false;
            }
        }

    } while (run_main);

    if (sntp_started)
    {
        sntp_stop();
    }
    if (dhcp_started && ethif)
    {
        dhcp_release_and_stop(ethif);
    }
    usb_Cleanup();
    sntp_started = false;
    dhcp_started = false;
}

static void run_http_test_server(void)
{
    struct netif *ethif = NULL;

    if (lwip_init(&lwip_conf) != ERR_OK)
    {
        return;
    }

    if (usb_Init(eth_usb_event_callback, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
    {
        return;
    }

    run_main = true;
    do
    {
        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            run_main = false;
        }
        if (netif_default && (!dhcp_started))
        {
            netif_set_status_callback(netif_default, ethif_status_callback_fn);
            dhcp_start(netif_default);
            dhcp_started = true;
        }
        if (!netif_default)
        {
            dhcp_started = false;
        }
        usb_HandleEvents();
        sys_check_timeouts();
    } while (run_main);

    dhcp_release_and_stop(ethif);
    usb_Cleanup();
    httpd_running = false;
}

int main(void)
{
    cfg_load(&g_cfg);

    uint8_t selected = 0;
    bool redraw = true;

    while (true)
    {
        if (redraw)
        {
            redraw_menu(selected);
            redraw = false;
        }

        uint8_t key = os_GetCSC();
        if (key == 0)
        {
            continue;
        }

        if (key == sk_Clear)
        {
            break;
        }

        if (key == sk_Up)
        {
            selected = (selected == 0) ? 7 : (selected - 1);
            redraw = true;
        }
        else if (key == sk_Down)
        {
            selected = (selected + 1) % 8;
            redraw = true;
        }
        else if (key == sk_2nd)
        {
            if (selected <= 3)
            {
                g_cfg.flags ^= (1u << selected);
                redraw = true;
            }
        }
        else if (key == sk_Left || key == sk_Right)
        {
            if (selected == 4)
            {
                if (key == sk_Left)
                {
                    if (g_cfg.max_heap > LWIP_CFG_HEAP_MIN)
                    {
                        g_cfg.max_heap -= LWIP_CFG_HEAP_STEP;
                    }
                }
                else
                {
                    if (g_cfg.max_heap + LWIP_CFG_HEAP_STEP <= LWIP_CFG_HEAP_MAX)
                    {
                        g_cfg.max_heap += LWIP_CFG_HEAP_STEP;
                    }
                }
                redraw = true;
            }
        }
        else if (key == sk_Enter)
        {
            if (selected == 5)
            {
                run_ntp_test();
                redraw = true;
            }
            else if (selected == 6)
            {
                if ((g_cfg.flags & LWIP_CFG_FLAG_HTTP_TEST) != 0)
                {
                    run_http_test_server();
                }
                redraw = true;
            }
            else if (selected == 7)
            {
                cfg_save(&g_cfg);
                break;
            }
        }
    }

    os_ClrHome();
    return 0;
}
