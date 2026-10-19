#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/power.h>
#include <sys/rtc.h>
#include <ti/getcsc.h>
#include <ti/info.h>
#include <ti/screen.h>
#include <ti/vars.h>
#include <time.h>

#include <lwip.h>
#include <lwip/wireless/wifi.h>

#define HTTP_PORT 80
#define REQUEST_TIMEOUT_MS 2000
#define CLOSE_TIMEOUT_MS 5000

static char body[3072];
static size_t body_len;
static char request[512];
static size_t request_len;
static uint16_t served;

static void put_line(uint8_t row, const char *format, ...)
{
    char text[27];
    char line[27];
    va_list args;

    va_start(args, format);
    vsnprintf(text, sizeof text, format, args);
    va_end(args);
    snprintf(line, sizeof line, "%-26s", text);
    os_SetCursorPos(row, 0);
    os_PutStrFull(line);
}

/* One "name: value" line of the response body. */
static void stat(const char *name, const char *format, ...)
{
    va_list args;
    int n;

    if (body_len >= sizeof body)
        return;
    n = snprintf(body + body_len, sizeof body - body_len, "%s: ", name);
    if (n > 0)
        body_len += (size_t)n;
    if (body_len >= sizeof body)
        return;
    va_start(args, format);
    n = vsnprintf(body + body_len, sizeof body - body_len, format, args);
    va_end(args);
    if (n > 0)
        body_len += (size_t)n;
    if (body_len + 1 < sizeof body)
        body[body_len++] = '\n';
}

static const char *yes_no(bool value)
{
    return value ? "yes" : "no";
}

static void collect_lwip(void)
{
    lwip_netif_info_t info = {0};
    struct mem_accounting_stats mem;

    stat("lwip.version", "%s", lwip_version_string());
    stat("lwip.uptime_ms", "%lu", (unsigned long)lwip_now_ms());
    stat("lwip.requests_served", "%u", served);
    stat("eth.interfaces", "%02X", eth_get_interfaces());

    lwip_default_netif_info(&info);
    stat("netif.present", "%s", yes_no(info.has_netif));
    stat("netif.up", "%s", yes_no(info.up));
    stat("netif.link_up", "%s", yes_no(info.link_up));
    stat("netif.dhcp_running", "%s", yes_no(info.dhcp_running));
    stat("netif.dhcp_state", "%u", info.dhcp_state);
    stat("netif.ipv4", "%u.%u.%u.%u", info.ipv4_addr[0], info.ipv4_addr[1], info.ipv4_addr[2],
         info.ipv4_addr[3]);
    stat("netif.netmask", "%u.%u.%u.%u", info.ipv4_netmask[0], info.ipv4_netmask[1],
         info.ipv4_netmask[2], info.ipv4_netmask[3]);
    stat("netif.gateway", "%u.%u.%u.%u", info.ipv4_gateway[0], info.ipv4_gateway[1],
         info.ipv4_gateway[2], info.ipv4_gateway[3]);

    if (!mem_get_stats(&mem))
    {
        stat("mem.error", "mem_get_stats failed");
        return;
    }
    stat("mem.total_heap", "%u", (unsigned)mem.total_heap);
    stat("mem.heap_limit", "%u", (unsigned)mem.heap_limit);
    stat("mem.heap_used", "%u", (unsigned)mem.heap_used);
    stat("mem.heap_free", "%u", (unsigned)mem.heap_free);
    stat("mem.user_reserved", "%u", (unsigned)mem.user_reserved);
    stat("mem.pbuf_pool_size", "%u", (unsigned)mem.pbuf_pool_size);
    stat("mem.pbuf_pool_used", "%u", (unsigned)mem.pbuf_pool_used);
    stat("mem.tls_used", "%u", (unsigned)mem.tls_used);
    stat("mem.tls_limit", "%u", (unsigned)mem.tls_limit);
    stat("mem.rx_ring_used", "%u", (unsigned)mem.rx_ring_used);
    stat("mem.rx_ring_size", "%u", (unsigned)mem.rx_ring_size);
    stat("mem.socket_ring_used", "%u", (unsigned)mem.socket_ring_used);
    stat("mem.socket_ring_size", "%u", (unsigned)mem.socket_ring_size);
    stat("mem.pbuf_pressure", "%u", (unsigned)mem.pbuf_pressure);
    stat("mem.heap_pressure", "%u", (unsigned)mem.heap_pressure);
    stat("mem.effective_pressure", "%u", (unsigned)mem.effective_pressure);
}

static void collect_wifi(void)
{
    lwip_wifi_state_t state;
    lwip_wifi_error_t err;

    stat("wifi.bridge", "%s", yes_no(lwip_wifi_available()));
    err = lwip_wifi_get_state(&state);
    if (err != LWIP_WIFI_OK)
    {
        stat("wifi.error", "%u", err);
        return;
    }
    stat("wifi.connected", "%s", yes_no(state.connected));
    stat("wifi.ssid", "%s", state.ssid);
    stat("wifi.rssi_dbm", "%d", state.rssi);
    stat("wifi.channel", "%u", state.channel);
    stat("wifi.bssid", "%02X:%02X:%02X:%02X:%02X:%02X", state.bssid[0], state.bssid[1],
         state.bssid[2], state.bssid[3], state.bssid[4], state.bssid[5]);
    stat("wifi.slot", "%u", state.slot);
    stat("wifi.saved_networks", "%u", state.saved);
}

static void collect_calc(void)
{
    const system_info_t *info = os_GetSystemInfo();
    void *free_start;

    stat("calc.hardware_version", "%u", info->hardwareVersion);
    stat("calc.hardware_type", "%u", info->hardwareType);
    stat("calc.os_version", "%u.%u.%u.%04u", info->osMajorVersion, info->osMinorVersion,
         info->osRevisionVersion, info->osBuildVersion);
    stat("calc.boot_version", "%u.%u.%u.%04u", info->bootMajorVersion, info->bootMinorVersion,
         info->bootRevisionVersion, info->bootBuildVersion);
    stat("calc.id", "%02X%02X%02X%02X%02X%02X%02X%02X", info->calcid[0], info->calcid[1],
         info->calcid[2], info->calcid[3], info->calcid[4], info->calcid[5], info->calcid[6],
         info->calcid[7]);
    stat("calc.language", "%04X", info->language);
    stat("calc.ram_free", "%u", (unsigned)os_MemChk(&free_start));
    os_ArcChk();
    stat("calc.archive_free", "%u", (unsigned)os_TempFreeArc);
    stat("calc.battery_level", "%u", boot_GetBatteryStatus());
    stat("calc.charging", "%s", yes_no(boot_BatteryCharging()));
    stat("calc.rtc_seconds", "%lu", (unsigned long)rtc_Time());
    stat("calc.clock_ticks", "%lu", (unsigned long)clock());
}

static void respond(struct lwip_socket *peer)
{
    static const char header[] = "HTTP/1.0 200 OK\r\n"
                                 "Content-Type: text/plain; charset=utf-8\r\n"
                                 "Cache-Control: no-store\r\n"
                                 "Connection: close\r\n"
                                 "\r\n";

    served++;
    body_len = 0;
    collect_lwip();
    collect_wifi();
    collect_calc();
    lwip_socket_write(peer, (const uint8_t *)header, sizeof header - 1);
    lwip_socket_write(peer, (const uint8_t *)body, body_len);
    lwip_socket_close(peer);
}

static bool request_complete(void)
{
    return strstr(request, "\r\n\r\n") || strstr(request, "\n\n") ||
           request_len >= sizeof request - 1;
}

int main(void)
{
    struct lwip_socket *listener = NULL;
    struct lwip_socket *peer = NULL;
    bool listening = false;
    bool answered = false;
    uint32_t peer_since = 0;

    os_ClrHome();
    put_line(0, "LWSTATS");
    if (!lwip_start() || !lwip_network_up())
    {
        put_line(9, "FAIL start %u", lwip_start_last_error());
        while (!os_GetCSC())
            ;
        return 1;
    }
    listener = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 0);
    if (!listener)
    {
        put_line(9, "FAIL socket");
        lwip_stop();
        while (!os_GetCSC())
            ;
        return 1;
    }
    put_line(1, "waiting for address");
    put_line(9, "clear quits");

    while (os_GetCSC() != sk_Clear)
    {
        lwip_service_events();

        if (!listening)
        {
            lwip_netif_info_t info = {0};

            if (!lwip_default_netif_info(&info) || !info.has_ipv4)
                continue;
            if (lwip_socket_listen(listener, HTTP_PORT) != LWIP_OK)
            {
                put_line(1, "FAIL listen");
                break;
            }
            listening = true;
            put_line(1, "http://%u.%u.%u.%u/", info.ipv4_addr[0], info.ipv4_addr[1],
                     info.ipv4_addr[2], info.ipv4_addr[3]);
        }

        /* One client at a time keeps this simple; browsers retry the rest. */
        if (!peer)
        {
            peer = lwip_socket_accept(listener);
            if (!peer)
                continue;
            peer_since = lwip_now_ms();
            request_len = 0;
            request[0] = '\0';
            answered = false;
        }

        if (!lwip_socket_is_active(peer) ||
            (answered && lwip_now_ms() - peer_since > CLOSE_TIMEOUT_MS))
        {
            if (lwip_socket_is_active(peer))
                lwip_socket_abort(peer);
            lwip_socket_destroy(peer);
            peer = NULL;
            continue;
        }
        if (answered)
            continue;

        request_len += lwip_socket_read(peer, (uint8_t *)request + request_len,
                                        sizeof request - 1 - request_len);
        request[request_len] = '\0';
        if (request_complete() || lwip_now_ms() - peer_since > REQUEST_TIMEOUT_MS)
        {
            respond(peer);
            answered = true;
            peer_since = lwip_now_ms();
            put_line(2, "requests %u", served);
            put_line(3, "body %u bytes", (unsigned)body_len);
        }
    }

    if (peer)
        lwip_socket_destroy(peer);
    lwip_socket_destroy(listener);
    lwip_stop();
    return 0;
}
