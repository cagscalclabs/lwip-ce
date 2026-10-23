#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <fileioc.h>
#include <ti/screen.h>

#include <lwip.h>
#include <lwip/wireless/wifi.h>

#define TEST_SSID "lwip-test-net"

static char log_text[4096];
static size_t log_len;
static uint8_t row;

static void say(const char *format, ...)
{
    static char line[96];
    va_list args;

    va_start(args, format);
    vsnprintf(line, sizeof line, format, args);
    va_end(args);
    if (row < 10)
    {
        char shown[27];
        size_t i;

        for (i = 0; i < sizeof shown - 1 && line[i]; i++)
            shown[i] = line[i] >= ' ' && line[i] <= '~' && line[i] != '[' ? line[i] : '?';
        shown[i] = '\0';
        os_SetCursorPos(row++, 0);
        os_PutStrFull(shown);
    }
    if (log_len + strlen(line) + 2 <= sizeof log_text)
        log_len += (size_t)snprintf(log_text + log_len, sizeof log_text - log_len, "%s\n", line);
}

static void list(const char *tag)
{
    static lwip_wifi_profile_t profiles[8];
    uint8_t count = 0;
    lwip_wifi_error_t err = lwip_wifi_list_profiles(profiles, 8, &count);

    say("%s list err %u count %u", tag, err, count);
    for (uint8_t i = 0; i < count; i++)
        say("  slot %u flags %02X sec %u %s", profiles[i].slot, profiles[i].flags, profiles[i].security,
            profiles[i].ssid);
}

static uint8_t find(const char *ssid)
{
    static lwip_wifi_profile_t profiles[8];
    uint8_t count = 0;

    lwip_wifi_list_profiles(profiles, 8, &count);
    for (uint8_t i = 0; i < count; i++)
        if (strcmp(profiles[i].ssid, ssid) == 0)
            return profiles[i].slot;
    return LWIP_WIFI_SLOT_NONE;
}

int main(void)
{
    lwip_wifi_state_t state;
    static lwip_wifi_network_t networks[16];
    uint8_t count = 0;
    uint8_t slot = LWIP_WIFI_SLOT_NONE;
    uint32_t start;
    uint8_t handle;

    os_ClrHome();
    if (!lwip_start() || !lwip_network_up())
    {
        say("FAIL start");
        return 1;
    }

    start = lwip_now_ms();
    while (!lwip_wifi_available() && lwip_now_ms() - start < 10000)
        lwip_service_events();
    say("bridge %s", lwip_wifi_available() ? "yes" : "no");

    if (lwip_wifi_get_state(&state) == LWIP_WIFI_OK)
        say("state conn %u slot %u rssi %d ch %u saved %u %s", state.connected, state.slot, state.rssi,
            state.channel, state.saved, state.ssid);
    else
        say("state failed");

    list("start");
    say("scan err %u", lwip_wifi_scan(networks, 16, &count));
    say("scan count %u", count);
    for (uint8_t i = 0; i < count; i++)
        say("  %d dBm ch %u sec %u %s", networks[i].rssi, networks[i].channel, networks[i].security,
            networks[i].ssid);

    say("save err %u", lwip_wifi_save_profile(LWIP_WIFI_SLOT_NONE, TEST_SSID, "not-a-real-pass",
                                              LWIP_WIFI_SEC_WPA2, LWIP_WIFI_PROFILE_ENABLED, &slot));
    say("saved slot %u", slot);
    say("rename err %u", lwip_wifi_save_profile(slot, TEST_SSID "-2", NULL, LWIP_WIFI_SEC_WPA3,
                                                LWIP_WIFI_PROFILE_ENABLED, &slot));
    say("renamed slot %u", slot);
    say("disable err %u", lwip_wifi_enable_profile(slot, false));
    list("edited");
    say("forget err %u", lwip_wifi_forget_profile(find(TEST_SSID "-2")));
    say("forget missing err %u", lwip_wifi_forget_profile(7));
    list("end");

    if (lwip_wifi_get_state(&state) == LWIP_WIFI_OK)
        say("state conn %u %s", state.connected, state.ssid);
    say("DONE");

    lwip_stop();
    handle = ti_Open("WIFILOG", "w");
    if (handle)
    {
        ti_Write(log_text, log_len, 1, handle);
        ti_Close(handle);
    }
    return 0;
}
