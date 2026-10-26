#include "bridge.h"
#include "profiles.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define CONSOLE_UART CONFIG_ESP_CONSOLE_UART_NUM
#define CONSOLE_LINE_MAX 384

static wifi_scan_entry_t s_scan[WIFI_SCAN_MAX];

static int nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c |= 0x20;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static bool unhex(const char *in, char *out, size_t size)
{
    size_t length = in ? strlen(in) : 0;

    if (in == NULL || length % 2 != 0 || length / 2 >= size) {
        return false;
    }
    for (size_t i = 0; i < length; i += 2) {
        int high = nibble(in[i]);
        int low = nibble(in[i + 1]);

        if (high < 0 || low < 0) {
            return false;
        }
        out[i / 2] = (char)(high << 4 | low);
    }
    out[length / 2] = 0;
    return true;
}

static void print_hex(const char *text)
{
    while (*text) {
        printf("%02x", (unsigned char)*text++);
    }
}

static char *next_field(char **cursor)
{
    char *field = *cursor;
    char *space;

    if (field == NULL) {
        return NULL;
    }
    space = strchr(field, ' ');
    if (space == NULL) {
        *cursor = NULL;
    } else {
        *space = 0;
        *cursor = space + 1;
    }
    return field;
}

static bool parse_number(const char *field, unsigned max, unsigned *out)
{
    char *end;
    unsigned long value;

    if (field == NULL || *field == 0) {
        return false;
    }
    value = strtoul(field, &end, 10);
    if (*end != 0 || value > max) {
        return false;
    }
    *out = (unsigned)value;
    return true;
}

static const char *cmd_version(char *args)
{
    (void)args;
    printf("@bridge-version %s\n", esp_app_get_description()->version);
    return NULL;
}

static const char *cmd_status(char *args)
{
    wifi_status_t status;

    (void)args;
    wifi_get_status(&status);
    printf("@wifi-status %s %u %d ", status.connected ? "connected" : status.joining ? "joining" : "idle",
           status.reason, status.rssi);
    print_hex(status.ssid);
    printf("\n");
    return NULL;
}

static const char *cmd_scan(char *args)
{
    int count = wifi_scan(s_scan, WIFI_SCAN_MAX);

    (void)args;
    if (count < 0) {
        return "busy";
    }
    for (int i = 0; i < count; i++) {
        printf("@wifi-scan %d %u %u ", s_scan[i].rssi, s_scan[i].channel, s_scan[i].security);
        print_hex(s_scan[i].ssid);
        printf("\n");
    }
    return NULL;
}

static const char *cmd_list(char *args)
{
    profile_view_t view;

    (void)args;
    for (uint8_t i = 0; profiles_view(i, &view); i++) {
        printf("@wifi-list %u %u %u ", view.slot, view.flags, view.security);
        print_hex(view.ssid);
        printf("\n");
    }
    return NULL;
}

static const char *cmd_add(char *args)
{
    char ssid[PROFILE_SSID_MAX];
    char password[PROFILE_PASSWORD_MAX];
    char username[PROFILE_USERNAME_MAX];
    unsigned security, flags;
    const char *error = NULL;
    uint8_t slot = PROFILE_NONE;

    if (!parse_number(next_field(&args), LWIP_WIFI_SEC_ENTERPRISE, &security) ||
        !parse_number(next_field(&args), PROFILE_F_HIDDEN | PROFILE_F_CHECK_SERVER, &flags) ||
        !unhex(next_field(&args), ssid, sizeof ssid) || ssid[0] == 0 ||
        !unhex(next_field(&args), password, sizeof password) ||
        !unhex(next_field(&args), username, sizeof username)) {
        error = "bad-request";
    } else if (security == LWIP_WIFI_SEC_ENTERPRISE ? username[0] == 0 : username[0] != 0) {
        error = "bad-request";
    } else if (security == LWIP_WIFI_SEC_OPEN && password[0] != 0) {
        error = "bad-request";
    } else {
        slot = profiles_save(ssid, username, password, (uint8_t)security, (uint8_t)(flags | PROFILE_F_ENABLED));
        if (slot == PROFILE_NONE) {
            error = "full";
        }
    }
    memset(password, 0, sizeof password);
    memset(username, 0, sizeof username);

    if (error == NULL) {
        printf("@wifi-add %u\n", slot);
        wifi_join_slot(slot);
    }
    return error;
}

static const char *cmd_forget(char *args)
{
    unsigned slot;

    if (!parse_number(next_field(&args), PROFILE_SLOTS - 1, &slot)) {
        return "bad-request";
    }
    return profiles_forget((uint8_t)slot) ? NULL : "not-found";
}

static const struct {
    const char *name;
    const char *(*run)(char *args);
} s_commands[] = {
    {"bridge-version", cmd_version},
    {"wifi-status", cmd_status},
    {"wifi-scan", cmd_scan},
    {"wifi-list", cmd_list},
    {"wifi-add", cmd_add},
    {"wifi-forget", cmd_forget},
};

static void run(char *line)
{
    char *args = line;
    const char *name = next_field(&args);

    for (size_t i = 0; i < sizeof s_commands / sizeof s_commands[0]; i++) {
        if (strcmp(name, s_commands[i].name) == 0) {
            const char *error = s_commands[i].run(args);

            if (error == NULL) {
                printf("@%s ok\n", name);
            } else {
                printf("@%s error %s\n", name, error);
            }
            fflush(stdout);
            return;
        }
    }
}

static void console_task(void *arg)
{
    char line[CONSOLE_LINE_MAX];
    size_t used = 0;
    bool overflow = false;

    (void)arg;

    for (;;) {
        char c;

        if (uart_read_bytes(CONSOLE_UART, &c, 1, portMAX_DELAY) != 1) {
            continue;
        }
        if (c != '\n' && c != '\r') {
            if (used < sizeof line - 1) {
                line[used++] = c;
            } else {
                overflow = true;
            }
            continue;
        }
        line[used] = 0;
        if (!overflow && used > 0) {
            run(line);
        }
        memset(line, 0, used);
        used = 0;
        overflow = false;
    }
}

esp_err_t console_init(void)
{
    esp_err_t err = uart_driver_install(CONSOLE_UART, 512, 0, 0, NULL, 0);

    if (err != ESP_OK) {
        return err;
    }
    xTaskCreate(console_task, "console", 4096, NULL, 3, NULL);
    return ESP_OK;
}
