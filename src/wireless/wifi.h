#ifndef LWIP_WIRELESS_WIFI_H
#define LWIP_WIRELESS_WIFI_H

#include <stdbool.h>
#include <stdint.h>

#define LWIP_WIFI_SSID_MAX 32
#define LWIP_WIFI_PASSWORD_MAX 64
#define LWIP_WIFI_SLOT_NONE 0xFF

#define LWIP_WIFI_PROFILE_ENABLED 0x01
#define LWIP_WIFI_PROFILE_HIDDEN 0x02
#define LWIP_WIFI_PROFILE_ACTIVE 0x04

typedef enum
{
    LWIP_WIFI_SEC_OPEN,
    LWIP_WIFI_SEC_WEP,
    LWIP_WIFI_SEC_WPA,
    LWIP_WIFI_SEC_WPA2,
    LWIP_WIFI_SEC_WPA3,
    LWIP_WIFI_SEC_WPA2_WPA3,
    LWIP_WIFI_SEC_ENTERPRISE
} lwip_wifi_security_t;

typedef enum
{
    LWIP_WIFI_OK,
    LWIP_WIFI_ERR_NO_BRIDGE,
    LWIP_WIFI_ERR_TIMEOUT,
    LWIP_WIFI_ERR_BAD_REQUEST,
    LWIP_WIFI_ERR_NOT_FOUND,
    LWIP_WIFI_ERR_FULL,
    LWIP_WIFI_ERR_MEM
} lwip_wifi_error_t;

typedef struct
{
    uint8_t slot;
    uint8_t flags;
    uint8_t security;
    char ssid[LWIP_WIFI_SSID_MAX + 1];
} lwip_wifi_profile_t;

typedef struct
{
    char ssid[LWIP_WIFI_SSID_MAX + 1];
    int8_t rssi;
    uint8_t channel;
    uint8_t security;
} lwip_wifi_network_t;

typedef struct
{
    bool connected;
    uint8_t slot;
    int8_t rssi;
    uint8_t channel;
    uint8_t bssid[6];
    uint8_t saved;
    char ssid[LWIP_WIFI_SSID_MAX + 1];
} lwip_wifi_state_t;

typedef void (*lwip_wifi_event_fn)(const lwip_wifi_state_t *state, void *arg);

bool lwip_wifi_available(void);

void lwip_wifi_set_event_cb(lwip_wifi_event_fn fn, void *arg);

lwip_wifi_error_t lwip_wifi_get_state(lwip_wifi_state_t *state);

lwip_wifi_error_t lwip_wifi_list_profiles(lwip_wifi_profile_t *profiles, uint8_t max, uint8_t *count);

lwip_wifi_error_t lwip_wifi_scan(lwip_wifi_network_t *networks, uint8_t max, uint8_t *count);

lwip_wifi_error_t lwip_wifi_save_profile(uint8_t slot, const char *ssid, const char *password,
                                         uint8_t security, uint8_t flags, uint8_t *saved);

lwip_wifi_error_t lwip_wifi_forget_profile(uint8_t slot);

lwip_wifi_error_t lwip_wifi_enable_profile(uint8_t slot, bool enabled);

lwip_wifi_error_t lwip_wifi_prefer_profile(uint8_t slot);

lwip_wifi_error_t lwip_wifi_connect(uint8_t slot);

lwip_wifi_error_t lwip_wifi_disconnect(void);

#endif
