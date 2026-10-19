#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "wifi_proto.h"

#define PROFILE_SLOTS 8
#define PROFILE_SSID_MAX (LWIP_WIFI_SSID_MAX + 1)
#define PROFILE_PASSWORD_MAX (LWIP_WIFI_PASSWORD_MAX + 1)
#define PROFILE_NONE LWIP_WIFI_SLOT_NONE

#define PROFILE_F_ENABLED LWIP_WIFI_PROFILE_ENABLED
#define PROFILE_F_HIDDEN LWIP_WIFI_PROFILE_HIDDEN
#define PROFILE_F_ACTIVE LWIP_WIFI_PROFILE_ACTIVE

typedef struct {
    uint8_t slot;
    uint8_t flags;
    uint8_t security;
    char ssid[PROFILE_SSID_MAX];
} profile_view_t;

esp_err_t profiles_init(void);

uint8_t profiles_count(void);
uint8_t profiles_active(void);

bool profiles_view(uint8_t index, profile_view_t *out);

uint8_t profiles_save(const char *ssid, const char *password,
                           uint8_t security, uint8_t flags);

bool profiles_forget(uint8_t slot);
bool profiles_enable(uint8_t slot, bool enabled);
bool profiles_prefer(uint8_t slot);

void profiles_mark_active(uint8_t slot);
void profiles_clear_active(void);

uint8_t profiles_pick(const char (*visible)[PROFILE_SSID_MAX],
                           uint8_t visible_count);

bool profiles_credentials(uint8_t slot, char *ssid, char *password,
                               uint8_t *security, uint8_t *flags);
