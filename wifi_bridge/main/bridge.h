#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_wifi_types.h"

#define CONTROL_ETHERTYPE 0x88B5
#define WIFI_SCAN_MAX 20

typedef struct {
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint8_t security;
} wifi_scan_entry_t;

typedef struct {
    bool connected;
    uint8_t slot;
    int8_t rssi;
    uint8_t channel;
    uint8_t bssid[6];
    char ssid[33];
} wifi_status_t;

esp_err_t bridge_init(void);
void bridge_set_wifi(bool up);
void bridge_send(const uint8_t *frame, size_t length);

esp_err_t wifi_init(void);
void wifi_get_status(wifi_status_t *out);
uint8_t wifi_scan(wifi_scan_entry_t *out, uint8_t max);
void wifi_join_slot(uint8_t slot);
void wifi_disconnect(void);
void wifi_resume(void);
void wifi_kick(void);

esp_err_t control_init(void);
void control_request(const uint8_t *frame, size_t length);
void control_notify(void);
