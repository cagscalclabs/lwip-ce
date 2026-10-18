#include "bridge.h"
#include "profiles.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"

#define TAG "wifi"
#define RETRY_MS 15000

enum {
    SEC_OPEN,
    SEC_WEP,
    SEC_WPA,
    SEC_WPA2,
    SEC_WPA3,
    SEC_WPA2_WPA3,
    SEC_ENTERPRISE,
};

static TaskHandle_t s_task;
static SemaphoreHandle_t s_scan_lock;
static volatile bool s_connected;
static volatile bool s_paused;
static volatile uint8_t s_pending = PROFILE_NONE;
static uint8_t s_slot = PROFILE_NONE;
static wifi_ap_record_t s_records[WIFI_SCAN_MAX];

static wifi_auth_mode_t auth_for(uint8_t security)
{
    switch (security) {
    case SEC_OPEN:
        return WIFI_AUTH_OPEN;
    case SEC_WEP:
        return WIFI_AUTH_WEP;
    case SEC_WPA:
        return WIFI_AUTH_WPA_PSK;
    case SEC_WPA3:
        return WIFI_AUTH_WPA3_PSK;
    case SEC_WPA2_WPA3:
        return WIFI_AUTH_WPA2_WPA3_PSK;
    case SEC_ENTERPRISE:
        return WIFI_AUTH_ENTERPRISE;
    default:
        return WIFI_AUTH_WPA2_PSK;
    }
}

static uint8_t security_from_auth(wifi_auth_mode_t auth)
{
    switch (auth) {
    case WIFI_AUTH_OPEN:
    case WIFI_AUTH_OWE:
        return SEC_OPEN;
    case WIFI_AUTH_WEP:
        return SEC_WEP;
    case WIFI_AUTH_WPA_PSK:
        return SEC_WPA;
    case WIFI_AUTH_WPA3_PSK:
        return SEC_WPA3;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        return SEC_WPA2_WPA3;
    case WIFI_AUTH_ENTERPRISE:
    case WIFI_AUTH_WPA3_ENTERPRISE:
        return SEC_ENTERPRISE;
    default:
        return SEC_WPA2;
    }
}

static uint16_t scan_records(void)
{
    uint16_t count = 0;

    xSemaphoreTake(s_scan_lock, portMAX_DELAY);
    if (esp_wifi_scan_start(NULL, true) == ESP_OK && esp_wifi_scan_get_ap_num(&count) == ESP_OK) {
        if (count > WIFI_SCAN_MAX) {
            count = WIFI_SCAN_MAX;
        }
        if (esp_wifi_scan_get_ap_records(&count, s_records) != ESP_OK) {
            count = 0;
        }
    }
    esp_wifi_clear_ap_list();
    return count;
}

uint8_t wifi_scan(wifi_scan_entry_t *out, uint8_t max)
{
    uint16_t count = scan_records();
    uint8_t used = 0;

    for (uint16_t i = 0; i < count && used < max; i++) {
        if (s_records[i].ssid[0] == 0) {
            continue;
        }
        memcpy(out[used].ssid, s_records[i].ssid, 32);
        out[used].ssid[32] = 0;
        out[used].rssi = s_records[i].rssi;
        out[used].channel = s_records[i].primary;
        out[used].security = security_from_auth(s_records[i].authmode);
        used++;
    }
    xSemaphoreGive(s_scan_lock);
    return used;
}

static uint8_t pick_profile(void)
{
    char visible[WIFI_SCAN_MAX][PROFILE_SSID_MAX];
    uint16_t count = scan_records();
    uint8_t slot;

    for (uint16_t i = 0; i < count; i++) {
        memcpy(visible[i], s_records[i].ssid, PROFILE_SSID_MAX - 1);
        visible[i][PROFILE_SSID_MAX - 1] = 0;
    }
    xSemaphoreGive(s_scan_lock);

    slot = profiles_pick(count ? (const char (*)[PROFILE_SSID_MAX])visible : NULL,
                              (uint8_t)count);
    return slot;
}

static void join(uint8_t slot)
{
    char ssid[PROFILE_SSID_MAX];
    char password[PROFILE_PASSWORD_MAX];
    uint8_t security;
    uint8_t flags;
    wifi_config_t config = {0};

    if (!profiles_credentials(slot, ssid, password, &security, &flags)) {
        return;
    }

    memcpy(config.sta.ssid, ssid, strnlen(ssid, sizeof config.sta.ssid));
    strncpy((char *)config.sta.password, password, sizeof config.sta.password - 1);
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    config.sta.threshold.authmode = password[0] ? auth_for(security) : WIFI_AUTH_OPEN;
    config.sta.pmf_cfg.capable = true;
    config.sta.pmf_cfg.required = security == SEC_WPA3;
    memset(password, 0, sizeof password);

    s_slot = slot;
    ESP_LOGI(TAG, "joining %s", ssid);
    esp_wifi_set_config(WIFI_IF_STA, &config);
    esp_wifi_connect();
}

static void wifi_task(void *arg)
{
    (void)arg;

    for (;;) {
        uint8_t pending = s_pending;

        if (pending != PROFILE_NONE) {
            s_pending = PROFILE_NONE;
            if (s_connected) {
                esp_wifi_disconnect();
                vTaskDelay(pdMS_TO_TICKS(200));
            }
            join(pending);
        } else if (!s_connected && !s_paused) {
            uint8_t slot = pick_profile();

            if (s_pending != PROFILE_NONE) {
                continue;
            }
            if (slot == PROFILE_NONE) {
                ESP_LOGW(TAG, "no saved network in range");
            } else {
                join(slot);
            }
        }
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(RETRY_MS));
    }
}

void wifi_kick(void)
{
    if (s_task != NULL) {
        xTaskNotifyGive(s_task);
    }
}

void wifi_join_slot(uint8_t slot)
{
    s_paused = false;
    s_pending = slot;
    wifi_kick();
}

void wifi_disconnect(void)
{
    s_paused = true;
    s_pending = PROFILE_NONE;
    esp_wifi_disconnect();
}

void wifi_resume(void)
{
    s_paused = false;
    if (s_connected) {
        esp_wifi_disconnect();
    }
    wifi_kick();
}

void wifi_get_status(wifi_status_t *out)
{
    wifi_ap_record_t ap;

    memset(out, 0, sizeof *out);
    out->slot = PROFILE_NONE;
    out->connected = s_connected;
    if (s_connected && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        out->slot = profiles_active();
        out->rssi = ap.rssi;
        out->channel = ap.primary;
        memcpy(out->bssid, ap.bssid, 6);
        memcpy(out->ssid, ap.ssid, 32);
    }
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;

    if (id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event = data;

        ESP_LOGW(TAG, "disconnected, reason %u", event->reason);
        s_connected = false;
        profiles_clear_active();
        bridge_set_wifi(false);
        control_notify();
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "connected");
        s_connected = true;
        profiles_mark_active(s_slot);
        bridge_set_wifi(true);
        control_notify();
    }
}

esp_err_t wifi_init(void)
{
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err;

    s_scan_lock = xSemaphoreCreateMutex();
    if (s_scan_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    err = profiles_init();
    if (err != ESP_OK) {
        return err;
    }

    err = esp_wifi_init(&config);
    if (err != ESP_OK) {
        return err;
    }

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, on_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "%u saved network(s)", profiles_count());
    xTaskCreate(wifi_task, "wifi", 4096, NULL, 5, &s_task);

    return ESP_OK;
}
