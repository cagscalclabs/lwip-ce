#include "bridge.h"
#include "profiles.h"

#include <string.h>

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_eap_client.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"

#define TAG "wifi"
#define RETRY_MS 15000

static TaskHandle_t s_task;
static SemaphoreHandle_t s_scan_lock;
static volatile bool s_connected;
static volatile bool s_joining;
static volatile bool s_paused;
static volatile uint8_t s_pending = PROFILE_NONE;
static uint8_t s_slot = PROFILE_NONE;
static volatile uint8_t s_reason = LWIP_WIFI_REASON_NONE;
static wifi_ap_record_t s_records[WIFI_SCAN_MAX];

static wifi_auth_mode_t auth_for(uint8_t security)
{
    switch (security) {
    case LWIP_WIFI_SEC_OPEN:
        return WIFI_AUTH_OPEN;
    case LWIP_WIFI_SEC_WEP:
        return WIFI_AUTH_WEP;
    case LWIP_WIFI_SEC_WPA:
        return WIFI_AUTH_WPA_PSK;
    case LWIP_WIFI_SEC_WPA3:
        return WIFI_AUTH_WPA3_PSK;
    case LWIP_WIFI_SEC_WPA2_WPA3:
        return WIFI_AUTH_WPA2_WPA3_PSK;
    case LWIP_WIFI_SEC_ENTERPRISE:
        return WIFI_AUTH_ENTERPRISE;
    default:
        return WIFI_AUTH_WPA2_PSK;
    }
}

static bool is_enterprise(wifi_auth_mode_t auth)
{
    return auth == WIFI_AUTH_ENTERPRISE || auth == WIFI_AUTH_WPA3_ENTERPRISE ||
           auth == WIFI_AUTH_WPA2_WPA3_ENTERPRISE || auth == WIFI_AUTH_WPA3_ENT_192 ||
           auth == WIFI_AUTH_WPA_ENTERPRISE;
}

static uint8_t security_from_auth(wifi_auth_mode_t auth)
{
    if (is_enterprise(auth)) {
        return LWIP_WIFI_SEC_ENTERPRISE;
    }
    switch (auth) {
    case WIFI_AUTH_OPEN:
    case WIFI_AUTH_OWE:
        return LWIP_WIFI_SEC_OPEN;
    case WIFI_AUTH_WEP:
        return LWIP_WIFI_SEC_WEP;
    case WIFI_AUTH_WPA_PSK:
        return LWIP_WIFI_SEC_WPA;
    case WIFI_AUTH_WPA3_PSK:
        return LWIP_WIFI_SEC_WPA3;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        return LWIP_WIFI_SEC_WPA2_WPA3;
    default:
        return LWIP_WIFI_SEC_WPA2;
    }
}

/* Returns -1 when the radio cannot scan right now, for example while joining. */
int wifi_scan(wifi_scan_entry_t *out, uint8_t max)
{
    uint16_t count = 0;
    int used = -1;

    xSemaphoreTake(s_scan_lock, portMAX_DELAY);
    if (esp_wifi_scan_start(NULL, true) == ESP_OK && esp_wifi_scan_get_ap_num(&count) == ESP_OK) {
        if (count > WIFI_SCAN_MAX) {
            count = WIFI_SCAN_MAX;
        }
        if (esp_wifi_scan_get_ap_records(&count, s_records) == ESP_OK) {
            used = 0;
            for (uint16_t i = 0; i < count; i++) {
                const char *ssid = (const char *)s_records[i].ssid;
                int at = 0;

                if (ssid[0] == 0) {
                    continue;
                }
                /* One entry per network: keep the strongest of its access points. */
                while (at < used && strncmp(out[at].ssid, ssid, LWIP_WIFI_SSID_MAX) != 0) {
                    at++;
                }
                if (at < used ? s_records[i].rssi <= out[at].rssi : used == max) {
                    continue;
                }
                if (at == used) {
                    used++;
                }
                memcpy(out[at].ssid, ssid, LWIP_WIFI_SSID_MAX);
                out[at].ssid[LWIP_WIFI_SSID_MAX] = 0;
                out[at].rssi = s_records[i].rssi;
                out[at].channel = s_records[i].primary;
                out[at].security = security_from_auth(s_records[i].authmode);
            }
        }
    }
    esp_wifi_clear_ap_list();
    xSemaphoreGive(s_scan_lock);
    return used;
}

static uint8_t pick_profile(void)
{
    static wifi_scan_entry_t found[WIFI_SCAN_MAX];
    char visible[WIFI_SCAN_MAX][PROFILE_SSID_MAX];
    int count = wifi_scan(found, WIFI_SCAN_MAX);

    if (count < 0) {
        count = 0;
    }
    for (int i = 0; i < count; i++) {
        memcpy(visible[i], found[i].ssid, PROFILE_SSID_MAX);
    }
    return profiles_pick(count ? (const char (*)[PROFILE_SSID_MAX])visible : NULL, (uint8_t)count);
}

/* PEAP or TTLS, whichever the network offers, with the username as both the
 * outer identity and the inner MSCHAPv2 name. */
/* Each call is an RPC on boards whose Wi-Fi runs on a co-processor (P4), and
 * firmware there may not implement them: each then times out after seconds.
 * So nothing is called for ordinary networks unless Enterprise was on, and
 * the first failure stops the rest. */
static void set_enterprise(const char *username, const char *password, bool check_server)
{
    static bool enabled;
    int user_len = username ? (int)strlen(username) : 0;

    if (username == NULL) {
        if (enabled) {
            enabled = false;
            esp_wifi_sta_enterprise_disable();
            esp_eap_client_clear_identity();
            esp_eap_client_clear_username();
            esp_eap_client_clear_password();
        }
        return;
    }
    enabled = true;
    if (esp_eap_client_set_identity((const unsigned char *)username, user_len) != ESP_OK ||
        esp_eap_client_set_username((const unsigned char *)username, user_len) != ESP_OK ||
        esp_eap_client_set_password((const unsigned char *)password, (int)strlen(password)) != ESP_OK ||
        esp_eap_client_use_default_cert_bundle(check_server) != ESP_OK ||
        esp_wifi_sta_enterprise_enable() != ESP_OK) {
        ESP_LOGW(TAG, "Enterprise sign-in is not available on this board");
    }
}

static void join(uint8_t slot)
{
    char ssid[PROFILE_SSID_MAX];
    char username[PROFILE_USERNAME_MAX];
    char password[PROFILE_PASSWORD_MAX];
    uint8_t security;
    uint8_t flags;
    bool enterprise;
    wifi_config_t config = {0};

    if (!profiles_credentials(slot, ssid, username, password, &security, &flags)) {
        return;
    }
    enterprise = security == LWIP_WIFI_SEC_ENTERPRISE;

    memcpy(config.sta.ssid, ssid, strnlen(ssid, sizeof config.sta.ssid));
    if (!enterprise) {
        strncpy((char *)config.sta.password, password, sizeof config.sta.password - 1);
    }
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    config.sta.threshold.authmode = password[0] ? auth_for(security) : WIFI_AUTH_OPEN;
    config.sta.pmf_cfg.capable = true;
    config.sta.pmf_cfg.required = security == LWIP_WIFI_SEC_WPA3;
    set_enterprise(enterprise ? username : NULL, password, (flags & PROFILE_F_CHECK_SERVER) != 0);
    memset(password, 0, sizeof password);
    memset(username, 0, sizeof username);

    s_slot = slot;
    ESP_LOGI(TAG, "joining %s", ssid);
    esp_wifi_set_config(WIFI_IF_STA, &config);
    memset(&config, 0, sizeof config);
    /* Set before connecting: the result event can arrive before connect returns. */
    s_joining = true;
    if (esp_wifi_connect() != ESP_OK) {
        s_joining = false;
    }
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
        } else if (!s_connected && !s_joining && !s_paused) {
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
    s_reason = LWIP_WIFI_REASON_NONE;
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
    s_reason = LWIP_WIFI_REASON_NONE;
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
    out->reason = s_reason;
    if (s_connected && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        out->slot = profiles_active();
        out->rssi = ap.rssi;
        out->channel = ap.primary;
        memcpy(out->bssid, ap.bssid, 6);
        memcpy(out->ssid, ap.ssid, 32);
    }
}

static uint8_t reason_from_event(uint8_t reason)
{
    switch (reason) {
    case WIFI_REASON_ASSOC_LEAVE:
    case WIFI_REASON_ROAMING:
        return LWIP_WIFI_REASON_NONE;
    case WIFI_REASON_NO_AP_FOUND:
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
        return LWIP_WIFI_REASON_NOT_FOUND;
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_802_1X_AUTH_FAILED:
        return LWIP_WIFI_REASON_AUTH;
    case WIFI_REASON_BEACON_TIMEOUT:
    case WIFI_REASON_MISSING_ACKS:
        return LWIP_WIFI_REASON_LOST;
    case WIFI_REASON_ASSOC_TOOMANY:
    case WIFI_REASON_NOT_AUTHORIZED_THIS_LOCATION:
    case WIFI_REASON_AP_INITIATED:
        return LWIP_WIFI_REASON_REJECTED;
    default:
        return LWIP_WIFI_REASON_OTHER;
    }
}

static void set_led(bool on)
{
#if CONFIG_BRIDGE_LED_GPIO >= 0
    gpio_set_level(CONFIG_BRIDGE_LED_GPIO, on);
#else
    (void)on;
#endif
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;

    if (id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event = data;
        bool was_connected = s_connected;

        ESP_LOGW(TAG, "disconnected, reason %u", event->reason);
        s_reason = s_paused ? LWIP_WIFI_REASON_NONE : reason_from_event(event->reason);
        s_connected = false;
        s_joining = false;
        profiles_clear_active();
        set_led(false);
        bridge_set_wifi(false);
        control_notify();
        /* Lost a working link: look for a network now. A failed join waits for
         * RETRY_MS instead, so a wrong password does not hammer the AP. */
        if (was_connected && !s_paused) {
            wifi_kick();
        }
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "connected");
        s_reason = LWIP_WIFI_REASON_NONE;
        s_connected = true;
        s_joining = false;
        profiles_mark_active(s_slot);
        set_led(true);
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
#if CONFIG_BRIDGE_LED_GPIO >= 0
    gpio_reset_pin(CONFIG_BRIDGE_LED_GPIO);
    gpio_set_direction(CONFIG_BRIDGE_LED_GPIO, GPIO_MODE_OUTPUT);
    set_led(false);
#endif

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
