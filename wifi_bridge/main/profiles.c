#include "profiles.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#define PROFILE_TAG "profiles"
#define PROFILE_NAMESPACE "lwip_wifi"
#define PROFILE_RECORD_VERSION 2

typedef struct {
    uint8_t version;
    uint8_t used;
    uint8_t security;
    uint8_t flags;
    uint32_t rank;
    char ssid[PROFILE_SSID_MAX];
    char password[PROFILE_PASSWORD_MAX];
    char username[PROFILE_USERNAME_MAX]; /* added in version 2 */
} profile_record_t;

/* Version 1 records are the same fields without the username. Its size
 * includes tail padding, so it is not offsetof(profile_record_t, username). */
typedef struct {
    uint8_t version;
    uint8_t used;
    uint8_t security;
    uint8_t flags;
    uint32_t rank;
    char ssid[PROFILE_SSID_MAX];
    char password[PROFILE_PASSWORD_MAX];
} profile_record_v1_t;

static profile_record_t s_records[PROFILE_SLOTS];
static uint8_t s_order[PROFILE_SLOTS];
static uint8_t s_count;
static uint8_t s_active = PROFILE_NONE;
static uint32_t s_next_rank = 1;
static SemaphoreHandle_t s_mutex;

static void lock(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
}

static void unlock(void)
{
    xSemaphoreGive(s_mutex);
}

static void slot_key(uint8_t slot, char *out, size_t size)
{
    snprintf(out, size, "p%u", (unsigned)slot);
}

static esp_err_t write_slot(uint8_t slot)
{
    nvs_handle_t handle;
    char key[8];
    esp_err_t err = nvs_open(PROFILE_NAMESPACE, NVS_READWRITE, &handle);

    if (err != ESP_OK) {
        return err;
    }

    slot_key(slot, key, sizeof key);

    if (s_records[slot].used) {
        err = nvs_set_blob(handle, key, &s_records[slot], sizeof(profile_record_t));
    } else {
        err = nvs_erase_key(handle, key);

        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_OK;
        }
    }

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    return err;
}

static void rebuild_order(void)
{
    uint8_t index;

    s_count = 0;

    for (index = 0; index < PROFILE_SLOTS; index++) {
        if (s_records[index].used) {
            s_order[s_count++] = index;
        }
    }

    for (uint8_t i = 1; i < s_count; i++) {
        uint8_t key = s_order[i];
        int j = (int)i - 1;

        while (j >= 0 && s_records[s_order[j]].rank < s_records[key].rank) {
            s_order[j + 1] = s_order[j];
            j--;
        }

        s_order[j + 1] = key;
    }
}

esp_err_t profiles_init(void)
{
    nvs_handle_t handle;
    esp_err_t err;

    s_mutex = xSemaphoreCreateMutex();

    if (s_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memset(s_records, 0, sizeof s_records);

    err = nvs_open(PROFILE_NAMESPACE, NVS_READWRITE, &handle);

    if (err != ESP_OK) {
        ESP_LOGW(PROFILE_TAG, "no credential store: %s", esp_err_to_name(err));
        return ESP_OK;
    }

    for (uint8_t slot = 0; slot < PROFILE_SLOTS; slot++) {
        char key[8];
        size_t size = sizeof(profile_record_t);

        slot_key(slot, key, sizeof key);

        if (nvs_get_blob(handle, key, &s_records[slot], &size) != ESP_OK ||
            !((size == sizeof(profile_record_t) && s_records[slot].version == PROFILE_RECORD_VERSION) ||
              (size == sizeof(profile_record_v1_t) && s_records[slot].version == 1))) {
            memset(&s_records[slot], 0, sizeof(profile_record_t));
            continue;
        }

        if (s_records[slot].version == 1) {
            memset(s_records[slot].username, 0, PROFILE_USERNAME_MAX);
            s_records[slot].version = PROFILE_RECORD_VERSION;
        }
        s_records[slot].ssid[PROFILE_SSID_MAX - 1] = 0;
        s_records[slot].password[PROFILE_PASSWORD_MAX - 1] = 0;
        s_records[slot].username[PROFILE_USERNAME_MAX - 1] = 0;
        s_records[slot].flags &= (uint8_t)~PROFILE_F_ACTIVE;

        if (s_records[slot].ssid[0] == 0) {
            memset(&s_records[slot], 0, sizeof(profile_record_t));
            continue;
        }

        if (s_records[slot].rank >= s_next_rank) {
            s_next_rank = s_records[slot].rank + 1;
        }
    }

    nvs_close(handle);
    rebuild_order();

    ESP_LOGI(PROFILE_TAG, "%u saved network(s)", (unsigned)s_count);

    return ESP_OK;
}

uint8_t profiles_count(void)
{
    uint8_t count;

    lock();
    count = s_count;
    unlock();

    return count;
}

uint8_t profiles_active(void)
{
    uint8_t active;

    lock();
    active = s_active;
    unlock();

    return active;
}

bool profiles_view(uint8_t index, profile_view_t *out)
{
    bool found = false;

    if (out == NULL) {
        return false;
    }

    lock();

    if (index < s_count) {
        const profile_record_t *record = &s_records[s_order[index]];

        out->slot = s_order[index];
        out->security = record->security;
        out->flags = record->flags;

        if (s_order[index] == s_active) {
            out->flags |= PROFILE_F_ACTIVE;
        }

        memcpy(out->ssid, record->ssid, PROFILE_SSID_MAX);
        out->ssid[PROFILE_SSID_MAX - 1] = 0;
        found = true;
    }

    unlock();

    return found;
}

uint8_t profiles_save(const char *ssid, const char *username, const char *password,
                           uint8_t security, uint8_t flags)
{
    uint8_t slot = PROFILE_NONE;

    if (ssid == NULL || ssid[0] == 0) {
        return PROFILE_NONE;
    }

    lock();

    for (uint8_t index = 0; index < PROFILE_SLOTS; index++) {
        if (s_records[index].used &&
            strcmp(s_records[index].ssid, ssid) == 0) {
            slot = index;
            break;
        }
    }

    if (slot == PROFILE_NONE) {
        for (uint8_t index = 0; index < PROFILE_SLOTS; index++) {
            if (!s_records[index].used) {
                slot = index;
                break;
            }
        }
    }

    if (slot == PROFILE_NONE) {
        unlock();
        return PROFILE_NONE;
    }

    memset(&s_records[slot], 0, sizeof(profile_record_t));
    s_records[slot].version = PROFILE_RECORD_VERSION;
    s_records[slot].used = 1;
    s_records[slot].security = security;
    s_records[slot].flags = (uint8_t)(flags & ~PROFILE_F_ACTIVE);
    s_records[slot].rank = s_next_rank++;
    strncpy(s_records[slot].ssid, ssid, PROFILE_SSID_MAX - 1);

    if (password != NULL) {
        strncpy(s_records[slot].password, password, PROFILE_PASSWORD_MAX - 1);
    }

    if (username != NULL) {
        strncpy(s_records[slot].username, username, PROFILE_USERNAME_MAX - 1);
    }

    rebuild_order();
    write_slot(slot);
    unlock();

    ESP_LOGI(PROFILE_TAG, "saved %s in slot %u", ssid, (unsigned)slot);

    return slot;
}

bool profiles_forget(uint8_t slot)
{
    bool erased = false;

    lock();

    if (slot < PROFILE_SLOTS && s_records[slot].used) {
        memset(&s_records[slot], 0, sizeof(profile_record_t));

        if (s_active == slot) {
            s_active = PROFILE_NONE;
        }

        rebuild_order();
        write_slot(slot);
        erased = true;
    }

    unlock();

    return erased;
}

bool profiles_enable(uint8_t slot, bool enabled)
{
    bool changed = false;

    lock();

    if (slot < PROFILE_SLOTS && s_records[slot].used) {
        if (enabled) {
            s_records[slot].flags |= PROFILE_F_ENABLED;
        } else {
            s_records[slot].flags &= (uint8_t)~PROFILE_F_ENABLED;
        }

        write_slot(slot);
        changed = true;
    }

    unlock();

    return changed;
}

bool profiles_prefer(uint8_t slot)
{
    bool changed = false;

    lock();

    if (slot < PROFILE_SLOTS && s_records[slot].used) {
        s_records[slot].rank = s_next_rank++;
        rebuild_order();
        write_slot(slot);
        changed = true;
    }

    unlock();

    return changed;
}

void profiles_mark_active(uint8_t slot)
{
    lock();

    if (slot < PROFILE_SLOTS && s_records[slot].used) {
        s_active = slot;

        /* Skip the flash write when the slot already leads the order. */
        if (s_order[0] != slot) {
            s_records[slot].rank = s_next_rank++;
            rebuild_order();
            write_slot(slot);
        }
    }

    unlock();
}

void profiles_clear_active(void)
{
    lock();
    s_active = PROFILE_NONE;
    unlock();
}

uint8_t profiles_pick(const char (*visible)[PROFILE_SSID_MAX],
                           uint8_t visible_count)
{
    uint8_t chosen = PROFILE_NONE;

    lock();

    if (visible != NULL && visible_count > 0) {
        for (uint8_t index = 0; index < s_count && chosen == PROFILE_NONE; index++) {
            const profile_record_t *record = &s_records[s_order[index]];

            if (!(record->flags & PROFILE_F_ENABLED)) {
                continue;
            }

            for (uint8_t seen = 0; seen < visible_count; seen++) {
                if (strcmp(record->ssid, visible[seen]) == 0) {
                    chosen = s_order[index];
                    break;
                }
            }
        }
    }

    /* Hidden networks never appear in a scan, so try them blind. */
    for (uint8_t index = 0; index < s_count && chosen == PROFILE_NONE; index++) {
        uint8_t flags = s_records[s_order[index]].flags;

        if ((flags & PROFILE_F_ENABLED) && (flags & PROFILE_F_HIDDEN)) {
            chosen = s_order[index];
        }
    }

    unlock();

    return chosen;
}

bool profiles_credentials(uint8_t slot, char *ssid, char *username, char *password,
                               uint8_t *security, uint8_t *flags)
{
    bool found = false;

    lock();

    if (slot < PROFILE_SLOTS && s_records[slot].used) {
        if (ssid != NULL) {
            memcpy(ssid, s_records[slot].ssid, PROFILE_SSID_MAX);
        }

        if (username != NULL) {
            memcpy(username, s_records[slot].username, PROFILE_USERNAME_MAX);
        }

        if (password != NULL) {
            memcpy(password, s_records[slot].password, PROFILE_PASSWORD_MAX);
        }

        if (security != NULL) {
            *security = s_records[slot].security;
        }

        if (flags != NULL) {
            *flags = s_records[slot].flags;
        }

        found = true;
    }

    unlock();

    return found;
}
