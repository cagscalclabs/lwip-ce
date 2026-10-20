#include "bridge.h"
#include "profiles.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"

#define TAG "control"
#define CTL_MAX 1514
#define CTL_QUEUE_LEN 4

typedef struct {
    uint16_t length;
    uint8_t data[CTL_MAX];
} request_t;

static QueueHandle_t s_queue;
static uint8_t s_reply[CTL_MAX];
static wifi_scan_entry_t s_scan[WIFI_SCAN_MAX];

static size_t put_string(uint8_t *out, size_t room, const char *text)
{
    size_t length = strnlen(text, LWIP_WIFI_SSID_MAX);

    if (room < length + 1) {
        return 0;
    }
    out[0] = (uint8_t)length;
    memcpy(out + 1, text, length);
    return length + 1;
}

static bool get_string(const uint8_t **in, const uint8_t *end, char *out, size_t size)
{
    size_t length;

    if (*in >= end) {
        return false;
    }
    length = **in;
    if (length >= size || (size_t)(end - *in) < length + 1) {
        return false;
    }
    memcpy(out, *in + 1, length);
    out[length] = 0;
    *in += length + 1;
    return true;
}

static size_t op_status(uint8_t *out, size_t room)
{
    wifi_status_t status;
    size_t used = 11;

    wifi_get_status(&status);
    out[0] = status.connected;
    out[1] = status.slot;
    out[2] = (uint8_t)status.rssi;
    out[3] = status.channel;
    memcpy(out + 4, status.bssid, 6);
    out[10] = profiles_count();
    used += put_string(out + used, room - used, status.ssid);
    return used;
}

static size_t op_list(uint8_t *out, size_t room)
{
    profile_view_t view;
    size_t used = 1;
    uint8_t count = 0;

    for (uint8_t index = 0; profiles_view(index, &view); index++) {
        size_t text;

        if (room - used < 3) {
            break;
        }
        text = put_string(out + used + 3, room - used - 3, view.ssid);
        if (text == 0) {
            break;
        }
        out[used] = view.slot;
        out[used + 1] = view.flags;
        out[used + 2] = view.security;
        used += 3 + text;
        count++;
    }
    out[0] = count;
    return used;
}

static uint8_t op_scan(uint8_t *out, size_t room, size_t *reply_used)
{
    int found = wifi_scan(s_scan, WIFI_SCAN_MAX);
    size_t used = 1;
    uint8_t count = 0;

    if (found < 0) {
        return CTL_ST_BUSY;
    }
    for (int index = 0; index < found; index++) {
        size_t text;

        if (room - used < 3) {
            break;
        }
        text = put_string(out + used + 3, room - used - 3, s_scan[index].ssid);
        if (text == 0) {
            break;
        }
        out[used] = (uint8_t)s_scan[index].rssi;
        out[used + 1] = s_scan[index].channel;
        out[used + 2] = s_scan[index].security;
        used += 3 + text;
        count++;
    }
    out[0] = count;
    *reply_used = used;
    return CTL_ST_OK;
}

static uint8_t op_save(const uint8_t *in, const uint8_t *end, uint8_t *out, size_t *used)
{
    char ssid[PROFILE_SSID_MAX];
    char password[PROFILE_PASSWORD_MAX];
    char old_ssid[PROFILE_SSID_MAX];
    char old_password[PROFILE_PASSWORD_MAX];
    uint8_t slot, security, flags, saved;
    bool existing;

    if (end - in < 3) {
        return CTL_ST_BAD_REQUEST;
    }
    slot = in[0];
    security = in[1];
    flags = in[2];
    in += 3;
    if (security > LWIP_WIFI_SEC_WPA2_WPA3 || !get_string(&in, end, ssid, sizeof ssid) ||
        ssid[0] == 0 || !get_string(&in, end, password, sizeof password)) {
        return CTL_ST_BAD_REQUEST;
    }

    existing = slot != PROFILE_NONE &&
               profiles_credentials(slot, old_ssid, old_password, NULL, NULL);
    if (slot != PROFILE_NONE && !existing) {
        return CTL_ST_NOT_FOUND;
    }
    if (existing && password[0] == 0) {
        memcpy(password, old_password, sizeof password);
    }
    if (existing && strcmp(old_ssid, ssid) != 0) {
        profiles_forget(slot);
    }

    saved = profiles_save(ssid, password, security, flags);
    memset(password, 0, sizeof password);
    memset(old_password, 0, sizeof old_password);
    if (saved == PROFILE_NONE) {
        return CTL_ST_FULL;
    }
    out[0] = saved;
    *used = 1;
    return CTL_ST_OK;
}

static void handle(const request_t *request)
{
    const uint8_t *frame = request->data;
    const uint8_t *in = frame + CTL_HEADER;
    const uint8_t *end = frame + request->length;
    uint8_t *out = s_reply + CTL_HEADER;
    size_t room = sizeof s_reply - CTL_HEADER;
    size_t used = 0;
    uint8_t status = CTL_ST_OK;
    uint8_t op = frame[15];

    switch (op) {
    case CTL_OP_STATUS:
        used = op_status(out, room);
        break;
    case CTL_OP_LIST:
        used = op_list(out, room);
        break;
    case CTL_OP_SCAN:
        status = op_scan(out, room, &used);
        break;
    case CTL_OP_SAVE:
        status = op_save(in, end, out, &used);
        break;
    case CTL_OP_FORGET:
        status = in < end && profiles_forget(in[0]) ? CTL_ST_OK : CTL_ST_NOT_FOUND;
        break;
    case CTL_OP_ENABLE:
        status = end - in >= 2 && profiles_enable(in[0], in[1] != 0) ? CTL_ST_OK : CTL_ST_NOT_FOUND;
        if (status == CTL_ST_OK) {
            wifi_kick();
        }
        break;
    case CTL_OP_PREFER:
        status = in < end && profiles_prefer(in[0]) ? CTL_ST_OK : CTL_ST_NOT_FOUND;
        break;
    case CTL_OP_CONNECT:
        if (in >= end) {
            status = CTL_ST_BAD_REQUEST;
        } else if (in[0] == PROFILE_NONE) {
            wifi_resume();
        } else if (profiles_credentials(in[0], NULL, NULL, NULL, NULL)) {
            wifi_join_slot(in[0]);
        } else {
            status = CTL_ST_NOT_FOUND;
        }
        break;
    case CTL_OP_DISCONNECT:
        wifi_disconnect();
        break;
    case CTL_OP_EVENT:
        used = op_status(out, room);
        break;
    default:
        status = CTL_ST_BAD_REQUEST;
        break;
    }

    control_reply(frame, s_reply, status, used);
    ESP_LOGI(TAG, "op %u status %u, %u byte reply", op, status, (unsigned)used);
}

void control_reply(const uint8_t *request, uint8_t *reply, uint8_t status, size_t used)
{
    uint8_t mac[6];

    esp_wifi_get_mac(WIFI_IF_STA, mac);
    if (request[15] == CTL_OP_EVENT) {
        memset(reply, 0xFF, 6);
    } else {
        memcpy(reply, request + 6, 6);
    }
    memcpy(reply + 6, mac, 6);
    reply[12] = CTL_ETHERTYPE >> 8;
    reply[13] = CTL_ETHERTYPE & 0xFF;
    reply[14] = CTL_VERSION;
    reply[15] = (uint8_t)(request[15] | CTL_REPLY);
    reply[16] = request[16];
    reply[17] = status;
    bridge_send(reply, CTL_HEADER + used);
}

static void control_task(void *arg)
{
    static request_t request;

    (void)arg;

    for (;;) {
        xQueueReceive(s_queue, &request, portMAX_DELAY);
        handle(&request);
    }
}

void control_notify(void)
{
    static request_t request;

    memset(request.data, 0, CTL_HEADER);
    request.data[14] = CTL_VERSION;
    request.data[15] = CTL_OP_EVENT;
    request.length = CTL_HEADER;
    xQueueSend(s_queue, &request, 0);
}

void control_request(const uint8_t *frame, size_t length)
{
    static request_t request;

    if (length < CTL_HEADER || length > CTL_MAX || frame[14] != CTL_VERSION || frame[15] == CTL_OP_EVENT) {
        return;
    }
    /* Crypto has its own task, so a long scan never stalls a TLS handshake. */
    if (crypto_request(frame, length)) {
        return;
    }
    request.length = (uint16_t)length;
    memcpy(request.data, frame, length);
    xQueueSend(s_queue, &request, 0);
}

esp_err_t control_init(void)
{
    s_queue = xQueueCreate(CTL_QUEUE_LEN, sizeof(request_t));
    if (s_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }
    xTaskCreatePinnedToCore(control_task, "control", 4096, NULL, 6, NULL, 1);
    return ESP_OK;
}
