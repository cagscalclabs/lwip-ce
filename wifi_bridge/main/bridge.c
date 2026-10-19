#include "bridge.h"

#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_private/wifi.h"
#include "esp_wifi.h"
#include "usb/cdc_acm_host.h"
#include "usb/usb_host.h"

#define TAG "bridge"
#define CALC_VID 0x16C0
#define CALC_PID 0x05E1
#define FRAME_MIN 14
#define FRAME_MAX 1514
#define USB_MPS 64
#define USB_BUFFER 2048
#define TX_QUEUE_LEN 32
#define TX_TIMEOUT_MS 1000
#define CDC_SET_NET_ADDRESS 0x82

typedef struct {
    uint16_t length;
    uint8_t data[];
} frame_t;

static QueueHandle_t s_tx_queue;
static SemaphoreHandle_t s_cdc_lock;
static SemaphoreHandle_t s_attach;
static cdc_acm_dev_hdl_t s_cdc;
static volatile bool s_wifi_up;

static void drop_queued(void)
{
    frame_t *frame;

    while (xQueueReceive(s_tx_queue, &frame, 0) == pdTRUE) {
        free(frame);
    }
}

#ifdef CONFIG_BRIDGE_LOG_TRAFFIC
static void log_ping(const uint8_t *frame, size_t length)
{
    size_t ihl;

    if (length < 34 || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != 1) {
        return;
    }
    ihl = (size_t)(frame[14] & 0x0F) * 4;
    if (length >= 14 + ihl + 8 && frame[14 + ihl] == 8) {
        ESP_LOGI(TAG, "ping from calculator to %u.%u.%u.%u seq %u", frame[30], frame[31],
                 frame[32], frame[33], (frame[14 + ihl + 6] << 8) | frame[14 + ihl + 7]);
    }
}

static void log_lease(const uint8_t *frame, size_t length)
{
    size_t ihl;
    const uint8_t *dhcp;

    if (length < 34 || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != 17) {
        return;
    }
    ihl = (size_t)(frame[14] & 0x0F) * 4;
    dhcp = frame + 14 + ihl + 8;
    if (length < 14 + ihl + 8 + 244 || frame[14 + ihl + 2] != 0 || frame[14 + ihl + 3] != 68 ||
        dhcp[0] != 2) {
        return;
    }
    for (size_t i = 240; i + 2 < length - (size_t)(dhcp - frame) && dhcp[i] != 255;
         i += dhcp[i] ? (size_t)dhcp[i + 1] + 2 : 1) {
        if (dhcp[i] == 53 && dhcp[i + 2] == 5) {
            ESP_LOGI(TAG, "calculator leased %u.%u.%u.%u", dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
            return;
        }
    }
}
#else
#define log_ping(frame, length)
#define log_lease(frame, length)
#endif

void bridge_send(const uint8_t *data, size_t length)
{
    size_t padded = length % USB_MPS == 0 ? length + 1 : length;
    frame_t *frame;

    if (s_cdc == NULL || length < FRAME_MIN || length > FRAME_MAX) {
        return;
    }
    frame = malloc(sizeof *frame + padded);
    if (frame == NULL) {
        return;
    }
    frame->length = (uint16_t)padded;
    memcpy(frame->data, data, length);
    if (padded != length) {
        frame->data[length] = 0;
    }
    if (xQueueSend(s_tx_queue, &frame, 0) != pdTRUE) {
        free(frame);
    }
}

static esp_err_t wifi_rx(void *buffer, uint16_t length, void *eb)
{
    const uint8_t *frame = buffer;

    /* Control frames only ever come from this bridge; one from the air is forged. */
    if (s_cdc != NULL && length >= FRAME_MIN &&
        ((frame[12] << 8) | frame[13]) != CTL_ETHERTYPE) {
        log_lease(buffer, length);
        bridge_send(buffer, length);
    }
    esp_wifi_internal_free_rx_buffer(eb);
    return ESP_OK;
}

static bool cdc_data(const uint8_t *data, size_t length, void *arg)
{
    (void)arg;

    if (length < FRAME_MIN || length > FRAME_MAX) {
        ESP_LOGW(TAG, "dropping %u byte frame from calculator", (unsigned)length);
        return true;
    }

    if (((data[12] << 8) | data[13]) == CTL_ETHERTYPE) {
        control_request(data, length);
        return true;
    }

    log_ping(data, length);
    if (s_wifi_up) {
        esp_wifi_internal_tx(WIFI_IF_STA, (void *)data, (uint16_t)length);
    }

    return true;
}

static void cdc_event(const cdc_acm_host_dev_event_data_t *event, void *arg)
{
    (void)arg;

    switch (event->type) {
    case CDC_ACM_HOST_DEVICE_DISCONNECTED:
        xSemaphoreTake(s_cdc_lock, portMAX_DELAY);
        if (s_cdc == event->data.cdc_hdl) {
            s_cdc = NULL;
        }
        xSemaphoreGive(s_cdc_lock);
        cdc_acm_host_close(event->data.cdc_hdl);
        drop_queued();
        ESP_LOGI(TAG, "calculator detached");
        break;

    case CDC_ACM_HOST_ERROR:
        ESP_LOGW(TAG, "cdc error %d", event->data.error);
        break;

    default:
        break;
    }
}

static void cdc_new_device(usb_device_handle_t device)
{
    const usb_device_desc_t *desc;

    if (usb_host_get_device_descriptor(device, &desc) == ESP_OK &&
        desc->idVendor == CALC_VID && desc->idProduct == CALC_PID) {
        xSemaphoreGive(s_attach);
    }
}

static void usb_lib_task(void *arg)
{
    (void)arg;

    for (;;) {
        uint32_t flags;

        usb_host_lib_handle_events(portMAX_DELAY, &flags);
        if (flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            usb_host_device_free_all();
        }
    }
}

static esp_err_t send_mac(cdc_acm_dev_hdl_t handle)
{
    uint8_t mac[6];
    esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, mac);

    if (err != ESP_OK) {
        return err;
    }
    return cdc_acm_host_send_custom_request(handle, 0x21, CDC_SET_NET_ADDRESS, 0, 0, sizeof mac, mac);
}

static void attach_task(void *arg)
{
    const cdc_acm_host_open_config_t config = {
        .vid = CALC_VID,
        .pid = CALC_PID,
        .interface_idx = 0,
        .dev_addr = CDC_HOST_ANY_DEV_ADDR,
        .connection_timeout_ms = 1000,
        .out_buffer_size = USB_BUFFER,
        .in_buffer_size = USB_BUFFER,
        .event_cb = cdc_event,
        .data_cb = cdc_data,
    };

    (void)arg;

    for (;;) {
        cdc_acm_dev_hdl_t handle;
        esp_err_t err;

        xSemaphoreTake(s_attach, portMAX_DELAY);
        if (s_cdc != NULL) {
            continue;
        }

        err = cdc_acm_host_open(&config, &handle);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "cannot open calculator: %s", esp_err_to_name(err));
            continue;
        }

        err = send_mac(handle);
        if (err == ESP_OK) {
            err = cdc_acm_host_set_control_line_state(handle, s_wifi_up, true);
        }
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "cannot set up calculator: %s", esp_err_to_name(err));
            cdc_acm_host_close(handle);
            continue;
        }

        xSemaphoreTake(s_cdc_lock, portMAX_DELAY);
        s_cdc = handle;
        xSemaphoreGive(s_cdc_lock);
        ESP_LOGI(TAG, "calculator attached, wifi %s", s_wifi_up ? "up" : "down");
    }
}

static void tx_task(void *arg)
{
    (void)arg;

    for (;;) {
        frame_t *frame;
        esp_err_t err = ESP_ERR_INVALID_STATE;

        xQueueReceive(s_tx_queue, &frame, portMAX_DELAY);

        xSemaphoreTake(s_cdc_lock, portMAX_DELAY);
        if (s_cdc != NULL) {
            err = cdc_acm_host_data_tx_blocking(s_cdc, frame->data, frame->length, TX_TIMEOUT_MS);
        }
        xSemaphoreGive(s_cdc_lock);

        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "tx %u bytes failed: %s", frame->length, esp_err_to_name(err));
        }

        free(frame);
    }
}

void bridge_set_wifi(bool up)
{
    s_wifi_up = up;
    if (up) {
        esp_wifi_internal_reg_rxcb(WIFI_IF_STA, wifi_rx);
    }

    xSemaphoreTake(s_cdc_lock, portMAX_DELAY);
    if (s_cdc != NULL) {
        cdc_acm_host_set_control_line_state(s_cdc, up, true);
    }
    xSemaphoreGive(s_cdc_lock);
}

esp_err_t bridge_init(void)
{
    const usb_host_config_t host_config = {
        .intr_flags = ESP_INTR_FLAG_LEVEL1,
    };
    const cdc_acm_host_driver_config_t driver_config = {
        .driver_task_stack_size = 4096,
        .driver_task_priority = 10,
        .xCoreID = 0,
        .new_dev_cb = cdc_new_device,
    };
    esp_err_t err;

    s_tx_queue = xQueueCreate(TX_QUEUE_LEN, sizeof(frame_t *));
    s_cdc_lock = xSemaphoreCreateMutex();
    s_attach = xSemaphoreCreateBinary();
    if (s_tx_queue == NULL || s_cdc_lock == NULL || s_attach == NULL) {
        return ESP_ERR_NO_MEM;
    }

    err = usb_host_install(&host_config);
    if (err != ESP_OK) {
        return err;
    }
    xTaskCreatePinnedToCore(usb_lib_task, "usb_lib", 4096, NULL, 11, NULL, 0);

    err = cdc_acm_host_install(&driver_config);
    if (err != ESP_OK) {
        return err;
    }

    xTaskCreatePinnedToCore(attach_task, "usb_attach", 4096, NULL, 9, NULL, 0);
    xTaskCreatePinnedToCore(tx_task, "usb_tx", 4096, NULL, 10, NULL, 0);

    return ESP_OK;
}
