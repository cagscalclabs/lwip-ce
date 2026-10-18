#include <string.h>

#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "drivers/usb_ethernet.h"
#include "lwip-imports.h"
#include "wireless/wifi.h"
#include "wireless/wifi_hook.h"

#define WIFI_ETHERTYPE 0x88B5
#define WIFI_VERSION 1
#define WIFI_HEADER 18
#define WIFI_REPLY_MAX 1024
#define WIFI_SHORT_TIMEOUT_MS 2000
#define WIFI_CHANGE_TIMEOUT_MS 6000
#define WIFI_SCAN_TIMEOUT_MS 10000

enum
{
    OP_STATUS = 1,
    OP_LIST,
    OP_SCAN,
    OP_SAVE,
    OP_FORGET,
    OP_ENABLE,
    OP_PREFER,
    OP_CONNECT,
    OP_DISCONNECT,
    OP_EVENT = 0x40,
};

static uint8_t g_seq;
static uint8_t g_wait_op;
static uint8_t g_wait_seq;
static bool g_waiting;
static bool g_done;
static uint8_t g_status;
static uint16_t g_reply_len;
static uint8_t *g_reply;
static lwip_wifi_event_fn g_event_fn;
static void *g_event_arg;

static bool parse_state(const uint8_t *data, uint16_t length, lwip_wifi_state_t *state)
{
    uint8_t ssid_len;

    if (length < 12)
        return false;
    state->connected = data[0] != 0;
    state->slot = data[1];
    state->rssi = (int8_t)data[2];
    state->channel = data[3];
    memcpy(state->bssid, &data[4], 6);
    state->saved = data[10];
    ssid_len = data[11];
    if (ssid_len > LWIP_WIFI_SSID_MAX || 12u + ssid_len > length)
        ssid_len = 0;
    memcpy(state->ssid, &data[12], ssid_len);
    state->ssid[ssid_len] = '\0';
    return true;
}

void lwip_wifi_set_event_cb(lwip_wifi_event_fn fn, void *arg)
{
    g_event_fn = fn;
    g_event_arg = arg;
}

err_t lwip_wifi_eth_input(struct pbuf *p, struct netif *netif)
{
    uint8_t header[WIFI_HEADER];
    uint16_t length;

    (void)netif;

    if (p->tot_len < WIFI_HEADER || pbuf_copy_partial(p, header, WIFI_HEADER, 0) != WIFI_HEADER ||
        ((header[12] << 8) | header[13]) != WIFI_ETHERTYPE)
        return ERR_VAL;

    if (header[14] == WIFI_VERSION && header[15] == (OP_EVENT | 0x80) && g_event_fn)
    {
        uint8_t body[12 + LWIP_WIFI_SSID_MAX];
        lwip_wifi_state_t state;
        uint16_t got = pbuf_copy_partial(p, body, sizeof body, WIFI_HEADER);

        pbuf_free(p);
        if (parse_state(body, got, &state))
            g_event_fn(&state, g_event_arg);
        return ERR_OK;
    }

    if (g_waiting && header[14] == WIFI_VERSION && header[15] == (g_wait_op | 0x80) &&
        header[16] == g_wait_seq)
    {
        length = (uint16_t)(p->tot_len - WIFI_HEADER);
        if (length > WIFI_REPLY_MAX)
            length = WIFI_REPLY_MAX;
        g_reply_len = pbuf_copy_partial(p, g_reply, length, WIFI_HEADER);
        g_status = header[17];
        g_done = true;
    }
    pbuf_free(p);
    return ERR_OK;
}

static void pump(void)
{
    usb_fn.handle_events();
    sys_check_timeouts();
}

bool lwip_wifi_available(void)
{
    return eth_device_netif() != NULL;
}

static lwip_wifi_error_t request(uint8_t op, const uint8_t *body, uint16_t body_len, uint32_t timeout_ms)
{
    struct netif *netif = eth_device_netif();
    struct pbuf *p;
    uint8_t *frame;
    uint32_t start;

    if (!netif)
        return LWIP_WIFI_ERR_NO_BRIDGE;
    if (!g_reply && !(g_reply = mem_malloc(WIFI_REPLY_MAX)))
        return LWIP_WIFI_ERR_MEM;

    p = pbuf_alloc(PBUF_RAW, (u16_t)(WIFI_HEADER + body_len), PBUF_RAM);
    if (!p)
        return LWIP_WIFI_ERR_MEM;

    frame = p->payload;
    memset(frame, 0xFF, 6);
    memcpy(frame + 6, netif->hwaddr, 6);
    frame[12] = WIFI_ETHERTYPE >> 8;
    frame[13] = WIFI_ETHERTYPE & 0xFF;
    frame[14] = WIFI_VERSION;
    frame[15] = op;
    frame[16] = ++g_seq;
    frame[17] = 0;
    if (body_len)
        memcpy(frame + WIFI_HEADER, body, body_len);

    g_wait_op = op;
    g_wait_seq = g_seq;
    g_done = false;
    g_waiting = true;
    err_t err = netif->linkoutput(netif, p);
    pbuf_free(p);
    if (err != ERR_OK)
    {
        g_waiting = false;
        return LWIP_WIFI_ERR_NO_BRIDGE;
    }

    start = sys_now();
    while (!g_done && sys_now() - start < timeout_ms)
        pump();
    g_waiting = false;

    if (!g_done)
        return LWIP_WIFI_ERR_TIMEOUT;
    switch (g_status)
    {
    case 0:
        return LWIP_WIFI_OK;
    case 2:
        return LWIP_WIFI_ERR_NOT_FOUND;
    case 3:
        return LWIP_WIFI_ERR_FULL;
    default:
        return LWIP_WIFI_ERR_BAD_REQUEST;
    }
}

static bool take_string(uint16_t *at, char *out)
{
    uint8_t length;

    if (*at >= g_reply_len)
        return false;
    length = g_reply[*at];
    if (length > LWIP_WIFI_SSID_MAX || *at + 1u + length > g_reply_len)
        return false;
    memcpy(out, &g_reply[*at + 1], length);
    out[length] = '\0';
    *at = (uint16_t)(*at + 1u + length);
    return true;
}

static uint16_t put_string(uint8_t *out, const char *text, size_t max)
{
    size_t length = text ? strlen(text) : 0;

    if (length > max)
        length = max;
    out[0] = (uint8_t)length;
    if (length)
        memcpy(out + 1, text, length);
    return (uint16_t)(length + 1);
}

lwip_wifi_error_t lwip_wifi_get_state(lwip_wifi_state_t *state)
{
    lwip_wifi_error_t err = request(OP_STATUS, NULL, 0, WIFI_SHORT_TIMEOUT_MS);

    if (err != LWIP_WIFI_OK)
        return err;
    return parse_state(g_reply, g_reply_len, state) ? LWIP_WIFI_OK : LWIP_WIFI_ERR_BAD_REQUEST;
}

lwip_wifi_error_t lwip_wifi_list_profiles(lwip_wifi_profile_t *profiles, uint8_t max, uint8_t *count)
{
    lwip_wifi_error_t err = request(OP_LIST, NULL, 0, WIFI_SHORT_TIMEOUT_MS);
    uint16_t at = 1;
    uint8_t used = 0;

    *count = 0;
    if (err != LWIP_WIFI_OK)
        return err;
    for (uint8_t i = 0; g_reply_len && i < g_reply[0] && used < max; i++)
    {
        if (at + 3u > g_reply_len)
            break;
        profiles[used].slot = g_reply[at];
        profiles[used].flags = g_reply[at + 1];
        profiles[used].security = g_reply[at + 2];
        at = (uint16_t)(at + 3);
        if (!take_string(&at, profiles[used].ssid))
            break;
        used++;
    }
    *count = used;
    return LWIP_WIFI_OK;
}

lwip_wifi_error_t lwip_wifi_scan(lwip_wifi_network_t *networks, uint8_t max, uint8_t *count)
{
    lwip_wifi_error_t err = request(OP_SCAN, NULL, 0, WIFI_SCAN_TIMEOUT_MS);
    uint16_t at = 1;
    uint8_t used = 0;

    *count = 0;
    if (err != LWIP_WIFI_OK)
        return err;
    for (uint8_t i = 0; g_reply_len && i < g_reply[0] && used < max; i++)
    {
        if (at + 3u > g_reply_len)
            break;
        networks[used].rssi = (int8_t)g_reply[at];
        networks[used].channel = g_reply[at + 1];
        networks[used].security = g_reply[at + 2];
        at = (uint16_t)(at + 3);
        if (!take_string(&at, networks[used].ssid))
            break;
        used++;
    }
    *count = used;
    return LWIP_WIFI_OK;
}

lwip_wifi_error_t lwip_wifi_save_profile(uint8_t slot, const char *ssid, const char *password,
                                         uint8_t security, uint8_t flags, uint8_t *saved)
{
    uint8_t body[3 + 1 + LWIP_WIFI_SSID_MAX + 1 + LWIP_WIFI_PASSWORD_MAX];
    uint16_t length = 3;
    lwip_wifi_error_t err;

    if (!ssid || !ssid[0] || strlen(ssid) > LWIP_WIFI_SSID_MAX ||
        (password && strlen(password) > LWIP_WIFI_PASSWORD_MAX))
        return LWIP_WIFI_ERR_BAD_REQUEST;

    body[0] = slot;
    body[1] = security;
    body[2] = flags;
    length = (uint16_t)(length + put_string(&body[length], ssid, LWIP_WIFI_SSID_MAX));
    length = (uint16_t)(length + put_string(&body[length], password, LWIP_WIFI_PASSWORD_MAX));
    err = request(OP_SAVE, body, length, WIFI_CHANGE_TIMEOUT_MS);
    memset(body, 0, sizeof body);
    if (err == LWIP_WIFI_OK && saved)
        *saved = g_reply_len ? g_reply[0] : LWIP_WIFI_SLOT_NONE;
    return err;
}

lwip_wifi_error_t lwip_wifi_forget_profile(uint8_t slot)
{
    return request(OP_FORGET, &slot, 1, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_enable_profile(uint8_t slot, bool enabled)
{
    uint8_t body[2] = {slot, enabled ? 1 : 0};

    return request(OP_ENABLE, body, sizeof body, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_prefer_profile(uint8_t slot)
{
    return request(OP_PREFER, &slot, 1, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_connect(uint8_t slot)
{
    return request(OP_CONNECT, &slot, 1, WIFI_CHANGE_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_disconnect(void)
{
    return request(OP_DISCONNECT, NULL, 0, WIFI_CHANGE_TIMEOUT_MS);
}
