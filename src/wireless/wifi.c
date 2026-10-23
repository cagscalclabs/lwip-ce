#include <string.h>

#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "drivers/usb_ethernet.h"
#include "lwip-imports.h"
#include "../tls/includes/bytes.h"
#include "wireless/crypto.h"
#include "wireless/wifi_hook.h"
#include "wireless/wifi_proto.h"

#define WIFI_REPLY_MAX 1024
#define WIFI_SHORT_TIMEOUT_MS 2000
#define WIFI_CHANGE_TIMEOUT_MS 6000
#define WIFI_SCAN_TIMEOUT_MS 10000

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
    state->reason = 12u + ssid_len < length ? data[12 + ssid_len] : LWIP_WIFI_REASON_NONE;
    return true;
}

void lwip_wifi_set_event_cb(lwip_wifi_event_fn fn, void *arg)
{
    g_event_fn = fn;
    g_event_arg = arg;
}

err_t lwip_wifi_eth_input(struct pbuf *p, struct netif *netif)
{
    uint8_t header[CTL_HEADER];
    uint16_t length;

    if (netif != eth_device_netif() || p->tot_len < CTL_HEADER ||
        pbuf_copy_partial(p, header, CTL_HEADER, 0) != CTL_HEADER ||
        ((header[12] << 8) | header[13]) != CTL_ETHERTYPE)
        return ERR_VAL;

    if (header[14] == CTL_VERSION && header[15] == (CTL_OP_EVENT | CTL_REPLY) && g_event_fn)
    {
        uint8_t body[13 + LWIP_WIFI_SSID_MAX];
        lwip_wifi_state_t state;
        uint16_t got = pbuf_copy_partial(p, body, sizeof body, CTL_HEADER);

        pbuf_free(p);
        if (parse_state(body, got, &state))
            g_event_fn(&state, g_event_arg);
        return ERR_OK;
    }

    if (lwip_crypto_reply(header, p))
    {
        pbuf_free(p);
        return ERR_OK;
    }

    if (g_waiting && header[14] == CTL_VERSION && header[15] == (g_wait_op | CTL_REPLY) &&
        header[16] == g_wait_seq)
    {
        length = (uint16_t)(p->tot_len - CTL_HEADER);
        if (length > WIFI_REPLY_MAX)
            length = WIFI_REPLY_MAX;
        g_reply_len = pbuf_copy_partial(p, g_reply, length, CTL_HEADER);
        g_status = header[17];
        g_done = true;
    }
    pbuf_free(p);
    return ERR_OK;
}

void lwip_wifi_reset(void)
{
    lwip_crypto_reset();
    g_waiting = false;
    g_reply = NULL;
    g_reply_len = 0;
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

struct pbuf *lwip_wifi_frame(uint8_t op, uint16_t body_len, uint8_t *seq)
{
    struct netif *netif = eth_device_netif();
    struct pbuf *p;
    uint8_t *frame;

    if (!netif)
        return NULL;
    p = pbuf_alloc(PBUF_RAW, (u16_t)(CTL_HEADER + body_len), PBUF_RAM);
    if (!p)
        return NULL;

    frame = p->payload;
    memset(frame, 0xFF, 6);
    memcpy(frame + 6, netif->hwaddr, 6);
    frame[12] = CTL_ETHERTYPE >> 8;
    frame[13] = CTL_ETHERTYPE & 0xFF;
    frame[14] = CTL_VERSION;
    frame[15] = op;
    frame[16] = ++g_seq;
    frame[17] = 0;
    *seq = g_seq;
    return p;
}

err_t lwip_wifi_frame_send(struct pbuf *p)
{
    struct netif *netif = eth_device_netif();
    err_t err = netif ? netif->linkoutput(netif, p) : ERR_IF;

    tls_secure_memzero((uint8_t *)p->payload + CTL_HEADER, p->len - CTL_HEADER);
    pbuf_free(p);
    return err;
}

static lwip_wifi_error_t exchange(uint8_t op, const uint8_t *body, uint16_t body_len, uint32_t timeout_ms)
{
    struct pbuf *p = lwip_wifi_frame(op, body_len, &g_wait_seq);
    uint32_t start;

    if (!p)
        return LWIP_WIFI_ERR_MEM;
    if (body_len)
        memcpy((uint8_t *)p->payload + CTL_HEADER, body, body_len);

    g_wait_op = op;
    g_done = false;
    g_waiting = true;
    if (lwip_wifi_frame_send(p) != ERR_OK)
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
    case CTL_ST_OK:
        return LWIP_WIFI_OK;
    case CTL_ST_NOT_FOUND:
        return LWIP_WIFI_ERR_NOT_FOUND;
    case CTL_ST_FULL:
        return LWIP_WIFI_ERR_FULL;
    case CTL_ST_BUSY:
        return LWIP_WIFI_ERR_BUSY;
    default:
        return LWIP_WIFI_ERR_BAD_REQUEST;
    }
}

/* Frees the reply buffer. Every public call releases it before returning: lwIP's
 * statics outlive the program, but the heap it came from may not. */
static lwip_wifi_error_t release(lwip_wifi_error_t err)
{
    if (g_reply)
        mem_free(g_reply);
    g_reply = NULL;
    g_reply_len = 0;
    return err;
}

/* On success the reply stays in g_reply until the caller calls release(). */
static lwip_wifi_error_t request(uint8_t op, const uint8_t *body, uint16_t body_len, uint32_t timeout_ms)
{
    lwip_wifi_error_t err;

    if (!eth_device_netif())
        return LWIP_WIFI_ERR_NO_BRIDGE;
    if (g_waiting)
        return LWIP_WIFI_ERR_BUSY;
    if (!(g_reply = mem_malloc(WIFI_REPLY_MAX)))
        return LWIP_WIFI_ERR_MEM;
    g_reply_len = 0;
    err = exchange(op, body, body_len, timeout_ms);
    return err == LWIP_WIFI_OK ? err : release(err);
}

/* For calls whose reply carries nothing but the status. */
static lwip_wifi_error_t command(uint8_t op, const uint8_t *body, uint16_t body_len, uint32_t timeout_ms)
{
    lwip_wifi_error_t err = request(op, body, body_len, timeout_ms);

    return err == LWIP_WIFI_OK ? release(err) : err;
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
    lwip_wifi_error_t err = request(CTL_OP_STATUS, NULL, 0, WIFI_SHORT_TIMEOUT_MS);

    if (err != LWIP_WIFI_OK)
        return err;
    return release(parse_state(g_reply, g_reply_len, state) ? LWIP_WIFI_OK : LWIP_WIFI_ERR_BAD_REQUEST);
}

lwip_wifi_error_t lwip_wifi_list_profiles(lwip_wifi_profile_t *profiles, uint8_t max, uint8_t *count)
{
    lwip_wifi_error_t err = request(CTL_OP_LIST, NULL, 0, WIFI_SHORT_TIMEOUT_MS);
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
    return release(LWIP_WIFI_OK);
}

lwip_wifi_error_t lwip_wifi_scan(lwip_wifi_network_t *networks, uint8_t max, uint8_t *count)
{
    lwip_wifi_error_t err = request(CTL_OP_SCAN, NULL, 0, WIFI_SCAN_TIMEOUT_MS);
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
    return release(LWIP_WIFI_OK);
}

lwip_wifi_error_t lwip_wifi_save_profile(uint8_t slot, const char *ssid, const char *password,
                                         uint8_t security, uint8_t flags, uint8_t *saved)
{
    uint8_t body[3 + 1 + LWIP_WIFI_SSID_MAX + 1 + LWIP_WIFI_PASSWORD_MAX];
    uint16_t length = 3;
    lwip_wifi_error_t err;

    if (!ssid || !ssid[0] || strlen(ssid) > LWIP_WIFI_SSID_MAX || security > LWIP_WIFI_SEC_WPA2_WPA3 ||
        (password && strlen(password) > LWIP_WIFI_PASSWORD_MAX))
        return LWIP_WIFI_ERR_BAD_REQUEST;

    body[0] = slot;
    body[1] = security;
    body[2] = flags;
    length = (uint16_t)(length + put_string(&body[length], ssid, LWIP_WIFI_SSID_MAX));
    length = (uint16_t)(length + put_string(&body[length], password, LWIP_WIFI_PASSWORD_MAX));
    err = request(CTL_OP_SAVE, body, length, WIFI_CHANGE_TIMEOUT_MS);
    tls_secure_memzero(body, sizeof body);
    if (err == LWIP_WIFI_OK && saved)
        *saved = g_reply_len ? g_reply[0] : LWIP_WIFI_SLOT_NONE;
    return err == LWIP_WIFI_OK ? release(err) : err;
}

lwip_wifi_error_t lwip_wifi_forget_profile(uint8_t slot)
{
    return command(CTL_OP_FORGET, &slot, 1, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_enable_profile(uint8_t slot, bool enabled)
{
    uint8_t body[2] = {slot, enabled ? 1 : 0};

    return command(CTL_OP_ENABLE, body, sizeof body, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_prefer_profile(uint8_t slot)
{
    return command(CTL_OP_PREFER, &slot, 1, WIFI_SHORT_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_connect(uint8_t slot)
{
    return command(CTL_OP_CONNECT, &slot, 1, WIFI_CHANGE_TIMEOUT_MS);
}

lwip_wifi_error_t lwip_wifi_disconnect(void)
{
    return command(CTL_OP_DISCONNECT, NULL, 0, WIFI_CHANGE_TIMEOUT_MS);
}

/* Waits for a crypto job, keeping the stack running meanwhile. */
static lwip_wifi_error_t settle(lwip_crypto_job_t job)
{
    lwip_crypto_status_t status;

    if (!job)
        return LWIP_WIFI_ERR_NO_BRIDGE;
    while ((status = lwip_crypto_take(job)) == LWIP_CRYPTO_PENDING)
        pump();
    if (status == LWIP_CRYPTO_OK)
        return LWIP_WIFI_OK;
    return status == LWIP_CRYPTO_REJECTED ? LWIP_WIFI_ERR_REJECTED : LWIP_WIFI_ERR_TIMEOUT;
}

uint8_t lwip_wifi_crypto_caps(void)
{
    return lwip_crypto_caps();
}

lwip_wifi_error_t lwip_wifi_x25519(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32])
{
    return settle(lwip_crypto_x25519(scalar, point, out));
}

lwip_wifi_error_t lwip_wifi_rsa_verify(bool pss, const uint8_t digest[32], const uint8_t *modulus,
                                       size_t mod_len, const uint8_t *exponent, size_t exp_len,
                                       const uint8_t *sig)
{
    return settle(lwip_crypto_rsa_verify(pss ? CTL_RSA_PSS_SHA256 : CTL_RSA_PKCS1_SHA256, digest,
                                         modulus, mod_len, exponent, exp_len, sig));
}

lwip_wifi_error_t lwip_wifi_random(uint8_t *out, uint8_t len)
{
    return settle(lwip_crypto_random(out, len));
}
