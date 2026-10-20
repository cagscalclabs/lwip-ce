#ifndef LWIP_WIRELESS_WIFI_H
#define LWIP_WIRELESS_WIFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LWIP_WIFI_SSID_MAX 32
#define LWIP_WIFI_PASSWORD_MAX 64
#define LWIP_WIFI_SLOT_NONE 0xFF

#define LWIP_WIFI_PROFILE_ENABLED 0x01
#define LWIP_WIFI_PROFILE_HIDDEN 0x02
#define LWIP_WIFI_PROFILE_ACTIVE 0x04

#define LWIP_WIFI_CAP_X25519 0x01
#define LWIP_WIFI_CAP_RSA 0x02
#define LWIP_WIFI_CAP_RANDOM 0x04
#define LWIP_WIFI_RANDOM_MAX 64

typedef enum
{
    LWIP_WIFI_SEC_OPEN,
    LWIP_WIFI_SEC_WEP,
    LWIP_WIFI_SEC_WPA,
    LWIP_WIFI_SEC_WPA2,
    LWIP_WIFI_SEC_WPA3,
    LWIP_WIFI_SEC_WPA2_WPA3
} lwip_wifi_security_t;

typedef enum
{
    LWIP_WIFI_OK,
    LWIP_WIFI_ERR_NO_BRIDGE,
    LWIP_WIFI_ERR_TIMEOUT,
    LWIP_WIFI_ERR_BAD_REQUEST,
    LWIP_WIFI_ERR_NOT_FOUND,
    LWIP_WIFI_ERR_FULL,
    LWIP_WIFI_ERR_MEM,
    LWIP_WIFI_ERR_BUSY,
    LWIP_WIFI_ERR_REJECTED
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

/* Crypto on the bridge. TLS already uses it on its own; these are for programs.
 * They wait for the answer, so call them from the main loop, not from a socket
 * callback. X25519 and RSA need the Crypto offload setting, random needs the
 * Bridge TRNG setting. LWIP_WIFI_ERR_NO_BRIDGE when no bridge offers the
 * operation, LWIP_WIFI_ERR_TIMEOUT when the bridge could not answer. */
uint8_t lwip_wifi_crypto_caps(void);

/* out = X25519(scalar, point); point NULL means the base point (a public key).
 * LWIP_WIFI_ERR_REJECTED for an all-zero result. */
lwip_wifi_error_t lwip_wifi_x25519(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);

/* RSA signature check over a SHA-256 digest, PKCS#1 v1.5 or PSS (salt length
 * 32). Numbers are big-endian; the signature is mod_len bytes.
 * LWIP_WIFI_OK when valid, LWIP_WIFI_ERR_REJECTED when not. */
lwip_wifi_error_t lwip_wifi_rsa_verify(bool pss, const uint8_t digest[32], const uint8_t *modulus,
                                       size_t mod_len, const uint8_t *exponent, size_t exp_len,
                                       const uint8_t *sig);

/* len (at most LWIP_WIFI_RANDOM_MAX) bytes from the bridge TRNG. */
lwip_wifi_error_t lwip_wifi_random(uint8_t *out, uint8_t len);

#endif
