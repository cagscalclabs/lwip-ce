#include "bridge.h"

#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "psa/crypto.h"

#define TAG "crypto"
#define CRYPTO_QUEUE_LEN 8
#define RSA_MAX 512
/* SEQUENCE { INTEGER n, INTEGER e } with long-form lengths and sign padding. */
#define RSA_DER_MAX (RSA_MAX + 255 + 16)

typedef struct {
    uint16_t length;
    uint8_t data[];
} request_t;

static QueueHandle_t s_queue;
static uint8_t s_reply[CTL_HEADER + (CTL_RANDOM_MAX > 65 ? CTL_RANDOM_MAX : 65)];
static uint8_t s_der[RSA_DER_MAX];

/* The bridge only answers when it is sure. Anything it cannot work out is
 * CTL_ST_BAD_REQUEST, and the calculator then does the work itself, so a
 * verdict never depends on a quirk of this side. */

static uint8_t x25519(const uint8_t *in, uint8_t *out)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key;
    psa_status_t err;
    size_t length = 0;
    uint8_t any = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    if (psa_import_key(&attributes, in, 32, &key) != PSA_SUCCESS) {
        return CTL_ST_BAD_REQUEST;
    }
    err = psa_raw_key_agreement(PSA_ALG_ECDH, key, in + 32, 32, out, 32, &length);
    psa_destroy_key(key);
    if (err != PSA_SUCCESS || length != 32) {
        memset(out, 0, 32);
        return CTL_ST_BAD_REQUEST;
    }
    for (int i = 0; i < 32; i++) {
        any |= out[i];
    }
    return any ? CTL_ST_OK : CTL_ST_REJECTED;
}

static uint8_t p256(const uint8_t *in, size_t in_len, uint8_t *out, size_t *used)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key;
    psa_status_t err;
    size_t length = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    if (psa_import_key(&attributes, in, 32, &key) != PSA_SUCCESS) {
        return CTL_ST_BAD_REQUEST;
    }
    if (in_len == 32) {
        err = psa_export_public_key(key, out, 65, &length);
    } else {
        err = psa_raw_key_agreement(PSA_ALG_ECDH, key, in + 32, 65, out, 32, &length);
    }
    psa_destroy_key(key);
    if (err != PSA_SUCCESS || length != (in_len == 32 ? 65u : 32u)) {
        memset(out, 0, 65);
        return CTL_ST_BAD_REQUEST;
    }
    *used = length;
    return CTL_ST_OK;
}

static uint8_t ecdsa_verify(const uint8_t *in)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_id_t key;
    psa_status_t err;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    if (psa_import_key(&attributes, in + 32, 65, &key) != PSA_SUCCESS) {
        return CTL_ST_BAD_REQUEST;
    }
    err = psa_verify_hash(key, alg, in, 32, in + 97, 64);
    psa_destroy_key(key);
    if (err == PSA_SUCCESS) {
        return CTL_ST_OK;
    }
    return err == PSA_ERROR_INVALID_SIGNATURE ? CTL_ST_REJECTED : CTL_ST_BAD_REQUEST;
}

static size_t der_length(uint8_t *out, size_t length)
{
    if (length < 0x80) {
        out[0] = (uint8_t)length;
        return 1;
    }
    if (length < 0x100) {
        out[0] = 0x81;
        out[1] = (uint8_t)length;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)(length >> 8);
    out[2] = (uint8_t)length;
    return 3;
}

static size_t der_integer(uint8_t *out, const uint8_t *value, size_t length)
{
    size_t used = 1;
    bool pad;

    while (length > 1 && value[0] == 0) {
        value++;
        length--;
    }
    pad = (value[0] & 0x80) != 0;
    out[0] = 0x02;
    used += der_length(out + used, length + pad);
    if (pad) {
        out[used++] = 0;
    }
    memcpy(out + used, value, length);
    return used + length;
}

/* PSA takes an RSA public key as a DER RSAPublicKey. */
static size_t rsa_public_der(const uint8_t *modulus, size_t mod_len, const uint8_t *exponent,
                             size_t exp_len)
{
    uint8_t *body = s_der + 4;
    size_t length = der_integer(body, modulus, mod_len);
    size_t header;

    length += der_integer(body + length, exponent, exp_len);
    s_der[0] = 0x30;
    header = 1 + der_length(s_der + 1, length);
    memmove(s_der + header, body, length);
    return header + length;
}

static uint8_t rsa_verify(const uint8_t *in, size_t in_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_key_id_t key;
    psa_status_t err;
    size_t mod_len, exp_len;
    const uint8_t *modulus, *exponent, *sig;

    if (in_len < 36) {
        return CTL_ST_BAD_REQUEST;
    }
    mod_len = in[33] | ((size_t)in[34] << 8);
    exp_len = in[35];
    if (mod_len == 0 || mod_len > RSA_MAX || exp_len == 0 || in_len != 36 + 2 * mod_len + exp_len) {
        return CTL_ST_BAD_REQUEST;
    }
    switch (in[0]) {
    case CTL_RSA_PKCS1_SHA256:
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
        break;
    case CTL_RSA_PSS_SHA256:
        /* Salt length equal to the hash length, as TLS 1.3 requires. */
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
        break;
    default:
        return CTL_ST_BAD_REQUEST;
    }
    modulus = in + 36;
    exponent = modulus + mod_len;
    sig = exponent + exp_len;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    if (psa_import_key(&attributes, s_der, rsa_public_der(modulus, mod_len, exponent, exp_len),
                       &key) != PSA_SUCCESS) {
        return CTL_ST_BAD_REQUEST;
    }
    err = psa_verify_hash(key, alg, in + 1, 32, sig, mod_len);
    psa_destroy_key(key);
    if (err == PSA_SUCCESS) {
        return CTL_ST_OK;
    }
    return err == PSA_ERROR_INVALID_SIGNATURE ? CTL_ST_REJECTED : CTL_ST_BAD_REQUEST;
}

static void handle(const uint8_t *frame, size_t length)
{
    const uint8_t *in = frame + CTL_HEADER;
    size_t in_len = length - CTL_HEADER;
    uint8_t *out = s_reply + CTL_HEADER;
    uint8_t status = CTL_ST_BAD_REQUEST;
    size_t used = 0;

    switch (frame[15]) {
    case CTL_OP_INFO:
        out[0] = CTL_CAP_X25519 | CTL_CAP_RSA | CTL_CAP_RANDOM | CTL_CAP_P256;
        used = 1;
        status = CTL_ST_OK;
        break;
    case CTL_OP_X25519:
        if (in_len == 64) {
            status = x25519(in, out);
            used = status == CTL_ST_OK ? 32 : 0;
        }
        break;
    case CTL_OP_RSA_VERIFY:
        status = rsa_verify(in, in_len);
        break;
    case CTL_OP_P256:
        if (in_len == 32 || in_len == 97) {
            status = p256(in, in_len, out, &used);
        }
        break;
    case CTL_OP_ECDSA_VERIFY:
        if (in_len == 161) {
            status = ecdsa_verify(in);
        }
        break;
    case CTL_OP_RANDOM:
        if (in_len >= 1 && in[0] > 0 && in[0] <= CTL_RANDOM_MAX) {
            used = in[0];
            esp_fill_random(out, used);
            status = CTL_ST_OK;
        }
        break;
    default:
        break;
    }
    control_reply(frame, s_reply, status, used);
    memset(out, 0, sizeof s_reply - CTL_HEADER);
    ESP_LOGI(TAG, "op %u status %u", frame[15], status);
}

static void crypto_task(void *arg)
{
    (void)arg;

    for (;;) {
        request_t *request;

        xQueueReceive(s_queue, &request, portMAX_DELAY);
        handle(request->data, request->length);
        memset(request->data, 0, request->length);
        free(request);
    }
}

bool crypto_request(const uint8_t *frame, size_t length)
{
    request_t *request;

    if (frame[15] < CTL_OP_INFO || frame[15] > CTL_OP_ECDSA_VERIFY) {
        return false;
    }
    request = malloc(sizeof *request + length);
    if (request == NULL) {
        return true;
    }
    request->length = (uint16_t)length;
    memcpy(request->data, frame, length);
    if (xQueueSend(s_queue, &request, 0) != pdTRUE) {
        memset(request->data, 0, length);
        free(request);
    }
    return true;
}

esp_err_t crypto_init(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    s_queue = xQueueCreate(CRYPTO_QUEUE_LEN, sizeof(request_t *));
    if (s_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }
    xTaskCreatePinnedToCore(crypto_task, "crypto", 6144, NULL, 7, NULL, 1);
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}
