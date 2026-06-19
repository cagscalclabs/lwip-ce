#include <stdint.h>
#include <string.h>
#include "../includes/hash.h"
#include "../includes/crypto_guard.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_HASH
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

static bool tls_sha256_init_adapter(void *ctx)
{
    return tls_sha256_init((struct tls_sha256_context *)ctx);
}

static void tls_sha256_update_adapter(void *ctx, const uint8_t *data, size_t len)
{
    tls_sha256_update((struct tls_sha256_context *)ctx, data, len);
}

static void tls_sha256_digest_adapter(void *ctx, uint8_t *digest)
{
    tls_sha256_digest((struct tls_sha256_context *)ctx, digest);
}

bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t algorithm)
{
    if (ctx == NULL)
    {
        ERROR();
        return false;
    }
    switch (algorithm)
    {
    case TLS_HASH_SHA256:
        ctx->digestlen = TLS_SHA256_DIGEST_LEN;
        ctx->init = tls_sha256_init_adapter;
        ctx->update = tls_sha256_update_adapter;
        ctx->digest = tls_sha256_digest_adapter;
        break; /*
    case TLS_SHA256_HW:
        ctx->digestlen = TLS_SHA256_DIGEST_LEN;
        ctx->init = tls_sha256hw_init;
        ctx->update = tls_sha256hw_update;
        ctx->digest = tls_sha256hw_digest;
        break;      */
    default:
        ERROR_CODE(algorithm);
        return false;
    }
    return ctx->init(&ctx->_private);
}

void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *data, size_t len)
{
    tls_crypto_guard_enable();
    ctx->update(&ctx->_private, data, len);
    tls_crypto_guard_disable();
}

void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *digest)
{
    tls_crypto_guard_enable();
    ctx->digest(&ctx->_private, digest);
    tls_crypto_guard_disable();
}

bool tls_mgf1(const uint8_t *data, size_t datalen, uint8_t *outbuf, size_t outlen, uint8_t hash_alg)
{
    uint32_t ctr = 0;
    uint8_t hash_digest[TLS_SHA256_DIGEST_LEN], ctr_data[4];
    struct tls_hash_context hash_data, hash_ctr;
    if (!tls_hash_context_init(&hash_data, hash_alg))
        return false;
    size_t hashlen = hash_data.digestlen;
    hash_data.update(&hash_data._private, data, datalen);
    for (size_t printlen = 0; printlen < outlen; printlen += hashlen, ctr++)
    {
        size_t copylen = (outlen - printlen > hashlen) ? hashlen : outlen - printlen;
        // memcpy(ctr_data, &ctr, 4);
        ctr_data[0] = (uint8_t)((ctr >> 24) & 0xff);
        ctr_data[1] = (uint8_t)((ctr >> 16) & 0xff);
        ctr_data[2] = (uint8_t)((ctr >> 8) & 0xff);
        ctr_data[3] = (uint8_t)((ctr >> 0) & 0xff);
        memcpy(&hash_ctr, &hash_data, sizeof hash_ctr);
        hash_ctr.update(&hash_ctr._private, ctr_data, 4);
        hash_ctr.digest(&hash_ctr._private, hash_digest);
        memcpy(&outbuf[printlen], hash_digest, copylen);
    }
    return true;
}
