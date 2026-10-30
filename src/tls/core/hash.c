#include <stdint.h>
#include <string.h>
#include "../includes/hash.h"
#include "../includes/bytes.h"
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

static bool tls_sha384_init_adapter(void *ctx)
{
    return tls_sha384_init((struct tls_sha384_context *)ctx);
}

static void tls_sha384_update_adapter(void *ctx, const uint8_t *data, size_t len)
{
    tls_sha384_update((struct tls_sha384_context *)ctx, data, len);
}

static void tls_sha384_digest_adapter(void *ctx, uint8_t *digest)
{
    tls_sha384_digest((struct tls_sha384_context *)ctx, digest);
}

bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t algorithm)
{
    if (ctx == NULL)
    {
        ERROR();
        return false;
    }
    tls_hash_clear(ctx);
    switch (algorithm)
    {
    case TLS_HASH_SHA256:
        ctx->digestlen = TLS_SHA256_DIGEST_LEN;
        ctx->blocklen = TLS_SHA256_BLOCK_LEN;
        ctx->init = tls_sha256_init_adapter;
        ctx->update = tls_sha256_update_adapter;
        ctx->digest = tls_sha256_digest_adapter;
        break;
    case TLS_HASH_SHA384:
        ctx->digestlen = TLS_SHA384_DIGEST_LEN;
        ctx->blocklen = TLS_SHA384_BLOCK_LEN;
        ctx->init = tls_sha384_init_adapter;
        ctx->update = tls_sha384_update_adapter;
        ctx->digest = tls_sha384_digest_adapter;
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
    if (!ctx->init(&ctx->_private))
    {
        tls_hash_clear(ctx);
        return false;
    }
    return true;
}

void tls_hash_context_copy(struct tls_hash_context *dst, const struct tls_hash_context *src)
{
    memcpy(dst, src, sizeof(*dst));
}

void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || ctx->update == NULL ||
        (data == NULL && len != 0))
    {
        ERROR();
        return;
    }
    tls_crypto_guard_enable();
    ctx->update(&ctx->_private, data, len);
    tls_crypto_guard_disable();
}

void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *digest)
{
    if (ctx == NULL || ctx->digest == NULL || digest == NULL)
    {
        ERROR();
        return;
    }
    tls_crypto_guard_enable();
    ctx->digest(&ctx->_private, digest);
    tls_crypto_guard_disable();
}

void tls_hash_clear(struct tls_hash_context *ctx)
{
    if (ctx != NULL)
        tls_secure_memzero(ctx, sizeof(*ctx));
}

bool tls_mgf1(const uint8_t *data, size_t datalen, uint8_t *outbuf, size_t outlen, uint8_t hash_alg)
{
    uint32_t ctr = 0;
    uint8_t hash_digest[TLS_HASH_MAX_DIGEST_LEN], ctr_data[4];
    struct tls_hash_context hash_data, hash_ctr;
    if (outbuf == NULL || (data == NULL && datalen != 0))
    {
        ERROR();
        return false;
    }
    if (!tls_hash_context_init(&hash_data, hash_alg))
    {
        tls_hash_clear(&hash_data);
        return false;
    }
    size_t hashlen = hash_data.digestlen;
    tls_crypto_guard_enable();
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
    tls_crypto_guard_disable();
    tls_hash_clear(&hash_ctr);
    tls_hash_clear(&hash_data);
    tls_secure_memzero(hash_digest, sizeof hash_digest);
    tls_secure_memzero(ctr_data, sizeof ctr_data);
    return true;
}
