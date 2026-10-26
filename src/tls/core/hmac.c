#include <string.h>
#include "../includes/hash.h"
#include "../includes/hmac.h"
#include "../includes/bytes.h"
#include "../includes/crypto_guard.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_HMAC
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

bool tls_hmac_context_init(struct tls_hmac_context *ctx, uint8_t algorithm,
                           const uint8_t *key, size_t keylen)
{
    struct tls_hash_context htmp = {0};
    uint8_t sum[TLS_HASH_MAX_BLOCK_LEN] = {0};
    uint8_t pad[TLS_HASH_MAX_BLOCK_LEN];

    if (ctx == NULL) { ERROR(); return false; }
    tls_hmac_clear(ctx);
    if (key == NULL && keylen != 0) { ERROR(); return false; }

    if (!tls_hash_context_init(&ctx->_inner, algorithm)) {
        tls_hmac_clear(ctx);
        return false;
    }
    ctx->digestlen = ctx->_inner.digestlen;
    ctx->blocklen = ctx->_inner.blocklen;
    ctx->update = tls_hmac_update;
    ctx->digest = tls_hmac_digest;

    if (ctx->blocklen == 0 || ctx->blocklen > TLS_HASH_MAX_BLOCK_LEN ||
        ctx->digestlen == 0 || ctx->digestlen > TLS_HASH_MAX_DIGEST_LEN ||
        ctx->digestlen > ctx->blocklen) {
        ERROR_CODE(algorithm);
        tls_hmac_clear(ctx);
        return false;
    }

    if (keylen > ctx->blocklen) {
        if (!tls_hash_context_init(&htmp, algorithm)) {
            ERROR();
            tls_hash_clear(&htmp);
            tls_secure_memzero(sum, sizeof sum);
            tls_secure_memzero(pad, sizeof pad);
            tls_hmac_clear(ctx);
            return false;
        }
        tls_hash_update(&htmp, key, keylen);
        tls_hash_digest(&htmp, sum);
        keylen = htmp.digestlen;
        tls_hash_clear(&htmp);
    } else if (keylen != 0) {
        memcpy(sum, key, keylen);
    }

    for (size_t i = 0; i < ctx->blocklen; i++)
        pad[i] = sum[i] ^ 0x36;

    tls_crypto_guard_enable();
    ctx->_inner.update(&ctx->_inner._private, pad, ctx->blocklen);

    for (size_t i = 0; i < ctx->blocklen; i++)
        pad[i] = sum[i] ^ 0x5C;
    if (!ctx->_inner.init(&ctx->_outer)) {
        tls_crypto_guard_disable();
        tls_secure_memzero(sum, sizeof sum);
        tls_secure_memzero(pad, sizeof pad);
        tls_hmac_clear(ctx);
        return false;
    }
    ctx->_inner.update(&ctx->_outer, pad, ctx->blocklen);
    tls_crypto_guard_disable();

    tls_secure_memzero(sum, sizeof sum);
    tls_secure_memzero(pad, sizeof pad);
    return true;
}

void tls_hmac_update(struct tls_hmac_context *ctx, const uint8_t *data, size_t len)
{
    tls_crypto_guard_enable();
    ctx->_inner.update(&ctx->_inner._private, data, len);
    tls_crypto_guard_disable();
}

void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *digest)
{
    uint8_t tbuf[TLS_HASH_MAX_DIGEST_LEN];
    union tls_hash_state inner;
    union tls_hash_state outer;

    memcpy(&inner, &ctx->_inner._private, sizeof inner);
    memcpy(&outer, &ctx->_outer, sizeof outer);
    tls_crypto_guard_enable();
    ctx->_inner.digest(&inner, tbuf);
    ctx->_inner.update(&outer, tbuf, ctx->digestlen);
    ctx->_inner.digest(&outer, digest);
    tls_crypto_guard_disable();
    tls_secure_memzero(tbuf, sizeof tbuf);
    tls_secure_memzero(&inner, sizeof inner);
    tls_secure_memzero(&outer, sizeof outer);
}

void tls_hmac_clear(struct tls_hmac_context *ctx)
{
    if (ctx != NULL)
        tls_secure_memzero(ctx, sizeof(*ctx));
}
