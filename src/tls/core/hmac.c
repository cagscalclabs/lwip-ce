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
    uint8_t sum[TLS_HASH_MAX_BLOCK_LEN];

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

    memset(sum, 0, sizeof sum);

    if (keylen > ctx->blocklen) {
        /* Hash the long key with the inner hash context, then reinitialize it
         * for the actual inner HMAC pad.  This keeps the 130+ byte temporary
         * hash context and the separate 128-byte pad buffer off the stack. */
        tls_hash_update(&ctx->_inner, key, keylen);
        tls_hash_digest(&ctx->_inner, sum);
        keylen = ctx->digestlen;
        if (!tls_hash_context_init(&ctx->_inner, algorithm)) {
            ERROR();
            tls_secure_memzero(sum, sizeof sum);
            tls_hmac_clear(ctx);
            return false;
        }
    } else if (keylen != 0) {
        memcpy(sum, key, keylen);
    }

    /* Build ipad in place, feed it, turn it into opad in place, feed that. */
    for (size_t i = 0; i < ctx->blocklen; i++)
        sum[i] ^= 0x36;

    tls_crypto_guard_enable();
    ctx->_inner.update(&ctx->_inner._private, sum, ctx->blocklen);

    for (size_t i = 0; i < ctx->blocklen; i++)
        sum[i] ^= 0x36 ^ 0x5C;
    if (!ctx->_inner.init(&ctx->_outer)) {
        tls_crypto_guard_disable();
        tls_secure_memzero(sum, sizeof sum);
        tls_hmac_clear(ctx);
        return false;
    }
    ctx->_inner.update(&ctx->_outer, sum, ctx->blocklen);
    tls_crypto_guard_disable();

    tls_secure_memzero(sum, sizeof sum);
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
    union tls_hash_state scratch;

    /* Digest a copy of the inner state, then reuse the same scratch for a
     * copy of the outer state.  The context itself stays intact, as before,
     * with one state-sized stack slot instead of two. */
    memcpy(&scratch, &ctx->_inner._private, sizeof scratch);
    tls_crypto_guard_enable();
    ctx->_inner.digest(&scratch, tbuf);
    memcpy(&scratch, &ctx->_outer, sizeof scratch);
    ctx->_inner.update(&scratch, tbuf, ctx->digestlen);
    ctx->_inner.digest(&scratch, digest);
    tls_crypto_guard_disable();
    tls_secure_memzero(tbuf, sizeof tbuf);
    tls_secure_memzero(&scratch, sizeof scratch);
}

void tls_hmac_clear(struct tls_hmac_context *ctx)
{
    if (ctx != NULL)
        tls_secure_memzero(ctx, sizeof(*ctx));
}
