
#include <string.h>
#include "../includes/hash.h"
#include "../includes/hmac.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_HMAC
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

static bool tls_hmac_sha256_init_adapter(void *ctx)
{
    return tls_sha256_init((struct tls_sha256_context *)ctx);
}

static void tls_hmac_sha256_update_adapter(void *ctx, const uint8_t *data, size_t len)
{
    tls_sha256_update((struct tls_sha256_context *)ctx, data, len);
}

static void tls_hmac_sha256_digest_adapter(void *ctx, uint8_t *digest)
{
    tls_sha256_digest((struct tls_sha256_context *)ctx, digest);
}

bool tls_hmac_context_init(struct tls_hmac_context *ctx, uint8_t algorithm, const uint8_t* key, size_t keylen){
    
    if((ctx==NULL)||
       (key==NULL)||
       (keylen==0)) { ERROR(); return false; }
    struct tls_hash_context htmp;
    uint8_t sum[64] = {0};
    
    if(keylen > 64){
        tls_hash_context_init(&htmp, algorithm);
        htmp.update(&htmp._private, key, keylen);
        htmp.digest(&htmp._private, sum);
        keylen = 32;
    }
    else memcpy(sum, key, keylen);
    
    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );
    
    for(int i = 0; i < 64; i++ ){
        ctx->ipad[i] ^= sum[i];
        ctx->opad[i] ^= sum[i];
    }
    
    switch(algorithm){
        case TLS_HASH_SHA256:
            ctx->digestlen = TLS_SHA256_DIGEST_LEN;
            ctx->update = tls_hmac_update;
            ctx->digest = tls_hmac_digest;
            ctx->_init = tls_hmac_sha256_init_adapter;
            ctx->_update = tls_hmac_sha256_update_adapter;
            ctx->_final = tls_hmac_sha256_digest_adapter;
            break;
       /* case TLS_SHA256_HW:
            ctx->digestlen = TLS_SHA256_DIGEST_LEN;
            ctx->init = tls_sha256hw_init;
            ctx->update = tls_sha256hw_update;
            ctx->digest = tls_sha256hw_digest;
            break; */
        default:
            ERROR_CODE(algorithm);
            return false;
    }
    ctx->_init(&ctx->_private);
    ctx->_update(&ctx->_private, ctx->ipad, sizeof ctx->ipad);
    return true;
}

void tls_hmac_update(struct tls_hmac_context *ctx, const uint8_t *data, size_t len) {
    ctx->_update(&ctx->_private, data, len);
}


void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *digest){
    uint8_t tbuf[64];
    struct tls_hmac_context htmp;
    memcpy(&htmp, ctx, sizeof(htmp));
    htmp._final(&htmp._private, tbuf);
    
    htmp._init(&htmp._private);
    htmp._update(&htmp._private, htmp.opad, sizeof htmp.opad);
    htmp._update(&htmp._private, tbuf, htmp.digestlen);
    htmp._final(&htmp._private, digest);
}
