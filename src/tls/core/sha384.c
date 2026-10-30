/**
 * @file sha384.c
 * @brief SHA-384 and SHA-512 (FIPS 180-4) using the SHA-512 compression
 *        primitive.
 *
 * SHA-384 and SHA-512 share the compression function (sha512.s), the 128-byte
 * block size and the 128-bit message-length encoding; they differ only in the
 * initial state vector and the number of digest bytes emitted. This file owns
 * buffering, padding, the length encoding and the output truncation.
 */

#include <string.h>
#include "../includes/hash.h"
#include "../includes/bytes.h"

void tls_sha512_compress(uint64_t state[8], const uint8_t block[TLS_SHA512_BLOCK_LEN]);

static const uint64_t sha384_iv[8] = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

static const uint64_t sha512_iv[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL
};

/* Both public context types have the same layout; access them through a
 * may_alias view so the shared core can operate on either without copying. */
struct sha512_state_view
{
    uint8_t data[TLS_SHA512_BLOCK_LEN];
    uint8_t datalen;
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
    uint64_t state[8];
} __attribute__((may_alias));

static bool sha512_init(void *vctx, const uint64_t iv[8])
{
    struct sha512_state_view *ctx = vctx;
    if (ctx == NULL)
        return false;
    tls_secure_memzero(ctx, sizeof(*ctx));
    memcpy(ctx->state, iv, sizeof(ctx->state));
    ctx->bitlen_hi = 0;
    ctx->bitlen_lo = 0;
    ctx->datalen = 0;
    return true;
}

static void sha512_update(void *vctx, const uint8_t *data, size_t len)
{
    struct sha512_state_view *ctx = vctx;
    if (ctx == NULL || (data == NULL && len != 0))
        return;

    if (len != 0)
    {
        uint64_t bits = (uint64_t)len << 3;
        uint64_t new_lo = ctx->bitlen_lo + bits;
        if (new_lo < ctx->bitlen_lo)
            ctx->bitlen_hi++;
        ctx->bitlen_lo = new_lo;
    }

    while (len > 0)
    {
        size_t space = (size_t)TLS_SHA512_BLOCK_LEN - (size_t)ctx->datalen;
        size_t take = (len < space) ? len : space;
        memcpy(ctx->data + ctx->datalen, data, take);
        ctx->datalen = (uint8_t)(ctx->datalen + take);
        data += take;
        len -= take;
        if (ctx->datalen == TLS_SHA512_BLOCK_LEN)
        {
            tls_sha512_compress(ctx->state, ctx->data);
            ctx->datalen = 0;
        }
    }
}

static void sha512_digest(void *vctx, uint8_t *digest, size_t digest_len)
{
    struct sha512_state_view local;
    struct sha512_state_view *ctx = vctx;
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
    size_t i;

    if (ctx == NULL || digest == NULL)
        return;

    memcpy(&local, ctx, sizeof(local));
    bitlen_hi = local.bitlen_hi;
    bitlen_lo = local.bitlen_lo;

    local.data[local.datalen++] = 0x80;
    if (local.datalen > (TLS_SHA512_BLOCK_LEN - 16))
    {
        memset(local.data + local.datalen, 0,
               (size_t)TLS_SHA512_BLOCK_LEN - (size_t)local.datalen);
        tls_sha512_compress(local.state, local.data);
        local.datalen = 0;
    }
    memset(local.data + local.datalen, 0,
           (size_t)(TLS_SHA512_BLOCK_LEN - 16) - (size_t)local.datalen);

    for (i = 0; i < 8; i++)
    {
        local.data[112 + i] = (uint8_t)(bitlen_hi >> (56 - 8 * i));
        local.data[120 + i] = (uint8_t)(bitlen_lo >> (56 - 8 * i));
    }
    tls_sha512_compress(local.state, local.data);

    for (i = 0; i < digest_len / 8; i++)
    {
        uint64_t w = local.state[i];
        digest[8 * i + 0] = (uint8_t)(w >> 56);
        digest[8 * i + 1] = (uint8_t)(w >> 48);
        digest[8 * i + 2] = (uint8_t)(w >> 40);
        digest[8 * i + 3] = (uint8_t)(w >> 32);
        digest[8 * i + 4] = (uint8_t)(w >> 24);
        digest[8 * i + 5] = (uint8_t)(w >> 16);
        digest[8 * i + 6] = (uint8_t)(w >> 8);
        digest[8 * i + 7] = (uint8_t)(w >> 0);
    }

    tls_secure_memzero(&local, sizeof(local));
}

bool tls_sha384_init(struct tls_sha384_context *ctx)
{
    return sha512_init(ctx, sha384_iv);
}

void tls_sha384_update(struct tls_sha384_context *ctx, const uint8_t *data, size_t len)
{
    sha512_update(ctx, data, len);
}

void tls_sha384_digest(struct tls_sha384_context *ctx, uint8_t *digest)
{
    sha512_digest(ctx, digest, TLS_SHA384_DIGEST_LEN);
}

bool tls_sha512_init(struct tls_sha512_context *ctx)
{
    return sha512_init(ctx, sha512_iv);
}

void tls_sha512_update(struct tls_sha512_context *ctx, const uint8_t *data, size_t len)
{
    sha512_update(ctx, data, len);
}

void tls_sha512_digest(struct tls_sha512_context *ctx, uint8_t *digest)
{
    sha512_digest(ctx, digest, TLS_SHA512_DIGEST_LEN);
}
