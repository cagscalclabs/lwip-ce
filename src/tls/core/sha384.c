/**
 * @file sha384.c
 * @brief SHA-384 (FIPS 180-4), built on the shared SHA-512 core.
 *
 * SHA-384 is SHA-512 with the SHA-384 initial state vector, truncated to the
 * first 48 digest bytes. The compression function (sha512.s), buffering,
 * padding and 128-bit length encoding live in sha512.c.
 */

#include "../includes/hash.h"
#include "sha512_internal.h"

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

bool tls_sha384_init(struct tls_sha384_context *ctx)
{
    return tls_sha512_core_init(ctx, sha384_iv);
}

void tls_sha384_update(struct tls_sha384_context *ctx, const uint8_t *data, size_t len)
{
    tls_sha512_core_update(ctx, data, len);
}

void tls_sha384_digest(struct tls_sha384_context *ctx, uint8_t *digest)
{
    tls_sha512_core_digest(ctx, digest, TLS_SHA384_DIGEST_LEN);
}
