#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <libload.h>

#include "lwip.h"

static const uint8_t expected_sha256_abc[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static const uint8_t hmac_key1[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
static const uint8_t hmac_data1[] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
static const uint8_t expected_hmac1[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};

static void show_result(bool ok)
{
    if (ok)
    {
        printf("success");
    }
    else
    {
        printf("failed");
    }
}

int main(void)
{
    os_ClrHome();

    if (!libload_IsLibLoaded(LWIP) || lwip_app_init() != 0)
    {
        show_result(false);
        os_GetKey();
        os_ClrHome();
        show_result(false);
        os_GetKey();
        return 1;
    }

    {
        struct tls_hash_context ctx;
        uint8_t digest[TLS_SHA256_DIGEST_LEN];
        bool ok = tls_hash_context_init(&ctx, TLS_HASH_SHA256);
        if (ok)
        {
            tls_hash_update(&ctx, (const uint8_t *)"abc", 3);
            tls_hash_digest(&ctx, digest);
            ok = (memcmp(digest, expected_sha256_abc, TLS_SHA256_DIGEST_LEN) == 0);
        }
        show_result(ok);
        os_GetKey();
        os_ClrHome();
    }

    {
        struct tls_hmac_context ctx;
        uint8_t digest[TLS_SHA256_DIGEST_LEN];
        bool ok = tls_hmac_context_init(&ctx, TLS_HASH_SHA256, hmac_key1, sizeof hmac_key1);
        if (ok)
        {
            tls_hmac_update(&ctx, hmac_data1, sizeof hmac_data1);
            tls_hmac_digest(&ctx, digest);
            ok = (memcmp(digest, expected_hmac1, TLS_SHA256_DIGEST_LEN) == 0);
        }
        show_result(ok);
        os_GetKey();
        os_ClrHome();
    }

    return 0;
}
