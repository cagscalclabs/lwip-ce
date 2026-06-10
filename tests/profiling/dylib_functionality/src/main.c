#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ti/screen.h>
#include <ti/getkey.h>
#include <ti/getcsc.h>

#include <lwip/core.h>
#include <lwip/conn.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/hmac.h>

void *os_FindAppStart(const char *name);

static void show_result(const char *line1, const char *line2)
{
    os_ClrHome();
    printf("%s", line1);
    if (line2)
    {
        printf("\n%s", line2);
    }
    os_GetKey();
}

static bool test_sha256(void)
{
    static const uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    struct tls_hash_context ctx;
    uint8_t digest[TLS_SHA256_DIGEST_LEN];

    if (!tls_hash_context_init(&ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_update(&ctx, (const uint8_t *)"abc", 3);
    tls_hash_digest(&ctx, digest);
    return memcmp(digest, expected, sizeof expected) == 0;
}

static bool test_hmac(void)
{
    static const uint8_t key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    static const uint8_t data[] = {
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    };
    static const uint8_t expected[] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    struct tls_hmac_context ctx;
    uint8_t digest[TLS_SHA256_DIGEST_LEN];

    if (!tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key, sizeof key))
    {
        return false;
    }
    tls_hmac_update(&ctx, data, sizeof data);
    tls_hmac_digest(&ctx, digest);
    return memcmp(digest, expected, sizeof expected) == 0;
}

static bool test_memory(void)
{
    uint8_t *region = (uint8_t *)mem_malloc(96);
    if (!region)
    {
        return false;
    }
    for (uint8_t i = 0; i < 96; ++i)
    {
        region[i] = (uint8_t)(i ^ 0x5a);
    }
    for (uint8_t i = 0; i < 96; ++i)
    {
        if (region[i] != (uint8_t)(i ^ 0x5a))
        {
            mem_free(region);
            return false;
        }
    }
    mem_free(region);
    return true;
}

int main(void)
{
    bool ok = false;

    if (!os_FindAppStart("lwIP"))
    {
        show_result("failed", "app missing");
        return 1;
    }

    os_ClrHome();
    printf("runtime");

    if (!lwip_init_runtime())
    {
        switch (lwip_runtime_last_error())
        {
        case 1:
            show_result("failed", "runtime app");
            break;
        case 2:
            show_result("failed", "runtime table");
            break;
        case 3:
            show_result("failed", "runtime count");
            break;
        default:
            show_result("failed", "runtime init");
            break;
        }
        return 1;
    }

    os_ClrHome();
    printf("lwip init");

    if (lwip_init() != ERR_OK)
    {
        show_result("failed", "lwip init");
        return 1;
    }

    ok = test_sha256() && test_hmac() && test_memory();
    show_result(ok ? "success" : "failed", ok ? NULL : "smoke test");
    return ok ? 0 : 1;
}
