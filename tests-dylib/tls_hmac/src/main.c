#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <lwip/cryptography/hmac.h>
#include <lwip.h>

/*
 * RFC 4231 HMAC-SHA-256 Test Vectors
 * Source: RFC 4231, Section 4
 */

/* Test Case 1: 20-byte key, "Hi There" */
const uint8_t key1[] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
};
const uint8_t data1[] = {0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65}; /* "Hi There" */
const uint8_t expected1[] = {
    0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
    0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
};

/* Test Case 2: "Jefe" key, "what do ya want for nothing?" */
const uint8_t key2[] = {0x4a,0x65,0x66,0x65}; /* "Jefe" */
const uint8_t data2[] = {
    0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,0x79,0x61,0x20,0x77,0x61,0x6e,0x74,0x20,
    0x66,0x6f,0x72,0x20,0x6e,0x6f,0x74,0x68,0x69,0x6e,0x67,0x3f
}; /* "what do ya want for nothing?" */
const uint8_t expected2[] = {
    0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
    0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
};

/* Test Case 3: 20-byte 0xaa key, 50-byte 0xdd data */
const uint8_t key3[] = {
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
};
const uint8_t data3[] = {
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
    0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd
};
const uint8_t expected3[] = {
    0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,
    0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
};

static volatile uint8_t timing_sink = 0;

struct timing_group {
    uint16_t len;
    uint16_t samples;
    uint32_t mean;
    uint32_t stddev;
    uint32_t pct_x100;
};

static uint32_t isqrt_u64(uint64_t x)
{
    uint64_t op = x;
    uint64_t res = 0;
    uint64_t one = (uint64_t)1 << 62;
    while (one > op)
        one >>= 2;
    while (one != 0)
    {
        if (op >= res + one)
        {
            op -= res + one;
            res = (res >> 1) + one;
        }
        else
        {
            res >>= 1;
        }
        one >>= 2;
    }
    return (uint32_t)res;
}

static void compute_stats(const uint32_t *samples, uint16_t count, struct timing_group *out)
{
    uint64_t sum = 0;
    for (uint16_t i = 0; i < count; i++)
        sum += samples[i];
    uint32_t mean = (count != 0) ? (uint32_t)(sum / count) : 0;
    uint64_t var_sum = 0;
    for (uint16_t i = 0; i < count; i++)
    {
        int64_t diff = (int64_t)samples[i] - (int64_t)mean;
        var_sum += (uint64_t)(diff * diff);
    }
    uint32_t var = (count != 0) ? (uint32_t)(var_sum / count) : 0;
    uint32_t stddev = isqrt_u64(var);
    uint32_t pct_x100 = (mean != 0) ? (uint32_t)(((uint64_t)stddev * 10000u) / mean) : 0;
    out->mean = mean;
    out->stddev = stddev;
    out->pct_x100 = pct_x100;
}

static uint32_t time_hmac(const uint8_t *data, size_t len)
{
    struct tls_hmac_context ctx;
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    clock_t start = clock();
    bool ok = tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key1, sizeof key1);
    if (ok)
    {
        ctx.update(&ctx, data, len);
        ctx.digest(&ctx, digest);
        timing_sink ^= digest[0];
    }
    if (!ok)
        timing_sink ^= 0xFF;
    return (uint32_t)(clock() - start);
}


/* Main function, called first */
int main(void)
{
    if (!lwip_start()) return 1;

    os_ClrHome();
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    struct tls_hmac_context ctx;

    // Test 1: RFC 4231 Test Case 1
    if(!tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key1, sizeof key1)) return 1;
    ctx.update(&ctx, data1, sizeof data1);
    ctx.digest(&ctx, digest);
    if(memcmp(digest, expected1, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 2: RFC 4231 Test Case 2
    if(!tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key2, sizeof key2)) return 1;
    ctx.update(&ctx, data2, sizeof data2);
    ctx.digest(&ctx, digest);
    if(memcmp(digest, expected2, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 3: RFC 4231 Test Case 3
    if(!tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key3, sizeof key3)) return 1;
    ctx.update(&ctx, data3, sizeof data3);
    ctx.digest(&ctx, digest);
    if(memcmp(digest, expected3, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    {
        const uint16_t samples = 5;
        const uint16_t lens[2] = {32, 256};
        struct timing_group groups[2] = {0};
        uint8_t buf[256];
        uint32_t ticks[5];

        for (uint8_t g = 0; g < 2; g++)
        {
            uint16_t len = lens[g];
            for (uint16_t i = 0; i < samples; i++)
            {
                for (uint16_t j = 0; j < len; j++)
                    buf[j] = (uint8_t)(j + i);
                ticks[i] = time_hmac(buf, len);
            }
            groups[g].len = len;
            groups[g].samples = samples;
            compute_stats(ticks, samples, &groups[g]);
        }

        printf("timing len=%u dev=%u.%02u%%\n",
               groups[0].len,
               groups[0].pct_x100 / 100,
               groups[0].pct_x100 % 100);
        printf("timing len=%u dev=%u.%02u%%",
               groups[1].len,
               groups[1].pct_x100 / 100,
               groups[1].pct_x100 % 100);
        os_GetKey();
        os_ClrHome();
    }

    return 0;
}
