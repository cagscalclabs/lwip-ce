#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/passwords.h>
#include <lwip.h>

/*
 * PBKDF2-HMAC-SHA256 Test Vectors
 * Source: RFC 6070 style vectors for SHA-256
 * (Generated using Python cryptography package, verified against RFC 6070 methodology)
 */

/* Test Case 1: password="password", salt="salt", c=1, dkLen=20 */
const char *password1 = "password";
const char *salt1 = "salt";
const uint8_t expected1[] = {
    0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c,0x43,0xe7,
    0x22,0x52,0x56,0xc4,0xf8,0x37,0xa8,0x65,0x48,0xc9
};

/* Test Case 2: password="password", salt="salt", c=2, dkLen=20 */
const char *password2 = "password";
const char *salt2 = "salt";
const uint8_t expected2[] = {
    0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3,0x2d,0x0a,
    0xdf,0xf9,0x28,0xf0,0x6d,0xd0,0x2a,0x30,0x3f,0x8e
};

/* Test Case 3: password="passwd", salt="salt", c=1, dkLen=32 (first 32 bytes of Test Case 7) */
const char *password3 = "passwd";
const char *salt3 = "salt";
const uint8_t expected3[] = {
    0x55,0xac,0x04,0x6e,0x56,0xe3,0x08,0x9f,0xec,0x16,
    0x91,0xc2,0x25,0x44,0xb6,0x05,0xf9,0x41,0x85,0x21,
    0x6d,0xde,0x04,0x65,0xe6,0x8b,0x9d,0x57,0xc2,0x0d,
    0xac,0xbc
};


/* Test Case 4: PBKDF2-HMAC-SHA384, password="password", salt="salt", c=2, dkLen=48 */
static const uint8_t expected4[] = {
    0x54,0xf7,0x75,0xc6,0xd7,0x90,0xf2,0x19,0x30,0x45,0x91,0x62,
    0xfc,0x53,0x5d,0xbf,0x04,0xa9,0x39,0x18,0x51,0x27,0x01,0x6a,
    0x04,0x17,0x6a,0x07,0x30,0xc6,0xf1,0xf4,0xfb,0x48,0x83,0x2a,
    0xd1,0x26,0x1b,0xaa,0xdd,0x2c,0xed,0xd5,0x08,0x14,0xb1,0xc8
};

/* Test Case 5: PBKDF2-HMAC-SHA512, password="password", salt="salt", c=2, dkLen=64 */
static const uint8_t expected5[] = {
    0xe1,0xd9,0xc1,0x6a,0xa6,0x81,0x70,0x8a,0x45,0xf5,0xc7,0xc4,
    0xe2,0x15,0xce,0xb6,0x6e,0x01,0x1a,0x2e,0x9f,0x00,0x40,0x71,
    0x3f,0x18,0xae,0xfd,0xb8,0x66,0xd5,0x3c,0xf7,0x6c,0xab,0x28,
    0x68,0xa3,0x9b,0x9f,0x78,0x40,0xed,0xce,0x4f,0xef,0x5a,0x82,
    0xbe,0x67,0x33,0x5c,0x77,0xa6,0x06,0x8e,0x04,0x11,0x27,0x54,
    0xf2,0x7c,0xcf,0x4e
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

static uint32_t time_pbkdf2(const uint8_t *password, size_t pass_len,
                            const uint8_t *salt, size_t salt_len)
{
    uint8_t key[32];
    clock_t start = clock();
    tls_pbkdf2(password, pass_len, salt, salt_len, key, 32, 10, TLS_HASH_SHA256);
    timing_sink ^= key[0];
    return (uint32_t)(clock() - start);
}


/* Main function, called first */
int main(void)
{
    if (!lwip_start()) return 1;

    os_ClrHome();
    uint8_t key[32];

    // Test 1: RFC 6070 style, c=1, dkLen=20
    tls_pbkdf2(password1, strlen(password1), salt1, strlen(salt1), key, 20, 1, TLS_HASH_SHA256);
    if(memcmp(key, expected1, sizeof expected1)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 2: RFC 6070 style, c=2, dkLen=20
    tls_pbkdf2(password2, strlen(password2), salt2, strlen(salt2), key, 20, 2, TLS_HASH_SHA256);
    if(memcmp(key, expected2, sizeof expected2)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 3: RFC 6070 style, c=1, dkLen=32
    tls_pbkdf2(password3, strlen(password3), salt3, strlen(salt3), key, 32, 1, TLS_HASH_SHA256);
    if(memcmp(key, expected3, sizeof expected3)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 4: PBKDF2-HMAC-SHA384 and SHA-512 (larger digest sizes)
    {
        uint8_t key384[48];
        uint8_t key512[64];
        bool ok384 = tls_pbkdf2(password1, strlen(password1), salt1, strlen(salt1),
                                key384, sizeof key384, 2, TLS_HASH_SHA384);
        bool ok512 = tls_pbkdf2(password1, strlen(password1), salt1, strlen(salt1),
                                key512, sizeof key512, 2, TLS_HASH_SHA512);
        if (ok384 && ok512 &&
            memcmp(key384, expected4, sizeof expected4) == 0 &&
            memcmp(key512, expected5, sizeof expected5) == 0)
            printf("success");
        else printf("failed");
    }
    os_GetKey();
    os_ClrHome();

    {
        const uint16_t samples = 5;
        const uint16_t lens[2] = {16, 32};
        struct timing_group groups[2] = {0};
        uint8_t passbuf[32];
        uint8_t saltbuf[16];
        uint32_t ticks[5];

        for (uint8_t i = 0; i < sizeof(saltbuf); i++)
            saltbuf[i] = (uint8_t)(0x33 + i);

        for (uint8_t g = 0; g < 2; g++)
        {
            uint16_t len = lens[g];
            for (uint16_t i = 0; i < samples; i++)
            {
                for (uint16_t j = 0; j < len; j++)
                    passbuf[j] = (uint8_t)(j + i);
                ticks[i] = time_pbkdf2(passbuf, len, saltbuf, sizeof(saltbuf));
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
