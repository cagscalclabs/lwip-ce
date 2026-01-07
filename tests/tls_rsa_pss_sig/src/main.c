/**
 * @file main.c
 * @brief RSA-PSS Unit Test - Signature + Public Key Verification
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <time.h>

/* TLS includes */
#include "rsa.h"
#include "hash.h"
#include "tls.h"
#include "lwip/mem.h"
#include "drivers/mem.h"

static const uint8_t test_rsa_pubkey_2048[256];
static const uint8_t test_rsa_sig_2048[256];

#define TLS_TEST_MAX_HEAP (20u * 1024u)
#define TLS_TEST_POOL_BYTES (16u * 1024u)
#define TLS_TEST_POOL_BLOCK 256u

static struct mem_buffer *tls_test_heap;

static bool tls_test_mem_init(void)
{
    if (!mem_init(TLS_TEST_MAX_HEAP, malloc, free, realloc))
    {
        return false;
    }
    tls_test_heap = mem_buffer_create(
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BLOCK,
        BUFFER_MALLOC_TYPE,
        NULL);
    if (!tls_test_heap)
    {
        return false;
    }
    mem_buffer_set_lwip_heap(tls_test_heap);
    mem_buffer_set_owner(tls_test_heap, MEM_BUF_OWNER_TLS_RX);
    return true;
}

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

static uint32_t time_pss_verify(void)
{
    const uint8_t msg[] = "hello world";
    uint8_t mhash[TLS_SHA256_DIGEST_LEN];
    uint8_t decoded_sig[sizeof(test_rsa_pubkey_2048)];
    struct tls_hash_context hash_ctx;
    clock_t start = clock();

    bool ok = tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256);
    if (ok)
    {
        tls_hash_update(&hash_ctx, msg, sizeof(msg) - 1);
        tls_hash_digest(&hash_ctx, mhash);
    }
    if (ok)
    {
        ok = tls_rsa_decrypt_signature(
            test_rsa_sig_2048, sizeof(test_rsa_sig_2048),
            decoded_sig, test_rsa_pubkey_2048, sizeof(test_rsa_pubkey_2048));
    }
    if (ok)
    {
        ok = tls_rsa_pss_verify(
            decoded_sig, sizeof(decoded_sig),
            mhash, sizeof(mhash),
            TLS_HASH_SHA256);
    }
    timing_sink ^= decoded_sig[0];
    if (!ok)
        timing_sink ^= 0xFF;
    return (uint32_t)(clock() - start);
}

/**
 * Test 1: RSA-PSS Verify (signature + public key)
 * Signature generated with OpenSSL:
 *   openssl dgst -sha256 -sign key.pem \
 *     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
 *     -out sig.bin msg.txt
 */
static const uint8_t test_rsa_pubkey_2048[256] = {
    0xa8,
    0xf0,
    0x37,
    0x96,
    0x6f,
    0xd8,
    0xf3,
    0xe4,
    0x02,
    0xfa,
    0x02,
    0xa1,
    0xc5,
    0x64,
    0xb6,
    0xda,
    0xb0,
    0xa9,
    0x57,
    0x16,
    0x20,
    0x85,
    0xaa,
    0x90,
    0xbf,
    0x02,
    0x76,
    0x3a,
    0x97,
    0xa8,
    0xe7,
    0x00,
    0x4c,
    0x61,
    0xe3,
    0x45,
    0x04,
    0xe1,
    0xa7,
    0x16,
    0x4c,
    0x53,
    0xc0,
    0xda,
    0x6d,
    0x18,
    0x6d,
    0xb2,
    0xdc,
    0x38,
    0x75,
    0xec,
    0xef,
    0x83,
    0x3e,
    0x9f,
    0x17,
    0xdf,
    0x7e,
    0xfe,
    0xc0,
    0x64,
    0xec,
    0xee,
    0x5c,
    0x31,
    0x68,
    0xec,
    0x0a,
    0x8b,
    0x3a,
    0xe7,
    0x3c,
    0x30,
    0x9c,
    0xcf,
    0xe9,
    0x78,
    0x7d,
    0xd9,
    0x8c,
    0xdb,
    0x74,
    0x23,
    0xec,
    0x9a,
    0x8a,
    0xe8,
    0x59,
    0x99,
    0xed,
    0x78,
    0xee,
    0xb5,
    0x28,
    0x93,
    0x5a,
    0x38,
    0xcc,
    0x23,
    0x96,
    0x50,
    0xf6,
    0x06,
    0x8d,
    0x5a,
    0xc1,
    0x1f,
    0xc9,
    0x69,
    0x22,
    0x1f,
    0xd2,
    0x66,
    0x95,
    0x7c,
    0x57,
    0xc5,
    0xd8,
    0xa7,
    0x93,
    0x5b,
    0x08,
    0xd7,
    0x5f,
    0x8f,
    0x44,
    0x87,
    0x8e,
    0x92,
    0x64,
    0xec,
    0x08,
    0x15,
    0x9b,
    0x8c,
    0x68,
    0x29,
    0xab,
    0x75,
    0x90,
    0x93,
    0xc1,
    0xf4,
    0x2c,
    0x47,
    0x03,
    0x36,
    0x38,
    0x17,
    0xbb,
    0x72,
    0xaf,
    0x9a,
    0xaf,
    0x21,
    0x9a,
    0x57,
    0x81,
    0x35,
    0xbc,
    0x5e,
    0xd9,
    0xd3,
    0xf9,
    0xe4,
    0x80,
    0x98,
    0x54,
    0x2e,
    0xeb,
    0xdc,
    0x73,
    0x5b,
    0x60,
    0xd6,
    0x2d,
    0xbf,
    0x38,
    0x4f,
    0x48,
    0x4c,
    0x82,
    0x3d,
    0x3c,
    0x69,
    0xdc,
    0x10,
    0x0e,
    0x7c,
    0x87,
    0xa6,
    0x9c,
    0x28,
    0xf2,
    0x6c,
    0x4a,
    0x1e,
    0xcc,
    0xf4,
    0x66,
    0x78,
    0x5f,
    0xb1,
    0x23,
    0x4c,
    0x57,
    0xf5,
    0x4d,
    0xfd,
    0x82,
    0x27,
    0x19,
    0x45,
    0x58,
    0xe6,
    0xa1,
    0x3b,
    0xaa,
    0x63,
    0xce,
    0xf6,
    0x9a,
    0x92,
    0xcb,
    0x10,
    0xe5,
    0x12,
    0x3b,
    0xe8,
    0x56,
    0xfd,
    0xb7,
    0xcd,
    0x30,
    0x43,
    0x4a,
    0x73,
    0x70,
    0xe1,
    0xdc,
    0xb8,
    0xbf,
    0x87,
    0x60,
    0xf9,
    0xa2,
    0x54,
    0x72,
    0x2c,
    0xdb,
    0x1a,
    0x97,
    0xa5,
    0x44,
    0x91,
};

static const uint8_t test_rsa_sig_2048[256] = {
    0x87,
    0xd5,
    0x4d,
    0x3a,
    0x79,
    0xa0,
    0x09,
    0x46,
    0x30,
    0x4b,
    0xf9,
    0x7a,
    0x81,
    0xdd,
    0x4a,
    0x16,
    0xb1,
    0xdf,
    0xd9,
    0x37,
    0x56,
    0x5b,
    0xc2,
    0x23,
    0x74,
    0x8c,
    0x5f,
    0x85,
    0x85,
    0x46,
    0x21,
    0x0e,
    0x8f,
    0x71,
    0x36,
    0xac,
    0xb8,
    0x61,
    0xa7,
    0x4e,
    0x5d,
    0xee,
    0x4f,
    0xd3,
    0xe1,
    0x85,
    0xd3,
    0x24,
    0x8d,
    0xc2,
    0x45,
    0x04,
    0xda,
    0x5f,
    0x18,
    0x98,
    0xb3,
    0x01,
    0x2a,
    0xbd,
    0xce,
    0xb1,
    0x60,
    0x37,
    0x99,
    0xe3,
    0x82,
    0xfd,
    0x32,
    0x8a,
    0x6e,
    0xd6,
    0x0e,
    0xef,
    0x50,
    0x0e,
    0x1d,
    0x89,
    0x24,
    0x00,
    0x23,
    0xee,
    0x30,
    0x97,
    0x8e,
    0xd6,
    0x16,
    0x36,
    0x2b,
    0x4c,
    0x25,
    0xca,
    0x42,
    0x99,
    0xf1,
    0x51,
    0xe5,
    0x33,
    0x3d,
    0x29,
    0x02,
    0x1b,
    0x77,
    0xe5,
    0x8d,
    0xfc,
    0x64,
    0xf9,
    0xea,
    0xc4,
    0x7f,
    0x23,
    0x29,
    0x12,
    0x63,
    0xdf,
    0x72,
    0xbf,
    0xdd,
    0xf2,
    0xa5,
    0x47,
    0x45,
    0xdc,
    0x4a,
    0x5b,
    0xdf,
    0xa2,
    0x1c,
    0x49,
    0xc2,
    0xdf,
    0x87,
    0xef,
    0xd2,
    0x57,
    0x0d,
    0x5f,
    0x97,
    0x03,
    0x1c,
    0xc1,
    0xef,
    0x5e,
    0x66,
    0x51,
    0xe4,
    0x20,
    0x77,
    0xf7,
    0x92,
    0xac,
    0x3b,
    0x9a,
    0x58,
    0xab,
    0x82,
    0x70,
    0x45,
    0xf5,
    0x88,
    0xe9,
    0x29,
    0x6e,
    0x7c,
    0x90,
    0x0a,
    0x6d,
    0xfa,
    0x5f,
    0xd8,
    0xdc,
    0xb0,
    0xe0,
    0x7e,
    0x33,
    0x6a,
    0x8c,
    0x52,
    0xe3,
    0x77,
    0x78,
    0x63,
    0x43,
    0x84,
    0xb9,
    0x9c,
    0x25,
    0x37,
    0xe0,
    0xb5,
    0x47,
    0xeb,
    0xf5,
    0xd8,
    0x9a,
    0x2c,
    0x3f,
    0x3c,
    0x0b,
    0xe1,
    0x49,
    0x43,
    0xfa,
    0x2a,
    0xff,
    0xcb,
    0x78,
    0x6a,
    0x5f,
    0x98,
    0x38,
    0x2c,
    0x04,
    0x72,
    0x4a,
    0x07,
    0xec,
    0xaf,
    0x2e,
    0xc5,
    0x1b,
    0x7e,
    0xc1,
    0x58,
    0x61,
    0x66,
    0x73,
    0x8a,
    0x3d,
    0x2c,
    0x3d,
    0x61,
    0x75,
    0x52,
    0xfb,
    0x7a,
    0xd6,
    0x9e,
    0x74,
    0xbe,
    0xee,
    0x41,
    0x3c,
    0x3b,
    0xd9,
    0xd2,
    0x91,
    0xc2,
    0x91,
    0xf9,
    0x5f,
    0xe8,
    0x25,
    0x4f,
    0x3f,
};

static bool test_pss_signature_verify(void)
{
    const uint8_t msg[] = "hello world";
    uint8_t mhash[TLS_SHA256_DIGEST_LEN];
    uint8_t decoded_sig[sizeof(test_rsa_pubkey_2048)];
    struct tls_hash_context hash_ctx;

    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }

    tls_hash_update(&hash_ctx, msg, sizeof(msg) - 1);
    tls_hash_digest(&hash_ctx, mhash);

    if (!tls_rsa_decrypt_signature(
            test_rsa_sig_2048, sizeof(test_rsa_sig_2048),
            decoded_sig, test_rsa_pubkey_2048, sizeof(test_rsa_pubkey_2048)))
        return false;

    return tls_rsa_pss_verify(
        decoded_sig, sizeof(decoded_sig),
        mhash, sizeof(mhash),
        TLS_HASH_SHA256);
}

int main(void)
{
    os_ClrHome();

    /* Initialize lwIP memory */
    if (!tls_test_mem_init())
    {
        printf("mem init failed\n");
        os_GetKey();
        return 1;
    }

    /* Initialize TLS context */
    if (!tls_init())
    {
        printf("TLS init failed\n");
        os_GetKey();
        return 1;
    }

    /* Run tests */
    bool test1 = test_pss_signature_verify();

    /* Output results */
    os_ClrHome();
    printf("Test 1 (Sig Verify): %s\n", test1 ? "success" : "fail");
    os_GetKey();

    /* Cleanup */
    tls_cleanup();

    {
        const uint16_t samples = 5;
        struct timing_group group = {0};
        uint32_t ticks[5];
        for (uint16_t i = 0; i < samples; i++)
            ticks[i] = time_pss_verify();
        group.len = (uint16_t)sizeof(test_rsa_sig_2048);
        group.samples = samples;
        compute_stats(ticks, samples, &group);
        printf("timing len=%u dev=%u.%02u%%",
               group.len,
               group.pct_x100 / 100,
               group.pct_x100 % 100);
        os_GetKey();
        os_ClrHome();
    }

    return test1 ? 0 : 1;
}
