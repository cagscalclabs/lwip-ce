/**
 * @file main.c
 * @brief RSA-OAEP Unit Test - Encode and Decode Tests
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>

/* TLS includes */
#include "rsa.h"
#include "hash.h"
#include "tls.h"
#include "lwip/mem.h"
#include "drivers/mem.h"

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

/**
 * Test 1: RSA-OAEP Encode
 * Tests that OAEP encoding succeeds with valid parameters
 */
static bool test_oaep_encode(void)
{
    const uint8_t message[] = {
        0xd4, 0x36, 0xe9, 0x95, 0x69, 0xfd, 0x32, 0xa7,
        0xc8, 0xa0, 0x5b, 0xbc, 0x90, 0xd3, 0x2c, 0x49};

    const size_t modulus_len = 128; /* 1024-bit RSA */
    uint8_t encoded[128];

    bool result = tls_rsa_encode_oaep(
        message, sizeof(message),
        encoded, modulus_len,
        NULL, /* no label */
        TLS_HASH_SHA256);

    return result;
}

/**
 * Test 2: RSA-OAEP Decode
 * Tests that OAEP decode can recover the original message
 */
static bool test_oaep_decode(void)
{
    const uint8_t message[] = {
        0xd4, 0x36, 0xe9, 0x95, 0x69, 0xfd, 0x32, 0xa7,
        0xc8, 0xa0, 0x5b, 0xbc, 0x90, 0xd3, 0x2c, 0x49};

    const size_t modulus_len = 128; /* 1024-bit RSA */
    uint8_t encoded[128];
    uint8_t decoded[128];

    /* First encode the message */
    if (!tls_rsa_encode_oaep(message, sizeof(message), encoded, modulus_len,
                             NULL, TLS_HASH_SHA256))
    {
        return false;
    }

    /* Now decode it */
    size_t decoded_len = tls_rsa_decode_oaep(
        encoded, modulus_len,
        decoded,
        NULL, /* no label */
        TLS_HASH_SHA256);

    /* Verify the decoded message matches original */
    if (decoded_len != sizeof(message))
    {
        return false;
    }

    return memcmp(message, decoded, sizeof(message)) == 0;
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
    bool test1 = test_oaep_encode();
    bool test2 = test_oaep_decode();

    /* Output results */
    os_ClrHome();
    printf("Test 1 (Encode): %s\n", test1 ? "success" : "fail");
    os_GetKey();
    os_ClrHome();
    printf("Test 2 (Decode): %s\n", test2 ? "success" : "fail");
    os_GetKey();

    /* Cleanup */
    tls_cleanup();

    os_GetKey();
    return (test1 && test2) ? 0 : 1;
}
