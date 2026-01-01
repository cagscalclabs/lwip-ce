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

/* External memory allocator refs */
extern void *(*caller_malloc_ref)(size_t);
extern void (*caller_free_ref)(void *);

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
    caller_malloc_ref = malloc;
    caller_free_ref = free;
    mem_init();

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
