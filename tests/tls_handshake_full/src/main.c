/**
 * @file main.c
 * @brief TLS 1.3 Handshake Packet Replay Test
 *
 * This test validates TLS 1.3-PSK handshake logic by feeding pre-recorded
 * packets into the TLS state machine and verifying correct behavior.
 *
 * No network connection required - runs standalone in CEmu.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/getkey.h>

/* TLS implementation headers */
#include "handshake.h"
#include "lwip/mem.h"

/* lwIP memory allocator function pointers */
extern void *(*caller_malloc_ref)(size_t);
extern void (*caller_free_ref)(void *);

/* Test configuration */
#define TEST_PSK_LEN 32
#define TEST_IDENTITY_LEN 16

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test failure tracking */
static char failed_tests[256];
static int failed_tests_len = 0;

/* Output tracking */
static int output_y = 0;
static char output_buf[256];

/* Test PSK and identity (must match pre-recorded handshake) */
static const uint8_t test_psk[TEST_PSK_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static const uint8_t test_identity[TEST_IDENTITY_LEN] = {
    'c', 'l', 'i', 'e', 'n', 't', '@', 't', 'e', 's', 't', '.', 'c', 'o', 'm', 0};

/* Pre-recorded ServerHello from TLS 1.3-PSK handshake */
static const uint8_t serverhello_packet[] = {
    /* TLS Record Layer Header */
    0x16,       /* Content Type: Handshake */
    0x03, 0x03, /* Legacy Version: TLS 1.2 */
    0x00, 0x3e, /* Length: 62 bytes */

    /* Handshake Protocol: ServerHello */
    0x02,             /* Handshake Type: ServerHello */
    0x00, 0x00, 0x3a, /* Length: 58 bytes */

    /* ServerHello Fields */
    0x03, 0x03, /* Version: TLS 1.2 (for compatibility) */

    /* Server Random (32 bytes) */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

    0x00, /* Session ID Length: 0 */

    0x13, 0x01, /* Cipher Suite: TLS_AES_128_GCM_SHA256 */
    0x00,       /* Compression: None */

    /* Extensions Length */
    0x00, 0x12, /* 18 bytes of extensions */

    /* Extension: supported_versions */
    0x00, 0x2b, /* Extension Type */
    0x00, 0x02, /* Length */
    0x03, 0x04, /* TLS 1.3 */

    /* Extension: key_share (PSK only - no DH share) */
    0x00, 0x33, /* Extension Type */
    0x00, 0x02, /* Length */
    0x00, 0x00, /* Empty key share */

    /* Extension: pre_shared_key */
    0x00, 0x29, /* Extension Type */
    0x00, 0x02, /* Length */
    0x00, 0x00  /* Selected identity: 0 */
};

/* Expected handshake transcript hash after ClientHello + ServerHello */
static const uint8_t expected_transcript_hash[32] = {
    /* @todo: Fill with actual hash from real handshake capture */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Helper to print a line */
#define TLS_HANDSHAKE_DEBUG

static void print_line(const char *msg)
{
#ifndef TLS_HANDSHAKE_DEBUG
    os_FontDrawText(msg, 0, output_y);
    output_y += 12;
#endif
}

/* Test helper macros */
#define TEST_ASSERT(condition, msg)                \
    do                                             \
    {                                              \
        tests_run++;                               \
        if (condition)                             \
        {                                          \
            tests_passed++;                        \
            sprintf(output_buf, "[PASS] %s", msg); \
            print_line(output_buf);                \
        }                                          \
        else                                       \
        {                                          \
            tests_failed++;                        \
            sprintf(output_buf, "[FAIL] %s", msg); \
            print_line(output_buf);                \
        }                                          \
    } while (0)

#define TEST_ASSERT_EQUAL(expected, actual, msg)                                                   \
    do                                                                                             \
    {                                                                                              \
        tests_run++;                                                                               \
        if ((expected) == (actual))                                                                \
        {                                                                                          \
            tests_passed++;                                                                        \
            sprintf(output_buf, "[PASS] %s", msg);                                                 \
            print_line(output_buf);                                                                \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            tests_failed++;                                                                        \
            sprintf(output_buf, "[FAIL] %s (exp:%d got:%d)", msg, (int)(expected), (int)(actual)); \
            print_line(output_buf);                                                                \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_MEM_EQUAL(expected, actual, len, msg)     \
    do                                                        \
    {                                                         \
        tests_run++;                                          \
        if (memcmp((expected), (actual), (len)) == 0)         \
        {                                                     \
            tests_passed++;                                   \
            sprintf(output_buf, "[PASS] %s", msg);            \
            print_line(output_buf);                           \
        }                                                     \
        else                                                  \
        {                                                     \
            tests_failed++;                                   \
            sprintf(output_buf, "[FAIL] %s (mismatch)", msg); \
            print_line(output_buf);                           \
        }                                                     \
    } while (0)

/**
 * Test 1: Initialize TLS context with PSK
 */
static void test_init_psk_context(void)
{
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    bool ret;
    int initial_failed = tests_failed;

    output_y = 30;
    print_line("=== Test 1: Init PSK ===");

    /* Set up PSK identity */
    memset(&psk_identity, 0, sizeof(psk_identity));
    memcpy(psk_identity.identity, test_identity, TEST_IDENTITY_LEN);
    psk_identity.identity_len = TEST_IDENTITY_LEN;

    /* Initialize context */
    ret = tls_handshake_init(&ctx, test_psk, &psk_identity);
    TEST_ASSERT(ret, "tls_handshake_init should succeed");

    /* Verify PSK was stored */
    TEST_ASSERT_MEM_EQUAL(test_psk, ctx.psk, TEST_PSK_LEN, "PSK should be stored correctly");

    /* Verify identity was stored */
    TEST_ASSERT_MEM_EQUAL(test_identity, ctx.psk_identity.identity, TEST_IDENTITY_LEN,
                          "PSK identity should be stored correctly");

    /* Verify initial state */
    TEST_ASSERT_EQUAL(TLS_STATE_INIT, ctx.state, "Context should be in INIT state");

    if (tests_failed > initial_failed)
    {
        failed_tests_len += snprintf(failed_tests + failed_tests_len,
                                     sizeof(failed_tests) - failed_tests_len,
                                     "Test 1 ");
    }
}

/**
 * Test 2: Process ServerHello packet
 */
static void test_process_serverhello(struct tls_handshake_context *ctx,
                                     uint8_t *client_hello_buf,
                                     size_t *client_hello_len)
{
    bool ret;
    int initial_failed = tests_failed;

    output_y = 30;
    print_line("=== Test 2: ServerHello ===");

    /* Generate ClientHello to set state to CLIENT_HELLO_SENT */
    ret = tls_generate_client_hello(ctx, client_hello_buf, 512, client_hello_len);
    TEST_ASSERT(ret, "ClientHello generation should succeed");

    /* Process ServerHello (skip TLS record header, process handshake message) */
    const uint8_t *handshake_msg = serverhello_packet + 5; /* Skip record header */
    size_t handshake_len = sizeof(serverhello_packet) - 5;

    ret = tls_process_server_hello(ctx, handshake_msg, handshake_len);
    TEST_ASSERT(ret, "ServerHello processing should succeed");

    /* Verify cipher suite was extracted */
    TEST_ASSERT_EQUAL(TLS_AES_128_GCM_SHA256, ctx->cipher_suite, "Cipher suite should be TLS_AES_128_GCM_SHA256");

    /* Verify server random was stored */
    const uint8_t *expected_random = serverhello_packet + 11; /* Offset to random in packet */
    TEST_ASSERT_MEM_EQUAL(expected_random, ctx->server_random, 32,
                          "Server random should be extracted");

    if (tests_failed > initial_failed)
    {
        failed_tests_len += snprintf(failed_tests + failed_tests_len,
                                     sizeof(failed_tests) - failed_tests_len,
                                     "Test 2 ");
    }
}

/**
 * Test 3: Derive handshake keys
 */
static void test_derive_handshake_keys(struct tls_handshake_context *ctx)
{
    bool ret;
    int initial_failed = tests_failed;

    output_y = 30;
    print_line("=== Test 3: Derive Keys ===");

    /* Derive handshake keys */
    ret = tls_derive_handshake_keys(ctx);
    TEST_ASSERT(ret, "Handshake key derivation should succeed");

    /* Verify keys were generated (non-zero check) */
    int all_zero = 1;
    for (int i = 0; i < 16; i++)
    {
        if (ctx->keys.server_handshake_key[i] != 0)
        {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(!all_zero, "Server handshake key should be non-zero");

    all_zero = 1;
    for (int i = 0; i < 16; i++)
    {
        if (ctx->keys.client_handshake_key[i] != 0)
        {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(!all_zero, "Client handshake key should be non-zero");

    if (tests_failed > initial_failed)
    {
        failed_tests_len += snprintf(failed_tests + failed_tests_len,
                                     sizeof(failed_tests) - failed_tests_len,
                                     "Test 3 ");
    }
}

/**
 * Test 4: Generate Finished message
 */
static void test_generate_finished(struct tls_handshake_context *ctx)
{
    uint8_t finished_msg[64];
    size_t finished_len;
    bool ret;
    int initial_failed = tests_failed;

    output_y = 30;
    print_line("=== Test 4: Finished ===");

    /* Generate Finished message */
    ret = tls_generate_finished(ctx, true, finished_msg, sizeof(finished_msg), &finished_len);
    TEST_ASSERT(ret, "Finished generation should succeed");

    /* Verify length (should be 36 bytes: 4-byte header + 32-byte verify_data) */
    TEST_ASSERT_EQUAL(36, finished_len, "Finished message should be 36 bytes");

    if (tests_failed > initial_failed)
    {
        failed_tests_len += snprintf(failed_tests + failed_tests_len,
                                     sizeof(failed_tests) - failed_tests_len,
                                     "Test 4 ");
    }
}

/**
 * Main test runner
 */
int main(void)
{
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    uint8_t client_hello_buf[512];
    size_t client_hello_len;

    /* Set up lwIP memory allocators */
    caller_malloc_ref = malloc;
    caller_free_ref = free;

    os_ClrHome();

    /* Test 1: Initialize PSK context */
    test_init_psk_context();
#ifndef TLS_HANDSHAKE_DEBUG
    os_GetKey();
#endif
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Initialize context for remaining tests */
    memset(&psk_identity, 0, sizeof(psk_identity));
    memcpy(psk_identity.identity, test_identity, TEST_IDENTITY_LEN);
    psk_identity.identity_len = TEST_IDENTITY_LEN;
    tls_handshake_init(&ctx, test_psk, &psk_identity);

    /* Test 2: Process ServerHello */
    test_process_serverhello(&ctx, client_hello_buf, &client_hello_len);
#ifndef TLS_HANDSHAKE_DEBUG
    os_GetKey();
#endif
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Test 3: Derive handshake keys */
    test_derive_handshake_keys(&ctx);
#ifndef TLS_HANDSHAKE_DEBUG
    os_GetKey();
#endif
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Test 4: Generate Finished message */
    test_generate_finished(&ctx);
#ifndef TLS_HANDSHAKE_DEBUG
    os_GetKey();
#endif
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Print final result */
    output_y = 30;
    if (tests_failed == 0)
    {
        os_FontDrawText("all tests PASSED", 0, 30);
    }
    else
    {
        sprintf(output_buf, "FAILED: %s", failed_tests);
        os_FontDrawText(output_buf, 0, 30);
    }

    os_GetKey();

    /* Return 0 for success, 1 for failure */
    return (tests_failed == 0) ? 0 : 1;
}
