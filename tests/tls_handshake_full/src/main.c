/**
 * @file main.c
 * @brief TLS 1.3 Full Handshake Test Suite (PSK Mode)
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdio.h>

#include "handshake.h"
#include "hkdf.h"
#include "hash.h"
#include "lwip/mem.h"

/* lwIP memory allocator function pointers */
extern void *(*caller_malloc_ref)(size_t);
extern void (*caller_free_ref)(void *);

/**
 * Test 1: Loopback encrypt/decrypt
 * Tests that encrypted data can be decrypted successfully
 */
static bool test_loopback_encrypt_decrypt(void)
{
    struct tls_handshake_context ctx;

    /* Test PSK and identity */
    uint8_t psk[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    struct tls_psk_identity identity = {
        .identity = {'t', 'e', 's', 't', '_', 'p', 's', 'k'},
        .identity_len = 8,
        .obfuscated_ticket_age = 0};

    /* Initialize handshake context */
    if (!tls_handshake_init(&ctx, psk, &identity))
    {
        return false;
    }

    /* Set state to allow key derivation (simulating ServerHello received) */
    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;

    /* Derive handshake keys */
    if (!tls_derive_handshake_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Derive application keys */
    if (!tls_derive_application_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Test data */
    const char *plaintext = "Hello, TLS 1.3!";
    size_t plaintext_len = strlen(plaintext);

    /* Encrypt */
    uint8_t ciphertext[256];
    size_t ciphertext_len = 0;
    if (!tls_encrypt_data(&ctx, (const uint8_t *)plaintext, plaintext_len,
                          ciphertext, sizeof(ciphertext), &ciphertext_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* For loopback test, copy client keys to server side and reset sequence */
    memcpy(ctx.keys.server_application_key, ctx.keys.client_application_key, 16);
    memcpy(ctx.keys.server_application_iv, ctx.keys.client_application_iv, 12);
    ctx.client_seq_num = 0;
    ctx.server_seq_num = 0;

    /* Decrypt */
    uint8_t decrypted[256];
    size_t decrypted_len = 0;
    if (!tls_decrypt_data(&ctx, ciphertext, ciphertext_len,
                          decrypted, sizeof(decrypted), &decrypted_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify */
    bool success = (decrypted_len == plaintext_len) &&
                   (memcmp(decrypted, plaintext, plaintext_len) == 0);

    tls_handshake_cleanup(&ctx);
    return success;
}

/**
 * Test 2: Mock server handshake
 * Tests full key derivation flow for PSK mode
 */
static bool test_mock_server_handshake(void)
{
    struct tls_handshake_context ctx;

    /* Test PSK (simulating resumed session) */
    uint8_t psk[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
        0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f};

    struct tls_psk_identity identity = {
        .identity = {'s', 'e', 's', 's', 'i', 'o', 'n', '_', 't', 'k', 't'},
        .identity_len = 11,
        .obfuscated_ticket_age = 12345};

    /* Initialize */
    if (!tls_handshake_init(&ctx, psk, &identity))
    {
        return false;
    }

    /* Generate ClientHello */
    uint8_t client_hello[512];
    size_t client_hello_len = 0;
    if (!tls_generate_client_hello(&ctx, client_hello, sizeof(client_hello),
                                   &client_hello_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify ClientHello was generated */
    if (client_hello_len == 0)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Set state for key derivation (simulating ServerHello received) */
    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;

    /* Derive keys (simulating what happens after ServerHello) */
    if (!tls_derive_handshake_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    if (!tls_derive_application_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* If we got here, key derivation succeeded */
    tls_handshake_cleanup(&ctx);
    return true;
}

/**
 * Test 3: Sequence number increment
 * Verifies sequence numbers increment correctly during encryption
 */
static bool test_sequence_number_increment(void)
{
    struct tls_handshake_context ctx;

    uint8_t psk[32] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

    struct tls_psk_identity identity = {
        .identity = {'s', 'e', 'q', '_', 't', 'e', 's', 't'},
        .identity_len = 8,
        .obfuscated_ticket_age = 0};

    /* Initialize and derive keys */
    if (!tls_handshake_init(&ctx, psk, &identity))
    {
        return false;
    }

    /* Set state for key derivation */
    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;

    if (!tls_derive_handshake_keys(&ctx) || !tls_derive_application_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Initial sequence number should be 0 */
    if (ctx.client_seq_num != 0)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt first message */
    const char *msg1 = "First";
    uint8_t ct1[64];
    size_t ct1_len;
    if (!tls_encrypt_data(&ctx, (const uint8_t *)msg1, strlen(msg1),
                          ct1, sizeof(ct1), &ct1_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Sequence number should be 1 */
    if (ctx.client_seq_num != 1)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt second message */
    const char *msg2 = "Second";
    uint8_t ct2[64];
    size_t ct2_len;
    if (!tls_encrypt_data(&ctx, (const uint8_t *)msg2, strlen(msg2),
                          ct2, sizeof(ct2), &ct2_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Sequence number should be 2 */
    if (ctx.client_seq_num != 2)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt third message */
    const char *msg3 = "Third";
    uint8_t ct3[64];
    size_t ct3_len;
    if (!tls_encrypt_data(&ctx, (const uint8_t *)msg3, strlen(msg3),
                          ct3, sizeof(ct3), &ct3_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Sequence number should be 3 */
    bool success = (ctx.client_seq_num == 3);

    tls_handshake_cleanup(&ctx);
    return success;
}

int main(void)
{
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Set up memory allocator for lwIP's custom malloc */
    caller_malloc_ref = malloc;
    caller_free_ref = free;
    mem_init();

    /* Test 1: Loopback encrypt/decrypt */
    bool test1 = test_loopback_encrypt_decrypt();
    if (test1)
    {
        printf("success");
    }
    else
    {
        printf("fail");
    }
    os_GetKey();
    os_ClrHome();

    /* Test 2: Mock server handshake */
    bool test2 = test_mock_server_handshake();
    if (test2)
    {
        printf("success");
    }
    else
    {
        printf("fail");
    }
    os_GetKey();
    os_ClrHome();

    /* Test 3: Sequence number increment */
    bool test3 = test_sequence_number_increment();
    if (test3)
    {
        printf("success");
    }
    else
    {
        printf("fail");
    }
    os_GetKey();

    return (test1 && test2 && test3) ? 0 : 1;
}
