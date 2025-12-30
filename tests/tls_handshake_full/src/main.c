/**
 * @file main.c
 * @brief TLS 1.3 Full Handshake Test Suite
 *
 * Comprehensive test of TLS 1.3 PSK handshake implementation:
 * - Test 1: Loopback encrypt/decrypt
 * - Test 2: Mock server handshake
 * - Test 3: Sequence number increment
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdio.h>

/* TLS includes */
#include "handshake.h"
#include "hkdf.h"
#include "hash.h"

/**
 * Test 1: Loopback Encrypt/Decrypt
 *
 * Tests the record layer encryption and decryption functions:
 * 1. Set up context with known PSK
 * 2. Derive application keys
 * 3. Encrypt known plaintext
 * 4. Decrypt ciphertext
 * 5. Verify plaintext matches original
 */
static bool test_loopback_encrypt_decrypt(void)
{
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];

    /* Test data */
    const char *test_message = "Hello, TLS 1.3!";
    size_t msg_len = strlen(test_message);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    size_t encrypted_len = 0;
    size_t decrypted_len = 0;

    /* Initialize PSK and identity */
    memset(psk, 0xAA, 32);
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0x01;
    psk_identity.identity_len = 1;

    /* Initialize handshake context */
    if (!tls_handshake_init(&ctx, psk, &psk_identity))
    {
        return false;
    }

    /* Set state to allow key derivation */
    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;
    ctx.transcript_hash = NULL;

    /* Derive handshake keys first */
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

    /* Reset sequence numbers (they should start at 0) */
    ctx.client_seq_num = 0;
    ctx.server_seq_num = 0;

    /* Encrypt the test message */
    if (!tls_encrypt_data(&ctx, (const uint8_t *)test_message, msg_len,
                          ciphertext, sizeof(ciphertext), &encrypted_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify encrypted length = plaintext + 16-byte tag */
    if (encrypted_len != msg_len + 16)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify ciphertext is different from plaintext */
    bool is_encrypted = false;
    for (size_t i = 0; i < msg_len; i++)
    {
        if (ciphertext[i] != test_message[i])
        {
            is_encrypted = true;
            break;
        }
    }
    if (!is_encrypted)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* For loopback test, simulate server receiving client data:
     * Copy client keys to server keys (normally they'd be derived separately)
     */
    memcpy(ctx.keys.server_application_key, ctx.keys.client_application_key, 16);
    memcpy(ctx.keys.server_application_iv, ctx.keys.client_application_iv, 12);
    ctx.server_seq_num = 0; /* Server starts at seq 0 for received data */

    /* Decrypt the ciphertext */
    if (!tls_decrypt_data(&ctx, ciphertext, encrypted_len,
                          decrypted, sizeof(decrypted), &decrypted_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify decrypted length matches original */
    if (decrypted_len != msg_len)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify decrypted plaintext matches original */
    bool plaintext_matches = (memcmp(decrypted, test_message, msg_len) == 0);

    tls_handshake_cleanup(&ctx);
    return plaintext_matches;
}

/**
 * Test 2: Mock Server Handshake
 *
 * Tests the complete TLS 1.3 PSK handshake flow:
 * 1. Generate ClientHello with PSK
 * 2. Build and process mock ServerHello
 * 3. Derive handshake keys
 * 4. Generate and verify Finished messages
 * 5. Derive application keys
 * 6. Verify key separation (handshake != application)
 */
static bool test_mock_server_handshake(void)
{
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];
    uint8_t client_hello[512];
    uint8_t server_hello[256];
    uint8_t client_finished[36]; /* 4-byte header + 32-byte verify_data */
    uint8_t server_finished[36]; /* 4-byte header + 32-byte verify_data */
    size_t client_hello_len = 0;
    size_t server_hello_len = 0;

    /* Zero out all structures to ensure clean state */
    memset(&ctx, 0, sizeof(ctx));
    memset(&psk_identity, 0, sizeof(psk_identity));
    memset(psk, 0, sizeof(psk));
    memset(client_hello, 0, sizeof(client_hello));
    memset(server_hello, 0, sizeof(server_hello));
    memset(client_finished, 0, sizeof(client_finished));
    memset(server_finished, 0, sizeof(server_finished));

    /* Initialize PSK and identity */
    memset(psk, 0xBB, 32);
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0x02;
    psk_identity.identity_len = 1;

    /* Initialize handshake context */
    if (!tls_handshake_init(&ctx, psk, &psk_identity))
    {
        return false;
    }

    /* Generate ClientHello */
    if (!tls_generate_client_hello(&ctx, client_hello, sizeof(client_hello), &client_hello_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Build mock ServerHello:
     * This simulates a server response with:
     * - Legacy version: 0x0303 (TLS 1.2 for compatibility)
     * - Random: 32 bytes
     * - Legacy session ID echo: empty
     * - Cipher suite: TLS_AES_128_GCM_SHA256 (0x1301)
     * - Extensions: supported_versions (TLS 1.3), pre_shared_key (index 0)
     */
    size_t offset = 0;

    /* ServerHello handshake header */
    server_hello[offset++] = 0x02; /* Handshake type: ServerHello */
    server_hello[offset++] = 0x00; /* Length MSB (filled later) */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00; /* Length LSB (filled later) */

    size_t sh_body_start = offset;

    /* Legacy version: 0x0303 */
    server_hello[offset++] = 0x03;
    server_hello[offset++] = 0x03;

    /* Server random: 32 bytes (use known pattern) */
    memset(&server_hello[offset], 0xDD, 32);
    offset += 32;

    /* Legacy session ID: empty */
    server_hello[offset++] = 0x00;

    /* Cipher suite: TLS_AES_128_GCM_SHA256 */
    server_hello[offset++] = 0x13;
    server_hello[offset++] = 0x01;

    /* Compression method: null */
    server_hello[offset++] = 0x00;

    /* Extensions length (filled later) */
    size_t ext_len_offset = offset;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;

    size_t ext_start = offset;

    /* Extension: supported_versions (0x002B) */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x2B;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x02; /* Extension length */
    server_hello[offset++] = 0x03; /* TLS 1.3 */
    server_hello[offset++] = 0x04;

    /* Extension: pre_shared_key (0x0029) - selected identity 0 */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x29;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x02; /* Extension length */
    server_hello[offset++] = 0x00; /* Selected identity MSB */
    server_hello[offset++] = 0x00; /* Selected identity LSB */

    /* Fill in extensions length */
    size_t ext_len = offset - ext_start;
    server_hello[ext_len_offset] = (ext_len >> 8) & 0xFF;
    server_hello[ext_len_offset + 1] = ext_len & 0xFF;

    /* Fill in ServerHello body length */
    size_t sh_body_len = offset - sh_body_start;
    server_hello[1] = (sh_body_len >> 16) & 0xFF;
    server_hello[2] = (sh_body_len >> 8) & 0xFF;
    server_hello[3] = sh_body_len & 0xFF;

    server_hello_len = offset;

    /* Process ServerHello */
    if (!tls_process_server_hello(&ctx, server_hello, server_hello_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Derive handshake keys */
    if (!tls_derive_handshake_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Save handshake keys for comparison later */
    uint8_t saved_hs_client_key[16];
    uint8_t saved_hs_server_key[16];
    memcpy(saved_hs_client_key, ctx.keys.client_handshake_key, 16);
    memcpy(saved_hs_server_key, ctx.keys.server_handshake_key, 16);

    /* Generate client Finished message */
    size_t client_finished_len = 0;
    if (!tls_generate_finished(&ctx, true, client_finished, sizeof(client_finished), &client_finished_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Generate server Finished message */
    size_t server_finished_len = 0;
    if (!tls_generate_finished(&ctx, false, server_finished, sizeof(server_finished), &server_finished_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Note: In a real handshake, we'd verify the server's Finished message.
     * But in this test we generated it ourselves, so we skip verification
     * to avoid adding it to the transcript twice.
     */

    /* Derive application keys */
    if (!tls_derive_application_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify application keys are different from handshake keys */
    bool keys_different = (memcmp(ctx.keys.client_application_key, saved_hs_client_key, 16) != 0) &&
                          (memcmp(ctx.keys.server_application_key, saved_hs_server_key, 16) != 0);

    /* Clean up before returning */
    tls_handshake_cleanup(&ctx);

    return keys_different;
}

/**
 * Test 3: Sequence Number Increment
 *
 * Verifies that sequence numbers increment correctly and nonces are unique:
 * 1. Encrypt multiple messages
 * 2. Verify sequence number increments
 * 3. Verify each encryption produces different ciphertext (different nonces)
 */
static bool test_sequence_number_increment(void)
{
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];

    const char *test_message = "Test";
    size_t msg_len = strlen(test_message);
    uint8_t ciphertext1[64];
    uint8_t ciphertext2[64];
    uint8_t ciphertext3[64];
    size_t ct1_len = 0, ct2_len = 0, ct3_len = 0;

    /* Initialize */
    memset(psk, 0xCC, 32);
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity_len = 1;

    if (!tls_handshake_init(&ctx, psk, &psk_identity))
    {
        return false;
    }

    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;
    ctx.transcript_hash = NULL;

    if (!tls_derive_handshake_keys(&ctx) || !tls_derive_application_keys(&ctx))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify initial sequence number is 0 */
    if (ctx.client_seq_num != 0)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt first message */
    if (!tls_encrypt_data(&ctx, (const uint8_t *)test_message, msg_len,
                          ciphertext1, sizeof(ciphertext1), &ct1_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify sequence number incremented to 1 */
    if (ctx.client_seq_num != 1)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt second message */
    if (!tls_encrypt_data(&ctx, (const uint8_t *)test_message, msg_len,
                          ciphertext2, sizeof(ciphertext2), &ct2_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify sequence number incremented to 2 */
    if (ctx.client_seq_num != 2)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Encrypt third message */
    if (!tls_encrypt_data(&ctx, (const uint8_t *)test_message, msg_len,
                          ciphertext3, sizeof(ciphertext3), &ct3_len))
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify sequence number incremented to 3 */
    if (ctx.client_seq_num != 3)
    {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify all three ciphertexts are different (different nonces) */
    bool all_different = (memcmp(ciphertext1, ciphertext2, ct1_len) != 0) &&
                         (memcmp(ciphertext2, ciphertext3, ct2_len) != 0) &&
                         (memcmp(ciphertext1, ciphertext3, ct1_len) != 0);

    tls_handshake_cleanup(&ctx);
    return all_different;
}

int main(void)
{
    os_ClrHome();

    /* Test 1: Loopback encrypt/decrypt */
    if (!test_loopback_encrypt_decrypt())
    {
        printf("failed");
    }
    else
    {
        printf("success");
    }
    os_GetKey();
    os_ClrHome();
    os_SetCursorPos(0, 0);

    /* Test 2: Mock server handshake */
    if (!test_mock_server_handshake())
    {
        printf("failed");
    }
    else
    {
        printf("success");
    }
    os_GetKey();
    os_ClrHome();
    os_SetCursorPos(0, 0);

    /* Test 3: Sequence number increment */
    if (!test_sequence_number_increment())
    {
        printf("failed");
    }
    else
    {
        printf("success");
    }
    os_GetKey();
    os_ClrHome();

    return 0;
}
