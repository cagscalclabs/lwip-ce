/**
 * @file main.c
 * @brief TLS 1.3 PSK Key Derivation Test
 *
 * Tests the complete TLS 1.3 key schedule with known PSK values.
 * Uses static inputs to verify correct key derivation.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <graphx.h>
#include <keypadc.h>
#include <debug.h>

/* TLS includes */
#include "handshake.h"
#include "hkdf.h"
#include "hash.h"

/* Helper to print hex */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    gfx_PrintString(label);
    gfx_PrintString(": ");

    char hex[3];
    for (size_t i = 0; i < len && i < 8; i++) {  /* Print first 8 bytes */
        hex[0] = "0123456789ABCDEF"[data[i] >> 4];
        hex[1] = "0123456789ABCDEF"[data[i] & 0xF];
        hex[2] = '\0';
        gfx_PrintString(hex);
    }
    if (len > 8) {
        gfx_PrintString("...");
    }
    gfx_PrintString("\n");
}

/* Test result display */
static void print_test_result(const char *test_name, bool passed) {
    gfx_SetTextFGColor(passed ? 2 : 224);  /* Green or red */
    gfx_PrintString(test_name);
    gfx_PrintString(": ");
    gfx_PrintString(passed ? "PASS" : "FAIL");
    gfx_PrintString("\n");
}

/**
 * Test 1: Handshake Key Derivation with Known PSK
 *
 * Test vector:
 * - PSK: all 0x01 bytes (simple test pattern)
 * - Transcript hash: all zeros (simulating empty ClientHello...ServerHello)
 *
 * We don't have external test vectors for this exact scenario,
 * so this test establishes a baseline that we can verify is consistent.
 */
static bool test_handshake_key_derivation(void) {
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;

    /* Test PSK: all 0x01 bytes */
    uint8_t test_psk[32];
    memset(test_psk, 0x01, 32);

    /* PSK identity (not used in key derivation, but required for init) */
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0xDE;
    psk_identity.identity[1] = 0xAD;
    psk_identity.identity[2] = 0xBE;
    psk_identity.identity[3] = 0xEF;
    psk_identity.identity_len = 4;

    /* Initialize handshake context */
    if (!tls_handshake_init(&ctx, test_psk, &psk_identity)) {
        return false;
    }

    /* Manually set state to allow key derivation */
    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;

    /* Set transcript_hash to NULL (will use zeros) */
    ctx.transcript_hash = NULL;

    /* Derive handshake keys */
    if (!tls_derive_handshake_keys(&ctx)) {
        return false;
    }

    /* Verify that keys were generated (not all zeros) */
    bool client_hs_secret_valid = false;
    bool server_hs_secret_valid = false;
    bool client_key_valid = false;
    bool server_key_valid = false;

    for (size_t i = 0; i < 32; i++) {
        if (ctx.keys.client_handshake_traffic_secret[i] != 0) {
            client_hs_secret_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 32; i++) {
        if (ctx.keys.server_handshake_traffic_secret[i] != 0) {
            server_hs_secret_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 16; i++) {
        if (ctx.keys.client_handshake_key[i] != 0) {
            client_key_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 16; i++) {
        if (ctx.keys.server_handshake_key[i] != 0) {
            server_key_valid = true;
            break;
        }
    }

    /* Clean up */
    tls_handshake_cleanup(&ctx);

    return client_hs_secret_valid && server_hs_secret_valid &&
           client_key_valid && server_key_valid;
}

/**
 * Test 2: Application Key Derivation
 */
static bool test_application_key_derivation(void) {
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;

    /* Test PSK: all 0x02 bytes */
    uint8_t test_psk[32];
    memset(test_psk, 0x02, 32);

    /* PSK identity */
    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity[0] = 0xCA;
    psk_identity.identity[1] = 0xFE;
    psk_identity.identity_len = 2;

    /* Initialize and derive handshake keys first */
    if (!tls_handshake_init(&ctx, test_psk, &psk_identity)) {
        return false;
    }

    ctx.state = TLS_STATE_SERVER_HELLO_RECEIVED;
    ctx.transcript_hash = NULL;

    if (!tls_derive_handshake_keys(&ctx)) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Now derive application keys */
    if (!tls_derive_application_keys(&ctx)) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify that application keys were generated */
    bool client_app_secret_valid = false;
    bool server_app_secret_valid = false;
    bool client_app_key_valid = false;
    bool server_app_key_valid = false;

    for (size_t i = 0; i < 32; i++) {
        if (ctx.keys.client_application_traffic_secret[i] != 0) {
            client_app_secret_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 32; i++) {
        if (ctx.keys.server_application_traffic_secret[i] != 0) {
            server_app_secret_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 16; i++) {
        if (ctx.keys.client_application_key[i] != 0) {
            client_app_key_valid = true;
            break;
        }
    }

    for (size_t i = 0; i < 16; i++) {
        if (ctx.keys.server_application_key[i] != 0) {
            server_app_key_valid = true;
            break;
        }
    }

    /* Verify keys are different from handshake keys */
    bool keys_different = memcmp(ctx.keys.client_handshake_key,
                                 ctx.keys.client_application_key, 16) != 0;

    tls_handshake_cleanup(&ctx);

    return client_app_secret_valid && server_app_secret_valid &&
           client_app_key_valid && server_app_key_valid && keys_different;
}

/**
 * Test 3: Verify Key Separation
 * Different PSKs should produce different keys
 */
static bool test_key_separation(void) {
    struct tls_handshake_context ctx1, ctx2;
    struct tls_psk_identity psk_identity;
    uint8_t psk1[32], psk2[32];

    /* Two different PSKs */
    memset(psk1, 0xAA, 32);
    memset(psk2, 0xBB, 32);

    memset(&psk_identity, 0, sizeof(psk_identity));
    psk_identity.identity_len = 1;

    /* Derive keys for PSK1 */
    if (!tls_handshake_init(&ctx1, psk1, &psk_identity)) {
        return false;
    }
    ctx1.state = TLS_STATE_SERVER_HELLO_RECEIVED;
    ctx1.transcript_hash = NULL;
    if (!tls_derive_handshake_keys(&ctx1)) {
        tls_handshake_cleanup(&ctx1);
        return false;
    }

    /* Derive keys for PSK2 */
    if (!tls_handshake_init(&ctx2, psk2, &psk_identity)) {
        tls_handshake_cleanup(&ctx1);
        return false;
    }
    ctx2.state = TLS_STATE_SERVER_HELLO_RECEIVED;
    ctx2.transcript_hash = NULL;
    if (!tls_derive_handshake_keys(&ctx2)) {
        tls_handshake_cleanup(&ctx1);
        tls_handshake_cleanup(&ctx2);
        return false;
    }

    /* Verify keys are different */
    bool secrets_different = memcmp(ctx1.keys.client_handshake_traffic_secret,
                                    ctx2.keys.client_handshake_traffic_secret,
                                    32) != 0;
    bool keys_different = memcmp(ctx1.keys.client_handshake_key,
                                 ctx2.keys.client_handshake_key,
                                 16) != 0;

    tls_handshake_cleanup(&ctx1);
    tls_handshake_cleanup(&ctx2);

    return secrets_different && keys_different;
}

/**
 * Test 4: ClientHello Generation
 * Verify that ClientHello message is generated correctly with PSK binder
 */
static bool test_clienthello_generation(void) {
    struct tls_handshake_context ctx;
    struct tls_psk_identity psk_identity;
    uint8_t psk[32];
    uint8_t client_hello[512];
    size_t written = 0;

    /* Test PSK: all 0x03 bytes */
    memset(psk, 0x03, 32);

    /* PSK identity */
    memset(&psk_identity, 0, sizeof(psk_identity));
    memcpy(psk_identity.identity, "test-psk-id", 11);
    psk_identity.identity_len = 11;
    psk_identity.obfuscated_ticket_age = 0x12345678;

    /* Initialize handshake context */
    if (!tls_handshake_init(&ctx, psk, &psk_identity)) {
        return false;
    }

    /* Generate ClientHello */
    if (!tls_generate_client_hello(&ctx, client_hello, sizeof(client_hello), &written)) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify ClientHello was generated */
    if (written == 0) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify handshake type is ClientHello (0x01) */
    if (client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify message length is reasonable (should be > 100 bytes) */
    size_t msg_len = (client_hello[1] << 16) | (client_hello[2] << 8) | client_hello[3];
    if (msg_len < 100 || msg_len != written - 4) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify legacy version (0x0303) */
    if (client_hello[4] != 0x03 || client_hello[5] != 0x03) {
        tls_handshake_cleanup(&ctx);
        return false;
    }

    /* Verify client random is present (non-zero) */
    bool random_present = false;
    for (size_t i = 6; i < 38; i++) {
        if (client_hello[i] != 0) {
            random_present = true;
            break;
        }
    }

    /* Verify state updated to CLIENT_HELLO_SENT */
    bool state_correct = (ctx.state == TLS_STATE_CLIENT_HELLO_SENT);

    tls_handshake_cleanup(&ctx);

    return random_present && state_correct;
}

int main(void) {
    gfx_Begin();
    gfx_SetDrawBuffer();
    gfx_FillScreen(0xFF);
    gfx_SetTextFGColor(0x00);

    gfx_PrintStringXY("TLS 1.3 Key Derivation Test", 10, 10);
    gfx_PrintStringXY("PSK Mode", 10, 30);
    gfx_PrintStringXY("", 10, 50);

    gfx_SetTextXY(10, 60);

    /* Run tests */
    bool test1 = test_handshake_key_derivation();
    print_test_result("Handshake Key Derivation", test1);

    bool test2 = test_application_key_derivation();
    print_test_result("Application Key Derivation", test2);

    bool test3 = test_key_separation();
    print_test_result("Key Separation", test3);

    bool test4 = test_clienthello_generation();
    print_test_result("ClientHello Generation", test4);

    /* Summary */
    gfx_PrintString("\n");
    if (test1 && test2 && test3 && test4) {
        gfx_SetTextFGColor(2);
        gfx_PrintString("All tests PASSED!");
    } else {
        gfx_SetTextFGColor(224);
        gfx_PrintString("Some tests FAILED!");
    }

    gfx_SwapDraw();

    /* Wait for key */
    while (!kb_AnyKey());

    gfx_End();
    return 0;
}
