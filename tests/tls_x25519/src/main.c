/*
 * X25519 ECDH Test - RFC 7748 Test Vectors
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tice.h>
#include <string.h>
#include <stdio.h>

#include "x25519.h"

/* Test helper */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    os_PutStrFull(label);
    for(size_t i = 0; i < len; i++) {
        char buf[4];
        sprintf(buf, "%02X", data[i]);
        os_PutStrFull(buf);
        if((i+1) % 16 == 0) os_NewLine();
    }
    os_NewLine();
}

static bool check_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    for(size_t i = 0; i < len; i++) {
        if(a[i] != b[i]) return false;
    }
    return true;
}

/* RFC 7748 Section 6.1 Test Vectors */
static const uint8_t alice_private[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t alice_public_expected[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};

static const uint8_t bob_private[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};

static const uint8_t bob_public_expected[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t shared_secret_expected[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
    0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
    0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

int main(void) {
    uint8_t alice_public[32];
    uint8_t bob_public[32];
    uint8_t shared_alice[32];
    uint8_t shared_bob[32];

    os_ClrHome();
    os_PutStrFull("X25519 Test (RFC 7748)\n");
    os_PutStrFull("=======================\n\n");

    /* Test 1: Alice generates public key */
    os_PutStrFull("Test 1: Alice public key\n");
    if(!x25519_public_key(alice_public, alice_private)) {
        os_PutStrFull("FAIL: x25519_public_key returned false\n");
        while(!os_GetCSC());
        return 1;
    }

    if(check_equal(alice_public, alice_public_expected, 32)) {
        os_PutStrFull("PASS\n\n");
    } else {
        os_PutStrFull("FAIL\n");
        print_hex("Expected: ", alice_public_expected, 32);
        print_hex("Got:      ", alice_public, 32);
        while(!os_GetCSC());
        return 1;
    }

    /* Test 2: Bob generates public key */
    os_PutStrFull("Test 2: Bob public key\n");
    if(!x25519_public_key(bob_public, bob_private)) {
        os_PutStrFull("FAIL: x25519_public_key returned false\n");
        while(!os_GetCSC());
        return 1;
    }

    if(check_equal(bob_public, bob_public_expected, 32)) {
        os_PutStrFull("PASS\n\n");
    } else {
        os_PutStrFull("FAIL\n");
        print_hex("Expected: ", bob_public_expected, 32);
        print_hex("Got:      ", bob_public, 32);
        while(!os_GetCSC());
        return 1;
    }

    /* Test 3: Alice computes shared secret */
    os_PutStrFull("Test 3: Shared secret (Alice)\n");
    if(!x25519(shared_alice, alice_private, bob_public)) {
        os_PutStrFull("FAIL: x25519 returned false\n");
        while(!os_GetCSC());
        return 1;
    }

    if(check_equal(shared_alice, shared_secret_expected, 32)) {
        os_PutStrFull("PASS\n\n");
    } else {
        os_PutStrFull("FAIL\n");
        print_hex("Expected: ", shared_secret_expected, 32);
        print_hex("Got:      ", shared_alice, 32);
        while(!os_GetCSC());
        return 1;
    }

    /* Test 4: Bob computes shared secret */
    os_PutStrFull("Test 4: Shared secret (Bob)\n");
    if(!x25519(shared_bob, bob_private, alice_public)) {
        os_PutStrFull("FAIL: x25519 returned false\n");
        while(!os_GetCSC());
        return 1;
    }

    if(check_equal(shared_bob, shared_secret_expected, 32)) {
        os_PutStrFull("PASS\n\n");
    } else {
        os_PutStrFull("FAIL\n");
        print_hex("Expected: ", shared_secret_expected, 32);
        print_hex("Got:      ", shared_bob, 32);
        while(!os_GetCSC());
        return 1;
    }

    /* Test 5: Both shared secrets match */
    os_PutStrFull("Test 5: Shared secrets match\n");
    if(check_equal(shared_alice, shared_bob, 32)) {
        os_PutStrFull("PASS\n\n");
    } else {
        os_PutStrFull("FAIL: Alice and Bob secrets differ\n");
        while(!os_GetCSC());
        return 1;
    }

    os_PutStrFull("=======================\n");
    os_PutStrFull("ALL TESTS PASSED!\n");
    os_PutStrFull("Press any key...\n");

    while(!os_GetCSC());
    return 0;
}
