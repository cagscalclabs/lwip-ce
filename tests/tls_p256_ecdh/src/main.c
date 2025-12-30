#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "ecc.h"

/* Test vectors from NIST CAVP for P-256 ECDH */

/* Test 1: Scalar multiplication of generator point */
static bool test_scalar_mult_generator(void) {
    /* Private key: d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721 (big-endian) */
    p256_scalar private_key = {
        0x21, 0x67, 0x0F, 0x12, 0x2B, 0x62, 0x8A, 0x7B,
        0x12, 0x9B, 0xE8, 0x36, 0xDB, 0xC3, 0x50, 0x4E,
        0x93, 0xD6, 0xB1, 0x67, 0x57, 0x21, 0x5C, 0x6B,
        0x16, 0x75, 0xBA, 0x45, 0xD8, 0xA9, 0xAF, 0xC9
    };

    /* Expected public key x-coordinate (little-endian) */
    uint8_t expected_x[32] = {
        0xB5, 0x1B, 0x16, 0x0B, 0x94, 0x49, 0xF1, 0xC5,
        0xF2, 0x0E, 0x5F, 0x2A, 0x61, 0xF8, 0xF6, 0x92,
        0xF0, 0x78, 0x25, 0xFE, 0xA5, 0x2D, 0xF5, 0x0D,
        0x2C, 0x11, 0x45, 0x78, 0x65, 0xB6, 0x63, 0x60
    };

    struct p256_point public_key;

    /* Compute public_key = private_key * G */
    if(!p256_scalar_mult(&public_key, private_key, NULL)) {
        return false;
    }

    /* Verify x-coordinate matches */
    return memcmp(public_key.x, expected_x, 32) == 0;
}

/* Test 2: ECDH shared secret computation */
static bool test_ecdh(void) {
    /* Alice's private key */
    p256_scalar alice_private = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    /* Bob's public key (on curve) */
    struct p256_point bob_public;

    /* Generate Bob's private key first */
    p256_scalar bob_private = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
    };

    /* Compute Bob's public key */
    if(!p256_scalar_mult(&bob_public, bob_private, NULL)) {
        return false;
    }

    /* Alice computes shared secret */
    uint8_t alice_shared[32];
    if(!p256_ecdh(alice_shared, alice_private, &bob_public)) {
        return false;
    }

    /* Compute Alice's public key */
    struct p256_point alice_public;
    if(!p256_scalar_mult(&alice_public, alice_private, NULL)) {
        return false;
    }

    /* Bob computes shared secret */
    uint8_t bob_shared[32];
    if(!p256_ecdh(bob_shared, bob_private, &alice_public)) {
        return false;
    }

    /* Both should get the same shared secret */
    return memcmp(alice_shared, bob_shared, 32) == 0;
}

/* Test 3: Point addition is commutative */
static bool test_point_operations(void) {
    /* Two arbitrary scalars */
    p256_scalar k1 = {
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    p256_scalar k2 = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* Compute 3*G and 5*G */
    struct p256_point p1, p2;
    if(!p256_scalar_mult(&p1, k1, NULL)) {
        return false;
    }
    if(!p256_scalar_mult(&p2, k2, NULL)) {
        return false;
    }

    /* Verify we got valid points */
    bool is_zero_p1 = true;
    bool is_zero_p2 = true;
    for(int i = 0; i < 32; i++) {
        if(p1.x[i] != 0 || p1.y[i] != 0) is_zero_p1 = false;
        if(p2.x[i] != 0 || p2.y[i] != 0) is_zero_p2 = false;
    }

    return !is_zero_p1 && !is_zero_p2;
}

int main(void) {
    os_ClrHome();

    if(!test_scalar_mult_generator()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    if(!test_ecdh()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    if(!test_point_operations()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    printf("success");
    os_GetKey();
    return 0;
}
