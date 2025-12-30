#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "x25519.h"

/* Benchmark: Single x25519 ECDH key exchange */
int main(void) {
    os_ClrHome();

    /* Alice's private key (random) */
    x25519_scalar alice_private = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    /* Bob's private key (random) */
    x25519_scalar bob_private = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
    };

    /* Generate Bob's public key: Bob_pub = bob_private * basepoint */
    x25519_point bob_public;
    if(!x25519_public_key(bob_public, bob_private)) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    /* Alice computes shared secret: shared = alice_private * Bob_pub */
    uint8_t shared_secret[32];
    if(!x25519(shared_secret, alice_private, bob_public)) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    /* Verify shared secret is not all zeros (sanity check) */
    bool is_zero = true;
    for(int i = 0; i < 32; i++) {
        if(shared_secret[i] != 0) {
            is_zero = false;
            break;
        }
    }

    if(is_zero) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    /* Also verify Bob's public key is not all zeros */
    is_zero = true;
    for(int i = 0; i < 32; i++) {
        if(bob_public[i] != 0) {
            is_zero = false;
            break;
        }
    }

    if(is_zero) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    printf("success");
    os_GetKey();
    return 0;
}
