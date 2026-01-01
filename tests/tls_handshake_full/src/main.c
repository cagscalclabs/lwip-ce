/**
 * @file main.c
 * @brief TLS 1.3 Full Handshake Test Suite
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdio.h>

#include "handshake.h"
#include "hkdf.h"
#include "hash.h"

/* TODO: Implement test functions */

static bool test_loopback_encrypt_decrypt(void) {
    return false; /* Not yet implemented */
}

static bool test_sequence_number_increment(void) {
    return false; /* Not yet implemented */
}

int main(void) {
    os_ClrHome();

    bool test1 = test_loopback_encrypt_decrypt();
    bool test2 = test_sequence_number_increment();

    if (test1 && test2) {
        printf("success");
    } else {
        printf("failed");
    }

    os_GetKey();
    return 0;
}
