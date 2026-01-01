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

/* Test 1 and 3 are from our working implementation */
/* Test 2 stub  - to be implemented later */

static bool test_loopback_encrypt_decrypt(void);
static bool test_sequence_number_increment(void);

int main(void) {
    os_ClrHome();

    /* Test 1: Loopback encrypt/decrypt */
    if (!test_loopback_encrypt_decrypt()) {
        printf("failed");
    } else {
        printf("success");
    }
    os_GetKey();
    os_ClrHome();

    /* Test 3: Sequence number increment */
    if (!test_sequence_number_increment()) {
        printf("failed");
    } else {
        printf("success");
    }
    os_GetKey();
    os_ClrHome();

    return 0;
}

/* Full test implementations would go here */
