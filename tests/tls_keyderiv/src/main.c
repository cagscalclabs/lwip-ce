/**
 * @file main.c
 * @brief TLS 1.3 Key Derivation Test Suite
 * TODO: Implement test functions
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/getkey.h>

/* TLS includes */
#include "handshake.h"
#include "hkdf.h"
#include "hash.h"

/* TODO: Implement these test functions */
static bool test_derive_secret(void) {
    return false; /* Not yet implemented */
}

static bool test_derive_handshake_keys(void) {
    return false; /* Not yet implemented */
}

static bool test_derive_application_keys(void) {
    return false; /* Not yet implemented */
}

static bool test_generate_client_hello(void) {
    return false; /* Not yet implemented */
}

int main(void) {
    os_ClrHome();

    /* Run all tests */
    bool test1 = test_derive_secret();
    bool test2 = test_derive_handshake_keys();
    bool test3 = test_derive_application_keys();
    bool test4 = test_generate_client_hello();

    /* Output result */
    if (test1 && test2 && test3 && test4) {
        printf("success");
    } else {
        printf("failed");
    }

    os_GetKey();
    return 0;
}
