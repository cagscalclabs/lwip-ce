#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hash.h"
#include "passwords.h"

/*
 * PBKDF2-HMAC-SHA256 Test Vectors
 * Source: RFC 6070 style vectors for SHA-256
 * (Generated using Python cryptography package, verified against RFC 6070 methodology)
 */

/* Test Case 1: password="password", salt="salt", c=1, dkLen=20 */
const char *password1 = "password";
const char *salt1 = "salt";
const uint8_t expected1[] = {
    0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c,0x43,0xe7,
    0x22,0x52,0x56,0xc4,0xf8,0x37,0xa8,0x65,0x48,0xc9
};

/* Test Case 2: password="password", salt="salt", c=2, dkLen=20 */
const char *password2 = "password";
const char *salt2 = "salt";
const uint8_t expected2[] = {
    0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3,0x2d,0x0a,
    0xdf,0xf9,0x28,0xf0,0x6d,0xd0,0x2a,0x30,0x3f,0x8e
};

/* Test Case 3: password="passwd", salt="salt", c=1, dkLen=32 (first 32 bytes of Test Case 7) */
const char *password3 = "passwd";
const char *salt3 = "salt";
const uint8_t expected3[] = {
    0x55,0xac,0x04,0x6e,0x56,0xe3,0x08,0x9f,0xec,0x16,
    0x91,0xc2,0x25,0x44,0xb6,0x05,0xf9,0x41,0x85,0x21,
    0x6d,0xde,0x04,0x65,0xe6,0x8b,0x9d,0x57,0xc2,0x0d,
    0xac,0xbc
};


/* Main function, called first */
int main(void)
{
    os_ClrHome();
    uint8_t key[32];

    // Test 1: RFC 6070 style, c=1, dkLen=20
    tls_pbkdf2(password1, strlen(password1), salt1, strlen(salt1), key, 20, 1, TLS_HASH_SHA256);
    if(memcmp(key, expected1, sizeof expected1)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 2: RFC 6070 style, c=2, dkLen=20
    tls_pbkdf2(password2, strlen(password2), salt2, strlen(salt2), key, 20, 2, TLS_HASH_SHA256);
    if(memcmp(key, expected2, sizeof expected2)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();

    // Test 3: RFC 6070 style, c=1, dkLen=32
    tls_pbkdf2(password3, strlen(password3), salt3, strlen(salt3), key, 32, 1, TLS_HASH_SHA256);
    if(memcmp(key, expected3, sizeof expected3)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    return 0;
}
