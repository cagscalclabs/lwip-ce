#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <debug.h>

#include "hash.h"

/*
 * NIST FIPS 180-4 SHA-256 Test Vectors
 * Source: NIST Example Algorithms, SHA-256 Examples
 */

/* Test 1: "abc" - NIST FIPS 180-4, Short Message */
const char *test1 = "abc";
const uint8_t expected1[] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};

/* Test 2: Empty string "" - NIST FIPS 180-4, Empty Message */
const char *test2 = "";
const uint8_t expected2[] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

/* Test 3: 448-bit message - NIST FIPS 180-4, Two Block Message */
const char *test3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const uint8_t expected3[] = {
    0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
    0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
};


/* Main function, called first */
int main(void)
{
    /* Clear the homescreen */
    os_ClrHome();
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    struct tls_hash_context ctx;
    
    // test 1
    if(!tls_hash_context_init(&ctx, TLS_HASH_SHA256)) return 1;
    tls_hash_update(&ctx, test1, strlen(test1));
    tls_hash_digest(&ctx, digest);
    if(memcmp(digest, expected1, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    
    // test 2
    tls_hash_context_init(&ctx, TLS_HASH_SHA256);
    ctx.update(&ctx._private, test2, strlen(test2));
    ctx.digest(&ctx._private, digest);
    if(memcmp(digest, expected2, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    
    // test 3
    tls_hash_context_init(&ctx, TLS_HASH_SHA256);
    ctx.update(&ctx._private, test3, strlen(test3));
    ctx.digest(&ctx._private, digest);
    if(memcmp(digest, expected3, TLS_SHA256_DIGEST_LEN)==0)
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    
    return 0;
}
