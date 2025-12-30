#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* P-256 field arithmetic functions */
extern void p256_mod_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
extern void p256_mod_sub(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
extern void p256_mod_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
extern void p256_mod_sqr(uint8_t out[32], const uint8_t a[32]);
extern void p256_mod_inv(uint8_t out[32], const uint8_t a[32]);

extern const uint8_t p256_prime[32];

static bool test_add(void) {
    /* Test: (p-1) + 1 = 0 (mod p) */
    uint8_t a[32], b[32], result[32], expected[32];

    /* a = p - 1 */
    memcpy(a, p256_prime, 32);
    a[0] -= 1;

    /* b = 1 */
    memset(b, 0, 32);
    b[0] = 1;

    /* expected = 0 */
    memset(expected, 0, 32);

    p256_mod_add(result, a, b);

    return memcmp(result, expected, 32) == 0;
}

static bool test_sub(void) {
    /* Test: 0 - 1 = p - 1 (mod p) */
    uint8_t a[32], b[32], result[32], expected[32];

    /* a = 0 */
    memset(a, 0, 32);

    /* b = 1 */
    memset(b, 0, 32);
    b[0] = 1;

    /* expected = p - 1 */
    memcpy(expected, p256_prime, 32);
    expected[0] -= 1;

    p256_mod_sub(result, a, b);

    return memcmp(result, expected, 32) == 0;
}

static bool test_mul(void) {
    /* Test: 2 * 3 = 6 */
    uint8_t a[32], b[32], result[32], expected[32];

    memset(a, 0, 32);
    a[0] = 2;

    memset(b, 0, 32);
    b[0] = 3;

    memset(expected, 0, 32);
    expected[0] = 6;

    p256_mod_mul(result, a, b);

    return memcmp(result, expected, 32) == 0;
}

static bool test_inv(void) {
    /* Test: a * inv(a) = 1 (mod p) */
    uint8_t a[32], inv_a[32], result[32], expected[32];

    /* Use a = 7 */
    memset(a, 0, 32);
    a[0] = 7;

    /* Compute inverse */
    p256_mod_inv(inv_a, a);

    /* Multiply a * inv(a) */
    p256_mod_mul(result, a, inv_a);

    /* Expected = 1 */
    memset(expected, 0, 32);
    expected[0] = 1;

    return memcmp(result, expected, 32) == 0;
}

int main(void) {
    os_ClrHome();

    if(!test_add()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    if(!test_sub()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    if(!test_mul()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    if(!test_inv()) {
        printf("failed");
        os_GetKey();
        return 1;
    }

    printf("success");
    os_GetKey();
    return 0;
}
