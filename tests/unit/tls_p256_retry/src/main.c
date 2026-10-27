/* RFC 6979 section 3.2 step h.3 regression test for the P-256 signer.
 *
 * tls_p256_sign() retries with a new nonce when r or s comes out zero. That
 * branch is unreachable in practice (probability ~2^-256 per signature), but
 * it must still advance K/V exactly as RFC 6979 requires. This test drives
 * the same code path directly: derive the first nonce, clobber the ladder
 * scratch the way the scalar multiply and modular inverse do, then advance
 * K/V and compare the retry nonce against an independent implementation.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ti/screen.h>
#include <ti/getcsc.h>

extern bool p256_test_retry_k(uint8_t out_k[32], const uint8_t hash[32],
                              const uint8_t priv[32]);

/* RFC 6979 A.2.5 "sample" key and SHA-256("sample"). */
static const uint8_t sample_private[32] = {
    0xc9,0xaf,0xa9,0xd8,0x45,0xba,0x75,0x16,0x6b,0x5c,0x21,0x57,0x67,0xb1,0xd6,0x93,
    0x4e,0x50,0xc3,0xdb,0x36,0xe8,0x9b,0x12,0x7b,0x8a,0x62,0x2b,0x12,0x0f,0x67,0x21
};
static const uint8_t sample_hash[32] = {
    0xaf,0x2b,0xdb,0xe1,0xaa,0x9b,0x6e,0xc1,0xe2,0xad,0xe1,0xd6,0x94,0xf4,0x1f,0xc7,
    0x1a,0x83,0x1d,0x02,0x68,0xe9,0x89,0x15,0x62,0x11,0x3d,0x8a,0x62,0xad,0xd1,0xbf
};
/* First nonce from RFC 6979 A.2.5 (sanity check of the unretried path). */
static const uint8_t expected_k1[32] = {
    0xa6,0xe3,0xc5,0x7d,0xd0,0x1a,0xbe,0x90,0x08,0x65,0x38,0x39,0x83,0x55,0xdd,0x4c,
    0x3b,0x17,0xaa,0x87,0x33,0x82,0xb0,0xf2,0x4d,0x61,0x29,0x49,0x3d,0x8a,0xad,0x60
};
/* Nonce after one h.3 rejection, computed with an independent RFC 6979
 * implementation (Python hmac/hashlib) fed the same private key and hash. */
static const uint8_t expected_k2[32] = {
    0x8e,0x83,0xdc,0x49,0x0b,0xc5,0xfc,0x4d,0x59,0x92,0xbd,0x63,0xcd,0x87,0xf2,0x54,
    0xad,0xff,0xcb,0x93,0x0f,0x8a,0x80,0x11,0x70,0x2a,0x88,0x87,0x0f,0x63,0x8f,0xdb
};

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void)
{
    uint8_t k[32];
    int failures = 0;

    memset(k, 0, sizeof(k));

    if (!p256_test_retry_k(k, sample_hash, sample_private))
    {
        failures++;
    }
    else if (memcmp(k, expected_k1, sizeof(k)) == 0)
    {
        /* The helper clobbers the scratch after the first nonce, so seeing
         * k1 here would mean the retry never ran. */
        failures++;
    }
    else if (memcmp(k, expected_k2, sizeof(k)) != 0)
    {
        failures++;
    }
    if (failures)
    {
        print_hex("got ", k, sizeof(k));
        print_hex("want", expected_k2, sizeof(expected_k2));
    }

    if (!failures)
    {
        os_ClrHome();
    }
    printf(failures ? "fail" : "success");
    while (!os_GetCSC())
    {
    }
    return failures ? 1 : 0;
}
