#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t enc_cap = 4 * ((size + 2) / 3);
    uint8_t *dec = malloc(size / 4 * 3 + 1);
    uint8_t *enc = malloc(enc_cap + 1);
    uint8_t *back = malloc(enc_cap / 4 * 3 + 1);
    size_t n, m;

    n = tls_base64_decode(data, size, dec, size / 4 * 3);
    assert(n <= size);
    if (n)
    {
        uint8_t *re = malloc(4 * ((n + 2) / 3) + 1);
        m = tls_base64_encode(dec, n, re, 4 * ((n + 2) / 3) + 1);
        assert(m == 4 * ((n + 2) / 3));
        free(re);
    }
    tls_base64_decode(data, size, dec, size / 4 * 3 - (size >= 4));
    n = tls_base64_encode(data, size, enc, enc_cap + 1);
    if (size)
    {
        assert(n == enc_cap);
        m = tls_base64_decode(enc, n, back, enc_cap / 4 * 3);
        assert(m == size && memcmp(back, data, size) == 0);
    }
    free(dec);
    free(enc);
    free(back);
    return 0;
}
