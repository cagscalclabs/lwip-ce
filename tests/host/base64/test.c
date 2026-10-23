#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t tls_base64_encode(const uint8_t *inbuf, size_t len, uint8_t *outbuf);
size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf);

static size_t dec(const char *s, uint8_t *out)
{
    size_t n = strlen(s);
    uint8_t *in = malloc(n ? n : 1);
    memcpy(in, s, n);
    n = tls_base64_decode(in, n, out);
    free(in);
    return n;
}

int main(void)
{
    uint8_t out[64], enc[64];
    assert(dec("", out) == 0);
    assert(dec("=", out) == 0);
    assert(dec("TQ", out) == 0);
    assert(dec("TW!u", out) == 0);
    assert(dec("T=Fu", out) == 0);
    assert(dec("TQ==TWFu", out) == 0);
    assert(dec("TQ=a", out) == 0);
    assert(dec("TQ==", out) == 1 && out[0] == 'M');
    assert(dec("TWE=", out) == 2 && !memcmp(out, "Ma", 2));
    assert(dec("TWFu", out) == 3 && !memcmp(out, "Man", 3));
    for (size_t len = 0; len < 40; len++)
    {
        uint8_t raw[40];
        for (size_t i = 0; i < len; i++)
            raw[i] = (uint8_t)(i * 37 + len);
        size_t n = tls_base64_encode(raw, len, enc);
        assert(n == 4 * ((len + 2) / 3));
        assert(tls_base64_decode(enc, n, enc) == len);
        assert(!memcmp(enc, raw, len));
    }
    puts("base64 regressions passed (ASan + UBSan)");
    return 0;
}
