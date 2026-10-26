#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "parsers/url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *src = malloc(size + 1);
    char *enc = malloc(size * 3 + 1);
    char *dec = malloc(size + 1);
    char small[8];
    size_t n, m;

    memcpy(src, data, size);
    src[size] = '\0';
    url_decode(dec, size + 1, src);
    url_decode(small, sizeof(small), src);
    url_encode(small, sizeof(small), src);
    n = url_encode_n(enc, size * 3 + 1, src, size);
    assert(n != URL_ERR);
    m = url_decode(dec, size + 1, enc);
    if (!memchr(src, '\0', size))
    {
        assert(m == size);
        assert(memcmp(dec, src, size) == 0);
    }
    {
        const char *keys[] = {src, "k"};
        const char *values[] = {"v", src};
        char *query = malloc(size * 6 + 16);
        url_build_query(query, size * 6 + 16, keys, values, 2);
        url_build_query(small, sizeof(small), keys, values, 2);
        free(query);
    }
    free(src);
    free(enc);
    free(dec);
    return 0;
}
