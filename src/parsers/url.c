/**
 * @file url.c
 * @brief URL encoding/decoding for lwIP-CE
 */

#include "url.h"
#include <string.h>

static bool is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9')
        || c == '-' || c == '_' || c == '.' || c == '~';
}

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char hex_chars[] = "0123456789ABCDEF";

size_t url_encode_n(char *dst, size_t dst_len, const char *src, size_t src_len)
{
    size_t out = 0;
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (is_unreserved(c)) {
            if (out + 2 > dst_len) return (size_t)-1;
            dst[out++] = (char)c;
        } else {
            if (out + 4 > dst_len) return (size_t)-1;
            dst[out++] = '%';
            dst[out++] = hex_chars[(c >> 4) & 0xF];
            dst[out++] = hex_chars[c & 0xF];
        }
    }
    dst[out] = '\0';
    return out;
}

size_t url_encode(char *dst, size_t dst_len, const char *src)
{
    return url_encode_n(dst, dst_len, src, strlen(src));
}

size_t url_decode(char *dst, size_t dst_len, const char *src)
{
    size_t out = 0;
    size_t i = 0;
    size_t src_len = strlen(src);
    while (i < src_len) {
        if (out + 2 > dst_len) return (size_t)-1;
        unsigned char c = (unsigned char)src[i];
        if (c == '%') {
            if (i + 2 >= src_len) return (size_t)-1;
            int hi = hex_digit((unsigned char)src[i+1]);
            int lo = hex_digit((unsigned char)src[i+2]);
            if (hi < 0 || lo < 0) return (size_t)-1;
            dst[out++] = (char)((hi << 4) | lo);
            i += 3;
        } else {
            dst[out++] = (char)c;
            i++;
        }
    }
    dst[out] = '\0';
    return out;
}

size_t url_build_query(char *dst, size_t dst_len,
                       const char * const *keys,
                       const char * const *values,
                       size_t count)
{
    size_t out = 0;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            if (out + 2 > dst_len) return (size_t)-1;
            dst[out++] = '&';
        }
        size_t n = url_encode(dst + out, dst_len - out, keys[i]);
        if (n == (size_t)-1) return (size_t)-1;
        out += n;
        if (out + 2 > dst_len) return (size_t)-1;
        dst[out++] = '=';
        n = url_encode(dst + out, dst_len - out, values[i]);
        if (n == (size_t)-1) return (size_t)-1;
        out += n;
    }
    dst[out] = '\0';
    return out;
}
