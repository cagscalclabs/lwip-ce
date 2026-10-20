#include <stdint.h>
#include <stdbool.h>
#include <string.h>

//#define MIN(a,b) (((a)<(b))?(a):(b))
static const char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int mod_table[] = {0, 2, 1};
size_t tls_base64_encode(const uint8_t *inbuf, size_t len, uint8_t *outbuf){
    size_t olen = 4 * ((len + 2) / 3);
    size_t j = 0;
    for (size_t i = 0; i < len;) {

        uint32_t octet_a = i < len ? (unsigned char)inbuf[i++] : 0;
        uint32_t octet_b = i < len ? (unsigned char)inbuf[i++] : 0;
        uint32_t octet_c = i < len ? (unsigned char)inbuf[i++] : 0;
        
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        
        outbuf[j++] = b64_charset[(triple >> 3 * 6) & 0x3F];
        outbuf[j++] = b64_charset[(triple >> 2 * 6) & 0x3F];
        outbuf[j++] = b64_charset[(triple >> 1 * 6) & 0x3F];
        outbuf[j++] = b64_charset[(triple >> 0 * 6) & 0x3F];
    }
    
    for (int i = 0; i < mod_table[len % 3]; i++)
        outbuf[olen - 1 - i] = '=';
    
    return j;
}

static int b64_value(uint8_t ch)
{
    const char *p = strchr(b64_charset, (int)ch);
    return p ? (int)(p - b64_charset) : -1;
}

size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf){
    size_t j = 0;

    if (!inbuf || !outbuf || len == 0 || (len & 3u) != 0)
        return 0;

    for (size_t i = 0; i < len; i += 4) {
        bool last = (i + 4 == len);
        bool pad_c = inbuf[i + 2] == '=';
        bool pad_d = inbuf[i + 3] == '=';
        int a = b64_value(inbuf[i]);
        int b = b64_value(inbuf[i + 1]);
        int c = pad_c ? 0 : b64_value(inbuf[i + 2]);
        int d = pad_d ? 0 : b64_value(inbuf[i + 3]);

        /* Padding is legal only in the final quartet. A padded third sextet
         * requires the fourth to be padded as well. */
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            ((!last) && (pad_c || pad_d)) || (pad_c && !pad_d))
            return 0;

        uint32_t triple = ((uint32_t)a << 18)
                        | ((uint32_t)b << 12)
                        | ((uint32_t)c << 6)
                        | (uint32_t)d;

        outbuf[j++] = (uint8_t)(triple >> 16);
        if (!pad_c) outbuf[j++] = (uint8_t)(triple >> 8);
        if (!pad_d) outbuf[j++] = (uint8_t)triple;
    }

    return j;
}
