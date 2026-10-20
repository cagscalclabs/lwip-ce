#include <stdint.h>
#include <string.h>

//#define MIN(a,b) (((a)<(b))?(a):(b))
char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf){

    size_t j = 0;
    if (len % 4) return 0;

    for (size_t i = 0; i < len; i += 4) {
        uint32_t triple = 0;
        uint8_t pad = 0;
        for (uint8_t k = 0; k < 4; k++) {
            uint8_t c = inbuf[i + k];
            int v = b64_value(c);
            if (c == '=' && k >= 2 && i + 4 == len) {
                pad++;
                v = 0;
            }
            else if (pad || v < 0) return 0;
            triple = (triple << 6) | (uint32_t)v;
        }
        outbuf[j++] = (triple >> 2 * 8) & 0xFF;
        if (pad < 2) outbuf[j++] = (triple >> 1 * 8) & 0xFF;
        if (pad < 1) outbuf[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return j;
}
