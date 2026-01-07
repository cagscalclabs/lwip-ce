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

size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf){

    size_t olen = len / 4 * 3;
    size_t j = 0;
    if (inbuf[len - 1] == '=') olen--;
    if (inbuf[len - 2] == '=') olen--;

    for (size_t i = 0; i < len;) {
        
        uint32_t sextet_a = inbuf[i] == '=' ? 0 & i++ : strchr(b64_charset, inbuf[i++]) - b64_charset;
        uint32_t sextet_b = inbuf[i] == '=' ? 0 & i++ : strchr(b64_charset, inbuf[i++]) - b64_charset;
        uint32_t sextet_c = inbuf[i] == '=' ? 0 & i++ : strchr(b64_charset, inbuf[i++]) - b64_charset;
        uint32_t sextet_d = inbuf[i] == '=' ? 0 & i++ : strchr(b64_charset, inbuf[i++]) - b64_charset;
        
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
        
        if (j < olen) outbuf[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < olen) outbuf[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < olen) outbuf[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    return j;
}
