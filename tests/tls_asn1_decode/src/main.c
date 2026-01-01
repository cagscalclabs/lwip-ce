#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "asn1.h"
#include "base64.h"

// test vectors

// A 4096 bit private key
uint8_t test1[] = "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";

uint8_t asn1_test[sizeof(test1) / 3 * 4] = {0};

/* Main function, called first */
int main(void)
{
    /* Clear the homescreen */
    os_ClrHome();
    struct tls_asn1_decoder_context ctx;
    size_t olen = 0;
    
    uint8_t *ptr;
    uint8_t tag;
    uint8_t depth;
    size_t len;
    
    
    // TEST 1
    olen = tls_base64_decode(test1, sizeof test1, asn1_test);
    if(!olen) return 1;
    
    if(!tls_asn1_decoder_init(&ctx, asn1_test, olen)) return 0;
    uint8_t count = 0;
    while(tls_asn1_decode_next(&ctx, NULL, &tag, &ptr, &len, &depth)){
        printf("%u:d=%u l=%u %s:%u\n", (ptr-asn1_test), depth, len, (tls_asn1_getform(tag)) ? "cons" : "prim", tls_asn1_gettag(tag));
        if(count++ == 5) {
            os_GetKey();
            os_ClrHome();
        }
    }
    os_GetKey();
    os_ClrHome();
    
    return 0;
}
