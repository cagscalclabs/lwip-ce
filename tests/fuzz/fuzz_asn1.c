#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "asn1.h"

static void walk(struct tls_asn1_cursor *c, const uint8_t *lo, const uint8_t *hi, unsigned depth)
{
    struct tls_asn1_tlv tlv;
    while (tls_asn1_next(c, &tlv))
    {
        assert(tlv.tlv >= lo && tlv.value >= tlv.tlv);
        assert(tlv.value == tlv.tlv + tlv.header_len);
        assert(tlv.len <= (size_t)(hi - tlv.value));
        tls_asn1_tag_number(tlv.tag);
        tls_asn1_tag_class(tlv.tag);
        if (depth < 64 && tls_asn1_tag_constructed(tlv.tag))
        {
            struct tls_asn1_cursor child;
            if (tls_asn1_child_cursor(&tlv, &child))
                walk(&child, tlv.value, tlv.value + tlv.len, depth + 1);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct tls_asn1_cursor c;
    if (tls_asn1_cursor_init(&c, data, size)) walk(&c, data, data + size, 0);
    return 0;
}
