#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asn1.h"
#include "base64.h"

/* A 4096-bit RSA private key encoded as base64 DER (payload only). */
static const uint8_t test1_b64[] =
    "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";

static void draw_line(const char *msg, int *y)
{
    os_FontDrawText(msg, 2, *y);
    *y += 12;
}

static bool test_cursor_simple(void)
{
    static const uint8_t der[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    struct tls_asn1_cursor top;
    struct tls_asn1_tlv seq;
    struct tls_asn1_cursor child;
    struct tls_asn1_tlv i1;
    struct tls_asn1_tlv i2;

    if (!tls_asn1_cursor_init(&top, der, sizeof(der)) || !tls_asn1_next(&top, &seq))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(seq.tag) || tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&seq, &child))
    {
        return false;
    }
    if (!tls_asn1_next(&child, &i1) || !tls_asn1_next(&child, &i2))
    {
        return false;
    }
    if (tls_asn1_tag_number(i1.tag) != ASN1_INTEGER || tls_asn1_tag_number(i2.tag) != ASN1_INTEGER)
    {
        return false;
    }
    if (i1.len != 1 || i2.len != 1 || i1.value[0] != 1 || i2.value[0] != 2)
    {
        return false;
    }
    return true;
}

static void test_cursor_large_dump(void)
{
    uint8_t der[(sizeof(test1_b64) / 4) * 3];
    struct tls_asn1_cursor cursor;
    struct tls_asn1_tlv tlv;
    int y = 30;
    size_t der_len;
    int shown = 0;
    char line[96];

    os_ClrHome();
    os_FontSelect(os_SmallFont);

    der_len = tls_base64_decode(test1_b64, sizeof(test1_b64) - 1, der);
    if (der_len == 0)
    {
        draw_line("decode large der: fail", &y);
        os_GetKey();
        return;
    }
    draw_line("decode large der: pass", &y);

    if (!tls_asn1_cursor_init(&cursor, der, der_len))
    {
        draw_line("cursor init: fail", &y);
        os_GetKey();
        return;
    }

    while (shown < 8 && tls_asn1_next(&cursor, &tlv))
    {
        snprintf(line, sizeof(line), "%u: class=%u c=%u tag=%u len=%u",
                 (unsigned)shown,
                 (unsigned)(tls_asn1_tag_class(tlv.tag) >> 6),
                 tls_asn1_tag_constructed(tlv.tag) ? 1u : 0u,
                 (unsigned)tls_asn1_tag_number(tlv.tag),
                 (unsigned)tlv.len);
        draw_line(line, &y);
        shown++;
    }
    os_GetKey();
}

int main(void)
{
    int y = 30;
    bool pass;

    os_ClrHome();
    os_FontSelect(os_SmallFont);

    pass = test_cursor_simple();
    draw_line(pass ? "cursor simple: pass" : "cursor simple: fail", &y);
    os_GetKey();

    test_cursor_large_dump();
    os_ClrHome();
    return pass ? 0 : 1;
}
