#include <stdint.h>
#include <stdbool.h>
#include "../includes/asn1.h"

static bool tls_asn1_parse_len(const uint8_t *p, const uint8_t *end, size_t *len, size_t *len_len)
{
    uint8_t first;
    size_t n;
    size_t value = 0;

    if (!p || p >= end || !len || !len_len)
    {
        return false;
    }

    first = *p;
    if ((first & 0x80) == 0)
    {
        *len = first;
        *len_len = 1;
        return true;
    }

    n = (size_t)(first & 0x7F);
    if (n == 0 || n > sizeof(size_t))
    {
        return false; /* DER forbids indefinite length; reject oversized lengths */
    }
    if ((size_t)(end - p) < (1 + n))
    {
        return false;
    }

    for (size_t i = 0; i < n; i++)
    {
        value = (value << 8) | (size_t)p[1 + i];
    }

    *len = value;
    *len_len = 1 + n;
    return true;
}

bool tls_asn1_cursor_init(struct tls_asn1_cursor *cursor, const uint8_t *data, size_t len)
{
    if (!cursor || !data)
    {
        return false;
    }
    cursor->cur = data;
    cursor->end = data + len;
    return true;
}

bool tls_asn1_next(struct tls_asn1_cursor *cursor, struct tls_asn1_tlv *out)
{
    const uint8_t *p;
    size_t content_len = 0;
    size_t len_len = 0;

    if (!cursor || !out || !cursor->cur || !cursor->end)
    {
        return false;
    }
    if (cursor->cur >= cursor->end)
    {
        return false;
    }

    p = cursor->cur;
    out->tlv = p;
    out->tag = *p++;

    if (!tls_asn1_parse_len(p, cursor->end, &content_len, &len_len))
    {
        return false;
    }
    p += len_len;

    if ((size_t)(cursor->end - p) < content_len)
    {
        return false;
    }

    out->header_len = 1 + len_len;
    out->value = p;
    out->len = content_len;
    cursor->cur = p + content_len;
    return true;
}

bool tls_asn1_child_cursor(const struct tls_asn1_tlv *parent, struct tls_asn1_cursor *child)
{
    if (!parent || !child || !parent->value)
    {
        return false;
    }
    if ((parent->tag & ASN1_CONSTRUCTED) == 0)
    {
        return false;
    }
    child->cur = parent->value;
    child->end = parent->value + parent->len;
    return true;
}

uint8_t tls_asn1_tag_number(uint8_t tag)
{
    return (uint8_t)(tag & 0x1F);
}

uint8_t tls_asn1_tag_class(uint8_t tag)
{
    return (uint8_t)(tag & 0xC0);
}

bool tls_asn1_tag_constructed(uint8_t tag)
{
    return (tag & ASN1_CONSTRUCTED) != 0;
}
