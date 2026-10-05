#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/base64.h"
#include "../includes/asn1.h"
#include "../includes/bytes.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/x509.h"
#include "../includes/tls.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_X509
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

static void *tls_x509_alloc(size_t size)
{
    return tls_fileio_alloc(size);
}

static void tls_x509_free(void *ptr)
{
    tls_fileio_free(ptr);
}


static bool tls_x509_is_string_tag(uint8_t tag)
{
    uint8_t n = tls_asn1_tag_number(tag);
    return (n == ASN1_UTF8STRING) ||
           (n == ASN1_PRINTABLESTRING) ||
           (n == ASN1_TELETEXSTRING) ||
           (n == ASN1_IA5STRING) ||
           (n == ASN1_BMPSTRING) ||
           (n == ASN1_UNIVERSALSTRING) ||
           (n == ASN1_VISIBLESTRING);
}

static bool tls_x509_oid_eq(const struct tls_asn1_tlv *oid_tlv, const uint8_t *oid, size_t oid_len)
{
    return oid_tlv && oid &&
           tls_asn1_tag_number(oid_tlv->tag) == ASN1_OBJECTID &&
           oid_tlv->len == oid_len &&
           memcmp(oid_tlv->value, oid, oid_len) == 0;
}

static bool tls_x509_parse_name_common_name(const struct tls_asn1_tlv *name_tlv,
                                            struct tls_asn1_serialization *out)
{
    static const uint8_t oid_common_name[] = {0x55, 0x04, 0x03};
    struct tls_asn1_cursor rdn_cursor;
    struct tls_asn1_tlv rdn_set;
    bool have_first_string = false;

    if (!name_tlv || !out)
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(name_tlv->tag) || tls_asn1_tag_number(name_tlv->tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(name_tlv, &rdn_cursor))
    {
        return false;
    }

    /*
     * Name ::= SEQUENCE OF RDN
     * RDN  ::= SET OF AttributeTypeAndValue
     *
     * We prefer CN (2.5.4.3), but fall back to the first string value to
     * preserve prior behavior for certs that omit CN but include other RDNs.
     */
    while (tls_asn1_next(&rdn_cursor, &rdn_set))
    {
        struct tls_asn1_cursor set_cursor;
        struct tls_asn1_tlv atv_seq;

        if (!tls_asn1_tag_constructed(rdn_set.tag) || tls_asn1_tag_number(rdn_set.tag) != ASN1_SET)
        {
            continue;
        }
        if (!tls_asn1_child_cursor(&rdn_set, &set_cursor))
        {
            return false;
        }

        while (tls_asn1_next(&set_cursor, &atv_seq))
        {
            struct tls_asn1_cursor atv_cursor;
            struct tls_asn1_tlv attr_oid;
            struct tls_asn1_tlv attr_value;

            if (!tls_asn1_tag_constructed(atv_seq.tag) || tls_asn1_tag_number(atv_seq.tag) != ASN1_SEQUENCE)
            {
                continue;
            }
            if (!tls_asn1_child_cursor(&atv_seq, &atv_cursor) ||
                !tls_asn1_next(&atv_cursor, &attr_oid) ||
                !tls_asn1_next(&atv_cursor, &attr_value))
            {
                return false;
            }
            if (!tls_x509_is_string_tag(attr_value.tag))
            {
                continue;
            }

            if (!have_first_string)
            {
                out->tag = attr_value.tag;
                out->data = (uint8_t *)attr_value.value;
                out->len = attr_value.len;
                have_first_string = true;
            }

            if (tls_x509_oid_eq(&attr_oid, oid_common_name, sizeof(oid_common_name)))
            {
                out->tag = attr_value.tag;
                out->data = (uint8_t *)attr_value.value;
                out->len = attr_value.len;
                return true;
            }
        }
    }

    return have_first_string;
}

static bool tls_x509_parse_algorithm_identifier(const struct tls_asn1_tlv *alg_tlv,
                                                struct tls_asn1_serialization *alg_out,
                                                struct tls_asn1_serialization *param_out,
                                                bool param_optional)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv oid;
    struct tls_asn1_tlv param;

    if (!alg_tlv || !alg_out)
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(alg_tlv->tag) || tls_asn1_tag_number(alg_tlv->tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(alg_tlv, &c) || !tls_asn1_next(&c, &oid))
    {
        return false;
    }
    if (tls_asn1_tag_number(oid.tag) != ASN1_OBJECTID)
    {
        return false;
    }

    alg_out->tag = oid.tag;
    alg_out->data = (uint8_t *)oid.value;
    alg_out->len = oid.len;

    if (param_out)
    {
        param_out->tag = 0;
        param_out->data = NULL;
        param_out->len = 0;
    }

    /* RFC 4055: RSASSA-PSS parameters are a SEQUENCE, unlike the NULL
     * parameters used by rsaEncryption / sha256WithRSAEncryption. Preserve
     * the parameter value for callers; parsing is not signature verification. */
    static const uint8_t oid_rsassa_pss[] = {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a
    };
    bool is_pss = tls_x509_oid_eq(&oid, oid_rsassa_pss, sizeof(oid_rsassa_pss));
    if (tls_asn1_next(&c, &param))
    {
        if (is_pss)
        {
            if (param.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
            {
                return false;
            }
        }
        else if (param.tag != ASN1_OBJECTID && param.tag != ASN1_NULL)
        {
            return false;
        }
        if (param_out && param.tag != ASN1_NULL)
        {
            param_out->tag = param.tag;
            param_out->data = (uint8_t *)param.value;
            param_out->len = param.len;
        }
    }
    else if (!param_optional)
    {
        return false;
    }

    /* Do not silently accept a second parameter or a truncated TLV. */
    return c.cur == c.end;
}

static bool tls_x509_parse_constraints_from_extensions(const uint8_t *ext_data, size_t ext_len,
                                                       bool *basic_constraints_present,
                                                       bool *basic_constraints_ca_true,
                                                       bool *key_usage_present,
                                                       bool *key_usage_key_cert_sign)
{
    static const uint8_t oid_basic_constraints[] = {0x55, 0x1D, 0x13};
    static const uint8_t oid_key_usage[] = {0x55, 0x1D, 0x0F};
    struct tls_asn1_cursor ext_cursor;
    struct tls_asn1_cursor ext_list_cursor;
    struct tls_asn1_tlv ext_tlv;

    if (!ext_data || ext_len == 0)
    {
        return false;
    }
    if (!tls_asn1_cursor_init(&ext_cursor, ext_data, ext_len))
    {
        return false;
    }

    /*
     * Expected input from parse_certificate() is the content of [3] EXPLICIT:
     * it contains one TLV: SEQUENCE OF Extension.
     * Accept both:
     * - wrapper form: 30 ... (SEQUENCE containing Extension entries)
     * - direct form: repeated Extension SEQUENCE items
     */
    ext_list_cursor = ext_cursor;
    if (tls_asn1_next(&ext_cursor, &ext_tlv))
    {
        if ((ext_tlv.header_len + ext_tlv.len) == ext_len &&
            tls_asn1_tag_constructed(ext_tlv.tag) &&
            tls_asn1_tag_number(ext_tlv.tag) == ASN1_SEQUENCE)
        {
            if (!tls_asn1_child_cursor(&ext_tlv, &ext_list_cursor))
            {
                return false;
            }
        }
        else
        {
            ext_list_cursor = ext_cursor;
            ext_list_cursor.cur = ext_data;
        }
    }
    else
    {
        return false;
    }

    *basic_constraints_present = false;
    *basic_constraints_ca_true = false;
    *key_usage_present = false;
    *key_usage_key_cert_sign = false;

    /*
     * ext_data is expected to point to Extension SEQUENCE elements
     * (the content of [3] EXPLICIT extensions wrapper).
     */
    while (tls_asn1_next(&ext_list_cursor, &ext_tlv))
    {
        struct tls_asn1_cursor ext_item_cursor;
        struct tls_asn1_tlv oid_tlv;
        struct tls_asn1_tlv maybe_critical_tlv;
        struct tls_asn1_tlv value_tlv;
        struct tls_asn1_tlv inner_tlv;
        struct tls_asn1_cursor inner_cursor;

        if (tls_asn1_tag_number(ext_tlv.tag) != ASN1_SEQUENCE || !tls_asn1_tag_constructed(ext_tlv.tag))
        {
            continue;
        }
        if (!tls_asn1_child_cursor(&ext_tlv, &ext_item_cursor))
        {
            continue;
        }
        if (!tls_asn1_next(&ext_item_cursor, &oid_tlv))
        {
            continue;
        }
        if (tls_asn1_tag_number(oid_tlv.tag) != ASN1_OBJECTID)
        {
            continue;
        }

        if (!tls_asn1_next(&ext_item_cursor, &maybe_critical_tlv))
        {
            continue;
        }
        if (tls_asn1_tag_number(maybe_critical_tlv.tag) == ASN1_BOOLEAN)
        {
            if (!tls_asn1_next(&ext_item_cursor, &value_tlv))
            {
                continue;
            }
        }
        else
        {
            value_tlv = maybe_critical_tlv;
        }

        if (tls_asn1_tag_number(value_tlv.tag) != ASN1_OCTETSTRING)
        {
            continue;
        }

        if (oid_tlv.len == sizeof(oid_basic_constraints) &&
            memcmp(oid_tlv.value, oid_basic_constraints, sizeof(oid_basic_constraints)) == 0)
        {
            /* extnValue wraps DER bytes; re-enter with a nested cursor. */
            if (!tls_asn1_cursor_init(&inner_cursor, value_tlv.value, value_tlv.len) ||
                !tls_asn1_next(&inner_cursor, &inner_tlv))
            {
                return false;
            }
            if (tls_asn1_tag_number(inner_tlv.tag) != ASN1_SEQUENCE || !tls_asn1_tag_constructed(inner_tlv.tag))
            {
                return false;
            }

            *basic_constraints_present = true;
            *basic_constraints_ca_true = false;
            if (inner_tlv.len > 0)
            {
                struct tls_asn1_cursor bc_cursor;
                struct tls_asn1_tlv bc_item;
                if (!tls_asn1_child_cursor(&inner_tlv, &bc_cursor))
                {
                    return false;
                }
                if (tls_asn1_next(&bc_cursor, &bc_item) &&
                    tls_asn1_tag_number(bc_item.tag) == ASN1_BOOLEAN &&
                    bc_item.len == 1 && bc_item.value[0] != 0)
                {
                    *basic_constraints_ca_true = true;
                }
            }
        }
        else if (oid_tlv.len == sizeof(oid_key_usage) &&
                 memcmp(oid_tlv.value, oid_key_usage, sizeof(oid_key_usage)) == 0)
        {
            /*
             * KeyUsage BIT STRING: byte[0] is unused-bit count.
             * keyCertSign is bit 5 from MSB ordering, which maps to 0x04 in
             * the first payload byte after the unused-bit count.
             */
            if (!tls_asn1_cursor_init(&inner_cursor, value_tlv.value, value_tlv.len) ||
                !tls_asn1_next(&inner_cursor, &inner_tlv))
            {
                return false;
            }
            if (tls_asn1_tag_number(inner_tlv.tag) != ASN1_BITSTRING ||
                inner_tlv.len < 2 || inner_tlv.value[0] > 7)
            {
                return false;
            }
            *key_usage_present = true;
            *key_usage_key_cert_sign = ((inner_tlv.value[1] & 0x04) != 0);
        }
    }

    return true;
}

static uint8_t tls_x509_ascii_lower(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

/* ASCII case-insensitive exact compare. DNS names are ASCII-only, so no
 * locale-aware folding is needed or wanted here. */
static bool tls_x509_name_eq_ci(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    size_t i;
    if (a_len != b_len)
    {
        return false;
    }
    for (i = 0; i < a_len; i++)
    {
        if (tls_x509_ascii_lower(a[i]) != tls_x509_ascii_lower(b[i]))
        {
            return false;
        }
    }
    return true;
}

/* Match hostname against a single SAN dNSName/CN pattern, with a single
 * leading-label wildcard: "*.example.com" matches "foo.example.com" but
 * not "example.com" or "foo.bar.example.com". A wildcard label must be
 * exactly "*" (no partial-label wildcards like "f*.example.com") and may
 * only appear as the leftmost label, matching CA/Browser Forum baseline
 * requirements rather than the more permissive (and more dangerous) RFC
 * 6125 grammar. */
static bool tls_x509_pattern_matches_host(const uint8_t *pattern, size_t pattern_len,
                                          const char *hostname, size_t hostname_len)
{
    const uint8_t *p_dot;
    size_t p_first_label_len;
    const char *h_dot;
    size_t h_first_label_len;

    if (pattern_len == hostname_len &&
        tls_x509_name_eq_ci(pattern, pattern_len, (const uint8_t *)hostname, hostname_len))
    {
        return true;
    }

    if (pattern_len < 3 || pattern[0] != '*' || pattern[1] != '.')
    {
        return false;
    }

    /* Reject "*.foo" matching a bare second-level host with no further
     * labels (e.g. "*.com" must not match "com"), and require the
     * wildcard's suffix to actually appear in the hostname. */
    p_dot = (const uint8_t *)memchr(pattern, '.', pattern_len);
    p_first_label_len = (size_t)(p_dot - pattern); /* always 1, the '*' */
    (void)p_first_label_len;

    h_dot = (const char *)memchr(hostname, '.', hostname_len);
    if (!h_dot)
    {
        /* Hostname has no dot at all -- can't match a "*.suffix" pattern,
         * and prevents "*.com"-style patterns from matching a single
         * label such as "com". */
        return false;
    }
    h_first_label_len = (size_t)(h_dot - hostname);
    if (h_first_label_len == 0)
    {
        return false;
    }

    {
        size_t pattern_suffix_len = pattern_len - 1; /* drop leading '*', keep '.' */
        const uint8_t *pattern_suffix = pattern + 1;
        size_t hostname_suffix_len = hostname_len - h_first_label_len;
        const char *hostname_suffix = hostname + h_first_label_len;

        return tls_x509_name_eq_ci(pattern_suffix, pattern_suffix_len,
                                   (const uint8_t *)hostname_suffix, hostname_suffix_len);
    }
}

/* OID 2.5.29.17 subjectAltName. GeneralName ::= CHOICE, dNSName is
 * [2] IMPLICIT IA5String (context-specific, primitive, tag number 2). */
static bool tls_x509_san_dns_matches(const uint8_t *ext_data, size_t ext_len,
                                     const char *hostname, size_t hostname_len,
                                     bool *san_present)
{
    static const uint8_t oid_subject_alt_name[] = {0x55, 0x1D, 0x11};
    struct tls_asn1_cursor ext_cursor;
    struct tls_asn1_cursor ext_list_cursor;
    struct tls_asn1_tlv ext_tlv;

    *san_present = false;

    if (!ext_data || ext_len == 0)
    {
        return false;
    }
    if (!tls_asn1_cursor_init(&ext_cursor, ext_data, ext_len))
    {
        return false;
    }

    /* Same wrapper-vs-direct handling as tls_x509_parse_constraints_from_extensions. */
    ext_list_cursor = ext_cursor;
    if (tls_asn1_next(&ext_cursor, &ext_tlv))
    {
        if ((ext_tlv.header_len + ext_tlv.len) == ext_len &&
            tls_asn1_tag_constructed(ext_tlv.tag) &&
            tls_asn1_tag_number(ext_tlv.tag) == ASN1_SEQUENCE)
        {
            if (!tls_asn1_child_cursor(&ext_tlv, &ext_list_cursor))
            {
                return false;
            }
        }
        else
        {
            ext_list_cursor = ext_cursor;
            ext_list_cursor.cur = ext_data;
        }
    }
    else
    {
        return false;
    }

    while (tls_asn1_next(&ext_list_cursor, &ext_tlv))
    {
        struct tls_asn1_cursor ext_item_cursor;
        struct tls_asn1_tlv oid_tlv;
        struct tls_asn1_tlv maybe_critical_tlv;
        struct tls_asn1_tlv value_tlv;

        if (tls_asn1_tag_number(ext_tlv.tag) != ASN1_SEQUENCE || !tls_asn1_tag_constructed(ext_tlv.tag))
        {
            continue;
        }
        if (!tls_asn1_child_cursor(&ext_tlv, &ext_item_cursor))
        {
            continue;
        }
        if (!tls_asn1_next(&ext_item_cursor, &oid_tlv))
        {
            continue;
        }
        if (tls_asn1_tag_number(oid_tlv.tag) != ASN1_OBJECTID)
        {
            continue;
        }

        if (!tls_asn1_next(&ext_item_cursor, &maybe_critical_tlv))
        {
            continue;
        }
        if (tls_asn1_tag_number(maybe_critical_tlv.tag) == ASN1_BOOLEAN)
        {
            if (!tls_asn1_next(&ext_item_cursor, &value_tlv))
            {
                continue;
            }
        }
        else
        {
            value_tlv = maybe_critical_tlv;
        }

        if (tls_asn1_tag_number(value_tlv.tag) != ASN1_OCTETSTRING)
        {
            continue;
        }

        if (oid_tlv.len == sizeof(oid_subject_alt_name) &&
            memcmp(oid_tlv.value, oid_subject_alt_name, sizeof(oid_subject_alt_name)) == 0)
        {
            struct tls_asn1_cursor san_cursor;
            struct tls_asn1_tlv san_item;
            bool matched = false;

            *san_present = true;

            if (!tls_asn1_cursor_init(&san_cursor, value_tlv.value, value_tlv.len))
            {
                return false;
            }

            /* subjectAltName ::= SEQUENCE OF GeneralName -- the OCTET STRING
             * payload IS the SEQUENCE; walk its children directly. */
            {
                struct tls_asn1_tlv san_seq;
                struct tls_asn1_cursor san_seq_cursor;
                if (!tls_asn1_next(&san_cursor, &san_seq) ||
                    tls_asn1_tag_number(san_seq.tag) != ASN1_SEQUENCE ||
                    !tls_asn1_tag_constructed(san_seq.tag))
                {
                    return false;
                }
                if (!tls_asn1_child_cursor(&san_seq, &san_seq_cursor))
                {
                    return false;
                }
                san_cursor = san_seq_cursor;
            }

            while (tls_asn1_next(&san_cursor, &san_item))
            {
                /* dNSName: context class, primitive, tag number 2 -- raw
                 * tag byte 0x82 ((2<<6) CONTEXTSPEC | (0<<5) PRIMITIVE | 2). */
                if (san_item.tag != (uint8_t)(ASN1_CONTEXTSPEC | ASN1_PRIMITIVE | 2u))
                {
                    continue;
                }
                if (tls_x509_pattern_matches_host(san_item.value, san_item.len,
                                                  hostname, hostname_len))
                {
                    matched = true;
                }
            }

            if (matched)
            {
                return true;
            }
            /* Found the extension but no dNSName entry matched -- keep
             * scanning in case the extension is (invalidly) repeated, but
             * do not fall through to CN: presence of SAN means CN is not
             * consulted, per RFC 6125 ss 6.4.4. */
        }
    }

    return false;
}

bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len,
                               const uint8_t *subject_cn, size_t subject_cn_len,
                               const char *hostname)
{
    bool san_present = false;
    size_t hostname_len;

    if (!hostname)
        return false;

    hostname_len = strlen(hostname);
    if (hostname_len == 0)
        return false;

    if (tls_x509_san_dns_matches(ext_data, ext_len, hostname, hostname_len, &san_present))
        return true;

    if (san_present)
        return false; /* SAN present but no match — don't fall back to CN */

    if (!subject_cn || subject_cn_len == 0)
        return false;

    return tls_x509_pattern_matches_host(subject_cn, subject_cn_len, hostname, hostname_len);
}

static bool tls_x509_digit_pair(const uint8_t *p, uint32_t *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
    {
        return false;
    }
    *out = (uint32_t)((p[0] - '0') * 10 + (p[1] - '0'));
    return true;
}

/* Days from civil 1970-01-01 to the given y/m/d (proleptic Gregorian).
 * Standard "days from civil" algorithm (Howard Hinnant), avoids any
 * libc calendar dependency. y is the full year (e.g. 2026), m is 1-12. */
static int32_t tls_x509_days_from_civil(int32_t y, uint32_t m, uint32_t d)
{
    int32_t era;
    uint32_t yoe;
    uint32_t doy;
    uint32_t doe;

    y -= (m <= 2) ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (uint32_t)(y - era * 400);
    doy = (153u * (m + (m > 2 ? -3 : 9)) + 2u) / 5u + d - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int32_t)doe - 719468;
}

bool tls_x509_time_to_unix(const uint8_t *data, size_t len, uint8_t tag,
                            uint32_t *out_secs)
{
    uint8_t tag_num;
    const uint8_t *v;
    uint32_t year, month, day, hour, minute, second;
    int32_t days;
    int64_t secs64;

    if (!data || len == 0 || !out_secs)
    {
        return false;
    }
    tag_num = tls_asn1_tag_number(tag);
    v = data;

    if (tag_num == ASN1_UTCTIME)
    {
        /* YYMMDDHHMMSSZ -- exactly 13 bytes. DER requires seconds and 'Z'. */
        uint32_t yy;
        if (len != 13 || v[12] != 'Z')
        {
            return false;
        }
        if (!tls_x509_digit_pair(v, &yy) ||
            !tls_x509_digit_pair(v + 2, &month) ||
            !tls_x509_digit_pair(v + 4, &day) ||
            !tls_x509_digit_pair(v + 6, &hour) ||
            !tls_x509_digit_pair(v + 8, &minute) ||
            !tls_x509_digit_pair(v + 10, &second))
        {
            return false;
        }
        /* RFC 5280 4.1.2.5.1 pivot: 50-99 => 19xx, 00-49 => 20xx. */
        year = (yy >= 50) ? (1900u + yy) : (2000u + yy);
    }
    else if (tag_num == ASN1_GENERALIZEDTIME)
    {
        /* YYYYMMDDHHMMSSZ -- exactly 15 bytes. */
        uint32_t y_hi, y_lo;
        if (len != 15 || v[14] != 'Z')
        {
            return false;
        }
        if (!tls_x509_digit_pair(v, &y_hi) ||
            !tls_x509_digit_pair(v + 2, &y_lo) ||
            !tls_x509_digit_pair(v + 4, &month) ||
            !tls_x509_digit_pair(v + 6, &day) ||
            !tls_x509_digit_pair(v + 8, &hour) ||
            !tls_x509_digit_pair(v + 10, &minute) ||
            !tls_x509_digit_pair(v + 12, &second))
        {
            return false;
        }
        year = y_hi * 100u + y_lo;
    }
    else
    {
        return false;
    }

    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 60 /* allow leap second */)
    {
        return false;
    }

    days = tls_x509_days_from_civil((int32_t)year, month, day);
    secs64 = (int64_t)days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
    if (secs64 < 0 || secs64 > (int64_t)UINT32_MAX)
    {
        /* Out of uint32_t Unix-seconds range (pre-1970 or post-2106) --
         * cleanly fail closed rather than silently truncating/wrapping. */
        return false;
    }

    *out_secs = (uint32_t)secs64;
    return true;
}

bool tls_x509_time_in_validity(const struct tls_x509_object *cert, uint32_t now_secs)
{
    uint32_t not_before_secs;
    uint32_t not_after_secs;

    if (!cert)
        return false;

    if (!tls_x509_time_to_unix(cert->valid_before, cert->valid_before_len,
                                cert->valid_before_tag, &not_before_secs) ||
        !tls_x509_time_to_unix(cert->valid_after,  cert->valid_after_len,
                                cert->valid_after_tag,  &not_after_secs))
    {
        return false;
    }
    if (not_before_secs > not_after_secs)
    {
        /* Malformed/inverted validity window. */
        return false;
    }
    return now_secs >= not_before_secs && now_secs <= not_after_secs;
}

bool tls_x509_has_valid_constraints(const uint8_t *ext_data, size_t ext_len)
{
    bool basic_constraints_present = false;
    bool basic_constraints_ca_true = false;
    bool key_usage_present = false;
    bool key_usage_key_cert_sign = false;

    if (!tls_x509_parse_constraints_from_extensions(ext_data, ext_len,
                                                    &basic_constraints_present,
                                                    &basic_constraints_ca_true,
                                                    &key_usage_present,
                                                    &key_usage_key_cert_sign))
    {
        return false;
    }

    if (!basic_constraints_present || !basic_constraints_ca_true)
    {
        return false;
    }
    if (key_usage_present && !key_usage_key_cert_sign)
    {
        return false;
    }

    return true;
}

bool tls_x509_has_required_ca_constraints(const uint8_t *cert_der, size_t cert_len)
{
    struct tls_x509_object parsed = {0};

    if (!tls_x509_parse_certificate(cert_der, cert_len, &parsed))
        return false;

    if (!parsed.extensions || parsed.extensions_len == 0)
        return false;

    return tls_x509_has_valid_constraints(parsed.extensions, parsed.extensions_len);
}

bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len,
                                struct tls_x509_object *out)
{
    struct tls_asn1_cursor top_cursor;
    struct tls_asn1_tlv cert_seq;
    struct tls_asn1_cursor cert_items;
    struct tls_asn1_tlv tbs;
    struct tls_asn1_tlv ca_sig_alg;
    struct tls_asn1_tlv ca_sig_val;

    /* Temporary serialization scratch for tls_x509_parse_algorithm_identifier
     * and tls_x509_parse_name_common_name — we only need their results
     * transiently to populate the flat fields in out. */
    struct tls_asn1_serialization scratch_alg;
    struct tls_asn1_serialization scratch_param;
    struct tls_asn1_serialization scratch_cn;

    if (!cert_der || cert_len == 0 || !out)
    {
        ERROR();
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->from_handshake = true; /* all pointers reference cert_der */

    if (!tls_asn1_cursor_init(&top_cursor, cert_der, cert_len) ||
        !tls_asn1_next(&top_cursor, &cert_seq))
        return false;

    if (!tls_asn1_tag_constructed(cert_seq.tag) ||
        tls_asn1_tag_number(cert_seq.tag) != ASN1_SEQUENCE)
        return false;

    if (!tls_asn1_child_cursor(&cert_seq, &cert_items) ||
        !tls_asn1_next(&cert_items, &tbs) ||
        !tls_asn1_next(&cert_items, &ca_sig_alg) ||
        !tls_asn1_next(&cert_items, &ca_sig_val))
        return false;

    if (!tls_asn1_tag_constructed(tbs.tag) ||
        tls_asn1_tag_number(tbs.tag) != ASN1_SEQUENCE)
        return false;

    if (tls_asn1_tag_number(ca_sig_val.tag) != ASN1_BITSTRING)
        return false;

    {
        struct tls_asn1_cursor tbs_cursor;
        struct tls_asn1_tlv item;
        struct tls_asn1_tlv sig_alg;
        struct tls_asn1_tlv issuer;
        struct tls_asn1_tlv validity;
        struct tls_asn1_tlv subject;
        struct tls_asn1_tlv spki;

        if (!tls_asn1_child_cursor(&tbs, &tbs_cursor))
            return false;

        if (!tls_asn1_next(&tbs_cursor, &item))
            return false;

        /* version is [0] EXPLICIT and optional in v1 certs. */
        if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
            tls_asn1_tag_number(item.tag) == 0 &&
            tls_asn1_tag_constructed(item.tag))
        {
            if (!tls_asn1_next(&tbs_cursor, &item))
                return false;
        }

        if (tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
            return false;

        if (!tls_asn1_next(&tbs_cursor, &sig_alg)  ||
            !tls_asn1_next(&tbs_cursor, &issuer)    ||
            !tls_asn1_next(&tbs_cursor, &validity)  ||
            !tls_asn1_next(&tbs_cursor, &subject)   ||
            !tls_asn1_next(&tbs_cursor, &spki))
            return false;

        /* issuer CN */
        memset(&scratch_cn, 0, sizeof(scratch_cn));
        if (!tls_x509_parse_name_common_name(&issuer, &scratch_cn))
            return false;
        out->issuer_cn     = scratch_cn.data;
        out->issuer_cn_len = scratch_cn.len;

        /* validity */
        {
            struct tls_asn1_cursor validity_cursor;
            struct tls_asn1_tlv not_before, not_after;

            if (!tls_asn1_tag_constructed(validity.tag) ||
                tls_asn1_tag_number(validity.tag) != ASN1_SEQUENCE)
                return false;

            if (!tls_asn1_child_cursor(&validity, &validity_cursor) ||
                !tls_asn1_next(&validity_cursor, &not_before) ||
                !tls_asn1_next(&validity_cursor, &not_after))
                return false;

            uint8_t nb_tag = tls_asn1_tag_number(not_before.tag);
            uint8_t na_tag = tls_asn1_tag_number(not_after.tag);
            if (nb_tag != ASN1_UTCTIME && nb_tag != ASN1_GENERALIZEDTIME)
                return false;
            if (na_tag != ASN1_UTCTIME && na_tag != ASN1_GENERALIZEDTIME)
                return false;

            out->valid_before     = not_before.value;
            out->valid_before_len = not_before.len;
            out->valid_before_tag = not_before.tag;
            out->valid_after      = not_after.value;
            out->valid_after_len  = not_after.len;
            out->valid_after_tag  = not_after.tag;
        }

        /* subject CN */
        memset(&scratch_cn, 0, sizeof(scratch_cn));
        if (!tls_x509_parse_name_common_name(&subject, &scratch_cn))
            return false;
        out->subject_cn     = scratch_cn.data;
        out->subject_cn_len = scratch_cn.len;

        /* SPKI — parse into pubkey */
        if (!tls_asn1_tag_constructed(spki.tag) ||
            tls_asn1_tag_number(spki.tag) != ASN1_SEQUENCE)
            return false;

        {
            struct tls_asn1_cursor spki_cursor;
            struct tls_asn1_tlv spki_alg;
            struct tls_asn1_tlv spki_bits;

            if (!tls_asn1_child_cursor(&spki, &spki_cursor) ||
                !tls_asn1_next(&spki_cursor, &spki_alg)      ||
                !tls_asn1_next(&spki_cursor, &spki_bits))
                return false;

            memset(&scratch_alg, 0, sizeof(scratch_alg));
            if (!tls_x509_parse_algorithm_identifier(&spki_alg, &scratch_alg,
                                                      &scratch_param, true))
                return false;

            if (tls_asn1_tag_number(spki_bits.tag) != ASN1_BITSTRING)
                return false;

            /* Infer the algorithm from the SPKI OID and extract key material. */
            tls_alg_t alg = tls_x509_oid_to_sig_alg(scratch_alg.data, scratch_alg.len);
            out->pubkey.alg       = alg;
            out->pubkey.allocated = false;

            if (alg == TLS_ALG_RSA_PSS_RSAE_SHA256 ||
                alg == TLS_ALG_RSA_PKCS1_SHA256)
            {
                /* BIT STRING payload: skip the leading unused-bits byte. */
                if (spki_bits.len < 2 || spki_bits.value[0] != 0x00)
                    return false;
                /* key_parse_spki (key.c) logic inline: parse RSAPublicKey. */
                struct tls_asn1_cursor rsa_c;
                struct tls_asn1_tlv rsa_seq, rsa_mod, rsa_exp;
                if (!tls_asn1_cursor_init(&rsa_c, spki_bits.value + 1,
                                          spki_bits.len - 1) ||
                    !tls_asn1_next(&rsa_c, &rsa_seq) ||
                    !tls_asn1_tag_constructed(rsa_seq.tag) ||
                    tls_asn1_tag_number(rsa_seq.tag) != ASN1_SEQUENCE)
                    return false;
                struct tls_asn1_cursor rsa_body;
                if (!tls_asn1_child_cursor(&rsa_seq, &rsa_body) ||
                    !tls_asn1_next(&rsa_body, &rsa_mod) ||
                    !tls_asn1_next(&rsa_body, &rsa_exp) ||
                    tls_asn1_tag_number(rsa_mod.tag) != ASN1_INTEGER ||
                    tls_asn1_tag_number(rsa_exp.tag) != ASN1_INTEGER)
                    return false;

                const uint8_t *mod = rsa_mod.value;
                size_t         mod_len = rsa_mod.len;
                if (mod_len > 1 && mod[0] == 0x00) { mod++; mod_len--; }

                out->pubkey.rsa.modulus  = mod;
                out->pubkey.rsa.mod_len  = mod_len;
                out->pubkey.rsa.exponent = rsa_exp.value;
                out->pubkey.rsa.exp_len  = rsa_exp.len;
            }
            else if (alg == TLS_ALG_ECDSA_SECP256R1_SHA256)
            {
                /* EC public key: BIT STRING value after the unused-bits byte. */
                if (spki_bits.len < 2)
                    return false;
                out->pubkey.ec.data = spki_bits.value + 1;
                out->pubkey.ec.len  = spki_bits.len  - 1;
            }
            /* else: unknown alg — pubkey fields remain zeroed; callers that
             * need to verify will fail via tls_key_verify returning UNKNOWN. */
        }

        /* extensions [3] EXPLICIT — expose inner content bytes */
        while (tls_asn1_next(&tbs_cursor, &item))
        {
            if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
                tls_asn1_tag_number(item.tag) == 3 &&
                tls_asn1_tag_constructed(item.tag))
            {
                out->extensions     = item.value;
                out->extensions_len = item.len;
                break;
            }
        }
    }

    /* Validate ca signature algorithm field exists (not used for value here). */
    memset(&scratch_alg, 0, sizeof(scratch_alg));
    if (!tls_x509_parse_algorithm_identifier(&ca_sig_alg, &scratch_alg,
                                              &scratch_param, true))
        return false;

    return true;
}

static bool tls_x509_decode_pem_certificate(const char *pem_data,
                                            size_t size,
                                            uint8_t *der_out,
                                            size_t der_out_len,
                                            size_t *der_written)
{
    const char begin_banner[] = "-----BEGIN CERTIFICATE-----";
    const char end_banner[] = "-----END CERTIFICATE-----";
    const char *p;
    const char *end;
    size_t b64_count = 0;
    size_t i = 0;

    if (!pem_data || !der_out || !der_written || size == 0)
    {
        return false;
    }
    if (size < (sizeof(begin_banner) - 1) ||
        memcmp(pem_data, begin_banner, sizeof(begin_banner) - 1) != 0)
    {
        return false;
    }

    end = pem_data + size;
    p = memchr(pem_data, '\n', size);
    if (!p)
    {
        return false;
    }
    p++;

    /*
     * Normalize PEM body into a contiguous base64 buffer in der_out,
     * then decode in place (safe because decoded output is smaller).
     */
    while (p < end)
    {
        if ((size_t)(end - p) >= (sizeof(end_banner) - 1) &&
            memcmp(p, end_banner, sizeof(end_banner) - 1) == 0)
        {
            break;
        }

        if (((*p >= 'A') && (*p <= 'Z')) ||
            ((*p >= 'a') && (*p <= 'z')) ||
            ((*p >= '0') && (*p <= '9')) ||
            (*p == '+') || (*p == '/') || (*p == '='))
        {
            if (b64_count >= der_out_len)
            {
                return false;
            }
            der_out[b64_count++] = (uint8_t)*p;
        }
        else if ((*p != '\n') && (*p != '\r') && (*p != ' ') && (*p != '\t'))
        {
            return false;
        }
        p++;
    }

    if (p >= end || b64_count == 0 || (b64_count & 3) != 0)
    {
        return false;
    }

    i = tls_base64_decode(der_out, b64_count, der_out);
    if (i == 0 || i > der_out_len)
    {
        return false;
    }

    *der_written = i;
    return true;
}

struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size)
{
    size_t der_cap;
    size_t total_len;
    size_t der_len = 0;
    struct tls_x509_object *obj;

    if (!pem_data || size == 0)
    {
        ERROR();
        return NULL;
    }

    /* PEM body is always shorter than the PEM text, so size is a safe cap. */
    der_cap   = size;
    total_len = sizeof(struct tls_x509_object) + der_cap;
    obj = (struct tls_x509_object *)tls_x509_alloc(total_len);
    if (!obj)
    {
        ERROR();
        return NULL;
    }
    memset(obj, 0, total_len);

    if (!tls_x509_decode_pem_certificate(pem_data, size, obj->der, der_cap, &der_len))
    {
        ERROR();
        tls_secure_memzero(obj, total_len);
        tls_x509_free(obj);
        return NULL;
    }
    /* Parse into the object itself.  tls_x509_parse_certificate does a
     * memset(out, 0, sizeof(*out)) internally, so set der_len AFTER the
     * parse call — otherwise it gets zeroed and never restored. */
    if (!tls_x509_parse_certificate(obj->der, der_len, obj))
    {
        ERROR();
        tls_secure_memzero(obj, total_len);
        tls_x509_free(obj);
        return NULL;
    }
    obj->der_len = der_len;
    obj->from_handshake = false;
    return obj;
}

void tls_x509_object_free(struct tls_x509_object *obj)
{
    if (!obj || obj->from_handshake)
        return;
    /* Recover allocation size: header + der_len (der_cap was size at alloc,
     * but we zeroed the rest so wiping the whole header+der_len is enough). */
    size_t total = sizeof(struct tls_x509_object) + obj->der_len;
    tls_secure_memzero(obj, total);
    tls_x509_free(obj);
}

/* OID byte strings for the three signature algorithms we recognise. */
static const uint8_t oid_rsa_encryption[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01  /* rsaEncryption (SPKI key type) */
};
static const uint8_t oid_sha256_rsa_pkcs1[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b  /* sha256WithRSAEncryption */
};
static const uint8_t oid_rsassa_pss[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a  /* id-RSASSA-PSS */
};
static const uint8_t oid_ecdsa_sha256[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02          /* ecdsa-with-SHA256 */
};

tls_alg_t tls_x509_oid_to_sig_alg(const uint8_t *oid, size_t oid_len)
{
    if (!oid || oid_len == 0)
    {
        return TLS_ALG_UNKNOWN;
    }
    /* rsaEncryption: the SPKI key-type OID used in SubjectPublicKeyInfo.
     * Distinct from sha256WithRSAEncryption (the signature algorithm OID)
     * but maps to the same RSA key representation. */
    if (oid_len == sizeof(oid_rsa_encryption) &&
        memcmp(oid, oid_rsa_encryption, oid_len) == 0)
    {
        return TLS_ALG_RSA_PKCS1_SHA256;
    }
    if (oid_len == sizeof(oid_sha256_rsa_pkcs1) &&
        memcmp(oid, oid_sha256_rsa_pkcs1, oid_len) == 0)
    {
        return TLS_ALG_RSA_PKCS1_SHA256;
    }
    if (oid_len == sizeof(oid_rsassa_pss) &&
        memcmp(oid, oid_rsassa_pss, oid_len) == 0)
    {
        return TLS_ALG_RSA_PSS_RSAE_SHA256;
    }
    if (oid_len == sizeof(oid_ecdsa_sha256) &&
        memcmp(oid, oid_ecdsa_sha256, oid_len) == 0)
    {
        return TLS_ALG_ECDSA_SECP256R1_SHA256;
    }
    return TLS_ALG_UNKNOWN;
}

tls_key_op_result_t tls_x509_signature_verify(const uint8_t *content, size_t content_len,
                                               const uint8_t *sig, size_t sig_len,
                                               const struct tls_key *key)
{
    if (!content || !sig || !key)
    {
        return TLS_KEY_OP_INVALID;
    }

    if (!TLS_ALG_IS_SIGNING(key->alg))
    {
        return TLS_KEY_OP_UNKNOWN;
    }

    /* Hash the content. */
    struct tls_hash_context hash_ctx;
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return TLS_KEY_OP_INVALID;
    }
    tls_hash_update(&hash_ctx, content, content_len);
    tls_hash_digest(&hash_ctx, digest);

    bool ok = false;
    switch (key->alg)
    {
        case TLS_ALG_RSA_PKCS1_SHA256:
            ok = tls_rsa_pkcs1_v15_sha256_verify(sig, sig_len, digest, &key->rsa);
            break;

        case TLS_ALG_RSA_PSS_RSAE_SHA256:
            if (sig_len > RSA_TRANSIENT_SIZE)
            {
                return TLS_KEY_OP_INVALID;
            }
            {
                uint8_t *em = __rsa_transient;
                if (tls_rsa_decrypt_signature(sig, sig_len, em, &key->rsa))
                {
                    ok = tls_rsa_pss_verify(em, key->rsa.mod_len, digest,
                                            TLS_SHA256_DIGEST_LEN, TLS_HASH_SHA256);
                }
                tls_secure_memzero(em, key->rsa.mod_len);
            }
            break;

        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return TLS_KEY_OP_UNSUPPORTED;

        default:
            return TLS_KEY_OP_UNKNOWN;
    }

    return ok ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
}

tls_key_op_result_t tls_x509_signature_verify_digest(const uint8_t digest[32],
                                                      const uint8_t *sig, size_t sig_len,
                                                      const struct tls_key *key)
{
    if (!digest || !sig || !key)
    {
        return TLS_KEY_OP_INVALID;
    }

    if (!TLS_ALG_IS_SIGNING(key->alg))
    {
        return TLS_KEY_OP_UNKNOWN;
    }

    bool ok = false;
    switch (key->alg)
    {
        case TLS_ALG_RSA_PKCS1_SHA256:
            ok = tls_rsa_pkcs1_v15_sha256_verify(sig, sig_len, digest, &key->rsa);
            break;

        case TLS_ALG_RSA_PSS_RSAE_SHA256:
            if (sig_len > RSA_TRANSIENT_SIZE)
            {
                return TLS_KEY_OP_INVALID;
            }
            {
                uint8_t *em = __rsa_transient;
                if (tls_rsa_decrypt_signature(sig, sig_len, em, &key->rsa))
                {
                    ok = tls_rsa_pss_verify(em, key->rsa.mod_len, digest,
                                            TLS_SHA256_DIGEST_LEN, TLS_HASH_SHA256);
                }
                tls_secure_memzero(em, key->rsa.mod_len);
            }
            break;

        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return TLS_KEY_OP_UNSUPPORTED;

        default:
            return TLS_KEY_OP_UNKNOWN;
    }

    return ok ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
}
