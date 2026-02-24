#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/base64.h"
#include "../includes/asn1.h"
#include "../includes/bytes.h"
#include "../includes/keyobject.h"
#include "../includes/x509.h"
#include "../includes/tls.h"

static void *tls_x509_alloc(size_t size)
{
    return tls_fileio_alloc(size);
}

static void tls_x509_free(void *ptr)
{
    tls_fileio_free(ptr);
}

/*
 * Field index contract used by handshake.c and truststore tests.
 * Keep this mapping stable unless all call sites are updated in lockstep.
 */
#define TLS_X509_IDX_SUBJSIGALG 0
#define TLS_X509_IDX_ISSUERNAME 1
#define TLS_X509_IDX_VALIDBEFORE 2
#define TLS_X509_IDX_VALIDAFTER 3
#define TLS_X509_IDX_SUBJECTNAME 4
#define TLS_X509_IDX_SPKIRAW 5
#define TLS_X509_IDX_PKEYALG 6
#define TLS_X509_IDX_PKEYPARAM 7
#define TLS_X509_IDX_PKEYBITS 8
#define TLS_X509_IDX_EXTENSIONS 9
#define TLS_X509_IDX_CASIGALG 10
#define TLS_X509_IDX_CASIGPARAM 11
#define TLS_X509_IDX_CASIGVAL 12

static void tls_x509_set_field(struct tls_asn1_serialization *f,
                               char *name,
                               uint8_t tag,
                               const uint8_t *data,
                               size_t len)
{
    f->name = name;
    f->tag = tag;
    f->data = (uint8_t *)data;
    f->len = len;
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

    if (tls_asn1_next(&c, &param))
    {
        /* Current callers only expose OBJECT IDENTIFIER params in output. */
        if (param_out && tls_asn1_tag_number(param.tag) == ASN1_OBJECTID)
        {
            param_out->tag = param.tag;
            param_out->data = (uint8_t *)param.value;
            param_out->len = param.len;
        }
        else if (tls_asn1_tag_number(param.tag) != ASN1_NULL)
        {
            /* Reject unexpected parameter encoding to keep parser strict. */
            return false;
        }
    }
    else if (!param_optional)
    {
        return false;
    }

    return true;
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
            return false;
        }
        if (!tls_asn1_child_cursor(&ext_tlv, &ext_item_cursor))
        {
            return false;
        }
        if (!tls_asn1_next(&ext_item_cursor, &oid_tlv))
        {
            return false;
        }
        if (tls_asn1_tag_number(oid_tlv.tag) != ASN1_OBJECTID)
        {
            return false;
        }

        if (!tls_asn1_next(&ext_item_cursor, &maybe_critical_tlv))
        {
            return false;
        }
        if (tls_asn1_tag_number(maybe_critical_tlv.tag) == ASN1_BOOLEAN)
        {
            if (!tls_asn1_next(&ext_item_cursor, &value_tlv))
            {
                return false;
            }
        }
        else
        {
            value_tlv = maybe_critical_tlv;
        }

        if (tls_asn1_tag_number(value_tlv.tag) != ASN1_OCTETSTRING)
        {
            return false;
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
    struct tls_asn1_serialization fields[13];
    struct tls_x509_parse_result parsed = {0};

    if (!tls_x509_parse_certificate(cert_der, cert_len, fields, &parsed))
    {
        return false;
    }

    if (!parsed.extensions || !parsed.extensions->data || parsed.extensions->len == 0)
    {
        return false;
    }
    return tls_x509_has_valid_constraints(parsed.extensions->data, parsed.extensions->len);
}

bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len,
                                struct tls_asn1_serialization fields[13],
                                struct tls_x509_parse_result *out)
{
    struct tls_asn1_cursor top_cursor;
    struct tls_asn1_tlv cert_seq;
    struct tls_asn1_cursor cert_items;
    struct tls_asn1_tlv tbs;
    struct tls_asn1_tlv ca_sig_alg;
    struct tls_asn1_tlv ca_sig_val;

    if (!cert_der || cert_len == 0 || !fields || !out)
    {
        return false;
    }

    memset(fields, 0, sizeof(struct tls_asn1_serialization) * 13);
    memset(out, 0, sizeof(*out));

    if (!tls_asn1_cursor_init(&top_cursor, cert_der, cert_len) ||
        !tls_asn1_next(&top_cursor, &cert_seq))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(cert_seq.tag) || tls_asn1_tag_number(cert_seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&cert_seq, &cert_items) ||
        !tls_asn1_next(&cert_items, &tbs) ||
        !tls_asn1_next(&cert_items, &ca_sig_alg) ||
        !tls_asn1_next(&cert_items, &ca_sig_val))
    {
        return false;
    }
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    if (!tls_asn1_tag_constructed(tbs.tag) || tls_asn1_tag_number(tbs.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (tls_asn1_tag_number(ca_sig_val.tag) != ASN1_BITSTRING)
    {
        return false;
    }

    {
        struct tls_asn1_cursor tbs_cursor;
        struct tls_asn1_tlv item;
        struct tls_asn1_tlv sig_alg;
        struct tls_asn1_tlv issuer;
        struct tls_asn1_tlv validity;
        struct tls_asn1_tlv subject;
        struct tls_asn1_tlv spki;

        if (!tls_asn1_child_cursor(&tbs, &tbs_cursor))
        {
            return false;
        }

        if (!tls_asn1_next(&tbs_cursor, &item))
        {
            return false;
        }
        /* version is [0] EXPLICIT and optional in v1 certs. */
        if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
            tls_asn1_tag_number(item.tag) == 0 &&
            tls_asn1_tag_constructed(item.tag))
        {
            if (!tls_asn1_next(&tbs_cursor, &item))
            {
                return false;
            }
        }

        if (tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
        {
            return false;
        }
        if (!tls_asn1_next(&tbs_cursor, &sig_alg) ||
            !tls_asn1_next(&tbs_cursor, &issuer) ||
            !tls_asn1_next(&tbs_cursor, &validity) ||
            !tls_asn1_next(&tbs_cursor, &subject) ||
            !tls_asn1_next(&tbs_cursor, &spki))
        {
            return false;
        }

        if (!tls_x509_parse_algorithm_identifier(&sig_alg,
                                                 &fields[TLS_X509_IDX_SUBJSIGALG],
                                                 NULL,
                                                 true))
        {
            return false;
        }
        fields[TLS_X509_IDX_SUBJSIGALG].name = "algorithm";

        if (!tls_x509_parse_name_common_name(&issuer, &fields[TLS_X509_IDX_ISSUERNAME]))
        {
            return false;
        }
        fields[TLS_X509_IDX_ISSUERNAME].name = "issuerName";

        {
            struct tls_asn1_cursor validity_cursor;
            struct tls_asn1_tlv not_before;
            struct tls_asn1_tlv not_after;

            if (!tls_asn1_tag_constructed(validity.tag) || tls_asn1_tag_number(validity.tag) != ASN1_SEQUENCE)
            {
                return false;
            }
            if (!tls_asn1_child_cursor(&validity, &validity_cursor) ||
                !tls_asn1_next(&validity_cursor, &not_before) ||
                !tls_asn1_next(&validity_cursor, &not_after))
            {
                return false;
            }
            if (!((tls_asn1_tag_number(not_before.tag) == ASN1_UTCTIME) ||
                  (tls_asn1_tag_number(not_before.tag) == ASN1_GENERALIZEDTIME)))
            {
                return false;
            }
            if (!((tls_asn1_tag_number(not_after.tag) == ASN1_UTCTIME) ||
                  (tls_asn1_tag_number(not_after.tag) == ASN1_GENERALIZEDTIME)))
            {
                return false;
            }

            tls_x509_set_field(&fields[TLS_X509_IDX_VALIDBEFORE],
                               "valid-before",
                               not_before.tag,
                               not_before.value,
                               not_before.len);
            tls_x509_set_field(&fields[TLS_X509_IDX_VALIDAFTER],
                               "valid-after",
                               not_after.tag,
                               not_after.value,
                               not_after.len);
        }

        if (!tls_x509_parse_name_common_name(&subject, &fields[TLS_X509_IDX_SUBJECTNAME]))
        {
            return false;
        }
        fields[TLS_X509_IDX_SUBJECTNAME].name = "subjectName";

        if (!tls_asn1_tag_constructed(spki.tag) || tls_asn1_tag_number(spki.tag) != ASN1_SEQUENCE)
        {
            return false;
        }
        tls_x509_set_field(&fields[TLS_X509_IDX_SPKIRAW],
                           "SubjectPublicKeyInfo",
                           spki.tag,
                           spki.tlv,
                           spki.header_len + spki.len);

        {
            struct tls_asn1_cursor spki_cursor;
            struct tls_asn1_tlv spki_alg;
            struct tls_asn1_tlv spki_bits;

            if (!tls_asn1_child_cursor(&spki, &spki_cursor) ||
                !tls_asn1_next(&spki_cursor, &spki_alg) ||
                !tls_asn1_next(&spki_cursor, &spki_bits))
            {
                return false;
            }
            if (!tls_x509_parse_algorithm_identifier(&spki_alg,
                                                     &fields[TLS_X509_IDX_PKEYALG],
                                                     &fields[TLS_X509_IDX_PKEYPARAM],
                                                     true))
            {
                return false;
            }
            fields[TLS_X509_IDX_PKEYALG].name = "algorithm";
            fields[TLS_X509_IDX_PKEYPARAM].name = "parameters";

            if (tls_asn1_tag_number(spki_bits.tag) != ASN1_BITSTRING)
            {
                return false;
            }
            tls_x509_set_field(&fields[TLS_X509_IDX_PKEYBITS],
                               "subjectPublicKey",
                               spki_bits.tag,
                               spki_bits.value,
                               spki_bits.len);
        }

        while (tls_asn1_next(&tbs_cursor, &item))
        {
            /*
             * extensions is [3] EXPLICIT.
             * We expose the *content* of the wrapper (which starts with
             * SEQUENCE OF Extension) so constraints parser can iterate it.
             */
            if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
                tls_asn1_tag_number(item.tag) == 3 &&
                tls_asn1_tag_constructed(item.tag))
            {
                tls_x509_set_field(&fields[TLS_X509_IDX_EXTENSIONS],
                                   "extensions",
                                   item.tag,
                                   item.value,
                                   item.len);
                break;
            }
        }
    }

    if (!tls_x509_parse_algorithm_identifier(&ca_sig_alg,
                                             &fields[TLS_X509_IDX_CASIGALG],
                                             &fields[TLS_X509_IDX_CASIGPARAM],
                                             true))
    {
        return false;
    }
    fields[TLS_X509_IDX_CASIGALG].name = "algorithm";
    fields[TLS_X509_IDX_CASIGPARAM].name = "parameters";
    tls_x509_set_field(&fields[TLS_X509_IDX_CASIGVAL],
                       "signatureValue",
                       ca_sig_val.tag,
                       ca_sig_val.value,
                       ca_sig_val.len);

    out->issuer_cn = &fields[TLS_X509_IDX_ISSUERNAME];
    out->subject_cn = &fields[TLS_X509_IDX_SUBJECTNAME];
    out->valid_before = &fields[TLS_X509_IDX_VALIDBEFORE];
    out->valid_after = &fields[TLS_X509_IDX_VALIDAFTER];
    out->spki_raw = &fields[TLS_X509_IDX_SPKIRAW];
    out->spki_algorithm = &fields[TLS_X509_IDX_PKEYALG];
    out->spki_key_bits = &fields[TLS_X509_IDX_PKEYBITS];
    out->extensions = &fields[TLS_X509_IDX_EXTENSIONS];

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

bool tls_x509_import_and_parse_certificate(const char *pem_data, size_t size,
                                           uint8_t *der_out, size_t der_out_len,
                                           size_t *der_written,
                                           struct tls_asn1_serialization fields[13],
                                           struct tls_x509_parse_result *out)
{
    size_t parsed_der_len = 0;

    if (!pem_data || size == 0 || !der_out || !der_written || !fields || !out)
    {
        return false;
    }

    if (!tls_x509_decode_pem_certificate(pem_data,
                                         size,
                                         der_out,
                                         der_out_len,
                                         &parsed_der_len))
    {
        return false;
    }

    *der_written = parsed_der_len;
    return tls_x509_parse_certificate(der_out, parsed_der_len, fields, out);
}

struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size)
{
    size_t der_cap;
    size_t total_len;
    struct tls_x509_object *obj;

    if (!pem_data || size == 0)
    {
        return NULL;
    }

    /* PEM decode writes base64 text before in-place decode, so cap must
       accommodate input text length. */
    der_cap = size;
    total_len = sizeof(struct tls_x509_object) + der_cap;
    obj = (struct tls_x509_object *)tls_x509_alloc(total_len);
    if (!obj)
    {
        return NULL;
    }
    memset(obj, 0, total_len);

    if (!tls_x509_import_and_parse_certificate(pem_data,
                                               size,
                                               obj->der,
                                               der_cap,
                                               &obj->der_len,
                                               obj->fields,
                                               &obj->parsed))
    {
        tls_secure_memzero(obj, total_len);
        tls_x509_free(obj);
        return NULL;
    }

    obj->length = total_len;
    obj->type = TLS_CERTIFICATE;
    return obj;
}

void tls_x509_object_destroy(struct tls_x509_object *obj)
{
    if (!obj)
    {
        return;
    }
    tls_secure_memzero(obj, obj->length);
    tls_x509_free(obj);
}
