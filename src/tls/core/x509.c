#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/base64.h"
#include "../includes/asn1.h"
#include "../includes/bytes.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/x509.h"
#include "x509_internal.h"
#include "ip_identity.h"
#include "key_internal.h"
#include "../includes/tls.h"
#include "../includes/crypto_guard.h"

/* P-256 and P-384 public API forward declarations (assembly in p256.s / p384.s). */
bool tls_p256_verify(const uint8_t sig[64], const uint8_t hash[32],
                     const uint8_t pub[65]);
bool tls_p384_verify(const uint8_t sig[96], const uint8_t hash[48],
                     const uint8_t pub[97]);

#define LWIP_DBG_FILE_ID LWIP_FILE_X509
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

const uint8_t *tls_ecdsa_parse_int(const uint8_t *der, size_t len,
                                   uint8_t out[32])
{
    size_t ilen;
    const uint8_t *v;

    if (!der || len < 3 || der[0] != 0x02)
        return NULL;
    ilen = der[1];
    /* ilen > 33 also rejects long-form lengths (0x80..0xFF). */
    if (ilen == 0 || ilen > 33 || ilen > len - 2)
        return NULL;
    v = der + 2;
    if (v[0] & 0x80)
        return NULL;                    /* negative: invalid for r/s */
    if (v[0] == 0x00)
    {
        /* A leading 0x00 is only legal DER as a sign pad before a byte with
         * the high bit set.  A lone 0x00 (value 0) is also rejected: r/s = 0
         * is never valid and tls_p256_verify would reject it anyway. */
        if (ilen < 2 || !(v[1] & 0x80))
            return NULL;
        v++;
        ilen--;
    }
    if (ilen > 32)
        return NULL;
    memset(out, 0, 32 - ilen);
    memcpy(out + (32 - ilen), v, ilen);
    return v + ilen;
}

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
    return tag == ASN1_UTF8STRING || tag == ASN1_PRINTABLESTRING ||
           tag == ASN1_TELETEXSTRING || tag == ASN1_IA5STRING ||
           tag == ASN1_BMPSTRING || tag == ASN1_UNIVERSALSTRING ||
           tag == ASN1_VISIBLESTRING;
}

static bool tls_x509_oid_eq(const struct tls_asn1_tlv *oid_tlv, const uint8_t *oid, size_t oid_len)
{
    return oid_tlv && oid &&
           oid_tlv->tag == ASN1_OBJECTID &&
           oid_tlv->len == oid_len &&
           memcmp(oid_tlv->value, oid, oid_len) == 0;
}

/* Validate the DER value octets of an OBJECT IDENTIFIER. Each subidentifier
 * is base-128 encoded, must terminate, and must not contain a redundant
 * leading zero continuation octet. The first subidentifier combines arcs
 * zero and one but follows the same base-128 encoding rules. */
static bool tls_x509_oid_value_der(const uint8_t *value, size_t len)
{
    bool at_subidentifier_start = true;

    if (!value || len == 0)
        return false;
    for (size_t i = 0; i < len; i++)
    {
        if (at_subidentifier_start && value[i] == 0x80u)
            return false;
        at_subidentifier_start = (value[i] & 0x80u) == 0;
    }
    return at_subidentifier_start;
}

static bool tls_x509_positive_integer_der(const struct tls_asn1_tlv *v,
                                          bool allow_zero)
{
    if (!v || v->tag != ASN1_INTEGER || v->len == 0 || (v->value[0] & 0x80))
        return false;
    if (v->len > 1 && v->value[0] == 0x00 && !(v->value[1] & 0x80))
        return false;
    if (!allow_zero && v->len == 1 && v->value[0] == 0)
        return false;
    return true;
}

/* Extract AuthorityKeyIdentifier.keyIdentifier (RFC 5280 section 4.2.1.1).
 * The returned pointer borrows the certificate DER. A missing AKI extension,
 * or an AKI containing only issuer/serial, is valid and returns a NULL ID;
 * malformed or duplicate AKI data fails closed. */
static bool tls_x509_parse_authority_key_id(const uint8_t *ext_data,
                                            size_t ext_len,
                                            const uint8_t **key_id,
                                            size_t *key_id_len)
{
    static const uint8_t oid_authority_key_id[] = {0x55, 0x1D, 0x23};
    struct tls_asn1_cursor outer, list;
    struct tls_asn1_tlv item;
    bool have_aki = false;

    if (!key_id || !key_id_len)
        return false;
    *key_id = NULL;
    *key_id_len = 0;
    if (!ext_data || ext_len == 0)
        return true;
    if (!tls_asn1_cursor_init(&outer, ext_data, ext_len) ||
        !tls_asn1_next(&outer, &item))
        return false;

    list = outer;
    if (item.header_len + item.len == ext_len &&
        item.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        if (!tls_asn1_child_cursor(&item, &list))
            return false;
    }
    else
    {
        list.cur = ext_data;
    }

    while (list.cur < list.end)
    {
        struct tls_asn1_cursor ec;
        struct tls_asn1_tlv ext, oid, next, value;

        if (!tls_asn1_next(&list, &ext) ||
            ext.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&ext, &ec) ||
            !tls_asn1_next(&ec, &oid) ||
            oid.tag != ASN1_OBJECTID ||
            !tls_asn1_next(&ec, &next))
            return false;
        if (next.tag == ASN1_BOOLEAN)
        {
            if (next.len != 1 ||
                (next.value[0] != 0x00 && next.value[0] != 0xFF) ||
                !tls_asn1_next(&ec, &value))
                return false;
        }
        else
        {
            value = next;
        }
        if (value.tag != ASN1_OCTETSTRING || ec.cur != ec.end)
            return false;

        if (oid.len == sizeof(oid_authority_key_id) &&
            memcmp(oid.value, oid_authority_key_id,
                   sizeof(oid_authority_key_id)) == 0)
        {
            struct tls_asn1_cursor vc, fields;
            struct tls_asn1_tlv sequence, field;
            uint8_t seen = 0;

            if (have_aki ||
                !tls_asn1_cursor_init(&vc, value.value, value.len) ||
                !tls_asn1_next(&vc, &sequence) || vc.cur != vc.end ||
                sequence.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                !tls_asn1_child_cursor(&sequence, &fields))
                return false;
            have_aki = true;

            while (fields.cur < fields.end)
            {
                uint8_t number;
                if (!tls_asn1_next(&fields, &field) ||
                    tls_asn1_tag_class(field.tag) != ASN1_CONTEXTSPEC)
                    return false;
                number = tls_asn1_tag_number(field.tag);
                if (number > 2 || (seen & (uint8_t)(1u << number)))
                    return false;
                seen |= (uint8_t)(1u << number);
                if ((number == 0 && (tls_asn1_tag_constructed(field.tag) || field.len == 0)) ||
                    (number == 1 && !tls_asn1_tag_constructed(field.tag)) ||
                    (number == 2 && tls_asn1_tag_constructed(field.tag)))
                    return false;
                if (number == 0)
                {
                    *key_id = field.value;
                    *key_id_len = field.len;
                }
            }
        }
    }
    return true;
}

static bool tls_x509_parse_name_common_name(const struct tls_asn1_tlv *name_tlv,
                                            struct tls_asn1_serialization *out)
{
    static const uint8_t oid_common_name[] = {0x55, 0x04, 0x03};
    struct tls_asn1_cursor rdn_cursor;
    struct tls_asn1_tlv rdn_set;

    if (!name_tlv || !out)
    {
        ERROR_CODE(0x01);
        return false;
    }
    if (name_tlv->tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        ERROR_CODE(0x02);
        return false;
    }
    if (!tls_asn1_child_cursor(name_tlv, &rdn_cursor))
    {
        ERROR_CODE(0x03);
        return false;
    }

    /*
     * Name ::= SEQUENCE OF RDN
     * RDN  ::= SET OF AttributeTypeAndValue
     *
     * Only CN (2.5.4.3) is returned. Other RDN string values must never be
     * treated as a CommonName.
     */
    while (tls_asn1_next(&rdn_cursor, &rdn_set))
    {
        struct tls_asn1_cursor set_cursor;
        struct tls_asn1_tlv atv_seq;

        if (rdn_set.tag != (ASN1_CONSTRUCTED | ASN1_SET))
        {
            continue;
        }
        if (!tls_asn1_child_cursor(&rdn_set, &set_cursor))
        {
            ERROR_CODE(0x04);
            return false;
        }

        while (tls_asn1_next(&set_cursor, &atv_seq))
        {
            struct tls_asn1_cursor atv_cursor;
            struct tls_asn1_tlv attr_oid;
            struct tls_asn1_tlv attr_value;

            if (atv_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
            {
                continue;
            }
            if (!tls_asn1_child_cursor(&atv_seq, &atv_cursor) ||
                !tls_asn1_next(&atv_cursor, &attr_oid) ||
                !tls_asn1_next(&atv_cursor, &attr_value))
            {
                ERROR_CODE(0x05);
                return false;
            }
            if (!tls_x509_is_string_tag(attr_value.tag))
            {
                continue;
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

    out->tag = 0;
    out->data = NULL;
    out->len = 0;
    return true;
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
        ERROR_CODE(0x06);
        return false;
    }
    if (alg_tlv->tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        ERROR_CODE(0x07);
        return false;
    }
    if (!tls_asn1_child_cursor(alg_tlv, &c) || !tls_asn1_next(&c, &oid))
    {
        ERROR_CODE(0x08);
        return false;
    }
    if (oid.tag != ASN1_OBJECTID)
    {
        ERROR_CODE(0x09);
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
    static const uint8_t oid_rsassa_pss[] = {TLS_OID_RSASSA_PSS_BYTES};
    bool is_pss = tls_x509_oid_eq(&oid, oid_rsassa_pss, sizeof(oid_rsassa_pss));
    if (tls_asn1_next(&c, &param))
    {
        if (is_pss)
        {
            if (param.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
            {
                ERROR_CODE(0x0a);
                return false;
            }
        }
        else if (param.tag != ASN1_OBJECTID && param.tag != ASN1_NULL)
        {
            ERROR_CODE(0x0b);
            return false;
        }
        if (param_out)
        {
            param_out->tag = param.tag;
            param_out->data = (uint8_t *)param.value;
            param_out->len = param.len;
        }
    }
    else if (!param_optional)
    {
        ERROR_CODE(0x0c);
        return false;
    }

    /* Do not silently accept a second parameter or a truncated TLV. */
    return c.cur == c.end;
}

static uint8_t nc_ascii_lower(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

static bool nc_equal_ci(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (nc_ascii_lower(a[i]) != nc_ascii_lower(b[i]))
            return false;
    return true;
}

/* Returns true if `name` matches the dNSName constraint `constraint`.
 * RFC 5280 §4.2.1.10: a leading '.' in the constraint is a domain suffix
 * match (".example.com" matches "a.example.com"); otherwise exact match or
 * subdomain. Section 7.2 requires case-insensitive, label-wise comparison. */
static bool nc_dns_matches(const uint8_t *name, size_t name_len,
                            const uint8_t *constraint, size_t clen)
{
    if (clen == 0 || name_len == 0)
        return false;
    if (constraint[0] == '.')
    {
        if (name_len <= clen)
            return false;
        return nc_equal_ci(name + name_len - clen, constraint, clen);
    }
    if (name_len == clen)
        return nc_equal_ci(name, constraint, clen);
    if (name_len > clen + 1 && name[name_len - clen - 1] == '.' &&
        nc_equal_ci(name + name_len - clen, constraint, clen))
        return true;
    return false;
}

static bool nc_dns_constraint_valid(const uint8_t *name, size_t len)
{
    size_t label_start = 0;

    if (!name || len == 0)
        return false;
    if (name[0] == '.')
        label_start = 1;
    if (label_start == len || len - label_start > 253)
        return false;
    for (size_t i = label_start; i <= len; i++)
    {
        if (i == len || name[i] == '.')
        {
            size_t label_len = i - label_start;
            if (label_len == 0 || label_len > 63 ||
                name[label_start] == '-' || name[i - 1] == '-')
                return false;
            label_start = i + 1;
            continue;
        }
        uint8_t c = name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

static bool nc_name_der_valid(const uint8_t *der, size_t der_len)
{
    struct tls_asn1_cursor outer, rdns;
    struct tls_asn1_tlv name, rdn;

    if (!tls_asn1_cursor_init(&outer, der, der_len) ||
        !tls_asn1_next(&outer, &name) || outer.cur != outer.end ||
        name.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        !tls_asn1_child_cursor(&name, &rdns))
        return false;
    while (rdns.cur < rdns.end)
    {
        struct tls_asn1_cursor attrs;
        struct tls_asn1_tlv attr;
        if (!tls_asn1_next(&rdns, &rdn) ||
            rdn.tag != (ASN1_CONSTRUCTED | ASN1_SET) || rdn.len == 0 ||
            !tls_asn1_child_cursor(&rdn, &attrs))
            return false;
        while (attrs.cur < attrs.end)
        {
            struct tls_asn1_cursor fields;
            struct tls_asn1_tlv oid, value;
            if (!tls_asn1_next(&attrs, &attr) ||
                attr.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                !tls_asn1_child_cursor(&attr, &fields) ||
                !tls_asn1_next(&fields, &oid) || oid.tag != ASN1_OBJECTID ||
                oid.len == 0 || !tls_asn1_next(&fields, &value) ||
                fields.cur != fields.end)
                return false;
        }
    }
    return true;
}

/* RFC 5280 7.1 defines a directoryName subtree by the leading RDNs of a
 * subject Name. This uses exact DER RDN equality, consistent with this
 * stack's documented constrained-platform Name-comparison policy. */
static bool nc_directory_matches(const uint8_t *name, size_t name_len,
                                 const struct tls_asn1_tlv *base)
{
    struct tls_asn1_cursor name_outer, constraint_outer, name_rdns, constraint_rdns;
    struct tls_asn1_tlv name_seq, constraint_seq, name_rdn, constraint_rdn;

    if (!nc_name_der_valid(name, name_len) ||
        !nc_name_der_valid(base->value, base->len) ||
        !tls_asn1_cursor_init(&name_outer, name, name_len) ||
        !tls_asn1_next(&name_outer, &name_seq) ||
        name_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        name_outer.cur != name_outer.end ||
        !tls_asn1_cursor_init(&constraint_outer, base->value, base->len) ||
        !tls_asn1_next(&constraint_outer, &constraint_seq) ||
        constraint_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        constraint_outer.cur != constraint_outer.end ||
        !tls_asn1_child_cursor(&name_seq, &name_rdns) ||
        !tls_asn1_child_cursor(&constraint_seq, &constraint_rdns))
        return false;

    while (constraint_rdns.cur < constraint_rdns.end)
    {
        if (!tls_asn1_next(&constraint_rdns, &constraint_rdn) ||
            !tls_asn1_next(&name_rdns, &name_rdn) ||
            constraint_rdn.header_len + constraint_rdn.len !=
                name_rdn.header_len + name_rdn.len ||
            memcmp(constraint_rdn.tlv, name_rdn.tlv,
                   constraint_rdn.header_len + constraint_rdn.len) != 0)
            return false;
    }
    return true;
}

/* Strictly parse one nameConstraints value and, when name is non-NULL,
 * enforce the subtrees of the matching GeneralName form against that name.
 * The mandatory directoryName form and dNSName are implemented. Other forms
 * fail closed rather than being silently ignored. */
static bool nc_validate_name(const uint8_t *nc_value, size_t nc_len,
                             uint8_t name_form,
                             const uint8_t *name, size_t name_len)
{
    struct tls_asn1_cursor nc_cur, subtrees_cur;
    struct tls_asn1_tlv nc_seq, subtrees;
    bool seen_permitted = false, seen_excluded = false;
    bool has_permitted = false, name_permitted = false;

    if (!tls_asn1_cursor_init(&nc_cur, nc_value, nc_len) ||
        !tls_asn1_next(&nc_cur, &nc_seq) ||
        nc_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        nc_cur.cur != nc_cur.end || nc_seq.len == 0 ||
        !tls_asn1_child_cursor(&nc_seq, &nc_cur))
        return false;

    while (nc_cur.cur < nc_cur.end)
    {
        if (!tls_asn1_next(&nc_cur, &subtrees))
            return false;
        bool is_permitted = subtrees.tag == 0xA0u;
        bool is_excluded = subtrees.tag == 0xA1u;
        if ((!is_permitted && !is_excluded) ||
            (is_permitted && (seen_permitted || seen_excluded)) ||
            (is_excluded && seen_excluded) || subtrees.len == 0)
            return false;
        seen_permitted |= is_permitted;
        seen_excluded |= is_excluded;

        if (!tls_asn1_child_cursor(&subtrees, &subtrees_cur))
            return false;

        while (subtrees_cur.cur < subtrees_cur.end)
        {
            struct tls_asn1_tlv subtree, base;
            if (!tls_asn1_next(&subtrees_cur, &subtree) ||
                subtree.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
                return false;
            struct tls_asn1_cursor sub_cur;
            if (!tls_asn1_child_cursor(&subtree, &sub_cur) ||
                !tls_asn1_next(&sub_cur, &base))
                return false;

            /* minimum has DEFAULT 0 and must therefore be absent in DER;
             * RFC 5280 also requires maximum to be absent. */
            if ((base.tag != 0x82u && base.tag != 0xA4u) ||
                base.len == 0 || sub_cur.cur != sub_cur.end ||
                (base.tag == 0x82u &&
                 !nc_dns_constraint_valid(base.value, base.len)))
                return false;
            if (base.tag == 0xA4u)
            {
                struct tls_asn1_cursor dc;
                struct tls_asn1_tlv dn;
                if (!nc_name_der_valid(base.value, base.len) ||
                    !tls_asn1_cursor_init(&dc, base.value, base.len) ||
                    !tls_asn1_next(&dc, &dn) || dc.cur != dc.end ||
                    dn.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
                    return false;
            }

            if (name && base.tag == name_form)
            {
                bool matches = base.tag == 0x82u
                    ? nc_dns_matches(name, name_len, base.value, base.len)
                    : nc_directory_matches(name, name_len, &base);
                if (is_permitted)
                {
                    has_permitted = true;
                    name_permitted |= matches;
                }
                else if (matches)
                    return false;
            }
        }
    }

    if (!seen_permitted && !seen_excluded)
        return false;
    if (name && has_permitted && !name_permitted)
        return false;
    return true;
}

/* Validate the extension subset needed by this client path builder. Anything
 * critical that we do not interpret is rejected; nameConstraints are parsed
 * for directoryName and dNSName entries, then enforced by the chain walker. */
bool tls_x509_validate_path_extensions(const struct tls_x509_object *cert,
                                       bool is_ca, size_t subordinate_ca_count)
{
    static const uint8_t oid_basic_constraints[] = {0x55, 0x1D, 0x13};
    static const uint8_t oid_key_usage[] = {0x55, 0x1D, 0x0F};
    static const uint8_t oid_subject_alt_name[] = {0x55, 0x1D, 0x11};
    static const uint8_t oid_extended_key_usage[] = {0x55, 0x1D, 0x25};
    static const uint8_t oid_name_constraints[] = {0x55, 0x1D, 0x1E};
    static const uint8_t oid_server_auth[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    static const uint8_t oid_any_eku[] = {0x55, 0x1D, 0x25, 0x00};
    struct tls_asn1_cursor outer, list;
    struct tls_asn1_tlv item;
    bool have_bc = false, ca = false, have_path_len = false;
    bool have_ku = false, digital_signature = false, key_cert_sign = false;
    bool have_eku = false, server_auth = false;
    const uint8_t *extensions_start;
    size_t path_len = 0;

    DEBUG(); /* path-extension validation entry: is_ca / subordinate_ca_count given by caller */
    if (!cert || !cert->extensions || cert->extensions_len == 0)
        return !is_ca; /* leaf extensions may be absent; CA constraints may not */
    if (!tls_asn1_cursor_init(&outer, cert->extensions, cert->extensions_len))
        return false;
    list = outer;
    if (!tls_asn1_next(&outer, &item))
        return false;
    if (item.header_len + item.len == cert->extensions_len &&
        item.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        if (!tls_asn1_child_cursor(&item, &list)) return false;
    }
    else
    {
        list = outer;
        list.cur = cert->extensions;
    }
    extensions_start = list.cur;

    while (list.cur < list.end)
    {
        struct tls_asn1_cursor ec, vc;
        struct tls_asn1_tlv ext, oid, next, value, inner;
        bool critical = false;
        if (!tls_asn1_next(&list, &ext) ||
            ext.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&ext, &ec) ||
            !tls_asn1_next(&ec, &oid) ||
            oid.tag != ASN1_OBJECTID ||
            !tls_asn1_next(&ec, &next))
            return false;
        if (next.tag == ASN1_BOOLEAN)
        {
            if (next.len != 1 || (next.value[0] != 0x00 && next.value[0] != 0xFF) ||
                !tls_asn1_next(&ec, &value))
                return false;
            /* critical BOOLEAN has DEFAULT FALSE and DER omits default values. */
            if (next.value[0] == 0x00)
                return false;
            critical = next.value[0] != 0;
        }
        else value = next;
        if (value.tag != ASN1_OCTETSTRING || ec.cur != ec.end)
            return false;

        /* RFC 5280 4.2 permits no duplicate extension, including unknown
         * non-critical extensions. Scan the already parsed prefix; extension
         * lists are short and this avoids fixed-size bookkeeping. */
        {
            struct tls_asn1_cursor prior = {extensions_start, ext.tlv};
            struct tls_asn1_tlv prior_ext;
            while (prior.cur < prior.end)
            {
                struct tls_asn1_cursor prior_body;
                struct tls_asn1_tlv prior_oid;
                if (!tls_asn1_next(&prior, &prior_ext) ||
                    prior_ext.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                    !tls_asn1_child_cursor(&prior_ext, &prior_body) ||
                    !tls_asn1_next(&prior_body, &prior_oid) ||
                    prior_oid.tag != ASN1_OBJECTID)
                    return false;
                if (prior_oid.len == oid.len &&
                    memcmp(prior_oid.value, oid.value, oid.len) == 0)
                    return false;
            }
        }

        bool is_bc = oid.len == sizeof(oid_basic_constraints) &&
                     memcmp(oid.value, oid_basic_constraints, sizeof(oid_basic_constraints)) == 0;
        bool is_ku = oid.len == sizeof(oid_key_usage) &&
                     memcmp(oid.value, oid_key_usage, sizeof(oid_key_usage)) == 0;
        bool is_san = oid.len == sizeof(oid_subject_alt_name) &&
                      memcmp(oid.value, oid_subject_alt_name, sizeof(oid_subject_alt_name)) == 0;
        bool is_eku = oid.len == sizeof(oid_extended_key_usage) &&
                      memcmp(oid.value, oid_extended_key_usage, sizeof(oid_extended_key_usage)) == 0;
        bool is_nc = oid.len == sizeof(oid_name_constraints) &&
                     memcmp(oid.value, oid_name_constraints, sizeof(oid_name_constraints)) == 0;

        if (is_nc)
        {
            /* RFC 5280 4.2.1.10: only CA certificates may carry this
             * extension and conforming issuers must mark it critical. */
            if (!is_ca || !critical ||
                !nc_validate_name(value.value, value.len, 0, NULL, 0))
                return false;
            continue;
        }
        if (!is_bc && !is_ku && !is_san && !is_eku)
        {
            if (critical) return false;
            continue;
        }
        if (is_san) continue; /* Fully parsed by hostname validation for leaves. */
        if (!tls_asn1_cursor_init(&vc, value.value, value.len) ||
            !tls_asn1_next(&vc, &inner) || vc.cur != vc.end)
            return false;

        if (is_bc)
        {
            struct tls_asn1_cursor bc;
            struct tls_asn1_tlv v;
            if (have_bc || inner.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                !tls_asn1_child_cursor(&inner, &bc)) return false;
            have_bc = true;
            if (bc.cur < bc.end)
            {
                if (!tls_asn1_next(&bc, &v)) return false;
                if (v.tag == ASN1_BOOLEAN)
                {
                    if (v.len != 1 || (v.value[0] != 0x00 && v.value[0] != 0xFF)) return false;
                    /* cA BOOLEAN also has DEFAULT FALSE. */
                    if (v.value[0] == 0x00) return false;
                    ca = v.value[0] != 0;
                    if (bc.cur == bc.end) goto basic_constraints_done;
                    if (!tls_asn1_next(&bc, &v)) return false;
                }
                if (v.tag != ASN1_INTEGER || v.len == 0 ||
                    v.len > sizeof(size_t) || (v.value[0] & 0x80) ||
                    (v.len > 1 && v.value[0] == 0x00 && !(v.value[1] & 0x80))) return false;
                for (size_t i = 0; i < v.len; i++) path_len = (path_len << 8) | v.value[i];
                have_path_len = true;
            }
basic_constraints_done:
            if (bc.cur != bc.end || (have_path_len && !ca)) return false;
        }
        else if (is_ku)
        {
            if (have_ku || inner.tag != ASN1_BITSTRING ||
                inner.len < 2 || inner.value[0] > 7) return false;
            {
                uint8_t unused = inner.value[0];
                uint8_t last = inner.value[inner.len - 1];
                uint8_t padding_mask = (uint8_t)((1u << unused) - 1u);
                /* Padding is zero, and DER omits every trailing zero bit from
                 * a named-bit list, so its final used bit must be one. */
                if ((last & padding_mask) != 0 ||
                    (last & (uint8_t)(1u << unused)) == 0)
                    return false;
            }
            have_ku = true;
            digital_signature = (inner.value[1] & 0x80) != 0;
            key_cert_sign = (inner.value[1] & 0x04) != 0;
        }
        else /* extendedKeyUsage */
        {
            struct tls_asn1_cursor eku;
            struct tls_asn1_tlv purpose;
            if (have_eku || inner.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                !tls_asn1_child_cursor(&inner, &eku)) return false;
            have_eku = true;
            while (eku.cur < eku.end)
            {
                if (!tls_asn1_next(&eku, &purpose) ||
                    purpose.tag != ASN1_OBJECTID ||
                    !tls_x509_oid_value_der(purpose.value, purpose.len))
                    return false;
                if ((purpose.len == sizeof(oid_server_auth) &&
                     memcmp(purpose.value, oid_server_auth, sizeof(oid_server_auth)) == 0) ||
                    (purpose.len == sizeof(oid_any_eku) &&
                     memcmp(purpose.value, oid_any_eku, sizeof(oid_any_eku)) == 0))
                    server_auth = true;
            }
        }
    }

    if (is_ca)
    {
        if (!have_bc || !ca)
        {
            DEBUG(); /* CA cert rejected: basicConstraints missing or CA=false */
        }
        else if (have_ku && !key_cert_sign)
        {
            DEBUG(); /* CA cert rejected: keyUsage present but keyCertSign not set */
        }
        else if (have_path_len && subordinate_ca_count > path_len)
        {
            DEBUG(); /* CA cert rejected: chain depth exceeds this cert's pathLenConstraint */
        }
        else if (have_eku && !server_auth)
        {
            DEBUG(); /* CA cert rejected: EKU present but lacks serverAuth/anyEKU */
        }
        return have_bc && ca && (!have_ku || key_cert_sign) &&
               (!have_path_len || subordinate_ca_count <= path_len) &&
               (!have_eku || server_auth);
    }
    if (have_ku && !digital_signature)
    {
        DEBUG(); /* leaf cert rejected: keyUsage present but digitalSignature not set */
    }
    else if (have_eku && !server_auth)
    {
        DEBUG(); /* leaf cert rejected: EKU present but lacks serverAuth/anyEKU */
    }
    return (!have_ku || digital_signature) && (!have_eku || server_auth);
}

static bool nc_store_name(uint8_t form, const uint8_t *name, size_t name_len,
                          uint8_t *out, size_t out_cap, size_t *used)
{
    if (!name || name_len == 0 || name_len > 0xFFFFFFu ||
        name_len > SIZE_MAX - 4u ||
        *used > SIZE_MAX - 4u - name_len)
        return false;
    if (out)
    {
        if (*used + 4u + name_len > out_cap)
            return false;
        out[*used] = form;
        out[*used + 1] = (uint8_t)(name_len >> 16);
        out[*used + 2] = (uint8_t)(name_len >> 8);
        out[*used + 3] = (uint8_t)name_len;
        memcpy(out + *used + 4, name, name_len);
    }
    *used += 4u + name_len;
    return true;
}

/* Retain only names relevant to the supported constraint forms: the subject
 * distinguished Name plus dNSName and directoryName SAN entries. */
bool tls_x509_collect_constraint_names(const struct tls_x509_object *cert,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    static const uint8_t oid_san[] = {0x55, 0x1D, 0x11};
    struct tls_asn1_cursor outer, list;
    struct tls_asn1_tlv item;
    size_t used = 0;

    if (!cert || !out_len)
        return false;
    *out_len = 0;
    if (!nc_name_der_valid(cert->subject_name, cert->subject_name_len) ||
        !nc_store_name(0xA4u, cert->subject_name, cert->subject_name_len,
                       out, out_cap, &used))
        return false;
    if (!cert->extensions || cert->extensions_len == 0)
    {
        *out_len = used;
        return true;
    }
    if (!tls_asn1_cursor_init(&outer, cert->extensions,
                              cert->extensions_len) ||
        !tls_asn1_next(&outer, &item))
        return false;
    list = outer;
    if (item.header_len + item.len == cert->extensions_len &&
        item.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        if (!tls_asn1_child_cursor(&item, &list)) return false;
    }
    else
        list.cur = cert->extensions;

    while (list.cur < list.end)
    {
        struct tls_asn1_cursor ec, vc, names;
        struct tls_asn1_tlv ext, oid, value, name, seq;
        if (!tls_asn1_next(&list, &ext) ||
            ext.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&ext, &ec) ||
            !tls_asn1_next(&ec, &oid) || oid.tag != ASN1_OBJECTID ||
            !tls_asn1_next(&ec, &value))
            return false;
        if (value.tag == ASN1_BOOLEAN && !tls_asn1_next(&ec, &value))
            return false;
        if (value.tag != ASN1_OCTETSTRING || ec.cur != ec.end)
            return false;
        if (oid.len != sizeof(oid_san) ||
            memcmp(oid.value, oid_san, sizeof(oid_san)) != 0)
            continue;
        if (!tls_asn1_cursor_init(&vc, value.value, value.len) ||
            !tls_asn1_next(&vc, &seq) || vc.cur != vc.end ||
            seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) || seq.len == 0 ||
            !tls_asn1_child_cursor(&seq, &names))
            return false;
        while (names.cur < names.end)
        {
            if (!tls_asn1_next(&names, &name))
                return false;
            if (name.tag != 0x82u && name.tag != 0xA4u)
                continue;
            if (name.tag == 0xA4u)
            {
                struct tls_asn1_cursor dc;
                struct tls_asn1_tlv dn;
                if (!nc_name_der_valid(name.value, name.len) ||
                    !tls_asn1_cursor_init(&dc, name.value, name.len) ||
                    !tls_asn1_next(&dc, &dn) || dc.cur != dc.end ||
                    dn.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
                    return false;
            }
            if (!nc_store_name(name.tag, name.value, name.len,
                               out, out_cap, &used))
                return false;
        }
        break;
    }
    *out_len = used;
    return true;
}

bool tls_x509_name_constraints_allow(const struct tls_x509_object *issuer,
                                     const uint8_t *names,
                                     size_t names_len)
{
    static const uint8_t oid_nc[] = {0x55, 0x1D, 0x1E};
    struct tls_asn1_cursor outer, list;
    struct tls_asn1_tlv item;

    if (!issuer || (names_len != 0 && !names))
        return false;
    if (!issuer->extensions || issuer->extensions_len == 0)
        return true;
    if (!tls_asn1_cursor_init(&outer, issuer->extensions,
                              issuer->extensions_len) ||
        !tls_asn1_next(&outer, &item))
        return false;
    list = outer;
    if (item.header_len + item.len == issuer->extensions_len &&
        item.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        if (!tls_asn1_child_cursor(&item, &list)) return false;
    }
    else
        list.cur = issuer->extensions;

    while (list.cur < list.end)
    {
        struct tls_asn1_cursor ec;
        struct tls_asn1_tlv ext, oid, value;
        if (!tls_asn1_next(&list, &ext) ||
            ext.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&ext, &ec) ||
            !tls_asn1_next(&ec, &oid) || oid.tag != ASN1_OBJECTID ||
            !tls_asn1_next(&ec, &value))
            return false;
        if (value.tag == ASN1_BOOLEAN && !tls_asn1_next(&ec, &value))
            return false;
        if (value.tag != ASN1_OCTETSTRING || ec.cur != ec.end)
            return false;
        if (oid.len != sizeof(oid_nc) ||
            memcmp(oid.value, oid_nc, sizeof(oid_nc)) != 0)
            continue;

        size_t off = 0;
        while (off < names_len)
        {
            uint8_t form;
            size_t name_len;
            if (names_len - off < 4)
                return false;
            form = names[off];
            name_len = ((size_t)names[off + 1] << 16) |
                       ((size_t)names[off + 2] << 8) | names[off + 3];
            off += 4;
            if ((form != 0x82u && form != 0xA4u) ||
                name_len > names_len - off ||
                !nc_validate_name(value.value, value.len, form,
                                  names + off, name_len))
                return false;
            off += name_len;
        }
        return nc_validate_name(value.value, value.len, 0, NULL, 0);
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
static bool tls_x509_san_matches(const uint8_t *ext_data, size_t ext_len,
                                     const char *hostname, size_t hostname_len,
                                     const uint8_t *ip, size_t ip_len,
                                     bool *san_present)
{
    static const uint8_t oid_subject_alt_name[] = {0x55, 0x1D, 0x11};
    struct tls_asn1_cursor ext_cursor;
    struct tls_asn1_cursor ext_list_cursor;
    struct tls_asn1_tlv ext_tlv;

    *san_present = false;

    if (!ext_data || ext_len == 0)
    {
        ERROR_CODE(0x30);
        return false;
    }
    if (!tls_asn1_cursor_init(&ext_cursor, ext_data, ext_len))
    {
        ERROR_CODE(0x31);
        return false;
    }

    /* Accept either a SEQUENCE wrapper or the Extension entries directly. */
    ext_list_cursor = ext_cursor;
    if (tls_asn1_next(&ext_cursor, &ext_tlv))
    {
        if ((ext_tlv.header_len + ext_tlv.len) == ext_len &&
            ext_tlv.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
        {
            if (!tls_asn1_child_cursor(&ext_tlv, &ext_list_cursor))
            {
                ERROR_CODE(0x1b);
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
        ERROR_CODE(0x1c);
        return false;
    }

    while (tls_asn1_next(&ext_list_cursor, &ext_tlv))
    {
        struct tls_asn1_cursor ext_item_cursor;
        struct tls_asn1_tlv oid_tlv;
        struct tls_asn1_tlv maybe_critical_tlv;
        struct tls_asn1_tlv value_tlv;

        if (ext_tlv.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
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
        if (oid_tlv.tag != ASN1_OBJECTID)
        {
            continue;
        }

        if (!tls_asn1_next(&ext_item_cursor, &maybe_critical_tlv))
        {
            continue;
        }
        if (maybe_critical_tlv.tag == ASN1_BOOLEAN)
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

        if (value_tlv.tag != ASN1_OCTETSTRING)
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
                ERROR_CODE(0x1d);
                return false;
            }

            /* subjectAltName ::= SEQUENCE OF GeneralName -- the OCTET STRING
             * payload IS the SEQUENCE; walk its children directly. */
            {
                struct tls_asn1_tlv san_seq;
                struct tls_asn1_cursor san_seq_cursor;
                if (!tls_asn1_next(&san_cursor, &san_seq) ||
                    san_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                    san_cursor.cur != san_cursor.end)
                {
                    ERROR_CODE(0x1e);
                    return false;
                }
                if (!tls_asn1_child_cursor(&san_seq, &san_seq_cursor))
                {
                    ERROR_CODE(0x1f);
                    return false;
                }
                san_cursor = san_seq_cursor;
            }

            while (san_cursor.cur < san_cursor.end)
            {
                if (!tls_asn1_next(&san_cursor, &san_item))
                {
                    ERROR_CODE(0x20);
                    return false;
                }
                if (san_item.tag == 0x87 && san_item.len != 4 && san_item.len != 16)
                {
                    ERROR_CODE(0x21);
                    return false;
                }
                if (ip_len)
                {
                    /* iPAddress [7] contains 4 or 16 network-order octets. */
                    if (san_item.tag == 0x87 && san_item.len == ip_len &&
                        memcmp(san_item.value, ip, ip_len) == 0)
                        matched = true;
                    continue;
                }
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

    ERROR_CODE(0x22);
    return false;
}

bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len,
                               const uint8_t *subject_cn, size_t subject_cn_len,
                               const char *hostname)
{
    bool san_present = false;
    size_t hostname_len;

    if (!hostname)
    {
        ERROR_CODE(0x23);
        return false;
    }

    hostname_len = strlen(hostname);
    if (hostname_len != 0 && hostname[hostname_len - 1] == '.')
        hostname_len--;
    if (hostname_len == 0)
    {
        ERROR_CODE(0x24);
        return false;
    }

    uint8_t ip[16];
    int ip_len = tls_identity_ip(hostname, ip);
    if (ip_len < 0)
    {
        /* Malformed IP-literal syntax (e.g. a hex/octal alias): reject
         * outright rather than authenticate it as a DNS identity. */
        ERROR_CODE(0x25);
        return false;
    }

    if (tls_x509_san_matches(ext_data, ext_len, hostname, hostname_len,
                              ip, (size_t)ip_len, &san_present))
        return true;

    (void)subject_cn;
    (void)subject_cn_len;
    if (san_present)
    {
        DEBUG(); /* SAN extension present but none of its entries matched the hostname */
    }
    else
    {
        DEBUG(); /* no SAN extension at all -- RFC 9525 forbids falling back to CN */
    }
    ERROR_CODE(0x26);
    return false; /* RFC 9525: identifiers must come from subjectAltName. */
}

static bool tls_x509_digit_pair(const uint8_t *p, uint32_t *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
    {
        ERROR_CODE(0x28);
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

static bool tls_x509_day_valid(uint32_t year, uint32_t month, uint32_t day)
{
    static const uint8_t dim[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint32_t max = dim[month - 1];

    if (month == 2 && (year % 4u == 0u) && (year % 100u != 0u || year % 400u == 0u))
        max = 29;
    return day <= max;
}

/* Converts a DER UTCTime/GeneralizedTime to Unix seconds. Instants outside the
 * uint32_t range saturate (before 1970 -> 0, after 2106 -> UINT32_MAX) instead
 * of failing: a notAfter of 9999-12-31 (RFC 5280 4.1.2.5, "no well-defined
 * expiration") must stay valid, and saturating is safe in both directions for
 * the window comparison (a far-future notBefore still rejects, a pre-1970
 * notAfter still counts as expired). */
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
        ERROR_CODE(0x29);
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
            ERROR_CODE(0x2a);
            return false;
        }
        if (!tls_x509_digit_pair(v, &yy) ||
            !tls_x509_digit_pair(v + 2, &month) ||
            !tls_x509_digit_pair(v + 4, &day) ||
            !tls_x509_digit_pair(v + 6, &hour) ||
            !tls_x509_digit_pair(v + 8, &minute) ||
            !tls_x509_digit_pair(v + 10, &second))
        {
            ERROR_CODE(0x2b);
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
            ERROR_CODE(0x2c);
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
            ERROR_CODE(0x2d);
            return false;
        }
        year = y_hi * 100u + y_lo;
    }
    else
    {
        ERROR_CODE(0x2e);
        return false;
    }

    if (month < 1 || month > 12 || day < 1 || !tls_x509_day_valid(year, month, day) ||
        hour > 23 || minute > 59 || second > 60 /* allow leap second */)
    {
        ERROR_CODE(0x2f);
        return false;
    }

    days = tls_x509_days_from_civil((int32_t)year, month, day);
    secs64 = (int64_t)days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
    if (secs64 < 0)
        secs64 = 0;
    else if (secs64 > (int64_t)UINT32_MAX)
        secs64 = (int64_t)UINT32_MAX;

    *out_secs = (uint32_t)secs64;
    return true;
}

bool tls_x509_time_in_validity(const struct tls_x509_object *cert, uint32_t now_secs)
{
    uint32_t not_before_secs;
    uint32_t not_after_secs;

    if (!cert)
    {
        ERROR_CODE(0x31);
        return false;
    }

    if (!tls_x509_time_to_unix(cert->not_before, cert->not_before_len,
                                cert->not_before_tag, &not_before_secs) ||
        !tls_x509_time_to_unix(cert->not_after,  cert->not_after_len,
                                cert->not_after_tag,  &not_after_secs))
    {
        ERROR_CODE(0x32);
        return false;
    }
    if (not_before_secs > not_after_secs)
    {
        /* Malformed/inverted validity window. */
        ERROR_CODE(0x33);
        return false;
    }
    if (now_secs < not_before_secs || now_secs > not_after_secs)
    {
        /* Trace each Unix timestamp as high/low 16-bit words: the compact
         * traceback extra field cannot hold a complete timestamp. Preserve
         * the order below so a remote DAST trace can diagnose clock skew. */
        ERROR_CODE(now_secs >> 16);
        ERROR_CODE(now_secs & 0xffffu);
        ERROR_CODE(not_before_secs >> 16);
        ERROR_CODE(not_before_secs & 0xffffu);
        ERROR_CODE(not_after_secs >> 16);
        ERROR_CODE(not_after_secs & 0xffffu);
        return false;
    }
    return true;
}

bool tls_x509_has_valid_constraints(const uint8_t *ext_data, size_t ext_len)
{
    struct tls_x509_object cert = {0};
    cert.extensions = ext_data;
    cert.extensions_len = ext_len;
    return tls_x509_validate_path_extensions(&cert, true, 0);
}

bool tls_x509_has_required_ca_constraints(const uint8_t *cert_der, size_t cert_len)
{
    struct tls_x509_object parsed = {0};

    if (!tls_x509_parse_certificate(cert_der, cert_len, &parsed))
    {
        ERROR_CODE(0x37);
        return false;
    }

    if (!parsed.extensions || parsed.extensions_len == 0)
    {
        ERROR_CODE(0x38);
        return false;
    }

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
    uint8_t cert_version = 0;

    if (!cert_der || cert_len == 0 || !out)
    {
        ERROR();
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->pubkey.type = TLS_KEY_TYPE_UNKNOWN;
    out->from_handshake = true; /* all pointers reference cert_der */

    if (!tls_asn1_cursor_init(&top_cursor, cert_der, cert_len) ||
        !tls_asn1_next(&top_cursor, &cert_seq))
    {
        ERROR_CODE(0x39);
        return false;
    }

    if (cert_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        top_cursor.cur != top_cursor.end)
    {
        ERROR_CODE(0x3a);
        return false;
    }

    if (!tls_asn1_child_cursor(&cert_seq, &cert_items) ||
        !tls_asn1_next(&cert_items, &tbs) ||
        !tls_asn1_next(&cert_items, &ca_sig_alg) ||
        !tls_asn1_next(&cert_items, &ca_sig_val) ||
        cert_items.cur != cert_items.end)
    {
        ERROR_CODE(0x3b);
        return false;
    }

    if (tbs.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
    {
        ERROR_CODE(0x3c);
        return false;
    }

    if (ca_sig_val.tag != ASN1_BITSTRING || ca_sig_val.len < 1 ||
        ca_sig_val.value[0] != 0)
    {
        ERROR_CODE(0x3d);
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
            ERROR_CODE(0x3e);
            return false;
        }

        if (!tls_asn1_next(&tbs_cursor, &item))
        {
            ERROR_CODE(0x3f);
            return false;
        }

        /* version is [0] EXPLICIT and optional in v1 certs. */
        if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
            tls_asn1_tag_number(item.tag) == 0 &&
            tls_asn1_tag_constructed(item.tag))
        {
            struct tls_asn1_cursor version_cursor;
            struct tls_asn1_tlv version;
            if (!tls_asn1_child_cursor(&item, &version_cursor) ||
                !tls_asn1_next(&version_cursor, &version) ||
                version_cursor.cur != version_cursor.end ||
                version.tag != ASN1_INTEGER || version.len != 1 ||
                version.value[0] == 0 || version.value[0] > 2)
            {
                ERROR_CODE(0x40);
                return false;
            }
            cert_version = version.value[0];
            if (!tls_asn1_next(&tbs_cursor, &item))
            {
                ERROR_CODE(0x40);
                return false;
            }
        }

        if (!tls_x509_positive_integer_der(&item, false) || item.len > 20)
        {
            ERROR_CODE(0x41);
            return false;
        }

        if (!tls_asn1_next(&tbs_cursor, &sig_alg)  ||
            !tls_asn1_next(&tbs_cursor, &issuer)    ||
            !tls_asn1_next(&tbs_cursor, &validity)  ||
            !tls_asn1_next(&tbs_cursor, &subject)   ||
            !tls_asn1_next(&tbs_cursor, &spki))
        {
            ERROR_CODE(0x42);
            return false;
        }

        /* issuer CN */
        out->issuer_name = issuer.tlv;
        out->issuer_name_len = issuer.header_len + issuer.len;
        if (issuer.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) || issuer.len == 0)
        {
            ERROR_CODE(0x43);
            return false;
        }
        memset(&scratch_cn, 0, sizeof(scratch_cn));
        if (!tls_x509_parse_name_common_name(&issuer, &scratch_cn))
        {
            ERROR_CODE(0x43);
            return false;
        }
        out->issuer_cn     = scratch_cn.data;
        out->issuer_cn_len = scratch_cn.len;

        /* validity */
        {
            struct tls_asn1_cursor validity_cursor;
            struct tls_asn1_tlv not_before, not_after;

            if (validity.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
            {
                ERROR_CODE(0x44);
                return false;
            }

            if (!tls_asn1_child_cursor(&validity, &validity_cursor) ||
                !tls_asn1_next(&validity_cursor, &not_before) ||
                !tls_asn1_next(&validity_cursor, &not_after) ||
                validity_cursor.cur != validity_cursor.end)
            {
                ERROR_CODE(0x45);
                return false;
            }

            uint8_t nb_tag = not_before.tag;
            uint8_t na_tag = not_after.tag;
            if (nb_tag != ASN1_UTCTIME && nb_tag != ASN1_GENERALIZEDTIME)
            {
                ERROR_CODE(0x46);
                return false;
            }
            if (na_tag != ASN1_UTCTIME && na_tag != ASN1_GENERALIZEDTIME)
            {
                ERROR_CODE(0x47);
                return false;
            }

            out->not_before     = not_before.value;
            out->not_before_len = not_before.len;
            out->not_before_tag = not_before.tag;
            out->not_after      = not_after.value;
            out->not_after_len  = not_after.len;
            out->not_after_tag  = not_after.tag;
        }

        /* subject CN */
        out->subject_name = subject.tlv;
        out->subject_name_len = subject.header_len + subject.len;
        memset(&scratch_cn, 0, sizeof(scratch_cn));
        if (!tls_x509_parse_name_common_name(&subject, &scratch_cn))
        {
            ERROR_CODE(0x48);
            return false;
        }
        out->subject_cn     = scratch_cn.data;
        out->subject_cn_len = scratch_cn.len;

        /* SPKI — parse into pubkey */
        if (spki.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE))
        {
            ERROR_CODE(0x49);
            return false;
        }

        {
            struct tls_asn1_cursor spki_cursor;
            struct tls_asn1_tlv spki_alg;
            struct tls_asn1_tlv spki_bits;

            if (!tls_asn1_child_cursor(&spki, &spki_cursor) ||
                !tls_asn1_next(&spki_cursor, &spki_alg)      ||
                !tls_asn1_next(&spki_cursor, &spki_bits) ||
                spki_cursor.cur != spki_cursor.end)
            {
                ERROR_CODE(0x4a);
                return false;
            }

            memset(&scratch_alg, 0, sizeof(scratch_alg));
            if (!tls_x509_parse_algorithm_identifier(&spki_alg, &scratch_alg,
                                                      &scratch_param, true))
            {
                ERROR_CODE(0x4b);
                return false;
            }

            if (spki_bits.tag != ASN1_BITSTRING)
            {
                ERROR_CODE(0x4c);
                return false;
            }

            /* Infer the algorithm from the SPKI OID and extract key material. */
            static const uint8_t rsa_oid[] = {TLS_OID_RSA_ENCRYPTION_BYTES};
            static const uint8_t ec_oid[] = {TLS_OID_EC_PUBLIC_KEY_BYTES};
            static const uint8_t p256_oid[] = {TLS_OID_SECP256R1_BYTES};
            static const uint8_t p384_oid[] = {TLS_OID_SECP384R1_BYTES};
            static const uint8_t pss_oid[] = {TLS_OID_RSASSA_PSS_BYTES};
            tls_alg_t alg = TLS_ALG_UNKNOWN;
            if (scratch_alg.len == sizeof(rsa_oid) &&
                !memcmp(scratch_alg.data, rsa_oid, sizeof(rsa_oid)) &&
                scratch_param.tag == ASN1_NULL && scratch_param.len == 0)
                alg = TLS_ALG_RSA_PKCS1_SHA256;
            else if (scratch_alg.len == sizeof(ec_oid) &&
                     !memcmp(scratch_alg.data, ec_oid, sizeof(ec_oid)) &&
                     scratch_param.tag == ASN1_OBJECTID && scratch_param.len == sizeof(p256_oid) &&
                     !memcmp(scratch_param.data, p256_oid, sizeof(p256_oid)))
                alg = TLS_ALG_ECDSA_SECP256R1_SHA256;
            else if (scratch_alg.len == sizeof(ec_oid) &&
                     !memcmp(scratch_alg.data, ec_oid, sizeof(ec_oid)) &&
                     scratch_param.tag == ASN1_OBJECTID && scratch_param.len == sizeof(p384_oid) &&
                     !memcmp(scratch_param.data, p384_oid, sizeof(p384_oid)))
                alg = TLS_ALG_ECDSA_SECP384R1_SHA384;
            else if (scratch_alg.len == sizeof(pss_oid) &&
                     !memcmp(scratch_alg.data, pss_oid, sizeof(pss_oid)))
            {
                /* id-RSASSA-PSS SPKI: validate that the embedded RSASSA-PSS-params
                 * specify SHA-256 / MGF1-SHA-256 / saltLen=32, which is the only
                 * PSS profile our verifier supports.  Any other profile rejects
                 * the certificate fail-closed rather than silently accepting it. */
                tls_alg_t pss_scheme = TLS_ALG_UNKNOWN;
                if (!tls_x509_signature_algorithm(&spki_alg, &pss_scheme) ||
                    pss_scheme != TLS_ALG_RSA_PSS_RSAE_SHA256)
                {
                    ERROR_CODE(0x51);
                    return false;
                }
                alg = TLS_ALG_RSA_PSS_RSAE_SHA256;
            }
            out->pubkey.type = alg == TLS_ALG_RSA_PKCS1_SHA256 ? TLS_KEY_TYPE_RSA
                : alg == TLS_ALG_RSA_PSS_RSAE_SHA256     ? TLS_KEY_TYPE_RSA
                : alg == TLS_ALG_ECDSA_SECP256R1_SHA256   ? TLS_KEY_TYPE_EC_P256
                : alg == TLS_ALG_ECDSA_SECP384R1_SHA384   ? TLS_KEY_TYPE_EC_P384
                : TLS_KEY_TYPE_UNKNOWN;
            out->pubkey.allocated = false;

            if (alg == TLS_ALG_RSA_PSS_RSAE_SHA256 ||
                alg == TLS_ALG_RSA_PKCS1_SHA256)
            {
                /* BIT STRING payload: skip the leading unused-bits byte. */
                if (spki_bits.len < 2 || spki_bits.value[0] != 0x00)
                {
                    ERROR_CODE(0x4d);
                    return false;
                }
                /* key_parse_spki (key.c) logic inline: parse RSAPublicKey. */
                struct tls_asn1_cursor rsa_c;
                struct tls_asn1_tlv rsa_seq, rsa_mod, rsa_exp;
                if (!tls_asn1_cursor_init(&rsa_c, spki_bits.value + 1,
                                          spki_bits.len - 1) ||
                    !tls_asn1_next(&rsa_c, &rsa_seq) ||
                    rsa_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                    rsa_c.cur != rsa_c.end)
                {
                    ERROR_CODE(0x4e);
                    return false;
                }
                struct tls_asn1_cursor rsa_body;
                if (!tls_asn1_child_cursor(&rsa_seq, &rsa_body) ||
                    !tls_asn1_next(&rsa_body, &rsa_mod) ||
                    !tls_asn1_next(&rsa_body, &rsa_exp) ||
                    rsa_body.cur != rsa_body.end ||
                    !tls_x509_positive_integer_der(&rsa_mod, false) ||
                    !tls_x509_positive_integer_der(&rsa_exp, false))
                {
                    ERROR_CODE(0x4f);
                    return false;
                }

                const uint8_t *mod = rsa_mod.value;
                size_t         mod_len = rsa_mod.len;
                if (mod_len > 1 && mod[0] == 0x00) { mod++; mod_len--; }

                out->pubkey.rsa.modulus  = mod;
                out->pubkey.rsa.mod_len  = mod_len;
                out->pubkey.rsa.exponent = rsa_exp.value;
                out->pubkey.rsa.exp_len  = rsa_exp.len;
            }
            else if (alg == TLS_ALG_ECDSA_SECP256R1_SHA256 ||
                     alg == TLS_ALG_ECDSA_SECP384R1_SHA384)
            {
                /* EC public key: BIT STRING value after the unused-bits byte. */
                if (spki_bits.len < 2 || spki_bits.value[0] != 0)
                {
                    ERROR_CODE(0x50);
                    return false;
                }
                out->pubkey.ec.pub  = spki_bits.value + 1;
                out->pubkey.ec.len  = spki_bits.len  - 1;
                out->pubkey.ec.priv = NULL;
            }
            /* else: unknown alg — pubkey fields remain zeroed; callers that
             * need to verify will fail via tls_key_verify returning UNKNOWN. */
        }

        /* Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3]
         * must be ordered, unique, and version-appropriate. */
        bool have_extensions = false;
        uint8_t last_optional_tag = 0;
        while (tbs_cursor.cur < tbs_cursor.end)
        {
            uint8_t optional_tag;
            if (!tls_asn1_next(&tbs_cursor, &item) ||
                tls_asn1_tag_class(item.tag) != ASN1_CONTEXTSPEC)
                return false;
            optional_tag = tls_asn1_tag_number(item.tag);
            if (optional_tag <= last_optional_tag || optional_tag < 1 || optional_tag > 3)
                return false;
            last_optional_tag = optional_tag;
            if (optional_tag == 3)
            {
                if (cert_version != 2 || have_extensions ||
                    !tls_asn1_tag_constructed(item.tag))
                    return false;
                have_extensions = true;
                out->extensions     = item.value;
                out->extensions_len = item.len;
                if (!tls_x509_parse_authority_key_id(out->extensions,
                                                     out->extensions_len,
                                                     &out->authority_key_id,
                                                     &out->authority_key_id_len))
                {
                    ERROR_CODE(0x52);
                    return false;
                }
            }
            else if (cert_version == 0 || tls_asn1_tag_constructed(item.tag) ||
                     item.len < 1 || item.value[0] > 7)
                return false;
        }
    }

    /* Validate ca signature algorithm field exists (not used for value here). */
    memset(&scratch_alg, 0, sizeof(scratch_alg));
    if (!tls_x509_parse_algorithm_identifier(&ca_sig_alg, &scratch_alg,
                                              &scratch_param, true))
    {
        ERROR_CODE(0x51);
        return false;
    }

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
        ERROR_CODE(0x52);
        return false;
    }
    if (size < (sizeof(begin_banner) - 1) ||
        memcmp(pem_data, begin_banner, sizeof(begin_banner) - 1) != 0)
    {
        ERROR_CODE(0x53);
        return false;
    }

    end = pem_data + size;
    p = memchr(pem_data, '\n', size);
    if (!p)
    {
        ERROR_CODE(0x54);
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
                ERROR_CODE(0x55);
                return false;
            }
            der_out[b64_count++] = (uint8_t)*p;
        }
        else if ((*p != '\n') && (*p != '\r') && (*p != ' ') && (*p != '\t'))
        {
            ERROR_CODE(0x56);
            return false;
        }
        p++;
    }

    if (p >= end || b64_count == 0 || (b64_count & 3) != 0)
    {
        ERROR_CODE(0x57);
        return false;
    }

    i = tls_base64_decode(der_out, b64_count, der_out, der_out_len);
    if (i == 0 || i > der_out_len)
    {
        ERROR_CODE(0x58);
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
    TLS_OID_RSA_ENCRYPTION_BYTES
};
static const uint8_t oid_sha256_rsa_pkcs1[] = {
    TLS_OID_SHA256_WITH_RSA_ENCRYPTION_BYTES
};
static const uint8_t oid_rsassa_pss[] = {
    TLS_OID_RSASSA_PSS_BYTES
};
static const uint8_t oid_ecdsa_sha256[] = {
    TLS_OID_ECDSA_WITH_SHA256_BYTES
};
static const uint8_t oid_ecdsa_sha384[] = {
    TLS_OID_ECDSA_WITH_SHA384_BYTES
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
    if (oid_len == sizeof(oid_ecdsa_sha384) &&
        memcmp(oid, oid_ecdsa_sha384, oid_len) == 0)
    {
        return TLS_ALG_ECDSA_SECP384R1_SHA384;
    }
    return TLS_ALG_UNKNOWN;
}

/* Match a SHA-256 AlgorithmIdentifier, accepting absent or NULL parameters. */
static bool x509_sha256_identifier(const struct tls_asn1_tlv *identifier)
{
    static const uint8_t sha256[] = {TLS_OID_SHA256_BYTES};
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv oid, param;
    if (identifier->tag != 0x30 || !tls_asn1_child_cursor(identifier, &c) ||
        !tls_asn1_next(&c, &oid) || oid.tag != ASN1_OBJECTID ||
        oid.len != sizeof(sha256) || memcmp(oid.value, sha256, sizeof(sha256)))
    {
        ERROR_CODE(0x59);
        return false;
    }
    if (c.cur != c.end &&
        (!tls_asn1_next(&c, &param) || param.tag != ASN1_NULL || param.len))
    {
        ERROR_CODE(0x5a);
        return false;
    }
    return c.cur == c.end;
}

bool tls_x509_signature_algorithm(const struct tls_asn1_tlv *identifier,
                                  tls_alg_t *alg)
{
    static const uint8_t mgf1[] = {TLS_OID_MGF1_BYTES};
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv oid, param;
    if (!alg)
    {
        ERROR_CODE(0x5b);
        return false;
    }
    *alg = TLS_ALG_UNKNOWN;
    if (!identifier || identifier->tag != 0x30 ||
        !tls_asn1_child_cursor(identifier, &c) || !tls_asn1_next(&c, &oid) ||
        oid.tag != ASN1_OBJECTID)
    {
        ERROR_CODE(0x5c);
        return false;
    }
    /* rsaEncryption identifies a key, never a certificate signature. */
    if (oid.len == sizeof(oid_rsa_encryption) &&
        !memcmp(oid.value, oid_rsa_encryption, oid.len))
    {
        ERROR_CODE(0x5d);
        return false;
    }
    tls_alg_t scheme = tls_x509_oid_to_sig_alg(oid.value, oid.len);
    if (scheme == TLS_ALG_RSA_PSS_RSAE_SHA256)
    {
        /* RFC 4055 defaults are SHA-1/MGF1-SHA-1/saltLen=20. Our verifier
         * supports only explicit SHA-256/MGF1-SHA-256/saltLen=32. */
        if (!tls_asn1_next(&c, &param) || param.tag != 0x30 || c.cur != c.end)
        {
            ERROR_CODE(0x5e);
            return false;
        }
        struct tls_asn1_cursor params;
        if (!tls_asn1_child_cursor(&param, &params))
        {
            ERROR_CODE(0x5f);
            return false;
        }
        uint8_t seen = 0;
        uint8_t previous = 0;
        while (params.cur != params.end)
        {
            struct tls_asn1_tlv field, value;
            struct tls_asn1_cursor explicit_value;
            if (!tls_asn1_next(&params, &field) || field.tag < 0xa0 || field.tag > 0xa3 ||
                (seen && field.tag <= previous) ||
                !tls_asn1_child_cursor(&field, &explicit_value) ||
                !tls_asn1_next(&explicit_value, &value) || explicit_value.cur != explicit_value.end)
            {
                ERROR_CODE(0x60);
                return false;
            }
            previous = field.tag;
            seen |= (uint8_t)(1u << (field.tag - 0xa0));
            if (field.tag == 0xa0)
            {
                if (!x509_sha256_identifier(&value))
                {
                    ERROR_CODE(0x61);
                    return false;
                }
            }
            else if (field.tag == 0xa1)
            {
                struct tls_asn1_cursor mask;
                struct tls_asn1_tlv mask_oid, hash;
                if (value.tag != 0x30 || !tls_asn1_child_cursor(&value, &mask) ||
                    !tls_asn1_next(&mask, &mask_oid) || mask_oid.tag != ASN1_OBJECTID ||
                    mask_oid.len != sizeof(mgf1) || memcmp(mask_oid.value, mgf1, sizeof(mgf1)) ||
                    !tls_asn1_next(&mask, &hash) || mask.cur != mask.end ||
                    !x509_sha256_identifier(&hash))
                {
                    ERROR_CODE(0x62);
                    return false;
                }
            }
            else if (value.tag != ASN1_INTEGER || value.len != 1 ||
                     value.value[0] != (field.tag == 0xa2 ? 32 : 1))
            {
                ERROR_CODE(0x63);
                return false;
            }
        }
        if ((seen & 7) != 7)
        {
            ERROR_CODE(0x64);
            return false;
        }
    }
    else
    {
        if (c.cur != c.end)
        {
            if (!tls_asn1_next(&c, &param) ||
                (scheme == TLS_ALG_RSA_PKCS1_SHA256 && (param.tag != ASN1_NULL || param.len)) ||
                scheme == TLS_ALG_ECDSA_SECP256R1_SHA256 ||
                scheme == TLS_ALG_ECDSA_SECP384R1_SHA384)
            {
                ERROR_CODE(0x65);
                return false;
            }
        }
        if (c.cur != c.end)
        {
            ERROR_CODE(0x66);
            return false;
        }
    }
    *alg = scheme;
    return true;
}

tls_key_op_result_t tls_x509_signature_verify(const uint8_t *content, size_t content_len,
                                               const uint8_t *sig, size_t sig_len,
                                               const struct tls_key *key, tls_alg_t alg)
{
    if (!content || !sig || !key)
    {
        return TLS_KEY_OP_INVALID;
    }

    if (!TLS_ALG_IS_SIGNING(alg))
    {
        return TLS_KEY_OP_UNKNOWN;
    }

    struct tls_hash_context hash_ctx;
    uint8_t hash_type = (alg == TLS_ALG_ECDSA_SECP384R1_SHA384)
                        ? (uint8_t)TLS_HASH_SHA384 : (uint8_t)TLS_HASH_SHA256;
    uint8_t digest[TLS_SHA384_DIGEST_LEN]; /* large enough for both */
    if (!tls_hash_context_init(&hash_ctx, hash_type))
    {
        return TLS_KEY_OP_INVALID;
    }
    tls_hash_update(&hash_ctx, content, content_len);
    tls_hash_digest(&hash_ctx, digest);

    return tls_x509_signature_verify_digest(digest, sig, sig_len, key, alg);
}

/* Parse one DER INTEGER from der[0..len) into a big-endian, left-zero-padded
 * buffer of coord_len bytes (32 for P-256, 48 for P-384).
 * Returns pointer past the INTEGER, or NULL on error. */
static const uint8_t *ecdsa_parse_int_n(const uint8_t *der, size_t len,
                                        uint8_t *out, size_t coord_len)
{
    if (!der || len < 3 || der[0] != 0x02) return NULL;
    size_t ilen = der[1];
    if (ilen == 0 || ilen > coord_len + 1 || ilen > len - 2) return NULL;
    const uint8_t *v = der + 2;
    if (v[0] & 0x80) return NULL;           /* negative */
    if (v[0] == 0x00)
    {
        if (ilen < 2 || !(v[1] & 0x80)) return NULL;
        v++; ilen--;
    }
    if (ilen > coord_len) return NULL;
    memset(out, 0, coord_len - ilen);
    memcpy(out + (coord_len - ilen), v, ilen);
    return v + ilen;
}

tls_key_op_result_t tls_x509_signature_verify_digest(const uint8_t digest[32],
                                                      const uint8_t *sig, size_t sig_len,
                                                      const struct tls_key *key, tls_alg_t alg)
{
    if (!digest || !sig || !key)
    {
        return TLS_KEY_OP_INVALID;
    }

    if (!TLS_ALG_IS_SIGNING(alg))
    {
        return TLS_KEY_OP_UNKNOWN;
    }

    bool ok = false;
    switch (alg)
    {
        case TLS_ALG_RSA_PKCS1_SHA256:
            if (!tls_key_supports_operation(key, alg)) return TLS_KEY_OP_INVALID;
            ok = tls_rsa_pkcs1_v15_sha256_verify(sig, sig_len, digest, &key->rsa);
            break;

        case TLS_ALG_RSA_PSS_RSAE_SHA256:
            if (!tls_key_supports_operation(key, alg)) return TLS_KEY_OP_INVALID;
            if (key->rsa.mod_len > RSA_TRANSIENT_SIZE ||
                sig_len != key->rsa.mod_len)
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
        {
            if (!tls_key_supports_operation(key, alg))
                return TLS_KEY_OP_INVALID;
            if (key->ec.len != 65 || !key->ec.pub)
                return TLS_KEY_OP_INVALID;
            /* sig is a DER SEQUENCE { INTEGER r, INTEGER s }.
             * Decode into a flat 64-byte r||s buffer for tls_p256_verify. */
            uint8_t rs[64];
            /* Minimum valid DER ECDSA-Sig-Value is 8 bytes. */
            if (sig_len < 8 || sig[0] != 0x30)
                return TLS_KEY_OP_INVALID;
            size_t seq_len = sig[1];
            if ((seq_len & 0x80) || 2 + seq_len != sig_len)
                return TLS_KEY_OP_INVALID;
            {
                const uint8_t *end = sig + sig_len;
                const uint8_t *p = tls_ecdsa_parse_int(sig + 2, sig_len - 2, rs);
                if (p)
                    p = tls_ecdsa_parse_int(p, (size_t)(end - p), rs + 32);
                if (p != end)   /* NULL (parse error) or trailing bytes */
                    return TLS_KEY_OP_INVALID;
            }
            tls_crypto_guard_enable();
            bool p256_ok = tls_p256_verify(rs, digest, key->ec.pub);
            tls_crypto_guard_disable();
            tls_secure_memzero(rs, sizeof(rs));
            return p256_ok ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
        }

        case TLS_ALG_ECDSA_SECP384R1_SHA384:
        {
            if (!tls_key_supports_operation(key, alg))
                return TLS_KEY_OP_INVALID;
            if (key->ec.len != 97 || !key->ec.pub)
                return TLS_KEY_OP_INVALID;
            uint8_t rs[96];
            if (sig_len < 8 || sig[0] != 0x30)
                return TLS_KEY_OP_INVALID;
            size_t seq_len = sig[1];
            if ((seq_len & 0x80) || 2 + seq_len != sig_len)
                return TLS_KEY_OP_INVALID;
            {
                const uint8_t *end = sig + sig_len;
                const uint8_t *p = ecdsa_parse_int_n(sig + 2, sig_len - 2, rs, 48);
                if (p)
                    p = ecdsa_parse_int_n(p, (size_t)(end - p), rs + 48, 48);
                if (p != end)
                    return TLS_KEY_OP_INVALID;
            }
            tls_crypto_guard_enable();
            bool p384_ok = tls_p384_verify(rs, digest, key->ec.pub);
            tls_crypto_guard_disable();
            tls_secure_memzero(rs, sizeof(rs));
            return p384_ok ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
        }

        default:
            return TLS_KEY_OP_UNKNOWN;
    }

    return ok ? TLS_KEY_OP_OK : TLS_KEY_OP_INVALID;
}
