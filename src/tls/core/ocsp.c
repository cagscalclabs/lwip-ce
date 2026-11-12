#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../includes/asn1.h"
#include "../includes/ocsp.h"
#include "../includes/diag_trap.h"
#include "../includes/x509.h"
#include "x509_internal.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_OCSP
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

/* Same custom allocator used throughout TLS core. */
void *tls_fileio_alloc(size_t size);
void  tls_fileio_free(void *ptr);

/* -----------------------------------------------------------------------
 * Minimal SHA-1 — used only for OCSP CertID (RFC 6960 §4.1.1).
 * Not exposed outside this TU.
 * ----------------------------------------------------------------------- */

#define SHA1_ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

typedef struct { uint32_t h[5]; uint8_t buf[64]; uint32_t lo, hi; } sha1_ctx_t;

static void sha1_process_block(sha1_ctx_t *ctx, const uint8_t block[64])
{
    /* 16-word rolling schedule avoids a 320-byte w[80] on the eZ80 stack. */
    uint32_t w[16], a, b, c, d, e, f, k, temp;
    int i;

    for (i = 0; i < 16; i++)
    {
        w[i]  = (uint32_t)block[i*4  ] << 24;
        w[i] |= (uint32_t)block[i*4+1] << 16;
        w[i] |= (uint32_t)block[i*4+2] <<  8;
        w[i] |= (uint32_t)block[i*4+3];
    }

    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2];
    d = ctx->h[3]; e = ctx->h[4];

    for (i = 0; i < 80; i++)
    {
        if (i >= 16)
        {
            uint32_t s = w[(i-3)&15] ^ w[(i-8)&15] ^ w[(i-14)&15] ^ w[i&15];
            w[i&15] = SHA1_ROTL(s, 1);
        }
        if      (i < 20) { f = (b & c) ^ (~b & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;           k = 0xCA62C1D6u; }
        temp = SHA1_ROTL(a, 5) + f + e + k + w[i&15];
        e = d; d = c; c = SHA1_ROTL(b, 30); b = a; a = temp;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c;
    ctx->h[3] += d; ctx->h[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->h[0] = 0x67452301u; ctx->h[1] = 0xEFCDAB89u;
    ctx->h[2] = 0x98BADCFEu; ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xC3D2E1F0u;
    ctx->lo = ctx->hi = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    uint32_t bits = (uint32_t)len << 3;
    uint32_t lo_prev = ctx->lo;
    ctx->lo += bits;
    if (ctx->lo < lo_prev) ctx->hi++;
    ctx->hi += (uint32_t)len >> 29;

    uint32_t partial = (lo_prev >> 3) & 63u;
    if (partial)
    {
        size_t fill = 64u - partial;
        if (len < fill) { memcpy(ctx->buf + partial, data, len); return; }
        memcpy(ctx->buf + partial, data, fill);
        sha1_process_block(ctx, ctx->buf);
        data += fill; len -= fill;
    }
    while (len >= 64)
    {
        sha1_process_block(ctx, data);
        data += 64; len -= 64;
    }
    if (len) memcpy(ctx->buf, data, len);
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t out[20])
{
    uint32_t partial = (ctx->lo >> 3) & 63u;
    ctx->buf[partial++] = 0x80;
    if (partial > 56)
    {
        memset(ctx->buf + partial, 0, 64 - partial);
        sha1_process_block(ctx, ctx->buf);
        partial = 0;
    }
    memset(ctx->buf + partial, 0, 56 - partial);
    ctx->buf[56] = (uint8_t)(ctx->hi >> 24); ctx->buf[57] = (uint8_t)(ctx->hi >> 16);
    ctx->buf[58] = (uint8_t)(ctx->hi >>  8); ctx->buf[59] = (uint8_t)(ctx->hi      );
    ctx->buf[60] = (uint8_t)(ctx->lo >> 24); ctx->buf[61] = (uint8_t)(ctx->lo >> 16);
    ctx->buf[62] = (uint8_t)(ctx->lo >>  8); ctx->buf[63] = (uint8_t)(ctx->lo      );
    sha1_process_block(ctx, ctx->buf);
    for (int i = 0; i < 5; i++)
    {
        out[i*4  ] = (uint8_t)(ctx->h[i] >> 24); out[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->h[i] >>  8); out[i*4+3] = (uint8_t)(ctx->h[i]      );
    }
    memset(ctx, 0, sizeof(*ctx));
}

static void sha1_oneshot(const uint8_t *data, size_t len,
                         uint8_t out[OCSP_SHA1_LEN])
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

/* -----------------------------------------------------------------------
 * DER helpers
 * ----------------------------------------------------------------------- */

static size_t der_length_bytes(size_t len)
{
    if (len < 0x80)  return 1;
    if (len < 0x100) return 2;
    return 3;
}

/* Total byte count of a TLV (1 tag + length bytes + value). */
static size_t der_tlv_size(size_t value_len)
{
    return 1 + der_length_bytes(value_len) + value_len;
}

/* Write DER header (tag + length) into buf.  Returns bytes written. */
static size_t der_write_header(uint8_t *buf, uint8_t tag, size_t len)
{
    buf[0] = tag;
    if (len < 0x80)  { buf[1] = (uint8_t)len; return 2; }
    if (len < 0x100) { buf[1] = 0x81; buf[2] = (uint8_t)len; return 3; }
    buf[1] = 0x82; buf[2] = (uint8_t)(len >> 8); buf[3] = (uint8_t)(len & 0xFF);
    return 4;
}

/* -----------------------------------------------------------------------
 * Step 1: tls_x509_get_ocsp_url
 *
 * OID 1.3.6.1.5.5.7.1.1  = id-pe-authorityInfoAccess
 * OID 1.3.6.1.5.5.7.48.1 = id-ad-ocsp
 * Context tag [6] IMPLICIT = uniformResourceIdentifier (IA5String)
 * ----------------------------------------------------------------------- */

static const uint8_t oid_aia[]  = { 0x2b,0x06,0x01,0x05,0x05,0x07,0x01,0x01 };
static const uint8_t oid_ocsp[] = { 0x2b,0x06,0x01,0x05,0x05,0x07,0x30,0x01 };

bool tls_x509_get_ocsp_url(const uint8_t *ext_data, size_t ext_len,
                            char **url_out)
{
    struct tls_asn1_cursor outer, list;
    struct tls_asn1_tlv    item;

    if (!url_out) return false;
    *url_out = NULL;

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
        struct tls_asn1_tlv    ext, oid, next, value;

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

        if (oid.len != sizeof(oid_aia) ||
            memcmp(oid.value, oid_aia, sizeof(oid_aia)) != 0)
            continue;

        /* Found the AIA extension — walk the AccessDescription SEQUENCE OF. */
        struct tls_asn1_cursor aia_cur, ad_inner;
        struct tls_asn1_tlv    aia_seq, ad, method, loc;

        if (!tls_asn1_cursor_init(&aia_cur, value.value, value.len) ||
            !tls_asn1_next(&aia_cur, &aia_seq) ||
            aia_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            aia_cur.cur != aia_cur.end ||
            !tls_asn1_child_cursor(&aia_seq, &aia_cur))
            return false;

        while (aia_cur.cur < aia_cur.end)
        {
            if (!tls_asn1_next(&aia_cur, &ad) ||
                ad.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
                !tls_asn1_child_cursor(&ad, &ad_inner) ||
                !tls_asn1_next(&ad_inner, &method) ||
                method.tag != ASN1_OBJECTID ||
                !tls_asn1_next(&ad_inner, &loc) ||
                ad_inner.cur != ad_inner.end)
                return false;

            if (method.len == sizeof(oid_ocsp) &&
                memcmp(method.value, oid_ocsp, sizeof(oid_ocsp)) == 0 &&
                loc.tag == 0x86 /* [6] IMPLICIT IA5String */)
            {
                char *url = (char *)tls_fileio_alloc(loc.len + 1);
                if (!url) return false;
                memcpy(url, loc.value, loc.len);
                url[loc.len] = '\0';
                *url_out = url;
                return true;
            }
        }
        return true;   /* AIA present but no OCSP entry */
    }
    return true;       /* AIA extension absent */
}

/* -----------------------------------------------------------------------
 * Step 2: tls_ocsp_hash_issuer
 * ----------------------------------------------------------------------- */

bool tls_ocsp_hash_issuer(const uint8_t *issuer_name,  size_t issuer_name_len,
                          const uint8_t *issuer_key,   size_t issuer_key_len,
                          uint8_t name_hash[OCSP_SHA1_LEN],
                          uint8_t  key_hash[OCSP_SHA1_LEN])
{
    if (!issuer_name || !issuer_name_len ||
        !issuer_key  || !issuer_key_len  ||
        !name_hash   || !key_hash)
        return false;

    sha1_oneshot(issuer_name, issuer_name_len, name_hash);
    sha1_oneshot(issuer_key,  issuer_key_len,   key_hash);
    return true;
}

/* -----------------------------------------------------------------------
 * Step 3: tls_ocsp_build_request
 *
 * Wire layout (RFC 6960 §4.1.1):
 *
 *   OCSPRequest SEQUENCE {
 *     TBSRequest SEQUENCE {
 *       requestList SEQUENCE OF {
 *         Request SEQUENCE {
 *           reqCert CertID SEQUENCE {
 *             hashAlgorithm AlgorithmIdentifier,
 *             issuerNameHash OCTET STRING (20),
 *             issuerKeyHash  OCTET STRING (20),
 *             serialNumber   INTEGER
 *           }
 *         }
 *       }
 *     }
 *   }
 *
 * Size calculation: build inside-out.
 *   certid_inner = content of CertID SEQUENCE (alg_id + 2 octet strings + integer)
 *   certid_tlv   = der_tlv_size(certid_inner)
 *   request_tlv  = der_tlv_size(certid_tlv)   -- Request wraps CertID
 *   list_tlv     = der_tlv_size(request_tlv)  -- requestList wraps Request
 *   tbs_tlv      = der_tlv_size(list_tlv)     -- TBSRequest wraps requestList
 *   total        = der_tlv_size(tbs_tlv)      -- OCSPRequest wraps TBSRequest
 * ----------------------------------------------------------------------- */

static const uint8_t sha1_alg_id[] = {
    0x30,0x09,
    0x06,0x05, 0x2b,0x0e,0x03,0x02,0x1a,
    0x05,0x00
};
#define SHA1_ALG_ID_LEN  sizeof(sha1_alg_id)

bool tls_ocsp_build_request(const uint8_t *serial, size_t serial_len,
                             const uint8_t name_hash[OCSP_SHA1_LEN],
                             const uint8_t  key_hash[OCSP_SHA1_LEN],
                             uint8_t **out, size_t *out_len)
{
    if (!serial || !serial_len || !name_hash || !key_hash || !out || !out_len)
        return false;
    *out = NULL; *out_len = 0;

    if (serial_len > 20)   /* RFC 5280 §4.1.2.2 */
        return false;

    size_t certid_inner = SHA1_ALG_ID_LEN
                        + der_tlv_size(OCSP_SHA1_LEN)   /* nameHash */
                        + der_tlv_size(OCSP_SHA1_LEN)   /* keyHash  */
                        + der_tlv_size(serial_len);     /* serial   */

    size_t certid_tlv  = der_tlv_size(certid_inner);
    size_t request_tlv = der_tlv_size(certid_tlv);
    size_t list_tlv    = der_tlv_size(request_tlv);
    size_t tbs_tlv     = der_tlv_size(list_tlv);
    size_t total       = der_tlv_size(tbs_tlv);

    uint8_t *buf = (uint8_t *)tls_fileio_alloc(total);
    if (!buf) return false;

    uint8_t *p = buf;

#define WH(tag, len) do { p += der_write_header(p, (tag), (len)); } while (0)
#define WB(src, n)   do { memcpy(p, (src), (n)); p += (n); } while (0)

    WH(0x30, tbs_tlv);         /* OCSPRequest  SEQUENCE */
    WH(0x30, list_tlv);        /* TBSRequest   SEQUENCE */
    WH(0x30, request_tlv);     /* requestList  SEQUENCE OF */
    WH(0x30, certid_tlv);      /* Request      SEQUENCE */
    WH(0x30, certid_inner);    /* CertID       SEQUENCE */
    WB(sha1_alg_id, SHA1_ALG_ID_LEN);
    WH(ASN1_OCTETSTRING, OCSP_SHA1_LEN); WB(name_hash, OCSP_SHA1_LEN);
    WH(ASN1_OCTETSTRING, OCSP_SHA1_LEN); WB(key_hash,  OCSP_SHA1_LEN);
    WH(ASN1_INTEGER,     serial_len);    WB(serial,     serial_len);

#undef WH
#undef WB

    if ((size_t)(p - buf) != total)
    {
        tls_fileio_free(buf);
        return false;
    }

    *out = buf; *out_len = total;
    return true;
}

void tls_ocsp_free(void *ptr)
{
    if (ptr)
        tls_fileio_free(ptr);
}

#define OCSP_CLOCK_SKEW_SECONDS 300u
#define OCSP_MAX_AGE_SECONDS 86400u

struct ocsp_parse_workspace
{
    struct tls_asn1_cursor c[4];
    struct tls_asn1_tlv t[10];
    uint8_t hash[OCSP_SHA1_LEN];
    struct tls_x509_object responder;
};

static bool ocsp_time(const struct tls_asn1_tlv *tlv, uint32_t *seconds)
{
    return tlv && tlv->tag == ASN1_GENERALIZEDTIME &&
           tls_x509_time_to_unix(tlv->value, tlv->len, tlv->tag, seconds);
}

static bool ocsp_not_too_future(uint32_t value, uint32_t now)
{
    return value <= now || value - now <= OCSP_CLOCK_SKEW_SECONDS;
}

static bool ocsp_sha1_identifier(const struct tls_asn1_tlv *identifier)
{
    static const uint8_t oid_sha1[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv oid, param;

    return identifier && identifier->tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE) &&
           tls_asn1_child_cursor(identifier, &c) &&
           tls_asn1_next(&c, &oid) && oid.tag == ASN1_OBJECTID &&
           oid.len == sizeof(oid_sha1) &&
           memcmp(oid.value, oid_sha1, sizeof(oid_sha1)) == 0 &&
           tls_asn1_next(&c, &param) && param.tag == ASN1_NULL &&
           param.len == 0 && c.cur == c.end;
}

static bool ocsp_serial_equal(const struct tls_asn1_tlv *encoded,
                              const uint8_t *serial, size_t serial_len)
{
    const uint8_t *a;
    size_t a_len;

    if (!encoded || encoded->tag != ASN1_INTEGER || encoded->len == 0 ||
        !serial || serial_len == 0 || (encoded->value[0] & 0x80u) != 0 ||
        (encoded->len > 1 && encoded->value[0] == 0 &&
         (encoded->value[1] & 0x80u) == 0))
        return false;
    a = encoded->value;
    a_len = encoded->len;
    while (a_len > 1 && *a == 0) { a++; a_len--; }
    while (serial_len > 1 && *serial == 0) { serial++; serial_len--; }
    return a_len == serial_len && memcmp(a, serial, a_len) == 0;
}

static bool ocsp_responder_id_matches_cert(
    const struct tls_asn1_tlv *responder_id,
    const struct tls_x509_object *cert,
    uint8_t hash[OCSP_SHA1_LEN])
{
    if (responder_id->tag == (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC | 1))
    {
        struct tls_asn1_cursor c;
        struct tls_asn1_tlv name;
        return cert->subject_name &&
               tls_asn1_cursor_init(&c, responder_id->value,
                                    responder_id->len) &&
               tls_asn1_next(&c, &name) && c.cur == c.end &&
               name.tag == (ASN1_CONSTRUCTED | ASN1_SEQUENCE) &&
               cert->subject_name_len == name.header_len + name.len &&
               memcmp(cert->subject_name, name.tlv,
                      cert->subject_name_len) == 0;
    }
    if (responder_id->tag == (ASN1_CONTEXTSPEC | 2) &&
        responder_id->len == OCSP_SHA1_LEN && cert->subject_pubkey_raw)
    {
        sha1_oneshot(cert->subject_pubkey_raw, cert->subject_pubkey_raw_len,
                     hash);
        return memcmp(hash, responder_id->value, OCSP_SHA1_LEN) == 0;
    }
    return false;
}

static const struct tls_key *ocsp_delegated_responder_key(
    struct ocsp_parse_workspace *w,
    const struct tls_asn1_tlv *certs,
    const struct tls_asn1_tlv *responder_id,
    const uint8_t issuer_name_hash[OCSP_SHA1_LEN],
    const struct tls_key *issuer_key,
    uint32_t now_secs)
{
    struct tls_asn1_cursor explicit_certs, list;
    struct tls_asn1_tlv sequence, encoded_cert;

    if (!certs ||
        certs->tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC) ||
        !tls_asn1_child_cursor(certs, &explicit_certs) ||
        !tls_asn1_next(&explicit_certs, &sequence) ||
        explicit_certs.cur != explicit_certs.end ||
        sequence.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        !tls_asn1_child_cursor(&sequence, &list))
        return NULL;

    while (list.cur < list.end)
    {
        const uint8_t *tbs, *sig;
        size_t tbs_len, sig_len;
        tls_alg_t cert_sig_alg;

        if (!tls_asn1_next(&list, &encoded_cert) ||
            encoded_cert.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_x509_parse_certificate(encoded_cert.tlv,
                                        encoded_cert.header_len +
                                            encoded_cert.len,
                                        &w->responder))
            return NULL;
        if (!ocsp_responder_id_matches_cert(responder_id, &w->responder,
                                            w->hash))
            continue;
        if (!w->responder.issuer_name ||
            !w->responder.subject_pubkey_raw ||
            w->responder.pubkey.type == TLS_KEY_TYPE_UNKNOWN ||
            !tls_x509_time_in_validity(&w->responder, now_secs) ||
            !tls_x509_validate_ocsp_responder_extensions(&w->responder))
            return NULL;
        sha1_oneshot(w->responder.issuer_name,
                     w->responder.issuer_name_len, w->hash);
        if (memcmp(w->hash, issuer_name_hash, OCSP_SHA1_LEN) != 0 ||
            !tls_x509_certificate_signature_material(
                encoded_cert.tlv, encoded_cert.header_len + encoded_cert.len,
                &tbs, &tbs_len, &cert_sig_alg, &sig, &sig_len) ||
            tls_x509_signature_verify(tbs, tbs_len, sig, sig_len, issuer_key,
                                      cert_sig_alg) != TLS_KEY_OP_OK)
            return NULL;
        return &w->responder.pubkey;
    }
    return NULL;
}

tls_ocsp_status_t tls_ocsp_parse_response(
    const uint8_t *buf, size_t len,
    const uint8_t *serial, size_t serial_len,
    const uint8_t issuer_name_hash[OCSP_SHA1_LEN],
    const uint8_t issuer_key_hash[OCSP_SHA1_LEN],
    const struct tls_key *issuer_key,
    uint32_t now_secs)
{
    LWDIAG(0x40);
    static const uint8_t oid_basic[] = {
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
    };
    struct ocsp_parse_workspace *w;
    tls_ocsp_status_t result = OCSP_PARSE_ERROR;
    tls_alg_t sig_alg = TLS_ALG_UNKNOWN;
    struct tls_asn1_tlv response_data, response_signature, responder_id;
    struct tls_asn1_tlv embedded_certs = {0};
    const struct tls_key *response_key = NULL;
    uint32_t produced_at, this_update, next_update = 0;
    bool has_next_update = false;

    if (!buf || len == 0 || !serial || serial_len == 0 ||
        !issuer_name_hash || !issuer_key_hash || !issuer_key || now_secs == 0)
        return OCSP_PARSE_ERROR;
    w = (struct ocsp_parse_workspace *)tls_fileio_alloc(sizeof(*w));
    if (!w)
        return OCSP_PARSE_ERROR;
    memset(w, 0, sizeof(*w));

    if (!tls_asn1_cursor_init(&w->c[0], buf, len) ||
        !tls_asn1_next(&w->c[0], &w->t[0]) ||
        w->t[0].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        w->c[0].cur != w->c[0].end ||
        !tls_asn1_child_cursor(&w->t[0], &w->c[0]) ||
        !tls_asn1_next(&w->c[0], &w->t[1]) ||
        w->t[1].tag != ASN1_ENUMERATED || w->t[1].len != 1)
        goto out;
    if (w->t[1].value[0] != 0)
    {
        result = OCSP_UNKNOWN;
        goto out;
    }
    if (!tls_asn1_next(&w->c[0], &w->t[2]) ||
        w->t[2].tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC) ||
        w->c[0].cur != w->c[0].end ||
        !tls_asn1_child_cursor(&w->t[2], &w->c[1]) ||
        !tls_asn1_next(&w->c[1], &w->t[3]) ||
        w->t[3].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        w->c[1].cur != w->c[1].end ||
        !tls_asn1_child_cursor(&w->t[3], &w->c[1]) ||
        !tls_asn1_next(&w->c[1], &w->t[4]) ||
        w->t[4].tag != ASN1_OBJECTID || w->t[4].len != sizeof(oid_basic) ||
        memcmp(w->t[4].value, oid_basic, sizeof(oid_basic)) != 0 ||
        !tls_asn1_next(&w->c[1], &w->t[5]) ||
        w->t[5].tag != ASN1_OCTETSTRING || w->c[1].cur != w->c[1].end)
        goto out;

    if (!tls_asn1_cursor_init(&w->c[0], w->t[5].value, w->t[5].len) ||
        !tls_asn1_next(&w->c[0], &w->t[0]) ||
        w->t[0].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        w->c[0].cur != w->c[0].end ||
        !tls_asn1_child_cursor(&w->t[0], &w->c[0]) ||
        !tls_asn1_next(&w->c[0], &w->t[1]) ||
        w->t[1].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        !tls_asn1_next(&w->c[0], &w->t[2]) ||
        !tls_x509_signature_algorithm(&w->t[2], &sig_alg) ||
        !tls_asn1_next(&w->c[0], &w->t[3]) ||
        w->t[3].tag != ASN1_BITSTRING || w->t[3].len < 2 ||
        w->t[3].value[0] != 0)
        goto out;
    response_data = w->t[1];
    response_signature = w->t[3];
    if (w->c[0].cur < w->c[0].end)
    {
        if (!tls_asn1_next(&w->c[0], &embedded_certs) ||
            embedded_certs.tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC) ||
            w->c[0].cur != w->c[0].end)
            goto out;
    }

    if (!tls_asn1_child_cursor(&response_data, &w->c[0]) ||
        !tls_asn1_next(&w->c[0], &w->t[4]))
        goto out;
    if (w->t[4].tag == (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC) &&
        !tls_asn1_next(&w->c[0], &w->t[4]))
        goto out;
    responder_id = w->t[4];
    if (responder_id.tag == (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC | 1))
    {
        if (!tls_asn1_cursor_init(&w->c[1], responder_id.value,
                                  responder_id.len) ||
            !tls_asn1_next(&w->c[1], &w->t[5]) ||
            w->t[5].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            w->c[1].cur != w->c[1].end)
            goto out;
        sha1_oneshot(w->t[5].tlv, w->t[5].header_len + w->t[5].len, w->hash);
        if (memcmp(w->hash, issuer_name_hash, OCSP_SHA1_LEN) == 0)
            response_key = issuer_key;
    }
    else if (responder_id.tag == (ASN1_CONTEXTSPEC | 2) &&
             responder_id.len == OCSP_SHA1_LEN &&
             memcmp(responder_id.value, issuer_key_hash,
                    OCSP_SHA1_LEN) == 0)
        response_key = issuer_key;
    else if (responder_id.tag != (ASN1_CONTEXTSPEC | 2) ||
             responder_id.len != OCSP_SHA1_LEN)
        goto out;
    if (!response_key)
        response_key = ocsp_delegated_responder_key(
            w, embedded_certs.tlv ? &embedded_certs : NULL, &responder_id,
            issuer_name_hash, issuer_key, now_secs);
    if (!response_key ||
        tls_x509_signature_verify(
            response_data.tlv, response_data.header_len + response_data.len,
            response_signature.value + 1, response_signature.len - 1,
            response_key, sig_alg) != TLS_KEY_OP_OK)
        goto out;
    if (!tls_asn1_next(&w->c[0], &w->t[4]) ||
        !ocsp_time(&w->t[4], &produced_at) ||
        !ocsp_not_too_future(produced_at, now_secs) ||
        !tls_asn1_next(&w->c[0], &w->t[5]) ||
        w->t[5].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
        !tls_asn1_child_cursor(&w->t[5], &w->c[0]))
        goto out;

    while (w->c[0].cur < w->c[0].end)
    {
        bool certid_match;
        has_next_update = false;
        next_update = 0;
        if (!tls_asn1_next(&w->c[0], &w->t[0]) ||
            w->t[0].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&w->t[0], &w->c[1]) ||
            !tls_asn1_next(&w->c[1], &w->t[1]) ||
            w->t[1].tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) ||
            !tls_asn1_child_cursor(&w->t[1], &w->c[2]) ||
            !tls_asn1_next(&w->c[2], &w->t[2]) ||
            !ocsp_sha1_identifier(&w->t[2]) ||
            !tls_asn1_next(&w->c[2], &w->t[3]) ||
            w->t[3].tag != ASN1_OCTETSTRING || w->t[3].len != OCSP_SHA1_LEN ||
            !tls_asn1_next(&w->c[2], &w->t[4]) ||
            w->t[4].tag != ASN1_OCTETSTRING || w->t[4].len != OCSP_SHA1_LEN ||
            !tls_asn1_next(&w->c[2], &w->t[5]) || w->c[2].cur != w->c[2].end)
            goto out;
        certid_match = memcmp(w->t[3].value, issuer_name_hash, OCSP_SHA1_LEN) == 0 &&
                       memcmp(w->t[4].value, issuer_key_hash, OCSP_SHA1_LEN) == 0 &&
                       ocsp_serial_equal(&w->t[5], serial, serial_len);
        if (!tls_asn1_next(&w->c[1], &w->t[6]) ||
            tls_asn1_tag_class(w->t[6].tag) != ASN1_CONTEXTSPEC ||
            tls_asn1_tag_number(w->t[6].tag) > 2 ||
            !tls_asn1_next(&w->c[1], &w->t[7]) ||
            !ocsp_time(&w->t[7], &this_update))
            goto out;
        if ((tls_asn1_tag_number(w->t[6].tag) == 0 &&
             (w->t[6].tag != ASN1_CONTEXTSPEC || w->t[6].len != 0)) ||
            (tls_asn1_tag_number(w->t[6].tag) == 1 &&
             w->t[6].tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC | 1)) ||
            (tls_asn1_tag_number(w->t[6].tag) == 2 &&
             (w->t[6].tag != (ASN1_CONTEXTSPEC | 2) || w->t[6].len != 0)))
            goto out;
        if (w->c[1].cur < w->c[1].end)
        {
            if (!tls_asn1_next(&w->c[1], &w->t[8]))
                goto out;
            if (w->t[8].tag == (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC))
            {
                if (!tls_asn1_child_cursor(&w->t[8], &w->c[3]) ||
                    !tls_asn1_next(&w->c[3], &w->t[9]) ||
                    w->c[3].cur != w->c[3].end ||
                    !ocsp_time(&w->t[9], &next_update))
                    goto out;
                has_next_update = true;
                if (w->c[1].cur < w->c[1].end &&
                    (!tls_asn1_next(&w->c[1], &w->t[8]) ||
                     w->t[8].tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC | 1)))
                    goto out;
            }
            else if (w->t[8].tag != (ASN1_CONSTRUCTED | ASN1_CONTEXTSPEC | 1))
                goto out;
            if (w->c[1].cur != w->c[1].end)
                goto out;
        }
        if (!certid_match)
            continue;
        if (!ocsp_not_too_future(this_update, now_secs) ||
            (produced_at < this_update &&
             this_update - produced_at > OCSP_CLOCK_SKEW_SECONDS) ||
            (has_next_update && now_secs > next_update &&
             now_secs - next_update > OCSP_CLOCK_SKEW_SECONDS) ||
            (has_next_update && next_update < this_update) ||
            (!has_next_update && now_secs > this_update &&
             now_secs - this_update > OCSP_MAX_AGE_SECONDS))
            goto out;
        result = tls_asn1_tag_number(w->t[6].tag) == 0 ? OCSP_GOOD :
                 tls_asn1_tag_number(w->t[6].tag) == 1 ? OCSP_REVOKED :
                                                        OCSP_UNKNOWN;
        goto out;
    }
    result = OCSP_UNKNOWN;

out:
    tls_fileio_free(w);
    return result;
}
