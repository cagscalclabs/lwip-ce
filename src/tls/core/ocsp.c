#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../includes/asn1.h"
#include "../includes/ocsp.h"

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
    uint32_t w[80], a, b, c, d, e, f, k, temp;
    int i;

    for (i = 0; i < 16; i++)
    {
        w[i]  = (uint32_t)block[i*4  ] << 24;
        w[i] |= (uint32_t)block[i*4+1] << 16;
        w[i] |= (uint32_t)block[i*4+2] <<  8;
        w[i] |= (uint32_t)block[i*4+3];
    }
    for (i = 16; i < 80; i++)
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2];
    d = ctx->h[3]; e = ctx->h[4];

    for (i = 0; i < 80; i++)
    {
        if      (i < 20) { f = (b & c) ^ (~b & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;           k = 0xCA62C1D6u; }
        temp = SHA1_ROTL(a, 5) + f + e + k + w[i];
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
    ctx->hi += (uint32_t)(len >> 29);

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
