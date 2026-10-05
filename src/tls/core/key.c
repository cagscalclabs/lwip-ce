/**
 * @file key.c
 * @author Anthony Cagliano
 * @brief Self-describing key operations: import, verify, sign, encrypt, decrypt.
 *
 * tls_key_import / tls_key_free handle PEM/DER parsing and allocation.
 * Operations select alg explicitly and validate key->type.  AES encrypt/decrypt operations
 * are fully one-shot: the AES context is constructed internally, a fresh IV
 * is generated via tls_random_bytes, and the context is destroyed on return.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../includes/hash.h"
#include "../includes/rsa.h"
#include "../includes/aes.h"
#include "../includes/random.h"
#include "../includes/bytes.h"
#include "../includes/base64.h"
#include "../includes/passwords.h"
#include "../includes/asn1.h"
#include "../includes/key.h"
#include "key_internal.h"
#include "../includes/x509.h"
#include "../includes/tls.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_KEY
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

/* ---------------------------------------------------------------------------
 * Import: OID table
 * --------------------------------------------------------------------------- */

/* DER OIDs referenced during key parsing. */
static const uint8_t OID_RSA_ENCRYPTION[]     = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01}; /* 9 */
static const uint8_t OID_EC_PUBLICKEY[]        = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};           /* 7 */
static const uint8_t OID_PBKDF2[]             = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c}; /* 9 */
static const uint8_t OID_PBES2[]              = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d}; /* 9 */
static const uint8_t OID_HMAC_SHA256[]        = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x09};      /* 8 */
static const uint8_t OID_AES_128_CBC[]        = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02}; /* 9 */
static const uint8_t OID_AES_256_CBC[]        = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a}; /* 9 */
static const uint8_t OID_AES_128_GCM[]        = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x06}; /* 9 */
static const uint8_t OID_AES_256_GCM[]        = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2e}; /* 9 */

static bool oid_eq(const struct tls_asn1_tlv *tlv,
                   const uint8_t *oid, size_t oid_len)
{
    return tlv && tls_asn1_tag_number(tlv->tag) == ASN1_OBJECTID
        && tlv->len == oid_len
        && memcmp(tlv->value, oid, oid_len) == 0;
}

/* ---------------------------------------------------------------------------
 * Import: PEM strip + base64 decode → DER
 * --------------------------------------------------------------------------- */

/*
 * Strips the -----BEGIN ...----- / -----END ...----- banners, collects only
 * valid base64 payload characters (skips whitespace), then decodes in-place.
 * der_cap must be >= pem_len (the base64 payload is always shorter than the
 * PEM text).  Returns the decoded DER length, or 0 on any error.
 */
static size_t key_pem_to_der(const char *pem, size_t pem_len,
                              const char *banner,
                              uint8_t *der, size_t der_cap)
{
    size_t banner_len = strlen(banner);
    if (pem_len < banner_len || memcmp(pem, banner, banner_len) != 0)
        return 0;

    /* Advance past the opening banner line. */
    const char *p   = memchr(pem, '\n', pem_len);
    if (!p) return 0;
    p++;

    const char *end = pem + pem_len;
    size_t b64_len  = 0;

    while (p < end)
    {
        if ((size_t)(end - p) >= 5 && memcmp(p, "-----", 5) == 0)
            break;
        char c = *p++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
        {
            if (b64_len >= der_cap) return 0;
            der[b64_len++] = (uint8_t)c;
        }
        else if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
        {
            return 0;
        }
    }

    if (b64_len == 0 || (b64_len & 3) != 0) return 0;
    size_t der_len = tls_base64_decode(der, b64_len, der);
    return (der_len > 0 && der_len <= der_cap) ? der_len : 0;
}

/* ---------------------------------------------------------------------------
 * Import: big-endian DER INTEGER → size_t (for iteration count / key length)
 * --------------------------------------------------------------------------- */

void rmemcpy(void *dest, void *src, size_t len);

static size_t key_der_int_to_size(const uint8_t *data, size_t len)
{
    size_t v = 0;
    rmemcpy(&v, (void *)data, len < sizeof(v) ? len : sizeof(v));
    return v;
}

/* ---------------------------------------------------------------------------
 * Import: parse RSA public key (PKCS#1 RSAPublicKey)
 *   SEQUENCE { INTEGER modulus, INTEGER publicExponent }
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_parse_rsa_pub(const uint8_t *der, size_t der_len,
                  struct tls_key *out)
{
    struct tls_asn1_cursor c, body;
    struct tls_asn1_tlv seq, mod, exp;

    if (!tls_asn1_cursor_init(&c, der, der_len)    ||
        !tls_asn1_next(&c, &seq)                    ||
        !tls_asn1_tag_constructed(seq.tag)           ||
        tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    if (!tls_asn1_child_cursor(&seq, &body)         ||
        !tls_asn1_next(&body, &mod)                  ||
        !tls_asn1_next(&body, &exp)                  ||
        tls_asn1_tag_number(mod.tag) != ASN1_INTEGER ||
        tls_asn1_tag_number(exp.tag) != ASN1_INTEGER)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* Skip leading zero byte PKCS#1 adds to keep modulus positive. */
    const uint8_t *mod_data = mod.value;
    size_t         mod_len  = mod.len;
    if (mod_len > 1 && mod_data[0] == 0x00) { mod_data++; mod_len--; }

    out->type = TLS_KEY_TYPE_RSA;
    out->rsa.mod_len  = mod_len;
    out->rsa.modulus  = mod_data;
    out->rsa.exp_len  = exp.len;
    out->rsa.exponent = exp.value;
    return TLS_KEY_IMPORT_OK;
}

/* ---------------------------------------------------------------------------
 * Import: parse RSA private key (PKCS#1 RSAPrivateKey) — public-key fields
 *   SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }
 *   We expose only n and e (indices 0 and 1 after version).
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_parse_rsa_priv(const uint8_t *der, size_t der_len,
                   struct tls_key *out)
{
    struct tls_asn1_cursor c, body;
    struct tls_asn1_tlv seq, item;

    if (!tls_asn1_cursor_init(&c, der, der_len)      ||
        !tls_asn1_next(&c, &seq)                      ||
        !tls_asn1_tag_constructed(seq.tag)             ||
        tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE  ||
        !tls_asn1_child_cursor(&seq, &body))
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* Skip version INTEGER. */
    if (!tls_asn1_next(&body, &item) ||
        tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    struct tls_asn1_tlv mod, exp;
    if (!tls_asn1_next(&body, &mod) || tls_asn1_tag_number(mod.tag) != ASN1_INTEGER ||
        !tls_asn1_next(&body, &exp) || tls_asn1_tag_number(exp.tag) != ASN1_INTEGER)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    const uint8_t *mod_data = mod.value;
    size_t         mod_len  = mod.len;
    if (mod_len > 1 && mod_data[0] == 0x00) { mod_data++; mod_len--; }

    out->type = TLS_KEY_TYPE_RSA;
    out->rsa.mod_len  = mod_len;
    out->rsa.modulus  = mod_data;
    out->rsa.exp_len  = exp.len;
    out->rsa.exponent = exp.value;
    return TLS_KEY_IMPORT_OK;
}

/* ---------------------------------------------------------------------------
 * Import: parse EC public key (uncompressed point from SPKI BIT STRING)
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_parse_ec_pub_point(const uint8_t *data, size_t len,
                       struct tls_key *out)
{
    /* BIT STRING has a leading unused-bits byte; skip it. */
    if (len != 66 || data[0] != 0 || data[1] != 4)
        return TLS_KEY_IMPORT_PARSE_FAIL;
    out->type = TLS_KEY_TYPE_EC_P256;
    out->ec.data = data + 1;
    out->ec.len  = len  - 1;
    return TLS_KEY_IMPORT_OK;
}

/* Only named P-256 is representable by the current EC algorithm enum. */
static bool key_p256(const struct tls_asn1_tlv *param)
{
    static const uint8_t oid[] = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    return oid_eq(param, oid, sizeof(oid));
}

static tls_key_import_result_t
key_parse_sec1(const uint8_t *der, size_t len, struct tls_key *out,
               bool inherited_p256)
{
    struct tls_asn1_cursor c, body;
    struct tls_asn1_tlv seq, version, secret, field, value;
    const uint8_t *point = NULL;
    size_t point_len = 0;
    bool have_params = false;
    if (!tls_asn1_cursor_init(&c, der, len) || !tls_asn1_next(&c, &seq) ||
        c.cur != c.end || seq.tag != 0x30 || !tls_asn1_child_cursor(&seq, &body) ||
        !tls_asn1_next(&body, &version) || version.tag != ASN1_INTEGER ||
        version.len != 1 || version.value[0] != 1 ||
        !tls_asn1_next(&body, &secret) || secret.tag != ASN1_OCTETSTRING || secret.len != 32)
        return TLS_KEY_IMPORT_PARSE_FAIL;
    while (body.cur != body.end)
    {
        struct tls_asn1_cursor explicit_value;
        if (!tls_asn1_next(&body, &field) ||
            !tls_asn1_child_cursor(&field, &explicit_value) ||
            !tls_asn1_next(&explicit_value, &value) || explicit_value.cur != explicit_value.end)
            return TLS_KEY_IMPORT_PARSE_FAIL;
        if (field.tag == 0xa0 && !have_params && !point)
        {
            if (!key_p256(&value)) return TLS_KEY_IMPORT_BAD_ALG;
            have_params = true;
        }
        else if (field.tag == 0xa1 && !point && value.tag == ASN1_BITSTRING)
        {
            point = value.value;
            point_len = value.len;
        }
        else return TLS_KEY_IMPORT_PARSE_FAIL;
    }
    if (!inherited_p256 && !have_params) return TLS_KEY_IMPORT_BAD_ALG;
    if (!point) return TLS_KEY_IMPORT_PARSE_FAIL;
    return key_parse_ec_pub_point(point, point_len, out);
}

/* ---------------------------------------------------------------------------
 * Import: parse SubjectPublicKeyInfo (public key wrapper)
 *   SEQUENCE { SEQUENCE { OID algorithm }, BIT STRING subjectPublicKey }
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_parse_spki(const uint8_t *der, size_t der_len, struct tls_key *out)
{
    struct tls_asn1_cursor c, spki_body, alg_body;
    struct tls_asn1_tlv spki, alg_seq, spk_bits, alg_oid;

    if (!tls_asn1_cursor_init(&c, der, der_len)       ||
        !tls_asn1_next(&c, &spki)                      ||
        !tls_asn1_tag_constructed(spki.tag)             ||
        tls_asn1_tag_number(spki.tag) != ASN1_SEQUENCE  ||
        !tls_asn1_child_cursor(&spki, &spki_body)       ||
        !tls_asn1_next(&spki_body, &alg_seq)            ||
        !tls_asn1_next(&spki_body, &spk_bits)           ||
        !tls_asn1_tag_constructed(alg_seq.tag)          ||
        tls_asn1_tag_number(alg_seq.tag) != ASN1_SEQUENCE ||
        tls_asn1_tag_number(spk_bits.tag) != ASN1_BITSTRING ||
        spk_bits.len < 1)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    if (!tls_asn1_child_cursor(&alg_seq, &alg_body) ||
        !tls_asn1_next(&alg_body, &alg_oid)          ||
        tls_asn1_tag_number(alg_oid.tag) != ASN1_OBJECTID)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    if (oid_eq(&alg_oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)))
    {
        /* RSAPublicKey is DER-inside-BIT STRING; first byte is unused-bit count. */
        if (spk_bits.value[0] != 0) return TLS_KEY_IMPORT_PARSE_FAIL;
        return key_parse_rsa_pub(spk_bits.value + 1, spk_bits.len - 1, out);
    }
    if (oid_eq(&alg_oid, OID_EC_PUBLICKEY, sizeof(OID_EC_PUBLICKEY)))
    {
        struct tls_asn1_tlv curve;
        if (!tls_asn1_next(&alg_body, &curve) || !key_p256(&curve) || alg_body.cur != alg_body.end)
            return TLS_KEY_IMPORT_BAD_ALG;
        return key_parse_ec_pub_point(spk_bits.value, spk_bits.len, out);
    }

    return TLS_KEY_IMPORT_BAD_ALG;
}

/* ---------------------------------------------------------------------------
 * Import: parse PKCS#8 OneAsymmetricKey (unencrypted private key wrapper)
 *   SEQUENCE { version, SEQUENCE { OID algorithm }, OCTET STRING privateKey }
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_parse_pkcs8_priv(const uint8_t *der, size_t der_len, struct tls_key *out)
{
    struct tls_asn1_cursor c, pki_body, alg_body;
    struct tls_asn1_tlv pki, version, alg_seq, priv_octet, alg_oid;

    if (!tls_asn1_cursor_init(&c, der, der_len)          ||
        !tls_asn1_next(&c, &pki)                          ||
        !tls_asn1_tag_constructed(pki.tag)                 ||
        tls_asn1_tag_number(pki.tag) != ASN1_SEQUENCE      ||
        !tls_asn1_child_cursor(&pki, &pki_body)            ||
        !tls_asn1_next(&pki_body, &version)                ||
        !tls_asn1_next(&pki_body, &alg_seq)                ||
        !tls_asn1_next(&pki_body, &priv_octet)             ||
        tls_asn1_tag_number(version.tag) != ASN1_INTEGER   ||
        !tls_asn1_tag_constructed(alg_seq.tag)             ||
        tls_asn1_tag_number(alg_seq.tag) != ASN1_SEQUENCE  ||
        tls_asn1_tag_number(priv_octet.tag) != ASN1_OCTETSTRING)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    if (!tls_asn1_child_cursor(&alg_seq, &alg_body) ||
        !tls_asn1_next(&alg_body, &alg_oid)          ||
        tls_asn1_tag_number(alg_oid.tag) != ASN1_OBJECTID)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    if (oid_eq(&alg_oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)))
        return key_parse_rsa_priv(priv_octet.value, priv_octet.len, out);

    if (oid_eq(&alg_oid, OID_EC_PUBLICKEY, sizeof(OID_EC_PUBLICKEY)))
    {
        struct tls_asn1_tlv curve;
        if (!tls_asn1_next(&alg_body, &curve) || !key_p256(&curve) || alg_body.cur != alg_body.end)
            return TLS_KEY_IMPORT_BAD_ALG;
        return key_parse_sec1(priv_octet.value, priv_octet.len, out, true);
    }

    return TLS_KEY_IMPORT_BAD_ALG;
}

/* ---------------------------------------------------------------------------
 * Import: decrypt EncryptedPrivateKeyInfo (PBES2)
 *
 * Supports all AES cipher modes available in this library:
 *   AES-128-CBC, AES-256-CBC  (RFC 8018 §6.2.2)
 *   AES-128-GCM, AES-256-GCM  (RFC 8018bis / RFC 9579)
 *
 * Decrypts in-place into buf[0..enc_data.len).  On success, *inner_der and
 * *inner_der_len point at the plaintext PKCS#8 OneAsymmetricKey DER inside
 * buf (PKCS#7 padding or GCM tag already stripped).
 * --------------------------------------------------------------------------- */

static tls_key_import_result_t
key_decrypt_pbes2(const uint8_t *epi_der, size_t epi_len,
                  const char *password,
                  uint8_t *buf,                /* scratch: buf[0..epi_len) */
                  const uint8_t **inner_der,
                  size_t         *inner_der_len)
{
    struct tls_asn1_cursor c, epi_body, enc_alg_cur;
    struct tls_asn1_cursor pbes2_cur, kdf_cur, pbkdf2_cur, enc_scheme_cur;
    struct tls_asn1_tlv encrypted_info, enc_alg, enc_data;
    struct tls_asn1_tlv pbes2_oid, pbes2_params;
    struct tls_asn1_tlv kdf_seq, enc_scheme;
    struct tls_asn1_tlv pbkdf2_oid, pbkdf2_params;
    struct tls_asn1_tlv salt, rounds_tlv, maybe_keylen, prf_seq, prf_oid;
    struct tls_asn1_tlv aes_oid, iv_tlv;

    /* EncryptedPrivateKeyInfo ::= SEQUENCE {
     *   encryptionAlgorithm AlgorithmIdentifier,
     *   encryptedData OCTET STRING } */
    if (!tls_asn1_cursor_init(&c, epi_der, epi_len)                  ||
        !tls_asn1_next(&c, &encrypted_info)                           ||
        !tls_asn1_tag_constructed(encrypted_info.tag)                 ||
        tls_asn1_tag_number(encrypted_info.tag) != ASN1_SEQUENCE      ||
        !tls_asn1_child_cursor(&encrypted_info, &epi_body)            ||
        !tls_asn1_next(&epi_body, &enc_alg)                           ||
        !tls_asn1_next(&epi_body, &enc_data)                          ||
        !tls_asn1_tag_constructed(enc_alg.tag)                        ||
        tls_asn1_tag_number(enc_alg.tag) != ASN1_SEQUENCE             ||
        tls_asn1_tag_number(enc_data.tag) != ASN1_OCTETSTRING)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* AlgorithmIdentifier must be PBES2. */
    if (!tls_asn1_child_cursor(&enc_alg, &enc_alg_cur)                ||
        !tls_asn1_next(&enc_alg_cur, &pbes2_oid)                      ||
        !tls_asn1_next(&enc_alg_cur, &pbes2_params)                   ||
        !oid_eq(&pbes2_oid, OID_PBES2, sizeof(OID_PBES2))             ||
        !tls_asn1_tag_constructed(pbes2_params.tag)                   ||
        tls_asn1_tag_number(pbes2_params.tag) != ASN1_SEQUENCE)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }. */
    if (!tls_asn1_child_cursor(&pbes2_params, &pbes2_cur)             ||
        !tls_asn1_next(&pbes2_cur, &kdf_seq)                          ||
        !tls_asn1_next(&pbes2_cur, &enc_scheme)                       ||
        !tls_asn1_tag_constructed(kdf_seq.tag)                        ||
        tls_asn1_tag_number(kdf_seq.tag) != ASN1_SEQUENCE             ||
        !tls_asn1_tag_constructed(enc_scheme.tag)                     ||
        tls_asn1_tag_number(enc_scheme.tag) != ASN1_SEQUENCE)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* KDF must be PBKDF2. */
    if (!tls_asn1_child_cursor(&kdf_seq, &kdf_cur)                    ||
        !tls_asn1_next(&kdf_cur, &pbkdf2_oid)                         ||
        !tls_asn1_next(&kdf_cur, &pbkdf2_params)                      ||
        !oid_eq(&pbkdf2_oid, OID_PBKDF2, sizeof(OID_PBKDF2))         ||
        !tls_asn1_tag_constructed(pbkdf2_params.tag)                  ||
        tls_asn1_tag_number(pbkdf2_params.tag) != ASN1_SEQUENCE)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* PBKDF2-params: salt OCTET STRING, iterationCount INTEGER,
     *   keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier OPTIONAL. */
    if (!tls_asn1_child_cursor(&pbkdf2_params, &pbkdf2_cur) ||
        !tls_asn1_next(&pbkdf2_cur, &salt)                  ||
        !tls_asn1_next(&pbkdf2_cur, &rounds_tlv)            ||
        tls_asn1_tag_number(salt.tag) != ASN1_OCTETSTRING   ||
        tls_asn1_tag_number(rounds_tlv.tag) != ASN1_INTEGER)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* Optional keyLength and prf. */
    maybe_keylen.tag   = 0; maybe_keylen.value = NULL; maybe_keylen.len = 0;
    prf_seq.tag        = 0; prf_seq.value      = NULL; prf_seq.len      = 0;
    if (tls_asn1_next(&pbkdf2_cur, &maybe_keylen))
    {
        if (tls_asn1_tag_number(maybe_keylen.tag) == ASN1_INTEGER)
        {
            /* keyLength present; prf may follow. */
            tls_asn1_next(&pbkdf2_cur, &prf_seq);
        }
        else
        {
            /* No keyLength; what we read is actually prf. */
            prf_seq    = maybe_keylen;
            maybe_keylen.tag = 0; maybe_keylen.value = NULL; maybe_keylen.len = 0;
        }
    }

    /* If a PRF AlgorithmIdentifier is present it must be HMAC-SHA-256. */
    if (prf_seq.tag != 0)
    {
        struct tls_asn1_cursor prf_cur;
        if (!tls_asn1_child_cursor(&prf_seq, &prf_cur) ||
            !tls_asn1_next(&prf_cur, &prf_oid)          ||
            !oid_eq(&prf_oid, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256)))
            return TLS_KEY_IMPORT_PARSE_FAIL;
    }

    /* Encryption scheme: OID + IV/nonce parameter. */
    if (!tls_asn1_child_cursor(&enc_scheme, &enc_scheme_cur) ||
        !tls_asn1_next(&enc_scheme_cur, &aes_oid)             ||
        !tls_asn1_next(&enc_scheme_cur, &iv_tlv)              ||
        tls_asn1_tag_number(iv_tlv.tag) != ASN1_OCTETSTRING)
        return TLS_KEY_IMPORT_PARSE_FAIL;

    /* Determine cipher mode and key length from the encryption OID. */
    uint8_t aes_mode;
    size_t  key_len;
    if      (oid_eq(&aes_oid, OID_AES_128_CBC, sizeof(OID_AES_128_CBC))) { aes_mode = TLS_AES_CBC; key_len = 16; }
    else if (oid_eq(&aes_oid, OID_AES_256_CBC, sizeof(OID_AES_256_CBC))) { aes_mode = TLS_AES_CBC; key_len = 32; }
    else if (oid_eq(&aes_oid, OID_AES_128_GCM, sizeof(OID_AES_128_GCM))) { aes_mode = TLS_AES_GCM; key_len = 16; }
    else if (oid_eq(&aes_oid, OID_AES_256_GCM, sizeof(OID_AES_256_GCM))) { aes_mode = TLS_AES_GCM; key_len = 32; }
    else return TLS_KEY_IMPORT_UNSUPPORTED_ENC;

    /* keyLength field overrides the OID-implied length when present. */
    if (maybe_keylen.value)
        key_len = key_der_int_to_size(maybe_keylen.value, maybe_keylen.len);

    size_t rounds = key_der_int_to_size(rounds_tlv.value, rounds_tlv.len);

    /* Derive the wrapping key with PBKDF2-HMAC-SHA256. */
    uint8_t derived[32];
    if (!tls_pbkdf2(password, strlen(password),
                    salt.value, salt.len,
                    derived, key_len,
                    rounds, TLS_HASH_SHA256))
        return TLS_KEY_IMPORT_DECRYPT_FAIL;

    /* Decrypt into buf.  GCM carries a 16-byte tag appended to ciphertext. */
    size_t pt_len = enc_data.len;
    struct tls_aes_context aes_ctx;
    bool ok = false;

    if (aes_mode == TLS_AES_GCM)
    {
        if (pt_len < TLS_AES_AUTH_TAG_SIZE) goto done;
        pt_len -= TLS_AES_AUTH_TAG_SIZE;
        const uint8_t *tag = enc_data.value + pt_len;
        if (!tls_aes_init(&aes_ctx, TLS_AES_GCM,
                          derived, key_len, iv_tlv.value, iv_tlv.len))
            goto done;
        if (!tls_aes_verify(&aes_ctx, NULL, 0, enc_data.value, pt_len, tag))
            goto done;
        /* Re-init for decrypt (verify consumed the context). */
        if (!tls_aes_init(&aes_ctx, TLS_AES_GCM,
                          derived, key_len, iv_tlv.value, iv_tlv.len))
            goto done;
        ok = tls_aes_decrypt(&aes_ctx, enc_data.value, pt_len, buf);
    }
    else /* CBC */
    {
        if (!tls_aes_init(&aes_ctx, TLS_AES_CBC,
                          derived, key_len, iv_tlv.value, iv_tlv.len))
            goto done;
        if (!tls_aes_decrypt(&aes_ctx, enc_data.value, enc_data.len, buf))
            goto done;
        /* Strip PKCS#7 padding. */
        if (enc_data.len == 0 || buf[enc_data.len - 1] > enc_data.len)
            goto done;
        pt_len = enc_data.len - buf[enc_data.len - 1];
        ok = true;
    }

done:
    tls_secure_memzero(&aes_ctx, sizeof(aes_ctx));
    tls_secure_memzero(derived,  sizeof(derived));
    if (!ok) return TLS_KEY_IMPORT_DECRYPT_FAIL;

    *inner_der     = buf;
    *inner_der_len = pt_len;
    return TLS_KEY_IMPORT_OK;
}

/* ---------------------------------------------------------------------------
 * Import: banner dispatch table
 * --------------------------------------------------------------------------- */

typedef enum
{
    KEY_FMT_PKCS1_RSA_PRIV,
    KEY_FMT_PKCS1_RSA_PUB,
    KEY_FMT_PKCS8_PRIV,
    KEY_FMT_PKCS8_ENC_PRIV,
    KEY_FMT_SPKI,
    KEY_FMT_SEC1_EC_PRIV,
} key_pem_fmt_t;

static const struct
{
    const char *banner;
    key_pem_fmt_t fmt;
} key_banners[] = {
    { "-----BEGIN RSA PRIVATE KEY-----",       KEY_FMT_PKCS1_RSA_PRIV  },
    { "-----BEGIN RSA PUBLIC KEY-----",        KEY_FMT_PKCS1_RSA_PUB   },
    { "-----BEGIN PRIVATE KEY-----",           KEY_FMT_PKCS8_PRIV      },
    { "-----BEGIN ENCRYPTED PRIVATE KEY-----", KEY_FMT_PKCS8_ENC_PRIV  },
    { "-----BEGIN PUBLIC KEY-----",            KEY_FMT_SPKI             },
    { "-----BEGIN EC PRIVATE KEY-----",        KEY_FMT_SEC1_EC_PRIV    },
};

/* Determine the encoding from its ASN.1 structure, independently of the
 * requested operation. The selected parser validates the contents/OID. */
static bool key_der_format(const uint8_t *der, size_t len, key_pem_fmt_t *fmt)
{
    struct tls_asn1_cursor c, body;
    struct tls_asn1_tlv seq, first, second;
    if (!tls_asn1_cursor_init(&c, der, len) || !tls_asn1_next(&c, &seq) ||
        c.cur != c.end || seq.tag != 0x30 || !tls_asn1_child_cursor(&seq, &body) ||
        !tls_asn1_next(&body, &first) || !tls_asn1_next(&body, &second))
        return false;
    if (first.tag == 0x30 && second.tag == ASN1_BITSTRING) *fmt = KEY_FMT_SPKI;
    else if (first.tag == 0x30 && second.tag == ASN1_OCTETSTRING) *fmt = KEY_FMT_PKCS8_ENC_PRIV;
    else if (first.tag == ASN1_INTEGER && second.tag == 0x30) *fmt = KEY_FMT_PKCS8_PRIV;
    else if (first.tag == ASN1_INTEGER && second.tag == ASN1_OCTETSTRING) *fmt = KEY_FMT_SEC1_EC_PRIV;
    else if (first.tag == ASN1_INTEGER && second.tag == ASN1_INTEGER)
        *fmt = body.cur == body.end ? KEY_FMT_PKCS1_RSA_PUB : KEY_FMT_PKCS1_RSA_PRIV;
    else return false;
    return true;
}

/* ---------------------------------------------------------------------------
 * tls_key_import / tls_key_destroy
 * --------------------------------------------------------------------------- */

tls_key_import_result_t tls_key_import(struct tls_key **out,
                                        const void *data, size_t len,
                                        tls_key_format_t format,
                                        const char *password)
{
    if (!out) return TLS_KEY_IMPORT_INVALID_ARG;
    *out = NULL;
    if (!data || len == 0 || len > SIZE_MAX - sizeof(struct tls_key) ||
        (format != TLS_KEY_FORMAT_PEM && format != TLS_KEY_FORMAT_DER))
        return TLS_KEY_IMPORT_INVALID_ARG;

    /*
     * Allocate a single block:
     *   [ tls_alloc_hdr (hidden) | struct tls_key | DER bytes ]
     *
     * The DER is copied into the trailing space so key material pointers
     * remain valid for the lifetime of the tls_key.  len is an upper bound
     * (PEM decodes to fewer bytes), which is fine — we don't expose the size.
     */
    size_t total = sizeof(struct tls_key) + len;
    struct tls_key *key = (struct tls_key *)tls_fileio_alloc(total);
    if (!key)
        return TLS_KEY_IMPORT_ALLOC_FAIL;

    memset(key, 0, sizeof(*key));
    key->type = TLS_KEY_TYPE_UNKNOWN;

    uint8_t *der_buf  = (uint8_t *)(key + 1);
    size_t   der_len  = 0;
    const uint8_t *parse_der     = NULL;
    size_t         parse_der_len = 0;
    tls_key_import_result_t rc   = TLS_KEY_IMPORT_PARSE_FAIL;

    key_pem_fmt_t fmt;

    if (format == TLS_KEY_FORMAT_PEM)
    {
        /* Identify the banner and pick the parse path. */
        const char *pem = (const char *)data;
        size_t      i;
        const char *matched_banner = NULL;
        for (i = 0; i < sizeof(key_banners) / sizeof(key_banners[0]); i++)
        {
            size_t blen = strlen(key_banners[i].banner);
            if (len >= blen && memcmp(pem, key_banners[i].banner, blen) == 0)
            {
                fmt            = key_banners[i].fmt;
                matched_banner = key_banners[i].banner;
                break;
            }
        }
        if (!matched_banner)
        {
            rc = TLS_KEY_IMPORT_PARSE_FAIL;
            goto fail;
        }

        der_len = key_pem_to_der(pem, len, matched_banner, der_buf, len);
        if (der_len == 0)
        {
            rc = TLS_KEY_IMPORT_PARSE_FAIL;
            goto fail;
        }
        parse_der     = der_buf;
        parse_der_len = der_len;
    }
    else /* TLS_KEY_FORMAT_DER */
    {
        memcpy(der_buf, data, len);
        parse_der = der_buf;
        parse_der_len = len;
        if (!key_der_format(parse_der, parse_der_len, &fmt))
            goto fail;
    }

    /* Handle encrypted private key — decrypt into der_buf, re-point. */
    if (fmt == KEY_FMT_PKCS8_ENC_PRIV)
    {
        if (!password)
        {
            rc = TLS_KEY_IMPORT_DECRYPT_FAIL;
            goto fail;
        }
        rc = key_decrypt_pbes2(parse_der, parse_der_len,
                                password, der_buf,
                                &parse_der, &parse_der_len);
        if (rc != TLS_KEY_IMPORT_OK)
            goto fail;
        /* After decryption we always have a plain PKCS#8 OneAsymmetricKey. */
        fmt = KEY_FMT_PKCS8_PRIV;
    }

    /* Parse the DER into key->rsa / key->ec pointers (into der_buf). */
    switch (fmt)
    {
        case KEY_FMT_PKCS1_RSA_PRIV:  rc = key_parse_rsa_priv(parse_der, parse_der_len, key); break;
        case KEY_FMT_PKCS1_RSA_PUB:   rc = key_parse_rsa_pub (parse_der, parse_der_len, key); break;
        case KEY_FMT_PKCS8_PRIV:      rc = key_parse_pkcs8_priv(parse_der, parse_der_len, key); break;
        case KEY_FMT_SPKI:            rc = key_parse_spki    (parse_der, parse_der_len, key); break;
        case KEY_FMT_SEC1_EC_PRIV:    rc = key_parse_sec1(parse_der, parse_der_len, key, false); break;
        default:                       rc = TLS_KEY_IMPORT_PARSE_FAIL; break;
    }
    if (rc != TLS_KEY_IMPORT_OK)
        goto fail;

    key->allocated = true;
    *out = key;
    return TLS_KEY_IMPORT_OK;

fail:
    tls_secure_memzero(key, total);
    tls_fileio_free(key);
    return rc;
}

void tls_key_free(struct tls_key *key)
{
    if (!key || !key->allocated) return;
    /*
     * tls_fileio_free zeroes the full allocation (tls_secure_memzero
     * in tls_fileio_free covers both header and key material).
     */
    tls_fileio_free(key);
}

/* ---------------------------------------------------------------------------
 * tls_key_verify / tls_key_sign
 * --------------------------------------------------------------------------- */

tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const struct tls_key *key, tls_alg_t alg)
{
    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }
    return tls_x509_signature_verify(content, content_len, sig, sig_len, key, alg);
}

tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                  uint8_t *sig_out, size_t *sig_len_out,
                                  const struct tls_key *key, tls_alg_t alg)
{
    (void)content;
    (void)content_len;
    (void)sig_out;
    (void)sig_len_out;

    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }

    switch (alg)
    {
        case TLS_ALG_RSA_PSS_RSAE_SHA256:
        case TLS_ALG_RSA_PKCS1_SHA256:
        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return tls_key_supports_operation(key, alg)
                ? TLS_KEY_OP_UNSUPPORTED : TLS_KEY_OP_INVALID;

        case TLS_ALG_UNKNOWN:
            return TLS_KEY_OP_UNKNOWN;

        default:
            /* Encryption-range alg passed to sign — wrong key type. */
            return TLS_KEY_OP_UNKNOWN;
    }
}

/* ---------------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------------- */

/* Returns the IV/nonce length for a given AES alg, or 0 if not AES. */
static size_t key_iv_len(tls_alg_t alg)
{
    switch (alg)
    {
        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
            return TLS_KEY_GCM_IV_LEN;
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            return TLS_KEY_CCM_NONCE_LEN;
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return TLS_AES_IV_SIZE;
        default:
            return 0;
    }
}

/* Maps tls_alg_t to the tls_aes_modes value expected by tls_aes_init. */
static uint8_t key_aes_mode(tls_alg_t alg)
{
    switch (alg)
    {
        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
            return TLS_AES_GCM;
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            return TLS_AES_CCM;
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
        default:
            return TLS_AES_CBC;
    }
}

static bool key_is_aead(tls_alg_t alg)
{
    return alg == TLS_ALG_AES_128_GCM || alg == TLS_ALG_AES_256_GCM ||
           alg == TLS_ALG_AES_128_CCM || alg == TLS_ALG_AES_256_CCM;
}

/* ---------------------------------------------------------------------------
 * Blob helpers
 *
 * Encrypt output: <u16 iv_len><iv><u16 ct_len><ct><u16 tag_len><tag>
 * Decrypt output: <u16 plain_len><plaintext>
 * All u16 values are little-endian.
 * --------------------------------------------------------------------------- */

#define BLOB_HDR  sizeof(uint16_t)

static void blob_write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t blob_read_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

/* Allocate an encrypt blob and return pointers to its field regions.
 * Returns the blob base, or NULL on allocation failure. */
static uint8_t *encrypt_blob_alloc(size_t iv_len, size_t ct_len, size_t tag_len,
                                    uint8_t **iv_out,
                                    uint8_t **ct_out,
                                    uint8_t **tag_out)
{
    size_t total = BLOB_HDR + iv_len + BLOB_HDR + ct_len + BLOB_HDR + tag_len;
    uint8_t *blob = (uint8_t *)tls_fileio_alloc(total);
    if (!blob)
        return NULL;

    uint8_t *p = blob;
    blob_write_u16(p, (uint16_t)iv_len);  p += BLOB_HDR;
    *iv_out = p;                            p += iv_len;
    blob_write_u16(p, (uint16_t)ct_len);  p += BLOB_HDR;
    *ct_out = p;                            p += ct_len;
    blob_write_u16(p, (uint16_t)tag_len); p += BLOB_HDR;
    *tag_out = p;

    return blob;
}

/* Parse the encrypt blob into its field pointers and lengths.
 * Returns false if the blob pointer is NULL. */
static bool encrypt_blob_parse(const uint8_t *blob,
                                 size_t *iv_len_out,  const uint8_t **iv_out,
                                 size_t *ct_len_out,  const uint8_t **ct_out,
                                 size_t *tag_len_out, const uint8_t **tag_out)
{
    if (!blob)
        return false;
    const uint8_t *p = blob;
    *iv_len_out  = blob_read_u16(p); p += BLOB_HDR; *iv_out  = p; p += *iv_len_out;
    *ct_len_out  = blob_read_u16(p); p += BLOB_HDR; *ct_out  = p; p += *ct_len_out;
    *tag_len_out = blob_read_u16(p); p += BLOB_HDR; *tag_out = p;
    return true;
}

/* Allocate a decrypt output blob: <u16 plain_len><plaintext>. */
static uint8_t *decrypt_blob_alloc(size_t plain_len, uint8_t **plain_out)
{
    uint8_t *blob = (uint8_t *)tls_fileio_alloc(BLOB_HDR + plain_len);
    if (!blob)
        return NULL;
    blob_write_u16(blob, (uint16_t)plain_len);
    *plain_out = blob + BLOB_HDR;
    return blob;
}

/* ---------------------------------------------------------------------------
 * AES one-shot encrypt (shared by plain and AAD variants)
 * --------------------------------------------------------------------------- */

static uint8_t *aes_encrypt_oneshot(tls_alg_t alg,
                                     const uint8_t *key_data,
                                     size_t key_len,
                                     const uint8_t *aad,
                                     size_t aad_len,
                                     const uint8_t *inbuf,
                                     size_t in_len)
{
    struct tls_aes_context ctx;
    size_t iv_len  = key_iv_len(alg);
    uint8_t mode   = key_aes_mode(alg);
    bool aead      = key_is_aead(alg);
    size_t tag_len = aead ? TLS_KEY_AES_TAG_LEN : 0;

    size_t ct_len;
    if (mode == TLS_AES_CBC)
    {
        size_t rem = in_len % TLS_AES_BLOCK_SIZE;
        ct_len = rem ? (in_len - rem + TLS_AES_BLOCK_SIZE) : in_len;
    }
    else
    {
        ct_len = in_len;
    }

    if (!tls_rng_healthcheck())
        return NULL;

    uint8_t *iv, *ct, *tag;
    uint8_t *blob = encrypt_blob_alloc(iv_len, ct_len, tag_len, &iv, &ct, &tag);
    if (!blob)
        return NULL;

    tls_random_bytes(iv, iv_len);

    bool ok = false;
    memset(&ctx, 0, sizeof(ctx));

    if (mode == TLS_AES_CCM)
    {
        ok = tls_aes_ccm_encrypt(key_data, key_len,
                                  iv, iv_len,
                                  aad, aad_len,
                                  inbuf, in_len,
                                  ct, tag, TLS_KEY_AES_TAG_LEN);
    }
    else
    {
        if (tls_aes_init(&ctx, mode, key_data, key_len, iv, iv_len) &&
            (!aad || !aad_len || tls_aes_update_aad(&ctx, aad, aad_len)) &&
            tls_aes_encrypt(&ctx, inbuf, in_len, ct) &&
            (!aead || tls_aes_digest(&ctx, tag)))
        {
            ok = true;
        }
        tls_secure_memzero(&ctx, sizeof(ctx));
    }

    if (!ok)
    {
        tls_cipher_blob_free(blob);
        return NULL;
    }
    return blob;
}


/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

void tls_cipher_blob_free(uint8_t *buf)
{
    tls_fileio_free(buf);
}

uint8_t *tls_cipher_blob_assemble(const uint8_t *iv,  size_t iv_len,
                                   const uint8_t *ct,  size_t ct_len,
                                   const uint8_t *tag, size_t tag_len)
{
    uint8_t *iv_p, *ct_p, *tag_p;
    uint8_t *blob = encrypt_blob_alloc(iv_len, ct_len, tag_len,
                                        &iv_p, &ct_p, &tag_p);
    if (!blob)
        return NULL;
    if (iv_len && iv)   memcpy(iv_p,  iv,  iv_len);
    if (ct_len && ct)   memcpy(ct_p,  ct,  ct_len);
    if (tag_len && tag) memcpy(tag_p, tag, tag_len);
    return blob;
}

uint8_t *tls_cipher_encrypt(const struct tls_key *key, tls_alg_t alg,
                          const uint8_t *in, size_t in_len)
{
    if (!key || !tls_key_supports_operation(key, alg) || !in)
        return NULL;

    switch (alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
        {
            if (!tls_rng_healthcheck())
                return NULL;
            uint8_t *iv_p, *ct_p, *tag_p;
            uint8_t *blob = encrypt_blob_alloc(0, key->rsa.mod_len, 0,
                                                &iv_p, &ct_p, &tag_p);
            if (!blob)
                return NULL;
            if (!tls_rsa_encrypt(in, in_len, ct_p, &key->rsa, TLS_HASH_SHA256))
            {
                tls_cipher_blob_free(blob);
                return NULL;
            }
            return blob;
        }

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(alg, key->aes.data, key->aes.len,
                                       NULL, 0, in, in_len);

        default:
            return NULL;
    }
}

uint8_t *tls_cipher_encrypt_aad(const struct tls_key *key, tls_alg_t alg,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *in, size_t in_len)
{
    if (!key || !tls_key_supports_operation(key, alg) || !in)
        return NULL;

    switch (alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            return tls_cipher_encrypt(key, alg, in, in_len);

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(alg, key->aes.data, key->aes.len,
                                       aad, aad_len, in, in_len);

        default:
            return NULL;
    }
}

uint8_t *tls_cipher_decrypt(const struct tls_key *key, tls_alg_t alg,
                          const uint8_t *blob)
{
    return tls_cipher_decrypt_aad(key, alg, NULL, 0, blob);
}

uint8_t *tls_cipher_decrypt_aad(const struct tls_key *key, tls_alg_t alg,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *blob)
{
    if (!key || !tls_key_supports_operation(key, alg) || !blob)
        return NULL;

    size_t iv_len, ct_len, tag_len;
    const uint8_t *iv, *ct, *tag;
    if (!encrypt_blob_parse(blob, &iv_len, &iv, &ct_len, &ct, &tag_len, &tag))
        return NULL;

    switch (alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
        {
            if (ct_len > RSA_TRANSIENT_SIZE)
                return NULL;
            if (!tls_rsa_decrypt_signature(ct, ct_len, __rsa_transient, &key->rsa))
                return NULL;
            uint8_t tmp[RSA_TRANSIENT_SIZE];
            size_t plen = tls_rsa_decode_oaep(__rsa_transient, ct_len,
                                               tmp, NULL, TLS_HASH_SHA256);
            tls_secure_memzero(__rsa_transient, ct_len);
            if (plen == 0)
                return NULL;
            uint8_t *plain;
            uint8_t *out = decrypt_blob_alloc(plen, &plain);
            if (!out)
                return NULL;
            memcpy(plain, tmp, plen);
            tls_secure_memzero(tmp, plen);
            return out;
        }

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
        {
            if (iv_len == 0 || (key_is_aead(alg) && tag_len == 0))
                return NULL;
            uint8_t *plain;
            uint8_t *out = decrypt_blob_alloc(ct_len, &plain);
            if (!out)
                return NULL;
            struct tls_aes_context ctx;
            bool ok = false;
            if (tls_aes_init(&ctx, key_aes_mode(alg),
                              key->aes.data, key->aes.len, iv, iv_len))
            {
                if (!key_is_aead(alg) ||
                    tls_aes_verify(&ctx, aad, aad_len, ct, ct_len, tag))
                {
                    if (tls_aes_decrypt(&ctx, ct, ct_len, plain))
                        ok = true;
                }
            }
            tls_secure_memzero(&ctx, sizeof(ctx));
            if (!ok)
            {
                tls_cipher_blob_free(out);
                return NULL;
            }
            return out;
        }

        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        {
            if (iv_len == 0 || tag_len == 0)
                return NULL;
            uint8_t *plain;
            uint8_t *out = decrypt_blob_alloc(ct_len, &plain);
            if (!out)
                return NULL;
            if (!tls_aes_ccm_decrypt(key->aes.data, key->aes.len,
                                      iv, iv_len,
                                      aad, aad_len,
                                      ct, ct_len,
                                      tag, TLS_KEY_AES_TAG_LEN,
                                      plain))
            {
                tls_cipher_blob_free(out);
                return NULL;
            }
            return out;
        }

        default:
            return NULL;
    }
}
