/**
 * @file key.c
 * @author Anthony Cagliano
 * @brief Self-describing key operations: import, verify, sign, encrypt, decrypt.
 *
 * tls_key_import / tls_key_free handle PEM/DER parsing and allocation.
 * All other functions dispatch on key->alg.  AES encrypt/decrypt operations
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
    if (len < 2) return TLS_KEY_IMPORT_PARSE_FAIL;
    out->ec.data = data + 1;
    out->ec.len  = len  - 1;
    return TLS_KEY_IMPORT_OK;
}

/* ---------------------------------------------------------------------------
 * Import: parse SubjectPublicKeyInfo (PKCS#8 public key wrapper)
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
        return key_parse_ec_pub_point(spk_bits.value, spk_bits.len, out);

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

    /* EC: the inner OCTET STRING is an ECPrivateKey (SEC1); we surface the
     * public key point when present, otherwise reject — we only expose the
     * public-key half through tls_key for now. */
    if (oid_eq(&alg_oid, OID_EC_PUBLICKEY, sizeof(OID_EC_PUBLICKEY)))
    {
        /* ECPrivateKey: SEQUENCE { version, OCTET STRING privkey,
         *   [0] OID params OPTIONAL, [1] BIT STRING pubkey OPTIONAL } */
        struct tls_asn1_cursor ec_body;
        struct tls_asn1_tlv ec_seq, ec_item;
        if (!tls_asn1_cursor_init(&ec_body, priv_octet.value, priv_octet.len))
            return TLS_KEY_IMPORT_PARSE_FAIL;
        if (!tls_asn1_next(&ec_body, &ec_seq) ||
            !tls_asn1_tag_constructed(ec_seq.tag) ||
            tls_asn1_tag_number(ec_seq.tag) != ASN1_SEQUENCE)
            return TLS_KEY_IMPORT_PARSE_FAIL;

        struct tls_asn1_cursor inner;
        if (!tls_asn1_child_cursor(&ec_seq, &inner)) return TLS_KEY_IMPORT_PARSE_FAIL;
        /* Skip version, skip private key bytes. */
        if (!tls_asn1_next(&inner, &ec_item)) return TLS_KEY_IMPORT_PARSE_FAIL;
        if (!tls_asn1_next(&inner, &ec_item)) return TLS_KEY_IMPORT_PARSE_FAIL;

        /* Scan optional context-specific fields for [1] public key. */
        while (tls_asn1_next(&inner, &ec_item))
        {
            if (tls_asn1_tag_class(ec_item.tag) == ASN1_CONTEXTSPEC &&
                tls_asn1_tag_number(ec_item.tag) == 1 &&
                tls_asn1_tag_constructed(ec_item.tag))
            {
                struct tls_asn1_cursor pubc;
                struct tls_asn1_tlv pubbit;
                if (!tls_asn1_child_cursor(&ec_item, &pubc) ||
                    !tls_asn1_next(&pubc, &pubbit) ||
                    tls_asn1_tag_number(pubbit.tag) != ASN1_BITSTRING)
                    return TLS_KEY_IMPORT_PARSE_FAIL;
                return key_parse_ec_pub_point(pubbit.value, pubbit.len, out);
            }
        }
        return TLS_KEY_IMPORT_PARSE_FAIL; /* no public key in EC private key */
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

/* ---------------------------------------------------------------------------
 * tls_key_import / tls_key_destroy
 * --------------------------------------------------------------------------- */

tls_key_import_result_t tls_key_import(struct tls_key **out,
                                        const void *data, size_t len,
                                        tls_key_format_t format,
                                        tls_alg_t alg,
                                        const char *password)
{
    if (!out || !data || len == 0)
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

    uint8_t *der_buf  = (uint8_t *)(key + 1);
    size_t   der_len  = 0;
    const uint8_t *parse_der     = NULL;
    size_t         parse_der_len = 0;
    tls_key_import_result_t rc   = TLS_KEY_IMPORT_PARSE_FAIL;

    key_pem_fmt_t fmt;
    bool          is_pem = false;

    if (format == TLS_KEY_FORMAT_PEM)
    {
        /* Identify the banner and pick the parse path. */
        is_pem = true;
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
        /*
         * For raw DER the caller must tell us what kind of key it is via alg.
         * We infer the DER structure from the algorithm family.
         */
        memcpy(der_buf, data, len);
        parse_der     = der_buf;
        parse_der_len = len;

        if (TLS_ALG_IS_SIGNING(alg) || alg == TLS_ALG_RSA_OAEP_SHA256)
            fmt = KEY_FMT_PKCS8_PRIV; /* try PKCS#8 wrapper first for DER */
        else
        {
            rc = TLS_KEY_IMPORT_BAD_ALG;
            goto fail;
        }
        is_pem = false;
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
        case KEY_FMT_SEC1_EC_PRIV:    rc = key_parse_pkcs8_priv(parse_der, parse_der_len, key); break;
        default:                       rc = TLS_KEY_IMPORT_PARSE_FAIL; break;
    }
    if (rc != TLS_KEY_IMPORT_OK)
        goto fail;

    /* Set the algorithm.  For PEM paths where alg == TLS_ALG_UNKNOWN we infer
     * a sensible default; the caller can always adjust key->alg afterwards. */
    if (alg != TLS_ALG_UNKNOWN)
    {
        key->alg = alg;
    }
    else
    {
        /* Auto-assign: RSA keys default to PSS-SHA256, EC to ECDSA-P256. */
        if (fmt == KEY_FMT_PKCS1_RSA_PRIV ||
            fmt == KEY_FMT_PKCS1_RSA_PUB  ||
            (fmt == KEY_FMT_PKCS8_PRIV && key->rsa.mod_len > 0))
            key->alg = TLS_ALG_RSA_PSS_RSAE_SHA256;
        else
            key->alg = TLS_ALG_ECDSA_SECP256R1_SHA256;
    }

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
                                    const struct tls_key *key)
{
    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }
    return tls_x509_signature_verify(content, content_len, sig, sig_len, key);
}

tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                  uint8_t *sig_out, size_t *sig_len_out,
                                  const struct tls_key *key)
{
    (void)content;
    (void)content_len;
    (void)sig_out;
    (void)sig_len_out;

    if (!key)
    {
        return TLS_KEY_OP_INVALID;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_PSS_RSAE_SHA256:
        case TLS_ALG_RSA_PKCS1_SHA256:
        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return TLS_KEY_OP_UNSUPPORTED;

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
 * AES one-shot encrypt (shared by plain and AAD variants)
 * --------------------------------------------------------------------------- */

static bool aes_encrypt_oneshot(tls_alg_t alg,
                                 const uint8_t *key_data, size_t key_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *inbuf, size_t in_len,
                                 struct tls_key_cipher_io *io)
{
    struct tls_aes_context ctx;
    size_t iv_len = key_iv_len(alg);
    uint8_t mode  = key_aes_mode(alg);
    bool ok = false;

    if (!io || !io->iv || !io->obuf)
    {
        return false;
    }
    if (key_is_aead(alg) && !io->tag)
    {
        return false;
    }

    /* Generate a fresh IV/nonce. */
    tls_random_bytes(io->iv, iv_len);

    /* Compute actual ciphertext length: CBC pads partial last block; all others
     * are same length as plaintext. */
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

    if (mode == TLS_AES_CCM)
    {
        if (!tls_aes_ccm_encrypt(key_data, key_len,
                                  io->iv, iv_len,
                                  aad, aad_len,
                                  inbuf, in_len,
                                  io->obuf, io->tag, TLS_KEY_AES_TAG_LEN))
        {
            goto cleanup;
        }
        ok = true;
    }
    else
    {
        if (!tls_aes_init(&ctx, mode, key_data, key_len, io->iv, iv_len))
        {
            goto cleanup;
        }
        if (aad && aad_len && !tls_aes_update_aad(&ctx, aad, aad_len))
        {
            goto cleanup;
        }
        if (!tls_aes_encrypt(&ctx, inbuf, in_len, io->obuf))
        {
            goto cleanup;
        }
        if (key_is_aead(alg) && !tls_aes_digest(&ctx, io->tag))
        {
            goto cleanup;
        }
        ok = true;
    }
    io->obuf_len = ct_len;

cleanup:
    tls_secure_memzero(&ctx, sizeof(ctx));
    return ok;
}


/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

bool tls_key_encrypt(struct tls_key *key,
                     const uint8_t *inbuf, size_t in_len,
                     struct tls_key_cipher_io *io)
{
    if (!key || !inbuf || !io)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            if (!io->obuf)
            {
                return false;
            }
            return tls_rsa_encrypt(inbuf, in_len, io->obuf,
                                   &key->rsa, TLS_HASH_SHA256);

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(key->alg,
                                       key->aes.data, key->aes.len,
                                       NULL, 0,
                                       inbuf, in_len, io);

        default:
            return false;
    }
}

bool tls_key_encrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *inbuf, size_t in_len,
                         struct tls_key_cipher_io *io)
{
    if (!key || !inbuf || !io)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            /* AAD not applicable to RSA-OAEP here; treat as plain encrypt. */
            if (!io->obuf)
            {
                return false;
            }
            return tls_rsa_encrypt(inbuf, in_len, io->obuf,
                                   &key->rsa, TLS_HASH_SHA256);

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
            return aes_encrypt_oneshot(key->alg,
                                       key->aes.data, key->aes.len,
                                       aad, aad_len,
                                       inbuf, in_len, io);

        default:
            return false;
    }
}

bool tls_key_decrypt(struct tls_key *key,
                     struct tls_key_cipher_io *io,
                     uint8_t *outbuf, size_t outbuf_len)
{
    return tls_key_decrypt_aad(key, NULL, 0, io, outbuf, outbuf_len);
}

bool tls_key_decrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         struct tls_key_cipher_io *io,
                         uint8_t *outbuf, size_t outbuf_len)
{
    if (!key || !io || !io->iv || !io->obuf || !outbuf || outbuf_len < io->obuf_len)
    {
        return false;
    }

    switch (key->alg)
    {
        case TLS_ALG_RSA_OAEP_SHA256:
            /* AAD not applicable to RSA-OAEP; aad is ignored. */
            if (io->obuf_len > RSA_TRANSIENT_SIZE)
            {
                return false;
            }
            {
                bool ok = false;
                if (tls_rsa_decrypt_signature(io->obuf, io->obuf_len, __rsa_transient, &key->rsa))
                {
                    ok = tls_rsa_decode_oaep(__rsa_transient, io->obuf_len,
                                             outbuf, NULL, TLS_HASH_SHA256) > 0;
                }
                tls_secure_memzero(__rsa_transient, io->obuf_len);
                return ok;
            }

        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_128_CBC:
        case TLS_ALG_AES_256_CBC:
        {
            if (key_is_aead(key->alg) && !io->tag)
            {
                return false;
            }
            struct tls_aes_context ctx;
            size_t iv_len = key_iv_len(key->alg);
            bool ok = false;
            if (!tls_aes_init(&ctx, key_aes_mode(key->alg),
                              key->aes.data, key->aes.len, io->iv, iv_len))
            {
                goto gcm_cbc_cleanup;
            }
            if (key_is_aead(key->alg))
            {
                if (!tls_aes_verify(&ctx, aad, aad_len,
                                    io->obuf, io->obuf_len, io->tag))
                {
                    goto gcm_cbc_cleanup;
                }
            }
            if (tls_aes_decrypt(&ctx, io->obuf, io->obuf_len, outbuf))
            {
                ok = true;
            }
gcm_cbc_cleanup:
            tls_secure_memzero(&ctx, sizeof(ctx));
            return ok;
        }

        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_256_CCM:
            if (!io->tag)
            {
                return false;
            }
            return tls_aes_ccm_decrypt(key->aes.data, key->aes.len,
                                        io->iv, key_iv_len(key->alg),
                                        aad, aad_len,
                                        io->obuf, io->obuf_len,
                                        io->tag, TLS_KEY_AES_TAG_LEN,
                                        outbuf);

        default:
            return false;
    }
}
