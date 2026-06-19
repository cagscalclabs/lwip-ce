#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/base64.h"
#include "../includes/asn1.h"
#include "../includes/keyobject.h"
#include "../includes/passwords.h"
#include "../includes/aes.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"
#include "../includes/pkcs8.h"
#include "../includes/tls.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_PKCS8
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

void rmemcpy(void *dest, void *src, size_t len);

/*
 * These indices document the exact PBES2/PBKDF2 extraction points from
 * EncryptedPrivateKeyInfo used by the decrypt path.
 */
#define TLS_PKCS8_ENCRYPTED_IDX_PBES2 0
#define TLS_PKCS8_ENCRYPTED_IDX_PBKDF2 1
#define TLS_PKCS8_ENCRYPTED_IDX_SALT 2
#define TLS_PKCS8_ENCRYPTED_IDX_ROUNDS 3
#define TLS_PKCS8_ENCRYPTED_IDX_KEYLEN 4
#define TLS_PKCS8_ENCRYPTED_IDX_HMAC 5
#define TLS_PKCS8_ENCRYPTED_IDX_AES 6
#define TLS_PKCS8_ENCRYPTED_IDX_IV 7
#define TLS_PKCS8_ENCRYPTED_IDX_DATA 8

static const char *const TLS_NAME_RSA_PRIV[TLS_PRIVKEY_RSA_FIELDS] = {
    "modulus",
    "publicExponent",
    "privateExponent",
    "prime1",
    "prime2",
    "exponent1",
    "exponent2",
    "coefficient"};

static const char *const TLS_NAME_EC_PRIV[TLS_PRIVKEY_EC_FIELDS] = {
    "privateKey",
    "curve oid",
    "publicKey"};

static const char *const TLS_NAME_RSA_PUB[TLS_PUBKEY_RSA_FIELDS] = {
    "modulus",
    "publicExponent"};

static const char *const TLS_NAME_EC_PUB[TLS_PUBKEY_EC_FIELDS] = {
    "EC Point"};

static bool tls_pkcs8_oid_eq(const struct tls_asn1_tlv *oid_tlv,
                             enum tls_objectids id)
{
    /* Explicit lengths avoid comparing against zero-padded table tails. */
    static const uint8_t oid_lens[] = {
        [TLS_OID_RSA_ENCRYPTION] = 9,
        [TLS_OID_EC_PUBLICKEY] = 7,
        [TLS_OID_EC_PRIVATEKEY] = 5,
        [TLS_OID_AES_128_GCM] = 9,
        [TLS_OID_AES_128_CBC] = 9,
        [TLS_OID_AES_256_GCM] = 9,
        [TLS_OID_AES_256_CBC] = 9,
        [TLS_OID_PBKDF2] = 9,
        [TLS_OID_PBES2] = 9,
        [TLS_OID_HMAC_SHA256] = 8,
        [TLS_OID_SHA256_RSA_ENCRYPTION] = 9,
        [TLS_OID_SHA384_RSA_ENCRYPTION] = 9,
        [TLS_OID_SHA256_ECDSA] = 8,
    };

    if (!oid_tlv || tls_asn1_tag_number(oid_tlv->tag) != ASN1_OBJECTID)
    {
        return false;
    }
    if ((size_t)id >= (sizeof(oid_lens) / sizeof(oid_lens[0])) || oid_lens[id] == 0)
    {
        return false;
    }
    return oid_tlv->len == oid_lens[id] &&
           memcmp(oid_tlv->value, tls_objectid_bytes[id], oid_lens[id]) == 0;
}

static void tls_pkcs8_set_field(struct tls_asn1_serialization *f,
                                const char *name,
                                uint8_t tag,
                                const uint8_t *data,
                                size_t len)
{
    f->name = (char *)name;
    f->tag = tag;
    f->data = (uint8_t *)data;
    f->len = len;
}

static void tls_pkcs8_set_serial_field(struct tls_pkcs8_object *obj,
                                       size_t idx,
                                       const char *name,
                                       uint8_t tag,
                                       const uint8_t *data,
                                       size_t len)
{
    if (!obj || idx >= TLS_PKCS8_MAX_FIELDS)
    {
        return;
    }
    tls_pkcs8_set_field(&obj->serialization.fields[idx], name, tag, data, len);
}

static bool tls_pkcs8_pem_decode(const char *pem,
                                 size_t pem_len,
                                 const char *begin_banner,
                                 uint8_t *der,
                                 size_t der_cap,
                                 size_t *der_len)
{
    const char *p;
    const char *end;
    size_t b64_count = 0;

    if (!pem || !begin_banner || !der || !der_len || pem_len == 0)
    {
        return false;
    }

    if (pem_len < strlen(begin_banner) ||
        memcmp(pem, begin_banner, strlen(begin_banner)) != 0)
    {
        return false;
    }

    end = pem + pem_len;
    p = memchr(pem, '\n', pem_len);
    if (!p)
    {
        return false;
    }
    p++;

    /*
     * Copy only base64 payload chars so wrapped PEM and CRLF inputs decode
     * consistently. Decoding then runs in-place in the same buffer.
     */
    while (p < end)
    {
        if ((size_t)(end - p) >= 5 && memcmp(p, "-----", 5) == 0)
        {
            break;
        }

        if (((*p >= 'A') && (*p <= 'Z')) ||
            ((*p >= 'a') && (*p <= 'z')) ||
            ((*p >= '0') && (*p <= '9')) ||
            (*p == '+') || (*p == '/') || (*p == '='))
        {
            if (b64_count >= der_cap)
            {
                return false;
            }
            der[b64_count++] = (uint8_t)*p;
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

    *der_len = tls_base64_decode(der, b64_count, der);
    return (*der_len != 0 && *der_len <= der_cap);
}

static bool tls_pkcs8_parse_rsa_private_der(struct tls_pkcs8_object *obj,
                                            const uint8_t *der,
                                            size_t der_len,
                                            tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv seq;
    struct tls_asn1_cursor body;
    struct tls_asn1_tlv item;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &seq))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(seq.tag) || tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&seq, &body))
    {
        return false;
    }

    if (!tls_asn1_next(&body, &item) || tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
    {
        return false;
    }

    /*
     * RSAPrivateKey ::= SEQUENCE {
     *   version, n, e, d, p, q, dP, dQ, qInv
     * }
     * We skip version in metadata and expose the 8 numeric key fields.
     */
    obj->type = TLS_KEY_PRIVATE | TLS_KEY_RSA;
    obj->algorithm = TLS_PKCS8_ALG_RSA;
    obj->serialization.len = TLS_PRIVKEY_RSA_FIELDS;
    for (size_t i = 0; i < TLS_PRIVKEY_RSA_FIELDS; i++)
    {
        if (!tls_asn1_next(&body, &item) || tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
        {
            return false;
        }
        tls_pkcs8_set_serial_field(obj, i, TLS_NAME_RSA_PRIV[i], item.tag, item.value, item.len);
    }

    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return true;
}

static bool tls_pkcs8_parse_ec_private_der(struct tls_pkcs8_object *obj,
                                           const uint8_t *der,
                                           size_t der_len,
                                           tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv seq;
    struct tls_asn1_cursor body;
    struct tls_asn1_tlv item;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    memset(obj->serialization.fields, 0, sizeof(obj->serialization.fields));

    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &seq))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(seq.tag) || tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&seq, &body))
    {
        return false;
    }

    if (!tls_asn1_next(&body, &item) || tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
    {
        return false;
    }
    if (!tls_asn1_next(&body, &item) || tls_asn1_tag_number(item.tag) != ASN1_OCTETSTRING)
    {
        return false;
    }
    tls_pkcs8_set_serial_field(obj, 0, TLS_NAME_EC_PRIV[0], item.tag, item.value, item.len);

    /*
     * ECPrivateKey optional context-specific fields:
     * [0] parameters (curve OID), [1] publicKey (BIT STRING).
     */
    while (tls_asn1_next(&body, &item))
    {
        if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
            tls_asn1_tag_number(item.tag) == 0 &&
            tls_asn1_tag_constructed(item.tag))
        {
            struct tls_asn1_cursor params;
            struct tls_asn1_tlv curve;
            if (!tls_asn1_child_cursor(&item, &params) ||
                !tls_asn1_next(&params, &curve) ||
                tls_asn1_tag_number(curve.tag) != ASN1_OBJECTID)
            {
                return false;
            }
            tls_pkcs8_set_serial_field(obj, 1, TLS_NAME_EC_PRIV[1], curve.tag, curve.value, curve.len);
        }
        else if (tls_asn1_tag_class(item.tag) == ASN1_CONTEXTSPEC &&
                 tls_asn1_tag_number(item.tag) == 1 &&
                 tls_asn1_tag_constructed(item.tag))
        {
            struct tls_asn1_cursor pubc;
            struct tls_asn1_tlv pubkey;
            if (!tls_asn1_child_cursor(&item, &pubc) ||
                !tls_asn1_next(&pubc, &pubkey) ||
                tls_asn1_tag_number(pubkey.tag) != ASN1_BITSTRING)
            {
                return false;
            }
            tls_pkcs8_set_serial_field(obj, 2, TLS_NAME_EC_PRIV[2], pubkey.tag, pubkey.value, pubkey.len);
        }
    }

    obj->type = TLS_KEY_PRIVATE | TLS_KEY_ECC;
    obj->algorithm = TLS_PKCS8_ALG_EC;
    if (obj->serialization.fields[1].data && obj->serialization.fields[2].data)
    {
        obj->serialization.len = TLS_PRIVKEY_EC_FIELDS;
    }
    else if (obj->serialization.fields[1].data || obj->serialization.fields[2].data)
    {
        obj->serialization.len = 2;
    }
    else
    {
        obj->serialization.len = 1;
    }
    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return true;
}

static bool tls_pkcs8_parse_public_der(struct tls_pkcs8_object *obj,
                                       const uint8_t *der,
                                       size_t der_len,
                                       tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv seq;
    struct tls_asn1_cursor body;
    struct tls_asn1_tlv item;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &seq))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(seq.tag) || tls_asn1_tag_number(seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!tls_asn1_child_cursor(&seq, &body))
    {
        return false;
    }

    obj->type = TLS_KEY_PUBLIC | TLS_KEY_RSA;
    obj->algorithm = TLS_PKCS8_ALG_RSA;
    obj->serialization.len = TLS_PUBKEY_RSA_FIELDS;
    for (size_t i = 0; i < TLS_PUBKEY_RSA_FIELDS; i++)
    {
        if (!tls_asn1_next(&body, &item) || tls_asn1_tag_number(item.tag) != ASN1_INTEGER)
        {
            return false;
        }
        tls_pkcs8_set_serial_field(obj, i, TLS_NAME_RSA_PUB[i], item.tag, item.value, item.len);
    }

    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return true;
}

static bool tls_pkcs8_parse_spki_public_der(struct tls_pkcs8_object *obj,
                                            const uint8_t *der,
                                            size_t der_len,
                                            tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv spki;
    struct tls_asn1_cursor spki_body;
    struct tls_asn1_tlv alg_seq;
    struct tls_asn1_tlv spk_bits;
    struct tls_asn1_cursor alg_body;
    struct tls_asn1_tlv alg_oid;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &spki))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(spki.tag) || tls_asn1_tag_number(spki.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&spki, &spki_body) ||
        !tls_asn1_next(&spki_body, &alg_seq) ||
        !tls_asn1_next(&spki_body, &spk_bits))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(alg_seq.tag) || tls_asn1_tag_number(alg_seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (tls_asn1_tag_number(spk_bits.tag) != ASN1_BITSTRING || spk_bits.len < 1)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&alg_seq, &alg_body) ||
        !tls_asn1_next(&alg_body, &alg_oid) ||
        tls_asn1_tag_number(alg_oid.tag) != ASN1_OBJECTID)
    {
        return false;
    }

    if (tls_pkcs8_oid_eq(&alg_oid, TLS_OID_EC_PUBLICKEY))
    {
        /* Preserve BIT STRING payload (including unused-bit byte) for parity. */
        obj->type = TLS_KEY_PUBLIC | TLS_KEY_ECC;
        obj->algorithm = TLS_PKCS8_ALG_EC;
        obj->serialization.len = TLS_PUBKEY_EC_FIELDS;
        tls_pkcs8_set_serial_field(obj, 0, TLS_NAME_EC_PUB[0], spk_bits.tag, spk_bits.value, spk_bits.len);
        if (error)
        {
            *error = TLS_PKCS8_ERR_NONE;
        }
        return true;
    }

    if (tls_pkcs8_oid_eq(&alg_oid, TLS_OID_RSA_ENCRYPTION))
    {
        /* RSA SubjectPublicKey is DER RSAPublicKey inside BIT STRING. */
        if (spk_bits.value[0] != 0)
        {
            return false;
        }
        return tls_pkcs8_parse_public_der(obj, spk_bits.value + 1, spk_bits.len - 1, error);
    }

    if (error)
    {
        *error = TLS_PKCS8_ERR_UNSUPPORTED_ALG;
    }
    return false;
}

static bool tls_pkcs8_decrypt_private(struct tls_pkcs8_object *obj,
                                      size_t der_len,
                                      const char *password,
                                      const uint8_t **inner_der,
                                      size_t *inner_der_len,
                                      tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv encrypted_info;
    struct tls_asn1_cursor epi;
    struct tls_asn1_tlv enc_alg;
    struct tls_asn1_tlv enc_data;
    struct tls_asn1_cursor enc_alg_cur;
    struct tls_asn1_tlv pbes2_oid;
    struct tls_asn1_tlv pbes2_params;
    struct tls_asn1_cursor pbes2_cur;
    struct tls_asn1_tlv kdf_seq;
    struct tls_asn1_tlv enc_scheme;
    struct tls_asn1_cursor kdf_cur;
    struct tls_asn1_tlv pbkdf2_oid;
    struct tls_asn1_tlv pbkdf2_params;
    struct tls_asn1_cursor pbkdf2_cur;
    struct tls_asn1_tlv salt;
    struct tls_asn1_tlv rounds;
    struct tls_asn1_tlv maybe_keylen;
    struct tls_asn1_tlv prf_seq;
    struct tls_asn1_tlv prf_oid;
    struct tls_asn1_cursor enc_scheme_cur;
    struct tls_asn1_tlv aes_oid;
    struct tls_asn1_tlv iv;
    size_t keylen = 0;
    size_t rounds_num = 0;
    uint8_t derived_key[32];
    struct tls_aes_context aes_ctx;

    if (error)
    {
        *error = TLS_PKCS8_ERR_DECRYPT_FAIL;
    }
    if (!obj || !password || !inner_der || !inner_der_len)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    /*
     * EncryptedPrivateKeyInfo parsing path:
     * SEQUENCE {
     *   encryptionAlgorithm (PBES2 expected),
     *   encryptedData OCTET STRING
     * }
     */
    if (!tls_asn1_cursor_init(&c, obj->data, der_len) || !tls_asn1_next(&c, &encrypted_info))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(encrypted_info.tag) || tls_asn1_tag_number(encrypted_info.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&encrypted_info, &epi) ||
        !tls_asn1_next(&epi, &enc_alg) ||
        !tls_asn1_next(&epi, &enc_data))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(enc_alg.tag) || tls_asn1_tag_number(enc_alg.tag) != ASN1_SEQUENCE)
    {
        return false;
    }
    if (tls_asn1_tag_number(enc_data.tag) != ASN1_OCTETSTRING)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&enc_alg, &enc_alg_cur) ||
        !tls_asn1_next(&enc_alg_cur, &pbes2_oid) ||
        !tls_asn1_next(&enc_alg_cur, &pbes2_params) ||
        !tls_pkcs8_oid_eq(&pbes2_oid, TLS_OID_PBES2) ||
        !tls_asn1_tag_constructed(pbes2_params.tag) ||
        tls_asn1_tag_number(pbes2_params.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&pbes2_params, &pbes2_cur) ||
        !tls_asn1_next(&pbes2_cur, &kdf_seq) ||
        !tls_asn1_next(&pbes2_cur, &enc_scheme) ||
        !tls_asn1_tag_constructed(kdf_seq.tag) ||
        tls_asn1_tag_number(kdf_seq.tag) != ASN1_SEQUENCE ||
        !tls_asn1_tag_constructed(enc_scheme.tag) ||
        tls_asn1_tag_number(enc_scheme.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&kdf_seq, &kdf_cur) ||
        !tls_asn1_next(&kdf_cur, &pbkdf2_oid) ||
        !tls_asn1_next(&kdf_cur, &pbkdf2_params) ||
        !tls_pkcs8_oid_eq(&pbkdf2_oid, TLS_OID_PBKDF2) ||
        !tls_asn1_tag_constructed(pbkdf2_params.tag) ||
        tls_asn1_tag_number(pbkdf2_params.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&pbkdf2_params, &pbkdf2_cur) ||
        !tls_asn1_next(&pbkdf2_cur, &salt) ||
        !tls_asn1_next(&pbkdf2_cur, &rounds) ||
        tls_asn1_tag_number(salt.tag) != ASN1_OCTETSTRING ||
        tls_asn1_tag_number(rounds.tag) != ASN1_INTEGER)
    {
        return false;
    }

    keylen = 0;
    maybe_keylen.tag = 0;
    maybe_keylen.value = NULL;
    maybe_keylen.len = 0;
    prf_seq.tag = 0;
    prf_seq.value = NULL;
    prf_seq.len = 0;

    if (tls_asn1_next(&pbkdf2_cur, &maybe_keylen))
    {
        if (tls_asn1_tag_number(maybe_keylen.tag) == ASN1_INTEGER)
        {
            if (tls_asn1_next(&pbkdf2_cur, &prf_seq))
            {
                if (!tls_asn1_tag_constructed(prf_seq.tag) || tls_asn1_tag_number(prf_seq.tag) != ASN1_SEQUENCE)
                {
                    return false;
                }
            }
        }
        else
        {
            prf_seq = maybe_keylen;
            maybe_keylen.tag = 0;
            maybe_keylen.value = NULL;
            maybe_keylen.len = 0;
            if (!tls_asn1_tag_constructed(prf_seq.tag) || tls_asn1_tag_number(prf_seq.tag) != ASN1_SEQUENCE)
            {
                return false;
            }
        }
    }

    if (prf_seq.tag != 0)
    {
        struct tls_asn1_cursor prf_cur;
        if (!tls_asn1_child_cursor(&prf_seq, &prf_cur) ||
            !tls_asn1_next(&prf_cur, &prf_oid) ||
            !tls_pkcs8_oid_eq(&prf_oid, TLS_OID_HMAC_SHA256))
        {
            return false;
        }
    }

    if (!tls_asn1_child_cursor(&enc_scheme, &enc_scheme_cur) ||
        !tls_asn1_next(&enc_scheme_cur, &aes_oid) ||
        !tls_asn1_next(&enc_scheme_cur, &iv) ||
        tls_asn1_tag_number(iv.tag) != ASN1_OCTETSTRING)
    {
        return false;
    }

    if (!(tls_pkcs8_oid_eq(&aes_oid, TLS_OID_AES_128_CBC) || tls_pkcs8_oid_eq(&aes_oid, TLS_OID_AES_256_CBC)))
    {
        return false;
    }

    if (maybe_keylen.value)
    {
        rmemcpy(&keylen, (void *)maybe_keylen.value, maybe_keylen.len);
    }
    else
    {
        keylen = tls_pkcs8_oid_eq(&aes_oid, TLS_OID_AES_128_CBC) ? 16 : 32;
    }

    rmemcpy(&rounds_num, (void *)rounds.value, rounds.len);

    if (!tls_pbkdf2(password,
                    strlen(password),
                    (uint8_t *)salt.value,
                    salt.len,
                    derived_key,
                    keylen,
                    rounds_num,
                    TLS_HASH_SHA256))
    {
        return false;
    }

    if (!tls_aes_init(&aes_ctx,
                      TLS_AES_CBC,
                      derived_key,
                      keylen,
                      (uint8_t *)iv.value,
                      iv.len))
    {
        return false;
    }

    if (!tls_aes_decrypt(&aes_ctx,
                         (uint8_t *)enc_data.value,
                         enc_data.len,
                         obj->data))
    {
        return false;
    }

    /* PKCS#7-style CBC padding length is in the final byte. */
    if (enc_data.len == 0 || obj->data[enc_data.len - 1] > enc_data.len)
    {
        return false;
    }

    *inner_der = obj->data;
    *inner_der_len = enc_data.len - obj->data[enc_data.len - 1];
    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return true;
}

static bool tls_pkcs8_parse_private_der(struct tls_pkcs8_object *obj,
                                        const uint8_t *der,
                                        size_t der_len,
                                        tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv pki;
    struct tls_asn1_cursor pki_body;
    struct tls_asn1_tlv version;
    struct tls_asn1_tlv alg_seq;
    struct tls_asn1_tlv priv_octet;
    struct tls_asn1_cursor alg_body;
    struct tls_asn1_tlv alg_oid;
    struct tls_asn1_tlv alg_param;
    bool have_alg_param = false;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }

    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &pki))
    {
        return false;
    }
    if (!tls_asn1_tag_constructed(pki.tag) || tls_asn1_tag_number(pki.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&pki, &pki_body) ||
        !tls_asn1_next(&pki_body, &version) ||
        !tls_asn1_next(&pki_body, &alg_seq) ||
        !tls_asn1_next(&pki_body, &priv_octet) ||
        tls_asn1_tag_number(version.tag) != ASN1_INTEGER ||
        tls_asn1_tag_number(priv_octet.tag) != ASN1_OCTETSTRING ||
        !tls_asn1_tag_constructed(alg_seq.tag) ||
        tls_asn1_tag_number(alg_seq.tag) != ASN1_SEQUENCE)
    {
        return false;
    }

    if (!tls_asn1_child_cursor(&alg_seq, &alg_body) ||
        !tls_asn1_next(&alg_body, &alg_oid) ||
        tls_asn1_tag_number(alg_oid.tag) != ASN1_OBJECTID)
    {
        return false;
    }
    if (tls_asn1_next(&alg_body, &alg_param))
    {
        have_alg_param = true;
    }

    if (tls_pkcs8_oid_eq(&alg_oid, TLS_OID_RSA_ENCRYPTION))
    {
        bool ok = tls_pkcs8_parse_rsa_private_der(obj, priv_octet.value, priv_octet.len, error);
        if (ok && error)
        {
            *error = TLS_PKCS8_ERR_NONE;
        }
        return ok;
    }
    if (tls_pkcs8_oid_eq(&alg_oid, TLS_OID_EC_PUBLICKEY))
    {
        bool ok = tls_pkcs8_parse_ec_private_der(obj, priv_octet.value, priv_octet.len, error);
        if (ok && !obj->serialization.fields[1].data &&
            have_alg_param && tls_asn1_tag_number(alg_param.tag) == ASN1_OBJECTID)
        {
            tls_pkcs8_set_serial_field(obj, 1, TLS_NAME_EC_PRIV[1],
                                       alg_param.tag, alg_param.value, alg_param.len);
            if (obj->serialization.len < 2)
            {
                obj->serialization.len = 2;
            }
        }
        if (ok && error)
        {
            *error = TLS_PKCS8_ERR_NONE;
        }
        return ok;
    }

    if (error)
    {
        *error = TLS_PKCS8_ERR_UNSUPPORTED_ALG;
    }
    return false;
}

static bool tls_pkcs8_parse_sec1_public_der(struct tls_pkcs8_object *obj,
                                            const uint8_t *der,
                                            size_t der_len,
                                            tls_pkcs8_error_t *error)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv p;

    if (error)
    {
        *error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
    }
    if (!obj || !der || der_len == 0)
    {
        if (error)
        {
            *error = TLS_PKCS8_ERR_INVALID_ARG;
        }
        return false;
    }
    if (!tls_asn1_cursor_init(&c, der, der_len) || !tls_asn1_next(&c, &p) ||
        tls_asn1_tag_number(p.tag) != ASN1_OCTETSTRING)
    {
        return false;
    }
    obj->type = TLS_KEY_PUBLIC | TLS_KEY_ECC;
    obj->algorithm = TLS_PKCS8_ALG_EC;
    obj->serialization.len = TLS_PUBKEY_EC_FIELDS;
    tls_pkcs8_set_serial_field(obj, 0, TLS_NAME_EC_PUB[0], p.tag, p.value, p.len);
    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return true;
}

struct _key_type_meta
{
    const char *pem_banner;
    uint8_t type;
    uint8_t algorithm;
    bool (*parse_func)(struct tls_pkcs8_object *obj, const uint8_t *der, size_t der_len, tls_pkcs8_error_t *error);
    uint8_t field_count;
};

static const struct _key_type_meta key_type_meta[] = {
    {"-----BEGIN RSA PRIVATE KEY-----", TLS_PKCS8_PRIVATE, TLS_PKCS8_ALG_RSA, tls_pkcs8_parse_rsa_private_der, TLS_PRIVKEY_RSA_FIELDS},
    {"-----BEGIN EC PRIVATE KEY-----", TLS_PKCS8_PRIVATE, TLS_PKCS8_ALG_EC, tls_pkcs8_parse_ec_private_der, TLS_PRIVKEY_EC_FIELDS},
    {"-----BEGIN PRIVATE KEY-----", TLS_PKCS8_PRIVATE, TLS_PKCS8_ALG_UNKNOWN, tls_pkcs8_parse_private_der, 0},
    {"-----BEGIN ENCRYPTED PRIVATE KEY-----", TLS_PKCS8_ENCRYPTED_PRIVATE, TLS_PKCS8_ALG_UNKNOWN, tls_pkcs8_parse_private_der, 0},
    {"-----BEGIN RSA PUBLIC KEY-----", TLS_PKCS8_PUBLIC, TLS_PKCS8_ALG_RSA, tls_pkcs8_parse_public_der, TLS_PUBKEY_RSA_FIELDS},
    {"-----BEGIN EC PUBLIC KEY-----", TLS_PKCS8_PUBLIC, TLS_PKCS8_ALG_EC, tls_pkcs8_parse_sec1_public_der, TLS_PUBKEY_EC_FIELDS},
    {"-----BEGIN PUBLIC KEY-----", TLS_PKCS8_PUBLIC, TLS_PKCS8_ALG_UNKNOWN, tls_pkcs8_parse_spki_public_der, 0},
};

struct tls_pkcs8_object *tls_pkcs8_import(const char *pem_data, size_t size, const char *password, tls_pkcs8_error_t *error)
{
    const struct _key_type_meta *meta = NULL;
    size_t der_cap;
    size_t der_len = 0;
    size_t total_len;
    struct tls_pkcs8_object *kf = NULL;
    const uint8_t *parse_der = NULL;
    size_t parse_der_len = 0;
    size_t i;
    tls_pkcs8_error_t local_error = TLS_PKCS8_ERR_NONE;

    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }

    if (!pem_data || size == 0)
    {
        local_error = TLS_PKCS8_ERR_INVALID_ARG;
        if (error)
        {
            *error = local_error;
        }
        ERROR_CODE(local_error);
        return NULL;
    }

    for (i = 0; i < (sizeof(key_type_meta) / sizeof(key_type_meta[0])); i++)
    {
        if (strncmp(pem_data, key_type_meta[i].pem_banner, strlen(key_type_meta[i].pem_banner)) == 0)
        {
            meta = &key_type_meta[i];
            break;
        }
    }
    if (!meta)
    {
        local_error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
        if (error)
        {
            *error = local_error;
        }
        ERROR_CODE(local_error);
        return NULL;
    }

    /*
     * PEM decode path normalizes base64 into this same buffer before decoding
     * in-place, so workspace must hold base64 input length (not just DER size).
     */
    der_cap = size;
    total_len = sizeof(struct tls_pkcs8_object) + der_cap;
    kf = (struct tls_pkcs8_object *)tls_fileio_alloc(total_len);

    if (!kf)
    {
        local_error = TLS_PKCS8_ERR_ALLOC_FAIL;
        if (error)
        {
            *error = local_error;
        }
        goto error;
    }

    kf->total_len = total_len;
    kf->type = 0;
    kf->algorithm = meta->algorithm;
    kf->serialization.len = meta->field_count;
    memset(kf->serialization.fields, 0, sizeof(kf->serialization.fields));

    if (!tls_pkcs8_pem_decode(pem_data, size, meta->pem_banner, kf->data, der_cap, &der_len))
    {
        local_error = TLS_PKCS8_ERR_PEM_DECODE_FAIL;
        if (error)
        {
            *error = local_error;
        }
        goto error;
    }

    if (meta->type == TLS_PKCS8_ENCRYPTED_PRIVATE)
    {
        if (!password)
        {
            local_error = TLS_PKCS8_ERR_PASSWORD_REQUIRED;
            if (error)
            {
                *error = local_error;
            }
            goto error;
        }
        if (!tls_pkcs8_decrypt_private(kf, der_len, password, &parse_der, &parse_der_len, error))
        {
            local_error = error ? *error : TLS_PKCS8_ERR_DECRYPT_FAIL;
            goto error;
        }
    }
    else
    {
        parse_der = kf->data;
        parse_der_len = der_len;
    }

    if (!meta->parse_func(kf, parse_der, parse_der_len, error))
    {
        if (meta->type == TLS_PKCS8_ENCRYPTED_PRIVATE)
        {
            local_error = TLS_PKCS8_ERR_DECRYPT_FAIL;
            if (error)
            {
                *error = local_error;
            }
        }
        else
        {
            local_error = error ? *error : TLS_PKCS8_ERR_NONE;
        }
        goto error;
    }

    if (error)
    {
        *error = TLS_PKCS8_ERR_NONE;
    }
    return kf;

error:
    ERROR_CODE(local_error);
    if (kf)
    {
        tls_secure_memzero(kf, total_len);
        tls_fileio_free(kf);
    }
    return NULL;
}

struct tls_keyobject *tls_pkcs8_import_private(const char *pem_data, size_t size, const char *password)
{
    struct tls_pkcs8_object *obj = tls_pkcs8_import(pem_data, size, password, NULL);
    if (!obj)
    {
        return NULL;
    }
    if ((obj->type & TLS_KEY_PRIVATE) != TLS_KEY_PRIVATE)
    {
        tls_pkcs8_object_destroy(obj);
        return NULL;
    }
    return (struct tls_keyobject *)obj;
}

struct tls_keyobject *tls_pkcs8_import_public(const char *pem_data, size_t size)
{
    struct tls_pkcs8_object *obj = tls_pkcs8_import(pem_data, size, NULL, NULL);
    if (!obj)
    {
        return NULL;
    }
    if ((obj->type & TLS_KEY_PRIVATE) != TLS_KEY_PUBLIC)
    {
        tls_pkcs8_object_destroy(obj);
        return NULL;
    }
    return (struct tls_keyobject *)obj;
}

struct tls_pkcs8_object *tls_pkcs8_object_import_private(const char *pem_data, size_t size, const char *password)
{
    return tls_pkcs8_import(pem_data, size, password, NULL);
}

struct tls_pkcs8_object *tls_pkcs8_object_import_public(const char *pem_data, size_t size)
{
    return tls_pkcs8_import(pem_data, size, NULL, NULL);
}

void tls_pkcs8_object_destroy(struct tls_pkcs8_object *obj)
{
    if (obj)
    {
        tls_secure_memzero(obj, obj->total_len);
        tls_fileio_free(obj);
    }
}

char *tls_pkcs8_str_error_arr[] = {
    "Invalid argument",
    "PEM decode failure",
    "Allocation failure",
    "Password required for encrypted key",
    "Unsupported algorithm",
    "Decryption failure"};

char *tls_pkcs8_strerror(tls_pkcs8_error_t error)
{
    if (!error || error > TLS_PKCS8_ERR_DECRYPT_FAIL)
        return NULL;
    return tls_pkcs8_str_error_arr[error - 1];
}
