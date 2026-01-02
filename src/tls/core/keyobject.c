#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "lwip/mem.h"

#include "../includes/base64.h"
#include "../includes/asn1.h"
#include "../includes/keyobject.h"
#include "../includes/passwords.h"
#include "../includes/aes.h"
#include "../includes/hash.h"

void rmemcpy(void *dest, void *src, size_t len);

uint8_t tls_objectid_bytes[][10] = {
    // PKCS and SECG object ids
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}, // TLS_OID_RSA_ENCRYPTION
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01},             // TLS_OID_EC_PUBLICKEY
    {0x2B, 0x81, 0x04, 0x01, 0x08},                         // TLS_OID_EC_PRIVATEKEY
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},       // TLS_OID_EC_SECP256R1

    // encryption algorithm identifiers (encrypted private key)
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06}, // TLS_OID_AES_128_GCM
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02}, // TLS_OID_AES_128_CBC
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}, // TLS_OID_AES_256_GCM
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A}, // TLS_OID_AES_256_CBC
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C}, // TLS_OID_PBKDF2
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D}, // TLS_OID_PBES2
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09},       // TLS_OID_HMAC_SHA256

    // X.509 identifiers
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}, // TLS_OID_SHA256_RSA_ENCRYPTION
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C}, // TLS_OID_SHA384_RSA_ENCRYPTION
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}        // TLS_OID_SHA256_ECDSA

};

/* -------------------------------------------------------------------------
 RSAPrivateKey ::= SEQUENCE {
     version           Version,          -- Always set to 0 for PKCS#1 v1.5
     modulus           INTEGER,          -- n (modulus)
     publicExponent    INTEGER,          -- e (public exponent)
     privateExponent   INTEGER,          -- d (private exponent)
     prime1            INTEGER,          -- p (first prime factor)
     prime2            INTEGER,          -- q (second prime factor)
     exponent1         INTEGER,          -- d mod (p-1) (private exponent mod p-1)
     exponent2         INTEGER,          -- d mod (q-1) (private exponent mod q-1)
     coefficient       INTEGER,          -- (inverse of q) mod p
     otherPrimeInfos   OtherPrimeInfos OPTIONAL  -- Only for multi-prime RSA, usually omitted
 }
 */
struct tls_asn1_schema tls_pkcs1_privkey_schema[] = {
    {"RSAPrivateKey", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"version", ASN1_INTEGER, 1, false, false, false, ASN1_MATCH, false},
    {"modulus", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"publicExponent", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"privateExponent", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"prime1", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"prime2", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"exponent1", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"exponent2", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"coefficient", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* -------------------------------------------------------------------------
 RSAPublicKey ::= SEQUENCE {
     modulus           INTEGER,    -- n (the modulus)
     publicExponent    INTEGER     -- e (the public exponent)
 }
 */
struct tls_asn1_schema tls_pkcs1_pubkey_schema[] = {
    {"RSAPublicKey", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"modulus", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {"publicExponent", ASN1_INTEGER, 1, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* -------------------------------------------------------------------------
 ECPrivateKey ::= SEQUENCE {
     version        1,
     privateKey     OCTET STRING,  -- Encoded private key value (d)
     parameters     [0] EXPLICIT ECParameters OPTIONAL,  -- Omitted if implied by curve
     publicKey      [0] EXPLICIT BIT STRING OPTIONAL     -- Optional encoded public key
 }
 */
struct tls_asn1_schema tls_sec1_privkey_schema[] = {
    {"ECPrivateKey", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"version", ASN1_INTEGER, 1, false, false, false, ASN1_MATCH, false},
    {"privateKey", ASN1_OCTETSTRING, 1, false, false, true, ASN1_MATCH, false},
    {"parameters [0]", ASN1_CONTEXTSPEC | ASN1_CONSTRUCTED | 0, 1, true, false, false, ASN1_MATCH, false},
    {"curve oid", ASN1_OBJECTID, 2, true, false, true, ASN1_MATCH, false},
    {"parameters [1]", ASN1_CONTEXTSPEC | ASN1_CONSTRUCTED | 1, 1, true, false, false, ASN1_MATCH, false},
    {"publicKey", ASN1_BITSTRING, 2, true, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* -------------------------------------------------------------------------
 ECPoint ::= OCTET STRING    -- Represents the public key (Q = d * G)
 */
struct tls_asn1_schema tls_sec1_pubkey_schema[] = {
    {"EC Point", ASN1_OCTETSTRING, 0, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* -------------------------------------------------------------------------
 PrivateKeyInfo ::= SEQUENCE {
     version                   Version,          -- Version is usually v1 (INTEGER 0)
     privateKeyAlgorithm        SEQUENCE {
         algorithm              OBJECT IDENTIFIER {id-ecPublicKey} (1.2.840.10045.2.1),
         parameters             OBJECT IDENTIFIER {secp256r1} (1.2.840.10045.3.1.7)
     },
     privateKey                 OCTET STRING,     -- Encoded private key
     attributes                 [0] IMPLICIT SET OF Attribute OPTIONAL   -- Optional attributes
 }
 */
struct tls_asn1_schema tls_pkcs8_privkey_schema[] = {
    {"PrivateKeyInfo", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"version", ASN1_INTEGER, 1, false, false, false, ASN1_MATCH, false},
    {"PrivateKeyAlgorithm", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 1, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 2, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_OBJECTID, 2, false, true, true, ASN1_MATCH, false},
    {"privateKey", ASN1_OCTETSTRING, 1, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* -------------------------------------------------------------------------
 EncryptedPrivateKeyInfo ::= SEQUENCE {
     EncryptionAlgorithmIdentifier ::= SEQUENCE {
         algorithm            OBJECT IDENTIFIER,       -- The OID of the encryption algorithm (e.g., AES)
         parameters           ANY DEFINED BY algorithm OPTIONAL -- Algorithm-specific parameters (e.g., IV)
     }
     encryptedData        OCTET STRING                    -- The encrypted private key
 }
*/
struct tls_asn1_schema tls_pkcs8_encrypted_privkey_schema[] = {
    {"EncryptedPrivateKeyInfo", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"EncryptionAlgorithmIdentifier", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 1, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 2, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 2, false, false, false, ASN1_MATCH, false},
    {"keyDerivFunc", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 3, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 4, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 4, false, false, false, ASN1_MATCH, false},
    {"salt", ASN1_OCTETSTRING, 5, false, false, true, ASN1_MATCH, false},
    {"rounds", ASN1_INTEGER, 5, false, false, true, ASN1_MATCH, false},
    {"keylen", ASN1_INTEGER, 5, true, false, true, ASN1_MATCH, false},
    {"prf", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 5, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 6, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_NULL, 6, false, false, false, ASN1_MATCH, false},
    {"encryptionScheme", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 3, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 4, false, false, true, ASN1_MATCH, false},
    {"iv", ASN1_OCTETSTRING, 4, false, false, true, ASN1_MATCH, false},
    {"encryptedData", ASN1_OCTETSTRING, 1, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};
#define TLS_PKCS8_ENCRYPTED_IDX_PBES2 0
#define TLS_PKCS8_ENCRYPTED_IDX_PBKDF2 1
#define TLS_PKCS8_ENCRYPTED_IDX_SALT 2
#define TLS_PKCS8_ENCRYPTED_IDX_ROUNDS 3
#define TLS_PKCS8_ENCRYPTED_IDX_KEYLEN 4
#define TLS_PKCS8_ENCRYPTED_IDX_HMAC 5
#define TLS_PKCS8_ENCRYPTED_IDX_AES 6
#define TLS_PKCS8_ENCRYPTED_IDX_IV 7
#define TLS_PKCS8_ENCRYPTED_IDX_DATA 8

/* -------------------------------------------------------------------------
 SubjectPublicKeyInfo ::= SEQUENCE {
     algorithm            SEQUENCE {
         algorithm        OBJECT IDENTIFIER {id-ecPublicKey} (1.2.840.10045.2.1),
         parameters       OBJECT IDENTIFIER {secp256r1} (1.2.840.10045.3.1.7)
     },
     subjectPublicKey     BIT STRING  -- Encoded public key
 }
 */
struct tls_asn1_schema tls_pkcs8_pubkey_schema[] = {
    {"SubjectPublicKeyInfo", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 0, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 1, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 2, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_OBJECTID, 2, true, true, true, ASN1_MATCH, false},
    {"subjectPublicKey", ASN1_BITSTRING, 1, false, false, true, ASN1_MATCH, false},
    {NULL, 0, 0, false, false, false, ASN1_MATCH, false}};

/* --------------------------------------------------------------------------
 Certificate ::= SEQUENCE {
     tbsCertificate       SEQUENCE {
         version             [0] EXPLICIT INTEGER DEFAULT v1,
         serialNumber        INTEGER,
         signature           SEQUENCE {
             algorithm            OBJECT IDENTIFIER,
             parameters           ANY DEFINED BY algorithm OPTIONAL -- Can be NULL
         },
         issuer              SEQUENCE OF SEQUENCE {
             type              OBJECT IDENTIFIER,
             value             ANY
         },
         validity            SEQUENCE {
             notBefore          CHOICE {
                 utcTime        UTCTime,
                 generalTime    GeneralizedTime
             },
             notAfter           CHOICE {
                 utcTime        UTCTime,
                 generalTime    GeneralizedTime
             }
         },
         subject             SEQUENCE OF SEQUENCE {
             type              OBJECT IDENTIFIER,
             value             ANY
         },
         subjectPublicKeyInfo SEQUENCE {
             algorithm         SEQUENCE {
                 algorithm      OBJECT IDENTIFIER,
                 parameters     ANY DEFINED BY algorithm OPTIONAL -- Can be NULL
             },
             subjectPublicKey  BIT STRING
         },
         issuerUniqueID      [1] IMPLICIT BIT STRING OPTIONAL,  -- v2 or v3
         subjectUniqueID     [2] IMPLICIT BIT STRING OPTIONAL,  -- v2 or v3
         extensions          [3] EXPLICIT SEQUENCE OF SEQUENCE {  -- v3 only
             extnID             OBJECT IDENTIFIER,
             critical           BOOLEAN DEFAULT FALSE,
             extnValue          OCTET STRING
         } OPTIONAL
     },
     signatureAlgorithm   SEQUENCE {
         algorithm            OBJECT IDENTIFIER,
         parameters           ANY DEFINED BY algorithm OPTIONAL -- Can be NULL
     },
     signatureValue       BIT STRING
 }
 */
struct tls_asn1_schema tls_x509_cert_schema[] = {
    {"algorithm", ASN1_OBJECTID, 3, false, false, true, ASN1_SEEK, false},
    // seek to issuer commonName
    {"issuerName", ASN1_OBJECTID, 5, false, false, true, ASN1_SEEK, false},
    {"issuerName", ASN1_UTF8STRING, 5, false, false, true, ASN1_MATCH, false},
    // ignore until
    {"validity", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 2, false, false, false, ASN1_SEEK, false},
    // select either or
    {"valid-before", ASN1_UTCTIME, 3, false, false, true, ASN1_MATCH, false},
    {"valid-before", ASN1_GENERALIZEDTIME, 3, false, false, true, ASN1_MATCH, false},
    // select either or
    {"valid-after", ASN1_UTCTIME, 3, false, false, true, ASN1_SEEK, false},
    {"valid-after", ASN1_GENERALIZEDTIME, 3, false, false, true, ASN1_MATCH, false},
    // ignore until, then read
    {"subject", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 2, false, false, false, ASN1_SEEK, false},
    {"subjectName", ASN1_OBJECTID, 5, false, false, true, ASN1_SEEK, false},
    {"subjectName", ASN1_UTF8STRING, 5, false, false, true, ASN1_MATCH, false},
    // ignore until, then decode normally (capture raw SPKI for pinning - use SEEK with raw_output)
    {"SubjectPublicKeyInfo", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 2, false, false, true, ASN1_SEEK, true},
    {"algorithm", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 3, false, false, false, ASN1_MATCH, false},
    {"algorithm", ASN1_OBJECTID, 4, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_OBJECTID, 4, true, true, true, ASN1_MATCH, false},
    {"subjectPublicKey", ASN1_BITSTRING, 3, false, false, true, ASN1_MATCH, false},
    {"signatureAlgorithm", ASN1_SEQUENCE | ASN1_CONSTRUCTED, 1, false, false, false, ASN1_SEEK, false},
    {"algorithm", ASN1_OBJECTID, 2, false, false, true, ASN1_MATCH, false},
    {"parameters", ASN1_OBJECTID, 2, true, true, true, ASN1_MATCH, false},
    {"signatureValue", ASN1_BITSTRING, 1, false, false, true, ASN1_MATCH, false},
    // then decode using pkcs1/sec1 rules
    {NULL, 0, 0, false, false, false, false, false}};

struct tls_lookup_data
{
    char *banner;
    struct tls_asn1_schema *decoder_schema;
};

struct tls_lookup_data pkcs_lookups[] = {
#define PKCS_LOOKUP_PRIVATE 0
    {"-----BEGIN RSA PRIVATE KEY-----", tls_pkcs1_privkey_schema},
    {"-----BEGIN EC PRIVATE KEY-----", tls_sec1_privkey_schema},
    {"-----BEGIN PRIVATE KEY-----", tls_pkcs8_privkey_schema},
    {"-----BEGIN ENCRYPTED PRIVATE KEY-----", tls_pkcs8_encrypted_privkey_schema},
#define PKCS_LOOKUP_PUBLIC 4
    {"-----BEGIN RSA PUBLIC KEY-----", tls_pkcs1_pubkey_schema},
    {"-----BEGIN EC PUBLIC KEY-----", tls_sec1_pubkey_schema},
    {"-----BEGIN PUBLIC KEY-----", tls_pkcs8_pubkey_schema},
#define PKCS_LOOKUP_CERTIFICATE 7
    {"-----BEGIN CERTIFICATE-----", tls_x509_cert_schema},
#define PKCS_LOOKUP_END 8
};

struct tls_keyobject *tls_keyobject_import_private(const char *pem_data, size_t size, const char *password)
{
    if ((pem_data == NULL) || (size == 0))
        return NULL;
    struct tls_asn1_schema *decoder_schema;
    struct tls_asn1_serialization tmp_serialize[9] = {0};
    uint8_t serialized_count = 0;
    struct tls_asn1_decoder_context asn1_ctx;
    uint8_t *b64_start = (uint8_t *)(strchr((char *)pem_data, '\n') + 1);
    uint8_t *b64_end = (uint8_t *)strchr((char *)b64_start, '\n');
    size_t b64_size = b64_end - b64_start;

    // locate banner, load schema for format
    for (int i = PKCS_LOOKUP_PRIVATE; i < PKCS_LOOKUP_PUBLIC; i++)
        if (strncmp((char *)pem_data, pkcs_lookups[i].banner, strlen(pkcs_lookups[i].banner)) == 0)
        {
            decoder_schema = pkcs_lookups[i].decoder_schema;
            goto file_type_ok;
        }
    return NULL; // if no matching banner found, fail

file_type_ok:
    // compute start/end of base64 section, sanity checks on size
    if (b64_size > size)
        return NULL;

    // decode base64 into DER
    uint8_t *asn1_buf = mem_malloc(b64_size / 3 * 4);
    if (asn1_buf == NULL)
        return NULL;

    size_t asn1_size = tls_base64_decode(b64_start, b64_size, asn1_buf);
    size_t tot_len = sizeof(struct tls_keyobject) + asn1_size;
    // allocate context
    struct tls_keyobject *kf = mem_malloc(tot_len);
    if (kf == NULL)
        return NULL;

    kf->length = tot_len;
    // copy ASN.1 data to struct data field
    memcpy(kf->data, asn1_buf, asn1_size);
    mem_free(asn1_buf);
    if (!tls_asn1_decoder_init(&asn1_ctx, kf->data, asn1_size))
        goto error;

    kf->type = 0 | TLS_KEY_PRIVATE;

    if (decoder_schema == tls_pkcs8_encrypted_privkey_schema)
    {
        if (password == NULL)
            goto error;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &tmp_serialize[serialized_count].tag,
                                      &tmp_serialize[serialized_count].data,
                                      &tmp_serialize[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
                serialized_count++;
        }
        if (
            (memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_PBES2].data, tls_objectid_bytes[TLS_OID_PBES2], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_PBES2].len) == 0) &&
            (memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_PBKDF2].data, tls_objectid_bytes[TLS_OID_PBKDF2], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_PBKDF2].len) == 0) &&
            (memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_HMAC].data, tls_objectid_bytes[TLS_OID_HMAC_SHA256], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_HMAC].len) == 0) &&
            ((memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].data, tls_objectid_bytes[TLS_OID_AES_128_CBC], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].len) == 0) ||
             (memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].data, tls_objectid_bytes[TLS_OID_AES_256_CBC], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].len) == 0)))
        {
            size_t keylen = 0, rounds = 0;
            uint8_t derived_key[32];
            struct tls_aes_context aes_ctx;
            // try to get keylen from keylen field if present
            if (tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_KEYLEN].data)
                rmemcpy(&keylen, tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_KEYLEN].data, tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_KEYLEN].len);
            else // else derive from AES algorithm
                keylen = (memcmp(tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].data, tls_objectid_bytes[TLS_OID_AES_128_CBC], tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_AES].len) == 0) ? 16 : 32;
            // get rounds from rounds field
            rmemcpy(&rounds, tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_ROUNDS].data, tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_ROUNDS].len);
            // derive key
            if (!tls_pbkdf2(password, strlen(password),
                            tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_SALT].data,
                            tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_SALT].len,
                            derived_key, keylen,
                            rounds, TLS_HASH_SHA256))
                goto error;

            // AES context init
            if (!tls_aes_init(&aes_ctx, TLS_AES_CBC, derived_key, keylen,
                              tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_IV].data,
                              tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_IV].len))
                goto error;

            // decrypt
            size_t cbc_len = tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_DATA].len;
            if (!tls_aes_decrypt(&aes_ctx,
                                 tmp_serialize[TLS_PKCS8_ENCRYPTED_IDX_DATA].data,
                                 cbc_len,
                                 kf->data))
                goto error;

            size_t cbc_actual_len = cbc_len - kf->data[cbc_len - 1];

            decoder_schema = tls_pkcs8_privkey_schema;
            // init decoder to end of decrypted content
            if (!tls_asn1_decoder_init(&asn1_ctx, kf->data, cbc_actual_len))
                goto error;
        }
        else
            goto error;
    }
    if (decoder_schema == tls_pkcs8_privkey_schema)
    {
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &tmp_serialize[serialized_count].tag,
                                      &tmp_serialize[serialized_count].data,
                                      &tmp_serialize[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
                serialized_count++;
        }
        // set decoder to start at private key bit/octet string
        if (!tls_asn1_decoder_init(&asn1_ctx, tmp_serialize[2].data, tmp_serialize[2].len))
            goto error;

        if (memcmp(tmp_serialize[0].data, tls_objectid_bytes[TLS_OID_RSA_ENCRYPTION], tmp_serialize[0].len) == 0)
            decoder_schema = tls_pkcs1_privkey_schema;
        else if (
            (memcmp(tmp_serialize[0].data, tls_objectid_bytes[TLS_OID_EC_PUBLICKEY], tmp_serialize[0].len) == 0) &&
            (memcmp(tmp_serialize[1].data, tls_objectid_bytes[TLS_OID_EC_SECP256R1], tmp_serialize[1].len) == 0))
            decoder_schema = tls_sec1_privkey_schema;
        else
            goto error;
    }
    if (decoder_schema == tls_pkcs1_privkey_schema)
    {
        kf->type |= TLS_KEY_RSA;
        decoder_schema = tls_pkcs1_privkey_schema;
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &kf->meta.privkey.rsa.fields[serialized_count].tag,
                                      &kf->meta.privkey.rsa.fields[serialized_count].data,
                                      &kf->meta.privkey.rsa.fields[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
            {
                kf->meta.privkey.rsa.fields[serialized_count].name = decoder_schema[i].name;
                serialized_count++;
            }
        }
        return kf;
    }
    if (decoder_schema == tls_sec1_privkey_schema)
    {
        kf->type |= TLS_KEY_ECC;
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &kf->meta.privkey.ec.fields[serialized_count].tag,
                                      &kf->meta.privkey.ec.fields[serialized_count].data,
                                      &kf->meta.privkey.ec.fields[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
            {
                kf->meta.privkey.ec.fields[serialized_count].name = decoder_schema[i].name;
                serialized_count++;
            }
        }
        return kf;
    }

error:
    memset(kf, 0, kf->length);
    mem_free(kf);
    return NULL;
}

struct tls_keyobject *tls_keyobject_import_public(const char *pem_data, size_t size)
{
    if ((pem_data == NULL) || (size == 0))
        return NULL;
    struct tls_asn1_schema *decoder_schema;
    struct tls_asn1_serialization tmp_serialize[9] = {0};
    uint8_t serialized_count = 0;
    struct tls_asn1_decoder_context asn1_ctx;
    uint8_t *b64_start = (uint8_t *)(strchr((char *)pem_data, '\n') + 1);
    uint8_t *b64_end = (uint8_t *)strchr((char *)b64_start, '\n');
    size_t b64_size = b64_end - b64_start;

    // locate banner, load schema for format
    for (int i = PKCS_LOOKUP_PUBLIC; i < PKCS_LOOKUP_CERTIFICATE; i++)
        if (strncmp((char *)pem_data, pkcs_lookups[i].banner, strlen(pkcs_lookups[i].banner)) == 0)
        {
            decoder_schema = pkcs_lookups[i].decoder_schema;
            goto file_type_ok;
        }
    return NULL; // if no matching banner found, fail

file_type_ok:
    // compute start/end of base64 section, sanity checks on size
    if (b64_size > size)
        return NULL;

    // decode base64 into DER
    uint8_t *asn1_buf = mem_malloc(b64_size / 3 * 4);
    if (asn1_buf == NULL)
        return NULL;

    size_t asn1_size = tls_base64_decode(b64_start, b64_size, asn1_buf);
    size_t tot_len = sizeof(struct tls_keyobject) + asn1_size;
    // allocate context
    struct tls_keyobject *kf = mem_malloc(tot_len);
    if (kf == NULL)
        return NULL;

    kf->length = tot_len;
    // copy ASN.1 data to struct data field
    memcpy(kf->data, asn1_buf, asn1_size);
    mem_free(asn1_buf);
    if (!tls_asn1_decoder_init(&asn1_ctx, kf->data, asn1_size))
        goto error;

    kf->type = 0 | TLS_KEY_PUBLIC;

    if (decoder_schema == tls_pkcs8_pubkey_schema)
    {
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &tmp_serialize[serialized_count].tag,
                                      &tmp_serialize[serialized_count].data,
                                      &tmp_serialize[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
                serialized_count++;
        }
        // set decoder to start at private key bit/octet string
        if (!tls_asn1_decoder_init(&asn1_ctx, tmp_serialize[2].data, tmp_serialize[2].len))
            goto error;
    }

    if (memcmp(tmp_serialize[0].data, tls_objectid_bytes[TLS_OID_RSA_ENCRYPTION], tmp_serialize[0].len) == 0)
        decoder_schema = tls_pkcs1_pubkey_schema;
    else if (
        (memcmp(tmp_serialize[0].data, tls_objectid_bytes[TLS_OID_EC_PUBLICKEY], tmp_serialize[0].len) == 0) &&
        (memcmp(tmp_serialize[1].data, tls_objectid_bytes[TLS_OID_EC_SECP256R1], tmp_serialize[1].len) == 0))
    {
        kf->type |= TLS_KEY_ECC;
        kf->meta.pubkey.ec.field.pubkey.tag = tmp_serialize[2].tag;
        kf->meta.pubkey.ec.field.pubkey.data = tmp_serialize[2].data;
        kf->meta.pubkey.ec.field.pubkey.len = tmp_serialize[2].len;
        kf->meta.pubkey.ec.field.pubkey.name = tls_sec1_pubkey_schema[0].name;
        return kf;
    }
    else
    {
        printf("invalid object id");
        goto error;
    }

    if (decoder_schema == tls_pkcs1_pubkey_schema)
    {
        kf->type |= TLS_KEY_RSA;
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &kf->meta.pubkey.rsa.fields[serialized_count].tag,
                                      &kf->meta.pubkey.rsa.fields[serialized_count].data,
                                      &kf->meta.pubkey.rsa.fields[serialized_count].len,
                                      NULL))
                goto error;
            if (decoder_schema[i].output)
            {
                kf->meta.pubkey.rsa.fields[serialized_count].name = decoder_schema[i].name;
                serialized_count++;
            }
        }
        return kf;
    }

error:
    memset(kf, 0, kf->length);
    mem_free(kf);
    return NULL;
}

#define TLS_X509_IDX_SUBJSIGALG     0
#define TLS_X509_IDX_ISSUERNAME     1
#define TLS_X509_IDX_VALIDBEFORE    2
#define TLS_X509_IDX_VALIDAFTER     3
#define TLS_X509_IDX_SUBJECTNAME    4
#define TLS_X509_IDX_SPKIRAW        5
#define TLS_X509_IDX_PKEYALG        6
#define TLS_X509_IDX_PKEYPARAM      7
#define TLS_X509_IDX_PKEYBITS       8
#define TLS_X509_IDX_CASIGALG       9
#define TLS_X509_IDX_CASIGPARAM     10
#define TLS_X509_IDX_CASIGVAL       11

uint8_t common_name_oid[] = {0x55, 0x04, 0x03};
struct tls_keyobject *tls_keyobject_import_certificate(const char *pem_data, size_t size)
{
    if ((pem_data == NULL) || (size == 0))
        return NULL;
    struct tls_asn1_schema *decoder_schema;
    struct tls_asn1_serialization tmp_serialize[TLS_X509_IDX_CASIGVAL + 1] = {0};
    uint8_t serialized_count = 0;
    struct tls_asn1_decoder_context asn1_ctx;
    uint8_t *b64_start = (uint8_t *)(strchr((char *)pem_data, '\n') + 1);
    uint8_t *b64_end = (uint8_t *)strchr((char *)b64_start, '\n');
    size_t b64_size = b64_end - b64_start;

    // locate banner, load schema for format
    for (int i = PKCS_LOOKUP_CERTIFICATE; i < PKCS_LOOKUP_END; i++)
        if (strncmp((char *)pem_data, pkcs_lookups[i].banner, strlen(pkcs_lookups[i].banner)) == 0)
        {
            decoder_schema = pkcs_lookups[i].decoder_schema;
            goto file_type_ok;
        }
    return NULL; // if no matching banner found, fail

file_type_ok:
    // compute start/end of base64 section, sanity checks on size
    if (b64_size > size)
        return NULL;

    // decode base64 into DER
    uint8_t *asn1_buf = mem_malloc(b64_size / 3 * 4);
    if (asn1_buf == NULL)
        return NULL;

    size_t asn1_size = tls_base64_decode(b64_start, b64_size, asn1_buf);
    size_t tot_len = sizeof(struct tls_keyobject) + asn1_size;
    // allocate context
    struct tls_keyobject *kf = mem_malloc(tot_len);
    if (kf == NULL)
        return NULL;

    kf->length = tot_len;
    // copy ASN.1 data to struct data field
    memcpy(kf->data, asn1_buf, asn1_size);
    mem_free(asn1_buf);
    if (!tls_asn1_decoder_init(&asn1_ctx, kf->data, asn1_size))
        goto error;

    kf->type = 0 | TLS_CERTIFICATE;

    for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
    {
        if ((i == 1) || (i == 9))
        {
            do
            {
                if (!tls_asn1_decode_next(&asn1_ctx,
                                          &decoder_schema[i],
                                          &tmp_serialize[serialized_count].tag,
                                          &tmp_serialize[serialized_count].data,
                                          &tmp_serialize[serialized_count].len,
                                          NULL))
                    goto error;
            } while (memcmp(common_name_oid, tmp_serialize[serialized_count].data, tmp_serialize[serialized_count].len));
        }
        else
        {
            if (tls_asn1_decode_next(&asn1_ctx,
                                     &decoder_schema[i],
                                     &tmp_serialize[serialized_count].tag,
                                     &tmp_serialize[serialized_count].data,
                                     &tmp_serialize[serialized_count].len,
                                     NULL))
            {
                if ((i == 4) || (i == 6))
                    i++;
                if (decoder_schema[i].output)
                {
                    tmp_serialize[serialized_count].name = decoder_schema[i].name;
                    serialized_count++;
                }
            }
            else
            {
                if (!((i >= 4) && (i <= 7)))
                    goto error;
            }
        }
    }

    if (!(
            (memcmp(tmp_serialize[TLS_X509_IDX_SUBJSIGALG].data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], tmp_serialize[TLS_X509_IDX_SUBJSIGALG].len) == 0) ||
            (memcmp(tmp_serialize[TLS_X509_IDX_SUBJSIGALG].data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], tmp_serialize[TLS_X509_IDX_SUBJSIGALG].len) == 0)))
        goto error;

    if (!(
            (memcmp(tmp_serialize[TLS_X509_IDX_CASIGALG].data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], tmp_serialize[TLS_X509_IDX_CASIGALG].len) == 0) ||
            (memcmp(tmp_serialize[TLS_X509_IDX_CASIGALG].data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], tmp_serialize[TLS_X509_IDX_CASIGALG].len) == 0)))
        goto error;

    // copy first 6 fields at once since they're sequential (added SPKI raw for pinning)
    memcpy(&kf->meta.certificate.field.subj_signature_alg, &tmp_serialize[TLS_X509_IDX_SUBJSIGALG], sizeof(struct tls_asn1_serialization) * 6);
    // these two are not sequential
    memcpy(&kf->meta.certificate.field.ca_signature_alg, &tmp_serialize[TLS_X509_IDX_CASIGALG], sizeof(struct tls_asn1_serialization));
    memcpy(&kf->meta.certificate.field.ca_signature, &tmp_serialize[TLS_X509_IDX_CASIGVAL], sizeof(struct tls_asn1_serialization));

    if (memcmp(tmp_serialize[TLS_X509_IDX_PKEYALG].data, tls_objectid_bytes[TLS_OID_RSA_ENCRYPTION], tmp_serialize[0].len) == 0)
    {
        if (!tls_asn1_decoder_init(&asn1_ctx, tmp_serialize[TLS_X509_IDX_PKEYBITS].data, tmp_serialize[TLS_X509_IDX_PKEYBITS].len))
            goto error;
        kf->type |= (TLS_KEY_RSA | 0);
        decoder_schema = tls_pkcs1_pubkey_schema;
        serialized_count = 0;
        for (uint24_t i = 0; decoder_schema[i].name != NULL; i++)
        {
            if (!tls_asn1_decode_next(&asn1_ctx,
                                      &decoder_schema[i],
                                      &kf->meta.certificate.field.pubkey.rsa.fields[serialized_count].tag,
                                      &kf->meta.certificate.field.pubkey.rsa.fields[serialized_count].data,
                                      &kf->meta.certificate.field.pubkey.rsa.fields[serialized_count].len,
                                      NULL))
                goto error;

            if (decoder_schema[i].output)
            {
                kf->meta.certificate.field.pubkey.rsa.fields[serialized_count].name = decoder_schema[i].name;
                serialized_count++;
            }
        }
        return kf;
    }
    else if (
        (memcmp(tmp_serialize[TLS_X509_IDX_PKEYALG].data, tls_objectid_bytes[TLS_OID_EC_PUBLICKEY], tmp_serialize[TLS_X509_IDX_PKEYALG].len) == 0) &&
        (memcmp(tmp_serialize[TLS_X509_IDX_PKEYPARAM].data, tls_objectid_bytes[TLS_OID_EC_SECP256R1], tmp_serialize[TLS_X509_IDX_PKEYPARAM].len) == 0))
    {
        kf->type |= (TLS_KEY_ECC | 0);
        kf->meta.certificate.field.pubkey.ec.ec_point.tag = tmp_serialize[TLS_X509_IDX_PKEYBITS].tag;
        kf->meta.certificate.field.pubkey.ec.ec_point.data = tmp_serialize[TLS_X509_IDX_PKEYBITS].data;
        kf->meta.certificate.field.pubkey.ec.ec_point.len = tmp_serialize[TLS_X509_IDX_PKEYBITS].len;
        kf->meta.certificate.field.pubkey.ec.ec_point.name = tls_sec1_pubkey_schema[0].name;
        return kf;
    }

error:
    memset(kf, 0, kf->length);
    mem_free(kf);
    return NULL;
}

void tls_keyobject_destroy(struct tls_keyobject *kf)
{
    // securely unrefs the keyobject
    memset(kf, 0, kf->length);
    mem_free(kf);
    kf = NULL;
}
