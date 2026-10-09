/**
 * @file tls_algorithms.h
 * @brief TLS algorithm identifiers and canonical DER OID value bytes.
 * 
 * @b {This file contains an exhaustive list of every algorithm currently offered in this TLS implementation.}
 *
 * This file identifies algorithms only. Parsing rules, parameter validation,
 * key compatibility, and execution deliberately remain with their respective
 * implementations so an OID match can never bypass algorithm-specific checks.
 *
 * The OID macros contain only the DER OBJECT IDENTIFIER value octets; they do
 * not include the ASN.1 tag or length. Instantiate them where storage is
 * needed, for example:
 *
 *     static const uint8_t oid[] = { TLS_OID_SHA256_BYTES };
 */

#ifndef TLS_ALGORITHMS_H
#define TLS_ALGORITHMS_H

#include <stdint.h>

/**
 * Operation identifier used by the public key and cipher APIs.
 *
 * Signing range (0x00-0x0F): asymmetric signature algorithms.
 * Encryption range (0x10-0xFE): symmetric and asymmetric encryption.
 */
typedef enum
{
    /* Signing / verification. */
    TLS_ALG_RSA_PSS_RSAE_SHA256    = 0x00,
    TLS_ALG_RSA_PKCS1_SHA256       = 0x01,
    TLS_ALG_ECDSA_SECP256R1_SHA256 = 0x02,

    /* Encryption / decryption. */
    TLS_ALG_AES_128_GCM            = 0x10,
    TLS_ALG_AES_256_GCM            = 0x11,
    TLS_ALG_AES_128_CCM            = 0x12,
    TLS_ALG_AES_256_CCM            = 0x13,
    TLS_ALG_AES_128_CBC            = 0x14,
    TLS_ALG_AES_256_CBC            = 0x15,
    TLS_ALG_RSA_OAEP_SHA256        = 0x16,

    TLS_ALG_UNKNOWN                = 0xFF,
} tls_alg_t;

#define TLS_ALG_IS_SIGNING(alg) \
    ((uint8_t)(alg) <= 0x0F)
#define TLS_ALG_IS_ENCRYPTION(alg) \
    ((uint8_t)(alg) >= 0x10 && (uint8_t)(alg) <= 0xFE)

/* Public-key algorithms and named groups. */
#define TLS_OID_RSA_ENCRYPTION_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 /* 1.2.840.113549.1.1.1 */
#define TLS_OID_RSAES_OAEP_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x07 /* 1.2.840.113549.1.1.7 */
#define TLS_OID_EC_PUBLIC_KEY_BYTES \
    0x2a,0x86,0x48,0xce,0x3d,0x02,0x01           /* 1.2.840.10045.2.1 */
#define TLS_OID_SECP256R1_BYTES \
    0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07      /* 1.2.840.10045.3.1.7 */
#define TLS_OID_X25519_BYTES \
    0x2b,0x65,0x6e                                /* 1.3.101.110 */

/* Signature algorithms and their parameter algorithms. */
#define TLS_OID_SHA256_WITH_RSA_ENCRYPTION_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b /* 1.2.840.113549.1.1.11 */
#define TLS_OID_RSASSA_PSS_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a /* 1.2.840.113549.1.1.10 */
#define TLS_OID_MGF1_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x08 /* 1.2.840.113549.1.1.8 */
#define TLS_OID_ECDSA_WITH_SHA256_BYTES \
    0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02      /* 1.2.840.10045.4.3.2 */

/* Hash, MAC, password KDF, and password-based encryption algorithms. */
#define TLS_OID_SHA256_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01 /* 2.16.840.1.101.3.4.2.1 */
#define TLS_OID_HMAC_WITH_SHA256_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x09      /* 1.2.840.113549.2.9 */
#define TLS_OID_PBKDF2_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c /* 1.2.840.113549.1.5.12 */
#define TLS_OID_PBES2_BYTES \
    0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d /* 1.2.840.113549.1.5.13 */

/* AES modes used by key operations and encrypted-key import. */
#define TLS_OID_AES_128_CBC_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02 /* 2.16.840.1.101.3.4.1.2 */
#define TLS_OID_AES_256_CBC_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a /* 2.16.840.1.101.3.4.1.42 */
#define TLS_OID_AES_128_GCM_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x06 /* 2.16.840.1.101.3.4.1.6 */
#define TLS_OID_AES_256_GCM_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2e /* 2.16.840.1.101.3.4.1.46 */
#define TLS_OID_AES_128_CCM_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x07 /* 2.16.840.1.101.3.4.1.7 */
#define TLS_OID_AES_256_CCM_BYTES \
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2f /* 2.16.840.1.101.3.4.1.47 */

#endif /* TLS_ALGORITHMS_H */
