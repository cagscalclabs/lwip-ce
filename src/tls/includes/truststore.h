/**
 * @file truststore.h
 * @author Anthony Cagliano
 * @brief Provides API for initializing and checking trust store for pins.
 * @reference: RFC 5280
 *
 * @note Custom PKI architecture engineered for constrained
 * runtime and storage environments.
 *
 * @warning This implementation currently validates that a
 * certificate chain terminates in a pinned root certificate,
 * but does not (yet) perform full cryptographic verification
 * of all intermediate certificate signatures.
 *
 * Security therefore depends on the assumption that an
 * attacker cannot construct an alternate certificate chain
 * terminating in a trusted pinned root without possession
 * of the corresponding signing authority.
 */

#ifndef TLS_TRUSTSTORE_H
#define TLS_TRUSTSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TLS_SPKI_SUBJECT_LEN  32
#define TLS_SPKI_SKI_LEN      32

/* Serialized signature algorithm IDs used in tls_truststore_entry.alg_id.
 * These are lwIP-internal codes, NOT ASN.1/DER OIDs. */
typedef enum
{
    TLS_CERT_SIG_RSA_PSS_SHA256       = 0, /* rsaEncryption + id-RSASSA-PSS / SHA-256 */
    TLS_CERT_SIG_RSA_PKCS1_SHA256     = 1, /* sha256WithRSAEncryption (PKCS#1 v1.5)   */
    TLS_CERT_SIG_RSA_PKCS1_SHA384     = 2, /* sha384WithRSAEncryption (PKCS#1 v1.5)   */
    TLS_CERT_SIG_ECDSA_SHA256         = 3, /* ecdsa-with-SHA256 (P-256)               */
    TLS_CERT_SIG_UNKNOWN              = 0xFF
} tls_cert_sig_alg_t;

typedef enum
{
    TLS_STORE_OK = 0,
    TLS_STORE_NOT_FOUND,
    TLS_STORE_SIZE_INVALID,
    TLS_STORE_VERSION_MISMATCH,
    TLS_STORE_HASH_FAIL,
    TLS_STORE_SIG_INVALID
} tls_truststore_status_t;

struct tls_truststore_state
{
    tls_truststore_status_t status;
    uint16_t size;
    uint16_t entry_count;
    uint16_t version;
    uint32_t created_timestamp;
};

struct tls_truststore_header
{
    uint8_t sig[256];           /* RSA-2048 signature over header fields + entries */
    uint16_t version;           /* Truststore format version */
    uint32_t created_timestamp; /* Unix timestamp when truststore was generated */
    uint16_t entry_count;       /* Number of SPKI entries in truststore */
};
#define TLS_SPKI_HEADER_LEN sizeof(struct tls_truststore_header)

/* Variable-length per-entry record. The key[] FAM holds the raw public key
 * bytes whose format depends on alg_id:
 *   RSA: uint8_t exp[3] (little-endian uint24) || uint8_t mod[key_len - 3]
 *   EC:  uint8_t point[key_len]  (x-coordinate, big-endian)
 * len covers the entire struct including the key[] bytes. */
struct tls_truststore_entry
{
    uint32_t len;                            /* total byte size of this entry */
    uint8_t  subject[TLS_SPKI_SUBJECT_LEN]; /* Subject CN, null-terminated, padded */
    uint8_t  ski[TLS_SPKI_SKI_LEN];         /* Subject Key Identifier, padded to 32 B */
    uint32_t expiry_start;                  /* notBefore Unix timestamp (uint32_t) */
    uint32_t expiry_end;                    /* notAfter  Unix timestamp (uint32_t) */
    uint8_t  alg_id;                        /* tls_cert_sig_alg_t */
    uint8_t  key[];                         /* variable-length public key bytes */
};

/******************
 * @brief Initializes the trust store, checks for the SPKI appvar,
 * RSA-decrypts the signature, verifies the signature, sets a flag
 * for session if looks good.
 * @returns [tls_truststore_status_t] status code
 */
tls_truststore_status_t tls_truststore_init(void);

/********************
 * @brief Attempts to find a certificate by Subject Key Identifier in the trust store.
 * @param ski       32-byte SKI value from the certificate's SubjectKeyIdentifier extension.
 * @param result    Out-pointer set to the in-place entry on match. May be NULL.
 * @returns [bool] True if match found, false otherwise.
 */
bool tls_truststore_lookup(const uint8_t *ski, struct tls_truststore_entry **result);

/********************
 * @brief Attempts to find a truststore entry whose subject[] matches the given
 *        name (issuer CN of the topmost cert in the chain).
 * @param subject   Name bytes (up to TLS_SPKI_SUBJECT_LEN), null-padded.
 * @param subject_len  Meaningful bytes in subject (0 < subject_len <= TLS_SPKI_SUBJECT_LEN).
 * @param result    Out-pointer set to the in-place entry on match. May be NULL.
 * @returns [bool] True if match found, false otherwise.
 */
bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t subject_len,
                                      struct tls_truststore_entry **result);

#endif /* TLS_TRUSTSTORE_H */
