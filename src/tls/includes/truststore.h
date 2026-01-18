#ifndef TLS_TRUSTSTORE_H
#define TLS_TRUSTSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TLS_SPKI_OWNER_ID_LEN 32
#define TLS_SPKI_ISSUER_LEN 32
#define TLS_SPKI_HASH_MAX_LEN 32

typedef enum {
    TLS_STORE_OK = 0,
    TLS_STORE_NOT_FOUND,
    TLS_STORE_SIZE_INVALID,
    TLS_STORE_VERSION_MISMATCH,
    TLS_STORE_HASH_FAIL,
    TLS_STORE_SIG_INVALID
} tls_truststore_status_t;

struct tls_truststore_header
{
    uint8_t sig[256];           /* RSA-2048 signature over header fields + entries */
    uint16_t version;           /* Truststore format version */
    uint32_t created_timestamp; /* Unix timestamp when truststore was generated */
    uint16_t entry_count;       /* Number of SPKI entries in truststore */
};
#define TLS_SPKI_HEADER_LEN sizeof(struct tls_truststore_header)

struct tls_spki_entry
{
    uint8_t owner_id[TLS_SPKI_OWNER_ID_LEN]; /* CN or identifier (null-terminated, padded) */
    uint8_t issuer_id[TLS_SPKI_ISSUER_LEN];  /* Issuer CN (null-terminated, padded) */
    uint32_t not_before;                     /* Unix timestamp */
    uint32_t not_after;                      /* Unix timestamp */
    uint8_t hash[TLS_SPKI_HASH_MAX_LEN];     /* SPKI hash (SHA-256)*/
};

enum tls_truststore_status
{
    TLS_STORE_UNINITIALIZED = 0,
    TLS_STORE_OK,
    TLS_STORE_NOT_FOUND,
    TLS_STORE_HASH_INIT_FAIL,
    TLS_STORE_SIZE_INVALID,
    TLS_STORE_VERSION_MISMATCH,
    TLS_STORE_SIG_DECRYPT_FAIL,
    TLS_STORE_SIG_INVALID,
    TLS_STORE_ENTRY_MISMATCH,
    TLS_STORE_TIME_INVALID
};

struct tls_truststore_state
{
    enum tls_truststore_status status;
    uint16_t size;
    uint16_t entry_count;
    uint16_t version;
    uint32_t created_timestamp;
};

enum tls_truststore_status tls_truststore_status(void);

/******************
 * @brief Initializes the trust store, checks for the SPKI appvar,
 * RSA-decrypts the signature, verifies the signature, sets a flag
 * for session if looks good.
 * @returns [tls_truststore_status_t] status code
 */
tls_truststore_status_t tls_truststore_init(void);

/********************
 * @brief Attempts to find an SPKI hash in the trust store.
 * @param recvd_hash    Computed hash of the SPKI field of the current certificate.
 * @param result        A tls_spki_entry struct to write the owner metadata to. NULL if you don't care.
 * @returns [bool] True if match found, false if otherwise.
 * @note So that we don't spend 12 hours on calculator doing a
 * complete full-chain validation on every TLS connection, we're
 * using pinned SPKI hashes of common intermediate roots, and the
 * security measure is that IF our chain contains a certificate where
 * the SPKI hash matches something in our trust store, we trust the
 * remote. The current SPKI trust store will be generated every so
 * often and made available as an AppVar named 'lwIPSPKI'. The AppVar
 * will be signed with the repo owner's secret key and the public key
 * will be distributed in this application.
 */
bool tls_truststore_lookup(uint8_t *recvd_hash, struct tls_spki_entry *result);
bool tls_truststore_lookup_ex(uint8_t *recvd_hash,
                              const uint8_t *owner_id,
                              const uint8_t *issuer_id,
                              struct tls_spki_entry *result);

#endif /* TLS_TRUSTSTORE_H */
