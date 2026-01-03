#ifndef TLS_TRUSTSTORE_H
#define TLS_TRUSTSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TLS_SPKI_OWNER_ID_LEN 32
#define TLS_SPKI_HASH_MAX_LEN 32

#define TLS_TRUSTSTORE_AGE_WARN_DAYS 365 /* Warn if truststore older than this */

struct tls_truststore_header
{
    uint32_t created_timestamp; /* Unix timestamp when truststore was generated */
};
#define TLS_SPKI_HEADER_LEN sizeof(struct tls_truststore_header)

struct tls_spki_entry
{
    uint8_t owner_id[TLS_SPKI_OWNER_ID_LEN]; /* CN or identifier (null-terminated, padded) */
    uint8_t hash[TLS_SPKI_HASH_MAX_LEN];     /* SPKI hash (SHA-256)*/
};

/******************
 * @brief Initializes the trust store, checks for the SPKI appvar,
 * RSA-decrypts the signature, verifies the signature, sets a flag
 * for session if looks good.
 * @returns [bool] True if successful, false if error
 */
bool tls_truststore_init(void);

/********************
 * @brief Attempts to find an SPKI hash in the trust store.
 * @param recvd_hash    Computed hash of the SPKI field of the current certificate.
 * @param result        A tls_spki_entry struct to write the owner metadata to. NULL if you don't care.
 * @returns [bool] True if match found, false if otherwise.
 * @note So that we don't spend 12 hours on calculator doing a
 * complete full-chain validation on every TLS connection, we're
 * using pinned  SPKI hashes of common intermediate roots, and the
 * security measure is that IF our chain contains a certificate where
 * the SPKI hash matches something in our trust store, we trust the
 * remote. The current SPKI trust store will be generated every so
 * often and made available as an AppVar named 'lwIPSPKI'. The AppVar
 * will be signed with the repo owner's secret key and the public key
 * will be distributed in this application.
 */
bool tls_truststore_lookup(uint8_t *recvd_hash, struct tls_spki_entry *result);

#endif /* TLS_TRUSTSTORE_H */
