/**
 * @file ocsp.h
 * @brief OCSP (Online Certificate Status Protocol) support — RFC 6960.
 *
 * Steps 1–3: AIA URL extraction, CertID construction, request encoding.
 * Network dispatch lives in the altcp layer and is not declared here.
 */

#ifndef TLS_OCSP_H
#define TLS_OCSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** SHA-1 digest length used by OCSP CertID. */
#define OCSP_SHA1_LEN 20

/**
 * @brief Extract the OCSP responder URL from a certificate's AIA extension.
 *
 * Walks the AuthorityInfoAccess extension (OID 1.3.6.1.5.5.7.1.1) looking
 * for an id-ad-ocsp AccessDescription (OID 1.3.6.1.5.5.7.48.1) whose
 * accessLocation is a uniformResourceIdentifier (IA5String, context tag 6).
 * The first matching URL is written into @p url_out as a NUL-terminated
 * ASCII string; subsequent entries are ignored.
 *
 * The function allocates @p url_out with @c tls_fileio_alloc.  On success
 * the caller owns the allocation and must free it with @c tls_fileio_free.
 * On failure (no AIA extension, no OCSP entry, malformed DER, allocation
 * error) @p url_out is set to NULL.
 *
 * @param ext_data   Raw bytes of the certificate's extensions field.
 * @param ext_len    Length of @p ext_data.
 * @param url_out    Receives a pointer to a NUL-terminated URL string, or
 *                   NULL if no OCSP URL is found.
 * @return true if the extension was absent or parsed successfully (even
 *         when no OCSP URL is present); false only on a malformed AIA that
 *         cannot be safely skipped.
 */
bool tls_x509_get_ocsp_url(const uint8_t *ext_data, size_t ext_len,
                            char **url_out);

/**
 * @brief Compute the SHA-1 hashes of an issuer's Name and public key.
 *
 * Produces the two 20-byte fields needed to build an OCSP CertID:
 *   issuerNameHash  = SHA-1(issuer->subject_name DER TLV)
 *   issuerKeyHash   = SHA-1(issuer->subject_pubkey_raw)
 *
 * @param issuer_name     Pointer to the issuer's subject Name DER bytes.
 * @param issuer_name_len Length of @p issuer_name.
 * @param issuer_key      Pointer to the issuer's raw SubjectPublicKey bytes.
 * @param issuer_key_len  Length of @p issuer_key.
 * @param name_hash       Output: 20-byte SHA-1 of the issuer Name.
 * @param key_hash        Output: 20-byte SHA-1 of the issuer public key.
 * @return true on success, false on bad arguments.
 */
bool tls_ocsp_hash_issuer(const uint8_t *issuer_name,  size_t issuer_name_len,
                          const uint8_t *issuer_key,   size_t issuer_key_len,
                          uint8_t name_hash[OCSP_SHA1_LEN],
                          uint8_t  key_hash[OCSP_SHA1_LEN]);

/**
 * @brief Free a buffer allocated by tls_x509_get_ocsp_url() or
 *        tls_ocsp_build_request().
 *
 * Safe to call with NULL.
 */
void tls_ocsp_free(void *ptr);

/**
 * @brief Encode a DER OCSPRequest for a single certificate.
 *
 * Builds the minimal OCSPRequest defined in RFC 6960 §4.1.1 for one
 * certificate, using SHA-1 as the hash algorithm in CertID.  The result
 * is a complete DER-encoded OCSPRequest suitable for HTTP POST.
 *
 * Memory is allocated with @c tls_fileio_alloc; on success the caller owns
 * the buffer and must free it with @c tls_fileio_free.  On failure @p out
 * is set to NULL and @p out_len to 0.
 *
 * @param serial         Certificate serial number (DER INTEGER value bytes).
 * @param serial_len     Length of @p serial.
 * @param name_hash      20-byte SHA-1(issuer Name) from tls_ocsp_hash_issuer.
 * @param key_hash       20-byte SHA-1(issuer key) from tls_ocsp_hash_issuer.
 * @param out            Receives a pointer to the encoded request buffer.
 * @param out_len        Receives the number of bytes in the buffer.
 * @return true on success.
 */
bool tls_ocsp_build_request(const uint8_t *serial, size_t serial_len,
                             const uint8_t name_hash[OCSP_SHA1_LEN],
                             const uint8_t  key_hash[OCSP_SHA1_LEN],
                             uint8_t **out, size_t *out_len);

#endif /* TLS_OCSP_H */
