/**
 * @file x509.h
 * @author Anthony Cagliano
 * @brief X.509 certificate parsing implementation
 * @reference: RFC 5280
 */

#ifndef TLS_X509_H
#define TLS_X509_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "asn1.h"
#include "key.h"

/**
 * Parsed X.509 certificate.
 *
 * All pointer members reference the certificate's DER bytes.  When
 * from_handshake is true those bytes live in the caller's buffer (zero extra
 * allocation, pointers borrow).  When false (standalone import via
 * tls_x509_import_certificate) the trailing der[] carries a heap copy and
 * every pointer references that copy; call tls_x509_object_free() to release.
 *
 * pubkey.allocated is always false — the key material is inside der[], not
 * independently allocated.  Never call tls_key_free() on pubkey.
 */
struct tls_x509_object
{
    bool from_handshake; /**< true: pointers borrow caller's buffer; no free. */

    /* Distinguished-name fields — raw string bytes (no NUL). */
    const uint8_t *issuer_cn;     size_t issuer_cn_len;
    const uint8_t *subject_cn;    size_t subject_cn_len;

    /* Validity window — data bytes + ASN.1 tag (UTCTime or GeneralizedTime). */
    const uint8_t *valid_before;  size_t valid_before_len;  uint8_t valid_before_tag;
    const uint8_t *valid_after;   size_t valid_after_len;   uint8_t valid_after_tag;

    /* Extensions content bytes (SEQUENCE OF Extension, inner of [3] EXPLICIT). */
    const uint8_t *extensions;    size_t extensions_len;

    /* Public key extracted from SubjectPublicKeyInfo. */
    struct tls_key pubkey;

    /* DER storage (only meaningful when !from_handshake). */
    size_t  der_len;
    uint8_t der[];
};

bool tls_x509_has_valid_constraints(const uint8_t *ext_data, size_t ext_len);
bool tls_x509_has_required_ca_constraints(const uint8_t *cert_der, size_t cert_len);

/**
 * @brief Map a DER-encoded OID to an algorithm identifier.
 *
 * Recognises these signature algorithm OIDs (ECDSA verification is unimplemented):
 *   - sha256WithRSAEncryption (1.2.840.113549.1.1.11) → TLS_ALG_RSA_PKCS1_SHA256
 *   - id-RSASSA-PSS           (1.2.840.113549.1.1.10) → TLS_ALG_RSA_PSS_RSAE_SHA256
 *   - ecdsa-with-SHA256       (1.2.840.10045.4.3.2)   → TLS_ALG_ECDSA_SECP256R1_SHA256
 *
 * Also maps rsaEncryption (a public-key OID) to TLS_ALG_RSA_PKCS1_SHA256.
 * This OID-only helper does not validate PSS parameters or key restrictions.
 * Any unrecognised OID returns TLS_ALG_UNKNOWN.
 *
 * @param oid      Pointer to the raw DER OID value bytes (excluding the 0x06 tag and length).
 * @param oid_len  Number of bytes pointed to by @p oid.
 * @return  tls_alg_t identifying the algorithm, or TLS_ALG_UNKNOWN.
 */
tls_alg_t tls_x509_oid_to_sig_alg(const uint8_t *oid, size_t oid_len);

/**
 * @brief Verify a signature over arbitrary content using a key and an explicit signature scheme.
 *
 * Dispatches on alg after checking the key type:
 *   - TLS_ALG_RSA_PKCS1_SHA256       → RSASSA-PKCS1-v1.5 SHA-256
 *   - TLS_ALG_RSA_PSS_RSAE_SHA256    → RSASSA-PSS SHA-256 (saltLen=32)
 *   - TLS_ALG_ECDSA_SECP256R1_SHA256 → TLS_KEY_OP_UNSUPPORTED
 *   - TLS_ALG_UNKNOWN / encryption   → TLS_KEY_OP_UNKNOWN
 *
 * The function SHA-256 hashes @p content internally before verifying.
 *
 * @param content      Signed data (e.g. DER TBSCertificate bytes).
 * @param content_len  Length of @p content.
 * @param sig          Raw signature bytes.
 * @param sig_len      Length of @p sig.
 * @param key          Self-describing key; key->type identifies its material.
 * @param alg       Signature scheme to verify.
 * @return  tls_key_op_result_t describing the outcome.
 */
tls_key_op_result_t tls_x509_signature_verify(const uint8_t *content, size_t content_len,
                                               const uint8_t *sig, size_t sig_len,
                                               const struct tls_key *key, tls_alg_t alg);

/**
 * @brief Verify a signature over a pre-computed SHA-256 digest.
 *
 * Same dispatch as tls_x509_signature_verify() but accepts an already-hashed
 * digest instead of raw content.  Used when the TBS bytes are no longer
 * available (e.g. certificate chain walker that pre-hashes and discards TBS).
 *
 * @param digest    32-byte SHA-256 digest of the signed content.
 * @param sig       Raw signature bytes.
 * @param sig_len   Length of @p sig.
 * @param key       Self-describing key; key->type identifies its material.
 * @param alg       Signature scheme to verify.
 * @return  tls_key_op_result_t describing the outcome.
 */
tls_key_op_result_t tls_x509_signature_verify_digest(const uint8_t digest[32],
                                                      const uint8_t *sig, size_t sig_len,
                                                      const struct tls_key *key, tls_alg_t alg);

/**
 * @brief Check whether a leaf certificate is valid for the given hostname.
 *
 * Walks the subjectAltName extension (if present) for dNSName entries and
 * matches each against @p hostname, including a single leading-label
 * wildcard (e.g. "*.example.com" matches "foo.example.com" but not
 * "foo.bar.example.com" or "example.com" itself). If the certificate has
 * no subjectAltName extension at all, falls back to matching the subject
 * CommonName instead (legacy behavior; SAN takes priority when present,
 * per RFC 6125). Comparison is ASCII case-insensitive.
 *
 * @param ext_data      Raw bytes of the leaf's extensions field (cert.extensions).
 * @param ext_len       Length of @p ext_data.
 * @param subject_cn    Subject CommonName bytes for CN fallback; may be NULL.
 * @param subject_cn_len Length of @p subject_cn.
 * @param hostname      NUL-terminated hostname the connection was made to.
 * @return true if the certificate is valid for @p hostname, false otherwise
 *         (including on any parse failure -- fails closed).
 */
bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len,
                               const uint8_t *subject_cn, size_t subject_cn_len,
                               const char *hostname);

/**
 * @brief Parse an X.509 UTCTime or GeneralizedTime value into Unix seconds.
 *
 * @param data     Raw value bytes (the TLV value, not the TLV header).
 * @param len      Length of @p data.
 * @param tag      Raw ASN.1 tag byte (ASN1_UTCTIME or ASN1_GENERALIZEDTIME).
 * @param out_secs Receives the Unix timestamp on success.
 * @return true on success, false on malformed input (fails closed).
 */
bool tls_x509_time_to_unix(const uint8_t *data, size_t len, uint8_t tag,
                            uint32_t *out_secs);

/**
 * @brief Check whether @p now_secs falls within the certificate validity window.
 *
 * Reads notBefore and notAfter directly from a parsed tls_x509_object.
 * Fails closed on any parse error or inverted window.
 *
 * @param cert      Parsed certificate whose validity fields to check.
 * @param now_secs  Current time, Unix seconds.
 * @return true if now_secs is within [notBefore, notAfter].
 */
bool tls_x509_time_in_validity(const struct tls_x509_object *cert, uint32_t now_secs);

/**
 * @brief Parse a DER-encoded X.509 certificate into @p out.
 *
 * All pointer fields in @p out reference bytes inside @p cert_der.
 * The caller must keep @p cert_der live for the lifetime of @p out.
 * Sets out->from_handshake = true.
 *
 * @param cert_der  DER-encoded certificate bytes.
 * @param cert_len  Length of @p cert_der.
 * @param out       Caller-allocated object to receive parsed fields.
 * @return true on success.
 */
bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len,
                                struct tls_x509_object *out);

/**
 * @brief Decode a PEM certificate and allocate a tls_x509_object.
 *
 * Allocates a single block: tls_x509_object header + DER bytes.
 * All pointer fields reference the trailing DER.  Free with
 * tls_x509_object_free().
 *
 * @param pem_data  PEM text starting with -----BEGIN CERTIFICATE-----.
 * @param size      Length of @p pem_data in bytes.
 * @return Allocated object on success, NULL on failure.
 */
struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size);

/**
 * @brief Free a tls_x509_object allocated by tls_x509_import_certificate().
 *
 * Safe to call with NULL.  No-op when obj->from_handshake is true.
 */
void tls_x509_object_free(struct tls_x509_object *obj);

#endif
