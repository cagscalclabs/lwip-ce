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

struct tls_x509_parse_result
{
    struct tls_asn1_serialization *issuer_cn;
    struct tls_asn1_serialization *subject_cn;
    struct tls_asn1_serialization *valid_before;
    struct tls_asn1_serialization *valid_after;
    struct tls_asn1_serialization *spki_raw;
    struct tls_asn1_serialization *spki_algorithm;
    struct tls_asn1_serialization *spki_key_bits;
    struct tls_asn1_serialization *extensions;
};

struct tls_x509_object
{
    size_t length;
    size_t type;
    size_t der_len;
    struct tls_asn1_serialization fields[13];
    struct tls_x509_parse_result parsed;
    uint8_t der[];
};

bool tls_x509_has_valid_constraints(const uint8_t *ext_data, size_t ext_len);
bool tls_x509_has_required_ca_constraints(const uint8_t *cert_der, size_t cert_len);

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
 * @param ext_data    Raw bytes of the leaf's extensions field (parsed.extensions->data).
 * @param ext_len     Length of @p ext_data.
 * @param subject_cn  Leaf's parsed subject CommonName (CN fallback), may be NULL.
 * @param hostname    NUL-terminated hostname the connection was made to.
 * @return true if the certificate is valid for @p hostname, false otherwise
 *         (including on any parse failure -- fails closed).
 */
bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len,
                               const struct tls_asn1_serialization *subject_cn,
                               const char *hostname);

/**
 * @brief Parse an X.509 UTCTime or GeneralizedTime value into Unix seconds.
 *
 * Supports the DER-mandated encodings: UTCTime "YYMMDDHHMMSSZ" (two-digit
 * year, RFC 5280 pivot: 50-99 => 19xx, 00-49 => 20xx) and GeneralizedTime
 * "YYYYMMDDHHMMSSZ". Both must be UTC (trailing 'Z'); fractional seconds
 * and explicit offsets are not accepted (DER requires 'Z' with no fraction
 * for certificate validity fields).
 *
 * @param tlv      Parsed ASN1_UTCTIME or ASN1_GENERALIZEDTIME TLV.
 * @param out_secs Receives the Unix timestamp on success.
 * @return true on success, false on malformed input (fails closed).
 */
bool tls_x509_time_to_unix(const struct tls_asn1_serialization *tlv, uint32_t *out_secs);

/**
 * @brief Check whether the current time falls within [valid_before, valid_after].
 *
 * @param valid_before  Parsed notBefore field (ASN1_UTCTIME/ASN1_GENERALIZEDTIME).
 * @param valid_after   Parsed notAfter field (ASN1_UTCTIME/ASN1_GENERALIZEDTIME).
 * @param now_secs      Current time, Unix seconds (caller-supplied so this stays testable).
 * @return true if now_secs is within the validity window, false otherwise
 *         (including on any parse failure -- fails closed).
 */
bool tls_x509_time_in_validity(const struct tls_asn1_serialization *valid_before,
                               const struct tls_asn1_serialization *valid_after,
                               uint32_t now_secs);
bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len,
                                struct tls_asn1_serialization fields[13],
                                struct tls_x509_parse_result *out);
bool tls_x509_import_and_parse_certificate(const char *pem_data, size_t size,
                                           uint8_t *der_out, size_t der_out_len,
                                           size_t *der_written,
                                           struct tls_asn1_serialization fields[13],
                                           struct tls_x509_parse_result *out);
struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size);
void tls_x509_object_destroy(struct tls_x509_object *obj);

#endif
