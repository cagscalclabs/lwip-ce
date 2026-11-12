#ifndef TLS_X509_INTERNAL_H
#define TLS_X509_INTERNAL_H

#include "../includes/x509.h"

/* Internal: decode a complete certificate signature AlgorithmIdentifier.
 * False means malformed or unsupported parameters; never guess PSS defaults. */
bool tls_x509_signature_algorithm(const struct tls_asn1_tlv *identifier,
                                  tls_alg_t *alg);

/* Internal: parse one strict-DER INTEGER (r or s of an ECDSA-Sig-Value)
 * from der[0..len) into a big-endian, left-zero-padded 32-byte buffer.
 * Rejects: wrong tag, long-form/zero/over-33 length, length past len,
 * negative values (first content byte >= 0x80), and non-minimal encodings
 * (a leading 0x00 not followed by a byte >= 0x80).  Returns a pointer just
 * past the INTEGER, or NULL on error (out contents then unspecified). */
const uint8_t *tls_ecdsa_parse_int(const uint8_t *der, size_t len,
                                   uint8_t out[32]);

/* Internal path-builder helpers. Names are serialized as a GeneralName tag,
 * a three-byte big-endian length, and raw value bytes. The mandatory
 * directoryName form stores the complete inner Name TLV. */
bool tls_x509_collect_constraint_names(const struct tls_x509_object *cert,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len);
bool tls_x509_name_constraints_allow(const struct tls_x509_object *issuer,
                                     const uint8_t *names,
                                     size_t names_len);

#endif
