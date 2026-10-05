#ifndef TLS_X509_INTERNAL_H
#define TLS_X509_INTERNAL_H

#include "../includes/x509.h"

/* Internal: decode a complete certificate signature AlgorithmIdentifier.
 * False means malformed or unsupported parameters; never guess PSS defaults. */
bool tls_x509_signature_algorithm(const struct tls_asn1_tlv *identifier,
                                  tls_alg_t *alg);

#endif
