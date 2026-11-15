#ifndef TLS_OCSP_INTERNAL_H
#define TLS_OCSP_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "../includes/key.h"
#include "../includes/ocsp.h"

/* OCSP CertID issuerKeyHash for an issuer known only by its key (a truststore
 * root): SHA-1 of the EC point, or of the DER RSAPublicKey re-encoded from
 * the modulus and exponent. */
bool tls_ocsp_hash_key(const struct tls_key *key, uint8_t key_hash[OCSP_SHA1_LEN]);

#endif /* TLS_OCSP_INTERNAL_H */
