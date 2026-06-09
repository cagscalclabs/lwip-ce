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
