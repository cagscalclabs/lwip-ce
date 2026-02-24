#ifndef TLS_PKCS8_H
#define TLS_PKCS8_H

#include <stddef.h>
#include "asn1.h"
#include "keyobject.h"

struct tls_keyobject;

typedef enum _pkcs8_error
{
    TLS_PKCS8_ERR_NONE,
    TLS_PKCS8_ERR_INVALID_ARG,
    TLS_PKCS8_ERR_PEM_DECODE_FAIL,
    TLS_PKCS8_ERR_ALLOC_FAIL,
    TLS_PKCS8_ERR_PASSWORD_REQUIRED,
    TLS_PKCS8_ERR_UNSUPPORTED_ALG,
    TLS_PKCS8_ERR_DECRYPT_FAIL,
} tls_pkcs8_error_t;

char *tls_pkcs8_strerror(tls_pkcs8_error_t error);

/*
// RSA private key fields
struct
{
    struct tls_asn1_serialization modulus;
    struct tls_asn1_serialization public_exponent;
    struct tls_asn1_serialization exponent;
    struct tls_asn1_serialization p;
    struct tls_asn1_serialization q;
    struct tls_asn1_serialization exp1;
    struct tls_asn1_serialization exp2;
    struct tls_asn1_serialization coeff;
} field;
 // EC private key fields
 {
    struct tls_asn1_serialization privkey;
    struct tls_asn1_serialization curve_id;
    struct tls_asn1_serialization pubkey;
} field;
 // RSA public key fields
 {
    struct tls_asn1_serialization modulus;
    struct tls_asn1_serialization exponent;
} field;
 struct
 // ECPoint field (public key only)
{
    struct tls_asn1_serialization pubkey;
} field;
 */
#define TLS_PKCS8_MAX_FIELDS 8
struct tls_pkcs8_object
{
    size_t total_len;
    uint8_t type;
    uint8_t algorithm;
    struct
    {
        size_t len;
        struct tls_asn1_serialization fields[TLS_PKCS8_MAX_FIELDS];
    } serialization;
    uint8_t data[];
};

enum tls_pkcs8_type
{
    TLS_PKCS8_PUBLIC,
    TLS_PKCS8_PRIVATE,
    TLS_PKCS8_ENCRYPTED_PRIVATE,
    TLS_PKCS1_PUBLIC,
    TLS_PKCS1_PRIVATE,
    TLS_SECG1_PUBLIC,
    TLS_SECG1_PRIVATE
};

enum tls_pkcs8_algorithm
{
    TLS_PKCS8_ALG_UNKNOWN = 0,
    TLS_PKCS8_ALG_RSA = 1,
    TLS_PKCS8_ALG_EC = 2
};

struct tls_pkcs8_object *tls_pkcs8_import(const char *pem_data, size_t size, const char *password, tls_pkcs8_error_t *error);
struct tls_keyobject *tls_pkcs8_import_private(const char *pem_data, size_t size, const char *password);
struct tls_keyobject *tls_pkcs8_import_public(const char *pem_data, size_t size);
struct tls_pkcs8_object *tls_pkcs8_object_import_private(const char *pem_data, size_t size, const char *password);
struct tls_pkcs8_object *tls_pkcs8_object_import_public(const char *pem_data, size_t size);
void tls_pkcs8_object_destroy(struct tls_pkcs8_object *obj);

#endif
