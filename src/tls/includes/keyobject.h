/// @file keyobject.h
/// @author ACagliano
/// @brief Module providing import and export of keyfiles.

#ifndef tls_keyobject_h
#define tls_keyobject_h

#include "asn1.h"

enum tls_key_type_flags {
    TLS_KEY_PUBLIC = 0,             /**< Indicates the @b tls_keyobject describes a public key. */
    TLS_KEY_PRIVATE = 1,            /**< Indicates the @b tls_keyobject describes a private key. */
    TLS_KEY_RSA = (0<<1),           /**< Indicates the @b tls_keyobject describes an RSA key. */
    TLS_KEY_ECC = (1<<1),           /**< Indicates the @b tls_keyobject describes an EC prime256v1 key. */
    TLS_CERTIFICATE = (1<<2)        /**< Indicates the @b tls_keyobject describes an X.509 certificate. */
};

enum tls_objectids {
    // PKCS/SECG object ids
    TLS_OID_RSA_ENCRYPTION,             /**< RSAEncryption => 1.2.840.113549.1.1.1 */
    TLS_OID_EC_PUBLICKEY,               /**< id-ecPublicKey => 1.2.840.10045.2.1 */
    TLS_OID_EC_PRIVATEKEY,              /**< id-ecPrivateKey => 1.3.132.1.8 */
    TLS_OID_EC_SECP256R1,               /**< secp256r1 (prime256v1) => 1.2.840.10045.3.1.7 */
    
    // encryption algorithm identifiers
    TLS_OID_AES_128_GCM,                /**< AES-128-GCM => 2.16.840.1.101.3.4.1.2 */
    TLS_OID_AES_128_CBC,                /**< AES-128-CBC  => 2.16.840.1.101.3.4.1.2 */
    TLS_OID_AES_256_GCM,                /**< AES-256-GCM => 2.16.840.1.101.3.4.2.1 */
    TLS_OID_AES_256_CBC,                /**< AES-256-CBC => 2.16.840.1.101.3.4.1.42 */
    // key derivation algorithm identifiers
    TLS_OID_PBKDF2,                     /**< PBKDF2 => 1.2.840.113549.1.5.12 */
    TLS_OID_PBES2,                      /**< PBES2 => 1.2.840.113549.1.5.13 */
    TLS_OID_HMAC_SHA256,                /**< HMAC-SHA256 => 1.2.840.113549.2.9 */
    
    // X.509 identifiers
    TLS_OID_SHA256_RSA_ENCRYPTION,      /**< sha256WithRSAEncryption => 1.2.840.113549.1.1.11 */
    TLS_OID_SHA384_RSA_ENCRYPTION,      /**< sha384WithRSAEncryption => 1.2.840.113549.1.1.12 */
    TLS_OID_SHA256_ECDSA                /**< sha256WithECDSA => 1.2.840.10045.4.3.2 */
};

/// @brief Array of bytearrays describing <b>OBJECT IDENTIFIERS</b> supported by this library.
extern uint8_t tls_objectid_bytes[][10];

#define TLS_PRIVKEY_RSA_FIELDS  8
#define TLS_PRIVKEY_EC_FIELDS   3
#define TLS_PUBKEY_RSA_FIELDS   2
#define TLS_PUBKEY_EC_FIELDS    1
#define TLS_CERTIFICATE_FIELDS  10


/// @brief Defines a container for metadata for various key and certificate types supported by this library.
struct tls_keyobject {
    size_t length;
    size_t type;
    union {
        /** Defines fields for an X.509 certificate. */
        union {
            struct tls_asn1_serialization fields[TLS_CERTIFICATE_FIELDS];
            struct {
                struct tls_asn1_serialization subj_signature_alg;
                struct tls_asn1_serialization issuer;
                struct tls_asn1_serialization valid_before;
                struct tls_asn1_serialization valid_after;
                struct tls_asn1_serialization subject;
                struct tls_asn1_serialization spki_raw;         /**< Raw DER bytes of SubjectPublicKeyInfo (for SPKI pinning) */
                struct tls_asn1_serialization ca_signature_alg;
                struct tls_asn1_serialization ca_signature;
                union {
                    union {
                        struct tls_asn1_serialization fields[2];
                        struct {
                            struct tls_asn1_serialization modulus;
                            struct tls_asn1_serialization exponent;
                        } field;
                    } rsa;
                    struct {
                        struct tls_asn1_serialization ec_point;
                    } ec;
                } pubkey;
            } field;
        } certificate;
        /** Defines fields for a PKCS#1, PKCS#8, or SEC1 private key. */
        union {
            union {
                struct tls_asn1_serialization fields[TLS_PRIVKEY_RSA_FIELDS];
                struct {
                    struct tls_asn1_serialization modulus;
                    struct tls_asn1_serialization public_exponent;
                    struct tls_asn1_serialization exponent;
                    struct tls_asn1_serialization p;
                    struct tls_asn1_serialization q;
                    struct tls_asn1_serialization exp1;
                    struct tls_asn1_serialization exp2;
                    struct tls_asn1_serialization coeff;
                } field;
            } rsa;
            union {
                struct tls_asn1_serialization fields[TLS_PRIVKEY_EC_FIELDS];
                struct {
                    struct tls_asn1_serialization privkey;
                    struct tls_asn1_serialization curve_id;
                    struct tls_asn1_serialization pubkey;
                } field;
            } ec;
        } privkey;
        /** Defines fields for a PKCS#1, PKCS#8, or SEC1 public key.. */
        union {
            union {
                struct tls_asn1_serialization fields[TLS_PUBKEY_RSA_FIELDS];
                struct {
                    struct tls_asn1_serialization modulus;
                    struct tls_asn1_serialization exponent;
                } field;
            } rsa;
            union {
                struct tls_asn1_serialization fields[TLS_PUBKEY_EC_FIELDS];
                struct {
                    struct tls_asn1_serialization pubkey;
                } field;
            } ec;
        } pubkey;
    } meta;
    uint8_t data[];
};


/****************************************************************************************
 * @brief Parses a PKCS#1, SEC1, or PKCS#8 private key and returns a structure populated with key metadata.
 * @param pem_data      Pointer to data to decode.
 * @param size          Length of data to decode.
 * @param password      Pointer to password to use if keyfile is encrypted. Can be @b NULL.
 * @returns A pointer to a @b tls_keyobject structure or @b NULL on error.
 * @note Data is passed by copy, which means that you can pass a pointer to data that is anywhere. Ex:
 * @code
 * uint8_t fp;
 * if((fp = ti_Open("MyKey", "r"))){
 *      struct tls_keyobject *kf = tls_keyobject_import_private(ti_GetDataPtr(fp), ti_GetSize(fp));
 *      if(!kf)     // do some error handling
 *      // do something with kf
 * }
 * @endcode
 */
struct tls_keyobject *tls_keyobject_import_private(const char *pem_data, size_t size, const char *password);


/****************************************************************************************
 * @brief Parses a PKCS#1, SEC1, or PKCS#8 public key and returns a structure populated with key metadata.
 * @param pem_data      Pointer to data to decode.
 * @param size          Length of data to decode.
 * @returns A pointer to a @b tls_keyobject strcture or @b NULL on error.
 * @note Data is passed by copy,
 */
struct tls_keyobject *tls_keyobject_import_public(const char *pem_data, size_t size);


/****************************************************************************************
 * @brief Parses a X.509 TLS certificate and returns a structure populated with certificate metadata.
 * @param pem_data      Pointer to data to decode.
 * @param size          Length of data to decode.
 * @returns A pointer to a @b tls_keyobject structure or @b NULL on error.
 * @note Data is passed by copy,
 */
struct tls_keyobject *tls_keyobject_import_certificate(const char *pem_data, size_t size);


/****************************************************************************************
 * @brief Erases a @b tls_keyobject, deallocates it, and then sets the pointer to @b NULL.
 * @param kf        Pointer to a @b tls_keyobject structure.
 */
void tls_keyobject_destroy(struct tls_keyobject *kf);

#endif
