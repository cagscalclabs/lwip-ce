/**
 * @file rsa.h
 * @author jacobly (modexp)
 * @author Anthony Cagliano
 * @brief Provides RSA implementation for between 1024 and 2048 bit keys,
 * including encryption and signature verification.
 * @reference: RFC 8017
 */

#ifndef tls_rsa_h
#define tls_rsa_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* powmod_exp_u24 takes a uint8_t for modulus size, with 0 encoding 256.
 * Anything larger than 256 bytes (2048 bits) is unrepresentable. */
#define RSA_MODULUS_MAX_SUPPORTED (2048 >> 3)
#define RSA_MODULUS_MIN_SUPPORTED (1024 >> 3)

/* Static .bss scratch for RSA OAEP/PSS encoded-message work (e.g. the
 * decrypted-signature buffer). Replaces a 256-byte stack local in the deep
 * crypto call chain. Defined in src/tls/core/share/memory.s. Pure scratch:
 * its contents do not persist across calls and callers must not assume any
 * particular initial value. Sized for the max supported modulus (RSA-2048). */
#define RSA_TRANSIENT_SIZE RSA_MODULUS_MAX_SUPPORTED
extern uint8_t __rsa_transient[RSA_TRANSIENT_SIZE];

#define RSA_PUBLIC_EXP 65537

/**
 * RSA public (or private) key as explicit exponent + modulus byte arrays.
 * Both public and private keys follow the same layout; the caller controls
 * which exponent is loaded.  Byte arrays are big-endian, no DER wrapping.
 *
 * For the common case of a public key with exponent 65537, initialise with:
 *   static const uint8_t exp[] = {0x01, 0x00, 0x01};
 *   struct tls_rsa_key key = { sizeof(exp), exp, mod_len, mod };
 * The RSA entry points decode these big-endian bytes for powmod_exp_u24.
 */
struct tls_rsa_key {
    size_t         exp_len;   /**< length of exponent in bytes (typically 3) */
    const uint8_t *exponent;  /**< big-endian exponent bytes                 */
    size_t         mod_len;   /**< length of modulus in bytes                */
    const uint8_t *modulus;   /**< big-endian modulus bytes                  */
};

/* Input is preserved unless inbuf == outbuf for exact in-place operation.
 * Partial input/output overlap is rejected. */
bool tls_rsa_encode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                         size_t modulus_len, const char *auth, uint8_t hash_alg);

/* Input is preserved unless inbuf == outbuf for exact in-place operation.
 * Partial input/output overlap is rejected. */
size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg);

bool tls_rsa_encrypt(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                     const struct tls_rsa_key *key, uint8_t hash_alg);

bool tls_rsa_decrypt_signature(const uint8_t *signature,
                               size_t signature_len,
                               uint8_t *outbuf,
                               const struct tls_rsa_key *key);

/**
 * @brief Verify RSA-PSS padding on an already-decrypted signature.
 *
 * This function verifies that the encoded message (EM) matches the expected
 * PSS padding structure for the given message hash. It does NOT perform
 * RSA modular exponentiation - the caller must decrypt the signature first.
 *
 * Uses only fixed-size local scratch buffers.
 * em_bits is derived internally as (em_len * 8) - 1.
 *
 * @param encoded_msg   The decrypted signature (EM), big-endian, emLen bytes
 * @param em_len        Length of encoded message in bytes (same as modulus length)
 * @param mhash         Hash of the message being verified
 * @param mhash_len     Length of mhash (must equal hash digest length)
 * @param hash_alg      Hash algorithm ID (TLS_HASH_SHA256, etc.)
 * @return true if PSS padding is valid, false otherwise
 */
bool tls_rsa_pss_verify(const uint8_t *encoded_msg, size_t em_len,
                        const uint8_t *mhash, size_t mhash_len,
                        uint8_t hash_alg);

/**
 * @brief Verify an RSASSA-PKCS1-v1.5 signature over a precomputed SHA-256 digest.
 *
 * Decrypts @p sig with the public key, then validates the EMSA-PKCS1-v1.5 encoding:
 *   EM = 0x00 || 0x01 || 0xFF...0xFF || 0x00 || DigestInfo(SHA-256, digest)
 *
 * @param sig      Raw signature bytes.
 * @param sig_len  Length of @p sig (must equal key->mod_len).
 * @param digest   SHA-256 digest of the signed content (32 bytes).
 * @param key      RSA public key.
 * @return true iff the signature is well-formed and the digest matches.
 */
bool tls_rsa_pkcs1_v15_sha256_verify(const uint8_t *sig, size_t sig_len,
                                     const uint8_t digest[32],
                                     const struct tls_rsa_key *key);

#endif
