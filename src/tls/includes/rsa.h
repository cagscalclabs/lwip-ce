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

/* Input is preserved unless inbuf == outbuf for exact in-place operation.
 * Partial input/output overlap is rejected. */
bool tls_rsa_encode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                         size_t modulus_len, const char *auth, uint8_t hash_alg);

/* Input is preserved unless inbuf == outbuf for exact in-place operation.
 * Partial input/output overlap is rejected. */
size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg);

bool tls_rsa_encrypt(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const uint8_t *pubkey, size_t keylen, uint8_t hash_alg);

bool tls_rsa_decrypt_signature(const uint8_t *signature,
                               size_t signature_len,
                               uint8_t *outbuf,
                               const uint8_t *pubkey,
                               size_t keylen);

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
 * @brief Compatibility cleanup hook.
 *
 * RSA padding primitives no longer allocate private workspace, so this is
 * currently a NULL-safe no-op kept for existing subsystem cleanup paths.
 */
void tls_rsa_padding_cleanup(void);

#endif
