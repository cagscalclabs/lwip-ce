/*
 * File: rsa.h
 * Author: Anthony Cagliano
 * Description: Verify RSA-PSS padding on an already-decrypted signature. This function
 *              verifies that the encoded message (EM) matches the expected PSS padding
 *              structure for the given message hash. It does NOT perform RSA modular
 *              exponentiation - the caller must decrypt the signature first. Uses only
 *              fixed-size local scratch buffers. em_bits is derived internally as
 *              (em_len * 8) - 1.
 * Generated: 2026-05-26T14:35:24Z
 */

#ifndef LWIP_PUBLIC_CRYPTOGRAPHY_RSA_H
#define LWIP_PUBLIC_CRYPTOGRAPHY_RSA_H

/* powmod_exp_u24 takes a uint8_t for modulus size, with 0 encoding 256.
 * Anything larger than 256 bytes (2048 bits) is unrepresentable. */
#define RSA_MODULUS_MAX_SUPPORTED (2048 >> 3)
#define RSA_MODULUS_MIN_SUPPORTED (1024 >> 3)

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

#endif
