/**
 * @file p256.h
 * @author Anthony Cagliano
 * @brief P-256 (secp256r1) ECDH and ECDSA primitives.
 * @reference RFC 6979, RFC 8446, FIPS 186-4
 *
 * All functions are constant-time with respect to private key material.
 * tls_p256_verify is variable-time (safe: all inputs are public).
 *
 * Interrupt safety: each call saves IFF1, asserts DI for the duration, and
 * restores IFF1 on return. Scratch memory is wiped on entry and exit.
 */

#ifndef tls_p256_h
#define tls_p256_h

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Derive the uncompressed P-256 public key from a private key.
 *
 * @param pub   Output: 65-byte uncompressed point (0x04 || X || Y).
 * @param priv  Input: 32-byte big-endian scalar (must be in [1, n-1]).
 * @return true on success, false if priv is out of range or produces the
 *         point at infinity.
 */
bool tls_p256_publickey(uint8_t pub[65], const uint8_t priv[32]);

/**
 * @brief Perform ECDH: compute the shared secret from a private key and a
 *        peer's public key.
 *
 * @param ss    Output: 32-byte X-coordinate of the shared point.
 * @param priv  Input: 32-byte big-endian private scalar.
 * @param peer  Input: 65-byte uncompressed peer public key (0x04 || X || Y).
 * @return true on success, false if inputs are invalid or the result is the
 *         point at infinity.
 */
bool tls_p256_secret(uint8_t ss[32], const uint8_t priv[32],
                     const uint8_t peer[65]);

/**
 * @brief Sign a 32-byte hash with a P-256 private key (RFC 6979 ECDSA).
 *
 * The nonce k is derived deterministically via HMAC-DRBG (RFC 6979), so no
 * external RNG is required and the function is constant-time.
 *
 * @param sig   Output: 64-byte raw signature (r || s, big-endian, 32 bytes each).
 * @param hash  Input: 32-byte message digest to sign.
 * @param priv  Input: 32-byte big-endian private scalar.
 * @return true on success, false if priv is out of range.
 */
bool tls_p256_sign(uint8_t sig[64], const uint8_t hash[32],
                   const uint8_t priv[32]);

/**
 * @brief Verify a P-256 ECDSA signature over a 32-byte hash.
 *
 * Variable-time (safe because sig, hash, and pub are all public).
 *
 * @param sig   Input: 64-byte raw signature (r || s, big-endian, 32 bytes each).
 * @param hash  Input: 32-byte message digest that was signed.
 * @param pub   Input: 65-byte uncompressed public key (0x04 || X || Y).
 * @return true if the signature is valid, false otherwise.
 */
bool tls_p256_verify(const uint8_t sig[64], const uint8_t hash[32],
                     const uint8_t pub[65]);

#endif
