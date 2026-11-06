/**
 * @file p384.h
 * @author Anthony Cagliano
 * @brief P-384 (secp384r1) ECDH and ECDSA primitives.
 * @reference RFC 6979, RFC 8446, FIPS 186-4
 *
 * All functions are constant-time with respect to private key material.
 * tls_p384_verify is variable-time (safe: all inputs are public).
 *
 * TLS use: P-384 is offered for ECDSA signatures
 * (ecdsa_secp384r1_sha384, 0x0503), used for CertificateVerify, certificate
 * chain links, and truststore anchors. The secp384r1 ECDHE group (0x0018) is
 * not currently offered, and local identity (mTLS) signing remains P-256.
 *
 * Interrupt safety: each call saves IFF1, asserts DI for the duration, and
 * restores IFF1 on return. Scratch memory is wiped on entry and exit.
 */

#ifndef tls_p384_h
#define tls_p384_h

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Derive the uncompressed P-384 public key from a private key.
 *
 * @param pub   Output: 97-byte uncompressed point (0x04 || X || Y).
 * @param priv  Input: 48-byte big-endian scalar (must be in [1, n-1]).
 * @return true on success, false if priv is out of range or produces the
 *         point at infinity.
 */
bool tls_p384_publickey(uint8_t pub[97], const uint8_t priv[48]);

/**
 * @brief Perform ECDH: compute the shared secret from a private key and a
 *        peer's public key.
 *
 * @param ss    Output: 48-byte X-coordinate of the shared point.
 * @param priv  Input: 48-byte big-endian private scalar.
 * @param peer  Input: 97-byte uncompressed peer public key (0x04 || X || Y).
 * @return true on success, false if inputs are invalid or the result is the
 *         point at infinity.
 */
bool tls_p384_secret(uint8_t ss[48], const uint8_t priv[48],
                     const uint8_t peer[97]);

/**
 * @brief Sign a 48-byte hash with a P-384 private key (RFC 6979 ECDSA).
 *
 * The nonce k is derived deterministically via HMAC-DRBG (RFC 6979) using
 * SHA-384, so no external RNG is required and the function is constant-time.
 *
 * @param sig   Output: 96-byte raw signature (r || s, big-endian, 48 each).
 * @param hash  Input: 48-byte message digest to sign.
 * @param priv  Input: 48-byte big-endian private scalar.
 * @return true on success, false if priv is out of range.
 */
bool tls_p384_sign(uint8_t sig[96], const uint8_t hash[48],
                   const uint8_t priv[48]);

/**
 * @brief Verify a P-384 ECDSA signature over a 48-byte hash.
 *
 * Variable-time (safe because sig, hash, and pub are all public).
 *
 * @param sig   Input: 96-byte raw signature (r || s, big-endian, 48 each).
 * @param hash  Input: 48-byte message digest that was signed.
 * @param pub   Input: 97-byte uncompressed public key (0x04 || X || Y).
 * @return true if the signature is valid, false otherwise.
 */
bool tls_p384_verify(const uint8_t sig[96], const uint8_t hash[48],
                     const uint8_t pub[97]);

#endif
