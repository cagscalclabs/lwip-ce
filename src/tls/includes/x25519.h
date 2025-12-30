#ifndef TLS_X25519_H
#define TLS_X25519_H

#include <stdint.h>
#include <stdbool.h>

/* X25519 Elliptic Curve Diffie-Hellman for TLS 1.3 */

#define X25519_BYTES 32  /* 255 bits = 32 bytes */

/**
 * @brief x25519 scalar (private key)
 * 32 bytes, little-endian
 */
typedef uint8_t x25519_scalar[X25519_BYTES];

/**
 * @brief x25519 point (public key, x-coordinate only)
 * 32 bytes, little-endian
 */
typedef uint8_t x25519_point[X25519_BYTES];

/**
 * @brief Compute x25519 public key from private key
 * Computes: public = scalar * base_point
 * @param public_key  Output: public key (32 bytes)
 * @param private_key Input: private key (32 bytes)
 * @return true on success
 */
bool x25519_public_key(x25519_point public_key, const x25519_scalar private_key);

/**
 * @brief Compute x25519 shared secret (ECDH)
 * Computes: shared = our_private * their_public
 * @param shared_secret Output: shared secret (32 bytes)
 * @param our_private   Input: our private key (32 bytes)
 * @param their_public  Input: peer's public key (32 bytes)
 * @return true on success, false if result is zero (invalid point)
 */
bool x25519(uint8_t shared_secret[X25519_BYTES],
            const x25519_scalar our_private,
            const x25519_point their_public);

/* Internal field arithmetic (mod 2^255-19) - implemented in assembly */

/**
 * @brief Modular addition: out = (a + b) mod p
 * p = 2^255 - 19
 */
void x25519_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

/**
 * @brief Modular subtraction: out = (a - b) mod p
 */
void x25519_sub(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

/**
 * @brief Modular multiplication: out = (a * b) mod p
 */
void x25519_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

/**
 * @brief Modular squaring: out = a^2 mod p
 */
void x25519_sqr(uint8_t out[32], const uint8_t a[32]);

/**
 * @brief Modular inversion: out = a^(-1) mod p
 */
void x25519_inv(uint8_t out[32], const uint8_t a[32]);

#endif /* TLS_X25519_H */
